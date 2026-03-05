"""
Lambda 2: QuickBooks Poster

Triggered by SQS when an invoice is approved.
Reads invoice from DynamoDB, posts to QuickBooks, attaches PDF.
"""

import os
import json
import logging
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Optional, Dict, Any

import boto3
import requests
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")
QB_SECRET_ARN = os.environ.get("QB_SECRET_ARN", "")
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "")
S3_BUCKET = os.environ.get("S3_BUCKET", "")
SNS_ALERT_TOPIC = os.environ.get("SNS_ALERT_TOPIC", "")

# Test flags
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"

# Status constants
STATUS_APPROVED = "APPROVED"
STATUS_POSTING = "POSTING"  # Claimed by worker
STATUS_POSTED = "POSTED"
STATUS_POST_FAILED = "POST_FAILED"

# QuickBooks API
QB_API_BASE = "https://quickbooks.api.intuit.com/v3/company"
QB_SANDBOX_API_BASE = "https://sandbox-quickbooks.api.intuit.com/v3/company"
QB_AUTH_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"

# Lease timeout for POSTING claims (if Lambda dies mid-post)
CLAIM_LEASE_MINUTES = 15

# Use sandbox in dev
USE_SANDBOX = os.environ.get("QB_USE_SANDBOX", "false").lower() == "true"

# AWS clients
secrets_client = boto3.client("secretsmanager")
dynamodb = boto3.resource("dynamodb")
s3_client = boto3.client("s3")
sns_client = boto3.client("sns")

table = dynamodb.Table(DYNAMODB_TABLE) if DYNAMODB_TABLE else None


def compute_qb_doc_number(bill_reference: str, entry_id: str) -> str:
    """
    Compute QB DocNumber - must match extractor logic exactly.
    Always replaces slashes and truncates to 21 chars (QB limit).
    """
    doc_number = (bill_reference or entry_id).replace("/", "-")
    return doc_number[:21]


class QuickBooksClient:
    """QuickBooks Online API client."""
    
    def __init__(self, client_id: str, client_secret: str, refresh_token: str, realm_id: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = refresh_token
        self.realm_id = realm_id
        self.access_token: Optional[str] = None
        self.token_expires_at: Optional[datetime] = None
        self.base_url = QB_SANDBOX_API_BASE if USE_SANDBOX else QB_API_BASE
    
    def _refresh_access_token(self) -> bool:
        """Refresh OAuth access token."""
        try:
            resp = requests.post(
                QB_AUTH_URL,
                data={"grant_type": "refresh_token", "refresh_token": self.refresh_token},
                auth=(self.client_id, self.client_secret),
                headers={"Accept": "application/json"},
                timeout=30
            )
            resp.raise_for_status()
            data = resp.json()
            
            self.access_token = data["access_token"]
            self.token_expires_at = datetime.utcnow() + timedelta(seconds=data.get("expires_in", 3600) - 60)
            
            if data.get("refresh_token"):
                self.refresh_token = data["refresh_token"]
            
            logger.info("QB access token refreshed")
            return True
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            return False
    
    def _ensure_token(self):
        """Ensure valid access token."""
        if not self.access_token or datetime.utcnow() >= self.token_expires_at:
            if not self._refresh_access_token():
                raise Exception("Failed to refresh QB token")
    
    def _request(self, method: str, endpoint: str, data: dict = None, params: dict = None) -> dict:
        """Make authenticated QB API request."""
        self._ensure_token()
        
        url = f"{self.base_url}/{self.realm_id}/{endpoint}"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        
        resp = requests.request(method, url, headers=headers, json=data, params=params, timeout=60)
        
        if resp.status_code >= 400:
            logger.error(f"QB API error: {resp.status_code} - {resp.text}")
        
        resp.raise_for_status()
        return resp.json()
    
    def find_vendor(self, vendor_name: str) -> Optional[dict]:
        """Find vendor by exact name, then fuzzy LIKE fallback."""
        safe_name = vendor_name.replace("'", "\\'")
        
        # Exact match first
        query = f"SELECT * FROM Vendor WHERE DisplayName = '{safe_name}'"
        try:
            result = self._request("GET", "query", params={"query": query})
            vendors = result.get("QueryResponse", {}).get("Vendor", [])
            if vendors:
                return vendors[0]
        except Exception as e:
            logger.warning(f"Vendor exact lookup failed: {e}")
            return None
        
        # Fuzzy fallback - catch punctuation/case variants
        query = f"SELECT * FROM Vendor WHERE DisplayName LIKE '%{safe_name}%'"
        try:
            result = self._request("GET", "query", params={"query": query})
            vendors = result.get("QueryResponse", {}).get("Vendor", [])
            
            if not vendors:
                return None
            
            # Normalize and compare
            def normalize(name: str) -> str:
                return "".join(c.lower() for c in (name or "") if c.isalnum())
            
            target = normalize(vendor_name)
            for v in vendors:
                if normalize(v.get("DisplayName", "")) == target:
                    logger.info(f"Fuzzy vendor match: '{v.get('DisplayName')}' for '{vendor_name}'")
                    return v
            
            # No normalized match among LIKE results
            return None
        except Exception as e:
            logger.warning(f"Vendor fuzzy lookup failed: {e}")
            return None
    
    def create_vendor(self, vendor_name: str) -> dict:
        """Create new vendor. Caller should have tried find_vendor first."""
        logger.info(f"Creating new QB vendor: '{vendor_name}'")
        result = self._request("POST", "vendor", {"DisplayName": vendor_name})
        return result.get("Vendor", {})
    
    def find_account(self, account_name: str) -> Optional[dict]:
        """
        Find account by name. Prefers exact FullyQualifiedName or Name match.
        Raises if multiple LIKE matches but no exact match (ambiguous).
        """
        search_name = account_name.split(":")[-1] if ":" in account_name else account_name
        safe_name = search_name.replace("'", "\\'")
        query = f"SELECT * FROM Account WHERE Name LIKE '%{safe_name}%'"
        
        try:
            result = self._request("GET", "query", params={"query": query})
            accounts = result.get("QueryResponse", {}).get("Account", [])
            
            if not accounts:
                return None
            
            # Exact match on FullyQualifiedName (e.g. "PRODUCTION COSTS - ALWAYS USE:Freight In")
            for acc in accounts:
                if acc.get("FullyQualifiedName") == account_name:
                    return acc
            
            # Exact match on Name (leaf name, e.g. "Freight In")
            for acc in accounts:
                if acc.get("Name") == search_name:
                    return acc
            
            # No exact match - ambiguous
            matched_names = [acc.get("FullyQualifiedName", acc.get("Name", "?")) for acc in accounts]
            logger.error(
                f"Ambiguous account match for '{account_name}': "
                f"found {len(accounts)} results: {matched_names}"
            )
            raise Exception(
                f"Ambiguous account: '{account_name}' matched {len(accounts)} accounts: {matched_names}. "
                f"Fix the qb_category mapping or QB chart of accounts."
            )
        except requests.exceptions.HTTPError:
            raise
        except Exception as e:
            if "Ambiguous" in str(e):
                raise
            logger.warning(f"Account lookup failed: {e}")
            return None
    
    def bill_exists(self, doc_number: str, vendor_name: str) -> tuple:
        """
        Check if bill already exists for this vendor.
        Returns (exists: bool, qb_bill_id: Optional[str]).
        Queries by DocNumber, then compares VendorRef.name to avoid
        false positives from DocNumber collisions across vendors.
        """
        safe_num = doc_number.replace("'", "\\'")
        query = f"SELECT Id, DocNumber, VendorRef FROM Bill WHERE DocNumber = '{safe_num}'"
        
        def normalize(name: str) -> str:
            return "".join(c.lower() for c in (name or "") if c.isalnum())
        
        try:
            result = self._request("GET", "query", params={"query": query})
            bills = result.get("QueryResponse", {}).get("Bill", [])
            
            if not bills:
                return False, None
            
            # Check for vendor match among bills with this DocNumber
            for bill in bills:
                qb_vendor = bill.get("VendorRef", {}).get("name", "")
                if normalize(qb_vendor) == normalize(vendor_name):
                    qb_id = bill.get("Id")
                    logger.info(f"Duplicate found: QB Bill {qb_id} for {vendor_name} doc {doc_number}")
                    return True, qb_id
            
            # DocNumber exists but different vendor - not a duplicate, log warning
            qb_vendors = [b.get("VendorRef", {}).get("name", "") for b in bills]
            logger.warning(
                f"DocNumber {doc_number} exists in QB but vendor differs: "
                f"QB={qb_vendors} vs posting='{vendor_name}' - proceeding with post"
            )
            return False, None
        except Exception as e:
            logger.error(f"Duplicate check failed for {doc_number}: {e}")
            raise
    
    def create_bill(self, bill_data: dict) -> dict:
        """Create bill."""
        result = self._request("POST", "bill", bill_data)
        return result.get("Bill", {})
    
    def upload_attachment(self, entity_type: str, entity_id: str, 
                          filename: str, content: bytes) -> dict:
        """Upload attachment to entity."""
        self._ensure_token()
        
        url = f"{self.base_url}/{self.realm_id}/upload"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
        }
        
        files = {"file_content_0": (filename, content, "application/pdf")}
        data = {
            "AttachableRef": json.dumps([{
                "EntityRef": {"type": entity_type, "value": entity_id}
            }])
        }
        
        resp = requests.post(url, headers=headers, files=files, data=data, timeout=120)
        resp.raise_for_status()
        return resp.json()


def get_qb_credentials() -> dict:
    """Get QB credentials from Secrets Manager."""
    if not QB_SECRET_ARN:
        return {
            "client_id": os.environ.get("QB_CLIENT_ID", ""),
            "client_secret": os.environ.get("QB_CLIENT_SECRET", ""),
            "use_sandbox": os.environ.get("QB_USE_SANDBOX", "false").lower() == "true",
            "companies": json.loads(os.environ.get("QB_COMPANIES", "{}")),
        }
    
    try:
        resp = secrets_client.get_secret_value(SecretId=QB_SECRET_ARN)
        return json.loads(resp["SecretString"])
    except ClientError as e:
        logger.error(f"Failed to get QB credentials: {e}")
        raise


def update_qb_refresh_token(company: str, new_refresh_token: str, credentials: dict):
    """Update refresh token for a specific company in Secrets Manager."""
    if not QB_SECRET_ARN:
        return
    
    try:
        if company in credentials.get("companies", {}):
            credentials["companies"][company]["refresh_token"] = new_refresh_token
            secrets_client.put_secret_value(SecretId=QB_SECRET_ARN, SecretString=json.dumps(credentials))
            logger.info(f"Updated QB refresh token for {company}")
    except ClientError as e:
        logger.error(f"Failed to update QB credentials: {e}")


def get_invoice(entry_id: str) -> Optional[dict]:
    """Get invoice from DynamoDB."""
    if not table:
        return None
    
    try:
        resp = table.get_item(Key={"entry_id": entry_id})
        item = resp.get("Item")
        if not item:
            return None
        # Decimal → float (not str) so numeric fields stay numeric after roundtrip
        return json.loads(json.dumps(item, default=lambda o: float(o) if isinstance(o, Decimal) else str(o)))
    except ClientError as e:
        logger.error(f"DynamoDB get failed: {e}")
        return None


def claim_invoice(entry_id: str) -> bool:
    """
    Attempt to claim invoice for processing.
    Uses conditional update: APPROVED → POSTING (or stale POSTING → POSTING).
    Only one worker can claim successfully.
    """
    if not table:
        return True
    
    now = datetime.utcnow()
    lease_cutoff = (now - timedelta(minutes=CLAIM_LEASE_MINUTES)).isoformat()
    
    try:
        # Try APPROVED → POSTING first
        table.update_item(
            Key={"entry_id": entry_id},
            UpdateExpression="SET #status = :posting, claim_time = :ts",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":posting": STATUS_POSTING,
                ":approved": STATUS_APPROVED,
                ":ts": now.isoformat()
            },
            ConditionExpression="#status = :approved"
        )
        logger.info(f"Claimed invoice {entry_id} for processing")
        return True
    except ClientError as e:
        if e.response['Error']['Code'] != 'ConditionalCheckFailedException':
            logger.error(f"Claim failed: {e}")
            return False
    
    # APPROVED claim failed - try re-claiming stale POSTING
    try:
        table.update_item(
            Key={"entry_id": entry_id},
            UpdateExpression="SET claim_time = :ts",
            ExpressionAttributeValues={
                ":posting": STATUS_POSTING,
                ":ts": now.isoformat(),
                ":cutoff": lease_cutoff,
            },
            ConditionExpression="#status = :posting AND claim_time < :cutoff",
            ExpressionAttributeNames={"#status": "status"},
        )
        logger.warning(f"Re-claimed stale POSTING invoice {entry_id}")
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            logger.warning(f"Invoice {entry_id} already claimed or not in claimable state")
        else:
            logger.error(f"Re-claim failed: {e}")
        return False


def update_invoice_status(entry_id: str, status: str, qb_bill_id: str = None, error: str = None):
    """Update invoice status in DynamoDB."""
    if not table:
        return
    
    try:
        update_expr = "SET #status = :status, posted_at = :ts"
        expr_values = {":status": status, ":ts": datetime.utcnow().isoformat()}
        
        if qb_bill_id:
            update_expr += ", qb_bill_id = :qb_id"
            expr_values[":qb_id"] = qb_bill_id
        
        if error:
            update_expr += ", post_error = :error"
            expr_values[":error"] = error
        
        table.update_item(
            Key={"entry_id": entry_id},
            UpdateExpression=update_expr,
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues=expr_values
        )
    except ClientError as e:
        logger.error(f"DynamoDB update failed: {e}")


def get_pdf_from_s3(s3_key: str) -> Optional[bytes]:
    """Get PDF from S3."""
    if not S3_BUCKET or not s3_key:
        return None
    
    try:
        resp = s3_client.get_object(Bucket=S3_BUCKET, Key=s3_key)
        return resp["Body"].read()
    except ClientError as e:
        logger.error(f"S3 get failed: {e}")
        return None


def move_pdf(source_key: str, dest_key: str):
    """Move PDF from pending to posted."""
    if not S3_BUCKET or not source_key:
        return
    
    try:
        s3_client.copy_object(
            Bucket=S3_BUCKET,
            CopySource={"Bucket": S3_BUCKET, "Key": source_key},
            Key=dest_key
        )
        s3_client.delete_object(Bucket=S3_BUCKET, Key=source_key)
        logger.info(f"Moved PDF to {dest_key}")
    except ClientError as e:
        logger.error(f"S3 move failed: {e}")


def send_alert(subject: str, message: str):
    """Send SNS alert."""
    if SNS_ALERT_TOPIC:
        try:
            sns_client.publish(TopicArn=SNS_ALERT_TOPIC, Subject=subject[:100], Message=message)
        except Exception as e:
            logger.error(f"Alert failed: {e}")


def normalize_date(date_val) -> Optional[str]:
    """Normalize date to YYYY-MM-DD for QB API. Handles date, datetime, ISO strings."""
    if not date_val:
        return None
    date_str = str(date_val)[:10]  # Truncate any time/timezone portion
    try:
        # Validate it's actually a date
        datetime.strptime(date_str, "%Y-%m-%d")
        return date_str
    except (ValueError, TypeError):
        logger.warning(f"Invalid date format: {date_val}")
        return None


def build_qb_bill(invoice: dict, qb: QuickBooksClient, account_cache: dict) -> dict:
    """Build QB bill payload."""
    
    # Find or create vendor
    vendor = qb.find_vendor(invoice["vendor_name"])
    if not vendor:
        logger.info(f"Creating vendor: {invoice['vendor_name']}")
        vendor = qb.create_vendor(invoice["vendor_name"])
    
    vendor_id = vendor.get("Id")
    if not vendor_id:
        raise Exception(f"No vendor ID for {invoice['vendor_name']}")
    
    # Build line items
    lines = []
    for idx, line in enumerate(invoice.get("line_items", []), start=1):
        qb_category = line.get("qb_category", "Inventory Asset:DTC Inventory")
        
        if qb_category not in account_cache:
            account = qb.find_account(qb_category)
            account_cache[qb_category] = account.get("Id") if account else None
        
        account_id = account_cache.get(qb_category)
        if not account_id:
            raise Exception(f"Account not found: {qb_category}")
        
        lines.append({
            "Id": str(idx),
            "LineNum": idx,
            "Amount": round(line.get("subtotal", 0), 2),
            "DetailType": "AccountBasedExpenseLineDetail",
            "AccountBasedExpenseLineDetail": {"AccountRef": {"value": account_id}},
            "Description": (line.get("description") or "")[:4000],
        })
    
    # Reconcile line totals with bill total (avoid QB rejection from rounding drift)
    if lines:
        line_total = sum(l["Amount"] for l in lines)
        bill_total = round(float(invoice.get("amount_untaxed", invoice.get("amount_total", 0))), 2)
        diff = round(bill_total - line_total, 2)
        
        if 0 < abs(diff) <= 0.05:
            # Adjust last line by the penny difference
            lines[-1]["Amount"] = round(lines[-1]["Amount"] + diff, 2)
            logger.info(f"Adjusted last line by ${diff:+.2f} to match bill total ${bill_total:.2f}")
        elif abs(diff) > 0.05:
            logger.warning(f"Line total ${line_total:.2f} differs from bill total ${bill_total:.2f} by ${diff:.2f}")
    
    bill = {
        "VendorRef": {"value": vendor_id},
        "Line": lines,
        "DocNumber": compute_qb_doc_number(invoice.get("bill_reference", ""), invoice.get("entry_id", "")),
        "PrivateNote": (invoice.get("po_number") or "")[:4000],
    }
    
    txn_date = normalize_date(invoice.get("bill_date"))
    if txn_date:
        bill["TxnDate"] = txn_date
    
    due_date = normalize_date(invoice.get("due_date"))
    if due_date:
        bill["DueDate"] = due_date
    
    return bill


def process_invoice(entry_id: str) -> bool:
    """Process single approved invoice."""
    
    logger.info(f"Processing: {entry_id}")
    
    # Get invoice
    invoice = get_invoice(entry_id)
    if not invoice:
        logger.error(f"Invoice not found: {entry_id}")
        return False
    
    # Check status - skip if already posted
    current_status = invoice.get("status")
    if current_status == STATUS_POSTED:
        logger.info(f"Already posted: {entry_id}")
        return True
    
    if current_status == STATUS_POSTING:
        # Check if claim is stale (Lambda died mid-post)
        claim_time = invoice.get("claim_time", "")
        if claim_time:
            try:
                claimed_at = datetime.fromisoformat(claim_time)
                elapsed = (datetime.utcnow() - claimed_at).total_seconds() / 60
                if elapsed > CLAIM_LEASE_MINUTES:
                    logger.warning(f"Stale POSTING claim on {entry_id} ({elapsed:.0f}min old), re-claiming")
                    # Fall through to claim logic below
                else:
                    logger.info(f"Already being processed by another worker: {entry_id} ({elapsed:.0f}min ago)")
                    return True
            except (ValueError, TypeError):
                logger.warning(f"Invalid claim_time for {entry_id}, re-claiming")
        else:
            logger.warning(f"POSTING with no claim_time for {entry_id}, re-claiming")
    
    if current_status not in (STATUS_APPROVED, STATUS_POSTING):
        logger.warning(f"Invoice not in claimable state: {entry_id} (status={current_status})")
        return False
    
    # Try to claim the invoice (atomic APPROVED → POSTING)
    if not claim_invoice(entry_id):
        logger.info(f"Could not claim {entry_id} - likely already processed")
        return True  # Not an error, just already handled
    
    company = invoice.get("company", "Unknown")
    
    if DRY_RUN:
        logger.info(f"[DRY RUN] Would post {entry_id} to QB for {company}")
        # Revert claim so invoice can be posted when DRY_RUN is turned off
        update_invoice_status(entry_id, STATUS_APPROVED, error="DRY_RUN - not posted")
        return True
    
    try:
        # Get QB credentials
        credentials = get_qb_credentials()
        companies = credentials.get("companies", {})
        company_creds = companies.get(company)
        
        if not company_creds:
            raise Exception(f"No QB credentials for company: {company}")
        
        realm_id = company_creds.get("realm_id")
        refresh_token = company_creds.get("refresh_token")
        
        if not realm_id or not refresh_token:
            raise Exception(f"Missing realm_id or refresh_token for company: {company}")
        
        # Initialize QB client
        qb = QuickBooksClient(
            client_id=credentials["client_id"],
            client_secret=credentials["client_secret"],
            refresh_token=refresh_token,
            realm_id=realm_id
        )
        
        # Check for duplicate in QB (use same DocNumber as we'll post)
        qb_doc_number = compute_qb_doc_number(
            invoice.get("bill_reference", ""), invoice.get("entry_id", "")
        )
        vendor_name = invoice.get("vendor_name", "")
        if qb_doc_number:
            already_exists, existing_qb_id = qb.bill_exists(qb_doc_number, vendor_name)
            if already_exists:
                logger.warning(f"Bill already exists in QB: {qb_doc_number} (QB ID: {existing_qb_id})")
                update_invoice_status(entry_id, STATUS_POSTED, qb_bill_id=existing_qb_id or "EXISTING")
                return True
        
        # Build and create bill
        account_cache = {}
        bill_data = build_qb_bill(invoice, qb, account_cache)
        created_bill = qb.create_bill(bill_data)
        
        qb_bill_id = created_bill.get("Id")
        if not qb_bill_id:
            raise Exception("Bill created but no ID returned")
        
        logger.info(f"Created QB bill: {qb_bill_id}")
        
        # Attach PDF
        pdf_key = invoice.get("pdf_s3_key")
        if pdf_key:
            pdf_data = get_pdf_from_s3(pdf_key)
            if pdf_data:
                filename = invoice.get("pdf_filename", f"{entry_id.replace('/', '-')}.pdf")
                try:
                    qb.upload_attachment("Bill", qb_bill_id, filename, pdf_data)
                    logger.info(f"Attached PDF to bill")
                except Exception as e:
                    logger.warning(f"PDF attachment failed (non-fatal): {e}")
        
        # Update refresh token if changed
        if qb.refresh_token != refresh_token:
            update_qb_refresh_token(company, qb.refresh_token, credentials)
        
        # Update status
        update_invoice_status(entry_id, STATUS_POSTED, qb_bill_id=qb_bill_id)
        
        # Move PDF
        if pdf_key:
            new_key = pdf_key.replace("pending/", "posted/")
            move_pdf(pdf_key, new_key)
        
        return True
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Failed to post {entry_id}: {error_msg}")
        update_invoice_status(entry_id, STATUS_POST_FAILED, error=error_msg)
        
        send_alert(
            f"[{ENVIRONMENT}] QB Posting Failed",
            f"Entry: {entry_id}\nCompany: {company}\nError: {error_msg}"
        )
        
        return False


def lambda_handler(event, context):
    """
    Handle SQS events.
    Uses partial batch failure reporting so one poison message
    doesn't block the entire batch from completing.
    """
    
    records = event.get("Records", [])
    logger.info(f"Processing {len(records)} messages")
    
    success = 0
    failed_message_ids = []
    
    for record in records:
        message_id = record.get("messageId", "unknown")
        try:
            body = json.loads(record.get("body", "{}"))
            entry_id = body.get("entry_id")
            
            if not entry_id:
                logger.warning(f"Message {message_id} missing entry_id - skipping")
                continue
            
            if process_invoice(entry_id):
                success += 1
            else:
                failed_message_ids.append(message_id)
                
        except Exception as e:
            failed_message_ids.append(message_id)
            logger.error(f"Error processing message {message_id}: {e}")
    
    summary = f"Success: {success}, Failed: {len(failed_message_ids)}"
    logger.info(summary)
    
    # Return failed message IDs for individual retry (requires ReportBatchItemFailures on the event source)
    if failed_message_ids:
        return {
            "batchItemFailures": [
                {"itemIdentifier": mid} for mid in failed_message_ids
            ]
        }
    
    return {"statusCode": 200, "body": json.dumps({"success": success, "failed": 0})}