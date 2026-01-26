"""
Lambda 2: QuickBooks Poster

Triggered by SQS when an invoice is approved.
Reads invoice from DynamoDB, posts to QuickBooks, attaches PDF.
"""

import os
import json
import logging
from datetime import datetime, timedelta
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

# Use sandbox in dev
USE_SANDBOX = os.environ.get("QB_USE_SANDBOX", "false").lower() == "true"

# AWS clients
secrets_client = boto3.client("secretsmanager")
dynamodb = boto3.resource("dynamodb")
s3_client = boto3.client("s3")
sns_client = boto3.client("sns")

table = dynamodb.Table(DYNAMODB_TABLE) if DYNAMODB_TABLE else None


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
    
    def _request(self, method: str, endpoint: str, data: dict = None) -> dict:
        """Make authenticated QB API request."""
        self._ensure_token()
        
        url = f"{self.base_url}/{self.realm_id}/{endpoint}"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        
        resp = requests.request(method, url, headers=headers, json=data, timeout=60)
        
        if resp.status_code >= 400:
            logger.error(f"QB API error: {resp.status_code} - {resp.text}")
        
        resp.raise_for_status()
        return resp.json()
    
    def find_vendor(self, vendor_name: str) -> Optional[dict]:
        """Find vendor by name."""
        # Escape single quotes in vendor name
        safe_name = vendor_name.replace("'", "\\'")
        query = f"SELECT * FROM Vendor WHERE DisplayName = '{safe_name}'"
        
        try:
            result = self._request("GET", f"query?query={query}")
            vendors = result.get("QueryResponse", {}).get("Vendor", [])
            return vendors[0] if vendors else None
        except Exception as e:
            logger.warning(f"Vendor lookup failed: {e}")
            return None
    
    def create_vendor(self, vendor_name: str) -> dict:
        """Create new vendor."""
        result = self._request("POST", "vendor", {"DisplayName": vendor_name})
        return result.get("Vendor", {})
    
    def find_account(self, account_name: str) -> Optional[dict]:
        """Find account by name."""
        search_name = account_name.split(":")[-1] if ":" in account_name else account_name
        safe_name = search_name.replace("'", "\\'")
        query = f"SELECT * FROM Account WHERE Name LIKE '%{safe_name}%'"
        
        try:
            result = self._request("GET", f"query?query={query}")
            accounts = result.get("QueryResponse", {}).get("Account", [])
            
            if accounts:
                for acc in accounts:
                    if acc.get("FullyQualifiedName") == account_name or acc.get("Name") == search_name:
                        return acc
                return accounts[0]
            return None
        except Exception as e:
            logger.warning(f"Account lookup failed: {e}")
            return None
    
    def bill_exists(self, doc_number: str) -> bool:
        """Check if bill already exists."""
        safe_num = doc_number.replace("'", "\\'")
        query = f"SELECT Id FROM Bill WHERE DocNumber = '{safe_num}'"
        
        try:
            result = self._request("GET", f"query?query={query}")
            bills = result.get("QueryResponse", {}).get("Bill", [])
            return len(bills) > 0
        except:
            return False
    
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
        return json.loads(json.dumps(item, default=str)) if item else None
    except ClientError as e:
        logger.error(f"DynamoDB get failed: {e}")
        return None


def claim_invoice(entry_id: str) -> bool:
    """
    Attempt to claim invoice for processing.
    Uses conditional update: APPROVED → POSTING.
    Only one worker can claim successfully.
    """
    if not table:
        return True
    
    try:
        table.update_item(
            Key={"entry_id": entry_id},
            UpdateExpression="SET #status = :posting, claim_time = :ts",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":posting": STATUS_POSTING,
                ":approved": STATUS_APPROVED,
                ":ts": datetime.utcnow().isoformat()
            },
            ConditionExpression="#status = :approved"
        )
        logger.info(f"Claimed invoice {entry_id} for processing")
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            logger.warning(f"Invoice {entry_id} already claimed or not in APPROVED state")
            return False
        logger.error(f"Claim failed: {e}")
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
    
    return {
        "VendorRef": {"value": vendor_id},
        "Line": lines,
        "DocNumber": (invoice.get("bill_reference") or invoice.get("entry_id", "").replace("/", "-"))[:21],
        "TxnDate": invoice.get("bill_date"),
        "DueDate": invoice.get("due_date"),
        "PrivateNote": (invoice.get("po_number") or "")[:4000],
    }


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
        logger.info(f"Already being processed by another worker: {entry_id}")
        return True
    
    if current_status != STATUS_APPROVED:
        logger.warning(f"Invoice not approved: {entry_id} (status={current_status})")
        return False
    
    # Try to claim the invoice (atomic APPROVED → POSTING)
    if not claim_invoice(entry_id):
        logger.info(f"Could not claim {entry_id} - likely already processed")
        return True  # Not an error, just already handled
    
    company = invoice.get("company", "Unknown")
    
    if DRY_RUN:
        logger.info(f"[DRY RUN] Would post {entry_id} to QB for {company}")
        update_invoice_status(entry_id, STATUS_POSTED, qb_bill_id="DRY_RUN")
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
        
        # Check for duplicate in QB
        bill_ref = invoice.get("bill_reference", "")
        if bill_ref and qb.bill_exists(bill_ref):
            logger.warning(f"Bill already exists in QB: {bill_ref}")
            update_invoice_status(entry_id, STATUS_POSTED, qb_bill_id="EXISTING")
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
    """Handle SQS events."""
    
    logger.info(f"Processing {len(event.get('Records', []))} messages")
    
    success = 0
    failed = 0
    
    for record in event.get("Records", []):
        try:
            body = json.loads(record.get("body", "{}"))
            entry_id = body.get("entry_id")
            
            if not entry_id:
                logger.warning("Message missing entry_id")
                continue
            
            if process_invoice(entry_id):
                success += 1
            else:
                failed += 1
                
        except Exception as e:
            failed += 1
            logger.error(f"Error processing message: {e}")
    
    summary = f"Success: {success}, Failed: {failed}"
    logger.info(summary)
    
    # If any failed, raise to retry via DLQ
    if failed > 0:
        raise Exception(f"Some invoices failed to post: {summary}")
    
    return {"statusCode": 200, "body": json.dumps({"success": success, "failed": failed})}