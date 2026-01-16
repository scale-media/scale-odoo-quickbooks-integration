"""
Lambda 1: Odoo Extractor

Extracts posted vendor bills from Odoo, validates them, saves PDFs to S3,
and writes metadata to DynamoDB with status=READY_FOR_APPROVAL.

Validation Rules:
- Required fields present (vendor, amount, date)
- Amount > 0
- Line items sum matches total (within tolerance)
- Not a duplicate (check DynamoDB)
- Company is known/mapped
"""

import os
import json
import base64
import logging
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Optional, List, Dict, Any, Tuple

import boto3
import requests
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")
ODOO_API_URL = os.environ.get("ODOO_API_URL", "https://scalemedia.odoo.com")
ODOO_SECRET_ARN = os.environ.get("ODOO_SECRET_ARN", "")
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "odoo-qb-invoices")
S3_BUCKET = os.environ.get("S3_BUCKET", "")
SNS_ALERT_TOPIC = os.environ.get("SNS_ALERT_TOPIC", "")

# Test flags
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"
TEST_START_DATE = os.environ.get("TEST_START_DATE", "")

# AWS clients
secrets_client = boto3.client("secretsmanager")
dynamodb = boto3.resource("dynamodb")
s3_client = boto3.client("s3")
sns_client = boto3.client("sns")

table = dynamodb.Table(DYNAMODB_TABLE) if DYNAMODB_TABLE else None

# Status constants
STATUS_READY_FOR_APPROVAL = "READY_FOR_APPROVAL"
STATUS_VALIDATION_FAILED = "VALIDATION_FAILED"
STATUS_DUPLICATE = "DUPLICATE"

# Company mapping
COMPANY_MAP = {
    "Digital Med, LLC dba 1MD Nutrition": "1MD",
    "Digital Med LLC": "1MD",
    "1MD Nutrition": "1MD",
    "New Momentum Media Inc. dba LiveConscious": "LiveConscious",
    "New Momentum Media Inc. dba Live Conscious": "LiveConscious",
    "New Momentum Media Inc": "LiveConscious",
    "LiveConscious": "LiveConscious",
    "Live Conscious": "LiveConscious",
    "Infinite Focus, Inc. dba Essential Elements": "EssentialElements",
    "Infinite Focus, Inc": "EssentialElements",
    "Essential Elements": "EssentialElements",
    "True Form Health, Inc. dba Tru Alchemy": "TruAlchemy",
    "True Form Health, Inc": "TruAlchemy",
    "Tru Alchemy": "TruAlchemy",
    "Beauty Science Group, Inc. dba Hair La Vie": "HairLaVie",
    "Scale Media, Inc.": "ScaleMedia",
}


def map_odoo_to_qb_account(account_code: str, account_name: str, product_name: str = "") -> str:
    """Map Odoo account codes to QuickBooks categories."""
    combined = f"{account_name} {product_name}".lower()
    
    # Stock/Inventory accounts
    if account_code and account_code.startswith("13210"):
        return "Inventory Asset:DTC Inventory"
    
    # Stock Interim Account (from your test data)
    if "stock interim" in combined:
        return "Inventory Asset:DTC Inventory"
    
    # Landed costs (51130)
    if account_code == "51130" or "landed" in combined:
        if any(t in combined for t in ["freight", "shipping", "inbound"]):
            return "PRODUCTION COSTS - ALWAYS USE:Freight In"
        if any(t in combined for t in ["pallet", "skid"]):
            return "PRODUCTION COSTS - ALWAYS USE:Freight In"
        if any(t in combined for t in ["die", "plate"]):
            return "PRODUCTION COSTS - ALWAYS USE:Packaging & Labeling"
        if "mock" in combined:
            return "PRODUCTION COSTS - ALWAYS USE:Packaging & Labeling"
        if "rework" in combined:
            return "PRODUCTION COSTS - ALWAYS USE:Packaging & Labeling"
        return "PRODUCTION COSTS - ALWAYS USE:Freight In"
    
    if "inventory" in combined:
        return "Inventory Asset:DTC Inventory"
    if "freight" in combined:
        return "PRODUCTION COSTS - ALWAYS USE:Freight In"
    
    return "Inventory Asset:DTC Inventory"


def get_payment_terms_days(terms_name: str) -> int:
    """Convert payment terms to days."""
    terms_map = {
        "Net10": 10, "Net 10": 10,
        "Net15": 15, "Net 15": 15,
        "Net30": 30, "Net 30": 30,
        "Net45": 45, "Net 45": 45,
        "Net60": 60, "Net 60": 60,
        "Net90": 90, "Net 90": 90,
        "Due on Receipt": 0, "Immediate": 0,
    }
    return terms_map.get(terms_name, 30)


class OdooClient:
    """Odoo JSON-RPC client with API key auth."""
    
    def __init__(self, base_url: str, database: str, username: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.database = database
        self.username = username
        self.api_key = api_key
        self.uid: Optional[int] = None
    
    def authenticate(self) -> bool:
        """Authenticate and get user ID."""
        payload = {
            "jsonrpc": "2.0",
            "method": "call",
            "params": {
                "service": "common",
                "method": "authenticate",
                "args": [self.database, self.username, self.api_key, {}]
            },
            "id": 1
        }
        
        try:
            resp = requests.post(f"{self.base_url}/jsonrpc", json=payload, timeout=30)
            result = resp.json()
            
            if "error" in result:
                logger.error(f"Odoo auth error: {result['error']}")
                return False
            
            self.uid = result.get("result")
            if self.uid and isinstance(self.uid, int):
                logger.info(f"Authenticated as user {self.uid}")
                return True
            return False
        except Exception as e:
            logger.error(f"Odoo auth failed: {e}")
            return False
    
    def _execute(self, model: str, method: str, args: list, kwargs: dict = None) -> Any:
        """Execute method on Odoo model."""
        payload = {
            "jsonrpc": "2.0",
            "method": "call",
            "params": {
                "service": "object",
                "method": "execute_kw",
                "args": [self.database, self.uid, self.api_key, model, method, args, kwargs or {}]
            },
            "id": 2
        }
        
        try:
            resp = requests.post(f"{self.base_url}/jsonrpc", json=payload, timeout=60)
            result = resp.json()
            if "error" in result:
                logger.error(f"Odoo error on {model}.{method}: {result['error']}")
                return None
            return result.get("result")
        except Exception as e:
            logger.error(f"Odoo call failed: {e}")
            return None
    
    def search_read(self, model: str, domain: list, fields: list, limit: int = 500) -> list:
        """Search and read records."""
        result = self._execute(model, "search_read", [domain], {"fields": fields, "limit": limit})
        return result if result else []
    
    def get_posted_vendor_bills(self, since_hours: int = 24) -> list:
        """Get posted vendor bills."""
        since = (datetime.utcnow() - timedelta(hours=since_hours)).strftime("%Y-%m-%d %H:%M:%S")
        
        domain = [
            ("move_type", "=", "in_invoice"),
            ("state", "=", "posted"),
            ("create_date", ">=", since),
        ]
        
        if TEST_START_DATE:
            domain.append(("create_date", ">=", TEST_START_DATE))
        
        fields = [
            "id", "name", "ref", "partner_id", "company_id",
            "invoice_date", "invoice_date_due", "date",
            "invoice_payment_term_id", "amount_total", "amount_untaxed",
            "currency_id", "invoice_line_ids", "invoice_origin", "create_date"
        ]
        
        return self.search_read("account.move", domain, fields)
    
    def get_invoice_lines(self, line_ids: List[int]) -> list:
        """Get invoice line details."""
        if not line_ids:
            return []
        return self.search_read(
            "account.move.line",
            [("id", "in", line_ids)],
            ["id", "name", "product_id", "account_id", "quantity", "price_unit", "price_subtotal"],
            limit=1000
        )
    
    def get_attachment(self, res_model: str, res_id: int) -> Optional[dict]:
        """Get PDF attachment."""
        attachments = self.search_read(
            "ir.attachment",
            [("res_model", "=", res_model), ("res_id", "=", res_id), ("mimetype", "=", "application/pdf")],
            ["id", "name", "datas", "file_size"],
            limit=5
        )
        
        if attachments:
            for att in attachments:
                if "invoice" in att.get("name", "").lower():
                    return att
            return attachments[0]
        return None


def get_odoo_credentials() -> dict:
    """Get Odoo credentials from Secrets Manager or env."""
    if not ODOO_SECRET_ARN:
        return {
            "database": os.environ.get("ODOO_DATABASE", "2jaszgithub-scale-media-master-305444"),
            "username": os.environ.get("ODOO_USERNAME", ""),
            "api_key": os.environ.get("ODOO_API_KEY", ""),
        }
    
    try:
        resp = secrets_client.get_secret_value(SecretId=ODOO_SECRET_ARN)
        return json.loads(resp["SecretString"])
    except ClientError as e:
        logger.error(f"Failed to get credentials: {e}")
        raise


def is_duplicate(entry_id: str) -> bool:
    """Check if entry exists in DynamoDB."""
    if not table:
        return False
    try:
        resp = table.get_item(Key={"entry_id": entry_id})
        return "Item" in resp
    except ClientError:
        return False


def validate_invoice(invoice_data: dict) -> Tuple[bool, List[str]]:
    """
    Validate invoice data.
    Returns (is_valid, list_of_issues).
    """
    issues = []
    warnings = []
    
    # Required fields
    if not invoice_data.get("vendor_name"):
        issues.append("Missing vendor name")
    
    if not invoice_data.get("bill_date"):
        issues.append("Missing bill date")
    
    # Amount validation
    amount = invoice_data.get("amount_total", 0)
    if amount <= 0:
        issues.append(f"Invalid amount: ${amount}")
    
    # Line items reconciliation
    line_items = invoice_data.get("line_items", [])
    if not line_items:
        issues.append("No line items")
    else:
        line_total = sum(l.get("subtotal", 0) for l in line_items)
        diff = abs(amount - line_total)
        if diff > 0.02:  # Allow 2 cent tolerance
            warnings.append(f"Line items (${line_total:.2f}) don't match total (${amount:.2f})")
    
    # Company validation
    if invoice_data.get("company") == "Unknown":
        warnings.append(f"Unknown company: {invoice_data.get('company_name')}")
    
    # PDF check
    if not invoice_data.get("pdf_s3_key"):
        warnings.append("No PDF attachment")
    
    # Intercompany check
    vendor_lower = (invoice_data.get("vendor_name") or "").lower()
    intercompany = ["scale media", "1md", "liveconscious", "essential elements", "tru alchemy"]
    if any(ic in vendor_lower for ic in intercompany):
        issues.append(f"Intercompany invoice - route to Chelsea")
    
    # TBD placeholder check
    ref = (invoice_data.get("bill_reference") or "").lower()
    if "tbd" in ref or "placeholder" in ref:
        issues.append("TBD placeholder invoice")
    
    invoice_data["validation_warnings"] = warnings
    invoice_data["validation_errors"] = issues
    
    return len(issues) == 0, issues


def upload_pdf_to_s3(pdf_data: bytes, company: str, entry_id: str) -> str:
    """Upload PDF to S3."""
    if not S3_BUCKET:
        return ""
    
    safe_id = entry_id.replace("/", "-")
    s3_key = f"pending/{company}/{safe_id}.pdf"
    
    if DRY_RUN:
        logger.info(f"[DRY RUN] Would upload to s3://{S3_BUCKET}/{s3_key}")
        return s3_key
    
    try:
        s3_client.put_object(
            Bucket=S3_BUCKET,
            Key=s3_key,
            Body=pdf_data,
            ContentType="application/pdf",
            Metadata={"entry_id": entry_id, "company": company}
        )
        logger.info(f"Uploaded PDF to s3://{S3_BUCKET}/{s3_key}")
        return s3_key
    except ClientError as e:
        logger.error(f"S3 upload failed: {e}")
        return ""


def save_to_dynamodb(invoice_data: dict, status: str):
    """Save invoice to DynamoDB with given status."""
    if not table:
        logger.info(f"[NO DB] Would save {invoice_data['entry_id']} with status={status}")
        return
    
    if DRY_RUN:
        logger.info(f"[DRY RUN] Would save {invoice_data['entry_id']} with status={status}")
        return
    
    try:
        item = json.loads(json.dumps(invoice_data), parse_float=Decimal)
        item["status"] = status
        item["created_at"] = datetime.utcnow().isoformat()
        item["expires_at"] = int((datetime.utcnow() + timedelta(days=365)).timestamp())
        
        table.put_item(Item=item)
        logger.info(f"Saved {invoice_data['entry_id']} with status={status}")
    except ClientError as e:
        logger.error(f"DynamoDB save failed: {e}")
        raise


def send_alert(subject: str, message: str):
    """Send alert via SNS."""
    if SNS_ALERT_TOPIC:
        try:
            sns_client.publish(TopicArn=SNS_ALERT_TOPIC, Subject=subject[:100], Message=message)
        except Exception as e:
            logger.error(f"Alert failed: {e}")


def process_bill(odoo: OdooClient, bill: dict) -> Optional[dict]:
    """Process single bill, validate, and return invoice data."""
    entry_id = bill.get("name", f"BILL-{bill['id']}")
    
    # Duplicate check
    if is_duplicate(entry_id):
        logger.info(f"Skipping {entry_id} - already exists")
        return None
    
    # Company
    company_name = ""
    if bill.get("company_id"):
        company_name = bill["company_id"][1] if isinstance(bill["company_id"], list) else str(bill["company_id"])
    company = COMPANY_MAP.get(company_name, "Unknown")
    
    # Vendor
    vendor_name = ""
    vendor_id = None
    if bill.get("partner_id"):
        if isinstance(bill["partner_id"], list):
            vendor_id = bill["partner_id"][0]
            vendor_name = bill["partner_id"][1]
    
    # Payment terms
    payment_terms = "Net30"
    if bill.get("invoice_payment_term_id"):
        if isinstance(bill["invoice_payment_term_id"], list):
            payment_terms = bill["invoice_payment_term_id"][1]
    
    # Line items
    line_ids = bill.get("invoice_line_ids", [])
    lines = odoo.get_invoice_lines(line_ids) if line_ids else []
    
    processed_lines = []
    for line in lines:
        subtotal = line.get("price_subtotal", 0)
        if not subtotal or subtotal == 0:
            continue
        
        account_code = ""
        account_name = ""
        if line.get("account_id") and isinstance(line["account_id"], list):
            account_name = line["account_id"][1]
            parts = account_name.split(" ", 1)
            if parts and parts[0].replace(".", "").isdigit():
                account_code = parts[0]
        
        product_name = ""
        if line.get("product_id") and isinstance(line["product_id"], list):
            product_name = line["product_id"][1]
        
        processed_lines.append({
            "line_id": line["id"],
            "description": line.get("name", ""),
            "product_name": product_name,
            "account_code": account_code,
            "account_name": account_name,
            "quantity": float(line.get("quantity", 0)),
            "unit_price": float(line.get("price_unit", 0)),
            "subtotal": float(subtotal),
            "qb_category": map_odoo_to_qb_account(account_code, account_name, product_name),
        })
    
    # PDF
    attachment = odoo.get_attachment("account.move", bill["id"])
    pdf_s3_key = None
    pdf_filename = None
    
    if attachment and attachment.get("datas"):
        try:
            pdf_data = base64.b64decode(attachment["datas"])
            pdf_s3_key = upload_pdf_to_s3(pdf_data, company, entry_id)
            pdf_filename = attachment.get("name")
        except Exception as e:
            logger.error(f"PDF processing failed for {entry_id}: {e}")
    
    # PO reference
    po_number = bill.get("invoice_origin") or bill.get("ref", "")
    
    # Build invoice data
    invoice_data = {
        "entry_id": entry_id,
        "odoo_id": bill["id"],
        "company": company,
        "company_name": company_name,
        "vendor_name": vendor_name,
        "vendor_id": vendor_id,
        "bill_reference": bill.get("ref", ""),
        "bill_date": bill.get("invoice_date") or bill.get("date"),
        "accounting_date": bill.get("date"),
        "due_date": bill.get("invoice_date_due"),
        "payment_terms": payment_terms,
        "payment_terms_days": get_payment_terms_days(payment_terms),
        "po_number": po_number,
        "amount_total": float(bill.get("amount_total", 0)),
        "amount_untaxed": float(bill.get("amount_untaxed", 0)),
        "currency": bill.get("currency_id", [None, "USD"])[1] if isinstance(bill.get("currency_id"), list) else "USD",
        "line_items": processed_lines,
        "pdf_s3_key": pdf_s3_key,
        "pdf_filename": pdf_filename,
    }
    
    return invoice_data


def lambda_handler(event, context):
    """Main handler."""
    logger.info(f"Starting extractor. DRY_RUN={DRY_RUN}")
    
    lookback_hours = event.get("lookback_hours", 24) if event else 24
    
    processed = 0
    validation_failed = 0
    skipped = 0
    errors = 0
    
    try:
        creds = get_odoo_credentials()
        odoo = OdooClient(
            base_url=ODOO_API_URL,
            database=creds["database"],
            username=creds["username"],
            api_key=creds["api_key"]
        )
        
        if not odoo.authenticate():
            raise Exception("Odoo authentication failed")
        
        bills = odoo.get_posted_vendor_bills(since_hours=lookback_hours)
        logger.info(f"Found {len(bills)} posted vendor bills")
        
        for bill in bills:
            try:
                invoice_data = process_bill(odoo, bill)
                
                if not invoice_data:
                    skipped += 1
                    continue
                
                # Validate
                is_valid, issues = validate_invoice(invoice_data)
                
                if is_valid:
                    save_to_dynamodb(invoice_data, STATUS_READY_FOR_APPROVAL)
                    processed += 1
                    logger.info(f"✓ {invoice_data['entry_id']} ready for approval")
                else:
                    save_to_dynamodb(invoice_data, STATUS_VALIDATION_FAILED)
                    validation_failed += 1
                    logger.warning(f"✗ {invoice_data['entry_id']} validation failed: {issues}")
                    
            except Exception as e:
                errors += 1
                logger.error(f"Error processing {bill.get('name')}: {e}")
        
        summary = f"Ready: {processed}, ValidationFailed: {validation_failed}, Skipped: {skipped}, Errors: {errors}"
        logger.info(summary)
        
        if errors > 0:
            send_alert(f"[{ENVIRONMENT}] Extractor: {errors} errors", summary)
        
        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": summary,
                "ready_for_approval": processed,
                "validation_failed": validation_failed,
                "skipped": skipped,
                "errors": errors
            })
        }
        
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        send_alert(f"[{ENVIRONMENT}] Extractor FAILED", str(e))
        raise


if __name__ == "__main__":
    os.environ["DRY_RUN"] = "true"
    result = lambda_handler({"lookback_hours": 72}, None)
    print(json.dumps(result, indent=2))
