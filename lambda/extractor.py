"""
Lambda 1: Odoo Extractor

Extracts posted vendor bills from Odoo, validates them, saves PDFs to S3,
and writes metadata to DynamoDB with status=READY_FOR_APPROVAL.

Validation Rules:
- Required fields present (vendor, amount, date)
- Amount > 0
- Line items sum matches total (within tolerance)
- Not a duplicate (check DynamoDB)
- Not already in QuickBooks
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

try:
    from dd_helpers import trace_span, emit_metric, tag_current_span
except ImportError:
    from contextlib import contextmanager
    @contextmanager
    def trace_span(*a, **kw): yield type('', (), {'set_tag': lambda *a: None, 'set_metric': lambda *a: None})()
    def emit_metric(*a, **kw): pass
    def tag_current_span(*a, **kw): pass

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")
ODOO_API_URL = os.environ.get("ODOO_API_URL", "https://scalemedia.odoo.com")
ODOO_SECRET_ARN = os.environ.get("ODOO_SECRET_ARN", "")
QB_SECRET_ARN = os.environ.get("QB_SECRET_ARN", "")
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "odoo-qb-invoices")
S3_BUCKET = os.environ.get("S3_BUCKET", "")
SNS_ALERT_TOPIC = os.environ.get("SNS_ALERT_TOPIC", "")

# Test flags
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"
TEST_START_DATE = os.environ.get("TEST_START_DATE", "")
QB_USE_SANDBOX = os.environ.get("QB_USE_SANDBOX", "false").lower() == "true"
SKIP_QB_CHECK = os.environ.get("SKIP_QB_CHECK", "false").lower() == "true"

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
STATUS_ALREADY_IN_QB = "ALREADY_IN_QB"

# Company mapping function (case-insensitive)
def map_company_name(odoo_company_name: str) -> str:
    """Map Odoo company name to short name (case-insensitive)."""
    if not odoo_company_name:
        return "Unknown"
    
    company_lower = odoo_company_name.lower()
    
    # Digital Med / 1MD
    if ("digital med" in company_lower and "1md" in company_lower) or \
       ("digital med" in company_lower and "nutrition" in company_lower) or \
       "1md nutrition" in company_lower:
        return "1MD"
    
    # New Momentum Media / LiveConscious
    elif ("new momentum" in company_lower and ("liveconscious" in company_lower or "live conscious" in company_lower)) or \
         "liveconscious" in company_lower or "live conscious" in company_lower:
        return "LiveConscious"
    
    # Infinite Focus / Essential Elements  
    elif ("infinite focus" in company_lower and "essential" in company_lower) or \
         "essential elements" in company_lower:
        return "EssentialElements"
    
    # True Form Health / Tru Alchemy / Direct Insight
    elif ("true form health" in company_lower and "tru alchemy" in company_lower) or \
         "tru alchemy" in company_lower or "direct insight" in company_lower:
        return "TruAlchemy"
    
    # Scale Media
    elif "scale media" in company_lower:
        return "ScaleMedia"
    
    else:
        return "Unknown"


def map_odoo_to_qb_account(account_code: str, account_name: str, product_name: str = "", company: str = "Unknown") -> str:
    """Map Odoo account codes to QuickBooks categories based on company."""
    combined = f"{account_name} {product_name}".lower()
    
    # Strip decimals from account codes (52120.2 → 52120)
    if account_code:
        account_code = account_code.split(".")[0]
    
    # Stock/Inventory accounts (same for all brands)
    if account_code and account_code.startswith("13210"):
        return "Inventory Asset:DTC Inventory"
    
    if "stock interim" in combined:
        return "Inventory Asset:DTC Inventory"
    
    # Company-specific mappings based on QB chart of accounts
    if company == "1MD":
        return map_1md_account(account_code, combined)
    elif company == "LiveConscious":
        return map_liveconscious_account(account_code, combined)
    elif company == "EssentialElements":
        return map_essentialelements_account(account_code, combined)
    elif company == "TruAlchemy":
        return map_trualchemy_account(account_code, combined)
    else:
        # Default fallback mapping
        return map_default_account(account_code, combined)


def map_1md_account(account_code: str, combined: str) -> str:
    """Digital Med LLC specific mappings."""
    
    # Freight/Shipping
    if account_code == "52130" or any(term in combined for term in ["freight", "shipping", "inbound"]):
        return "PRODUCTION COSTS - ALWAYS USE:Freight In"
    
    # 3PL Services
    if account_code == "52120" or any(term in combined for term in ["3pl fulfillment", "fulfillment services"]):
        return "PRODUCTION COSTS - ALWAYS USE:Delivery Costs - Always Use"
    
    # Outbound Postage
    if account_code == "52140" or any(term in combined for term in ["outbound postage", "delivery costs"]):
        return "PRODUCTION COSTS - ALWAYS USE:Delivery Costs - Always Use"
    
    # Returns/RTS
    if account_code == "52150" or "rts" in combined or "returns postage" in combined:
        return "PRODUCTION COSTS - ALWAYS USE:Delivery Costs for RTS - Always Use"
    
    # Not Freight (packaging, pallets, dies, rework)
    if (account_code == "52120" and "not freight" in combined) or \
       any(term in combined for term in ["pallet", "skid", "die", "plate", "mock", "rework", "packaging"]):
        return "PRODUCTION COSTS - ALWAYS USE:Packaging & Labeling - Always Use"
    
    # Quality Testing
    if account_code == "52500" or "quality" in combined or "lab test" in combined:
        return "PRODUCTION COSTS - ALWAYS USE:Manufacturing - Always Use"
    
    # Amazon Distribution/FBA
    if account_code == "52220" or ("amazon" in combined and any(term in combined for term in ["distribution", "3pl"])):
        return "PRODUCTION COSTS - ALWAYS USE:FBA Manufacturing - Always Use"
    
    # Amazon FBA Fees
    if account_code == "52270" or ("amazon" in combined and "fba fees" in combined):
        return "COS Marketplace:Amazon FBA Selling Fees"
    
    # Walmart Distribution
    if account_code == "52320" or ("walmart" in combined and "distribution" in combined):
        return "PRODUCTION COSTS - ALWAYS USE:Delivery Costs - Always Use"
    
    # Scrap Loss
    if account_code == "52180" or "scrap" in combined:
        return "PRODUCTION COSTS - ALWAYS USE:Scraps"
    
    # Default to inventory for unknown
    return "Inventory Asset:DTC Inventory"


def map_liveconscious_account(account_code: str, combined: str) -> str:
    """New Momentum Media (LiveConscious) specific mappings."""
    
    if account_code == "52130" or any(term in combined for term in ["freight", "shipping", "inbound"]):
        return "PRODUCTION COSTS - ALWAYS USE:Freight In"
    
    if account_code == "52120" or any(term in combined for term in ["3pl fulfillment", "fulfillment services"]):
        return "PRODUCTION COSTS - ALWAYS USE:Delivery Costs - Always Use"
    
    if account_code == "52140" or any(term in combined for term in ["outbound postage", "delivery costs"]):
        return "PRODUCTION COSTS - ALWAYS USE:Delivery Costs - Always Use"
    
    if account_code == "52150" or "rts" in combined or "returns postage" in combined:
        return "PRODUCTION COSTS - ALWAYS USE:Delivery Costs for RTS - Always Use"
    
    if (account_code == "52120" and "not freight" in combined) or \
       any(term in combined for term in ["pallet", "skid", "die", "plate", "mock", "rework", "packaging"]):
        return "PRODUCTION COSTS - ALWAYS USE:Packaging & Labeling - Always Use"
    
    if account_code == "52500" or "quality" in combined or "lab test" in combined:
        return "PRODUCTION COSTS - ALWAYS USE:Quality Testing"
    
    # Amazon FBA specific
    if account_code == "52220" or ("amazon" in combined and any(term in combined for term in ["distribution", "3pl"])):
        return "PRODUCTION COSTS - ALWAYS USE:FBA Manufacturing - Always Use"
    
    if account_code == "52270" or ("amazon" in combined and "fba fees" in combined):
        return "COS Marketplace:Amazon FBA Selling Fees"
    
    # Walmart specific
    if account_code == "52320" or ("walmart" in combined and "distribution" in combined):
        return "PRODUCTION COSTS - ALWAYS USE:WMT Shipping Costs - Always Use"
    
    if account_code == "52180" or "scrap" in combined:
        return "PRODUCTION COSTS - ALWAYS USE:Scraps"
    
    return "Inventory Asset:DTC Inventory"


def map_essentialelements_account(account_code: str, combined: str) -> str:
    """Infinite Focus (EssentialElements) specific mappings."""
    
    if account_code == "52130" or any(term in combined for term in ["freight", "shipping", "inbound"]):
        return "PRODUCTION COSTS - ALWAYS USE:Freight In"
    
    if account_code == "52120" or any(term in combined for term in ["3pl fulfillment", "fulfillment services"]):
        return "PRODUCTION COSTS - ALWAYS USE:Delivery Costs - Always Use"
    
    if account_code == "52140" or any(term in combined for term in ["outbound postage", "delivery costs"]):
        return "PRODUCTION COSTS - ALWAYS USE:Delivery Costs - Always Use"
    
    if account_code == "52150" or "rts" in combined or "returns postage" in combined:
        return "PRODUCTION COSTS - ALWAYS USE:Delivery Costs for RTS - Always Use"
    
    if (account_code == "52120" and "not freight" in combined) or \
       any(term in combined for term in ["pallet", "skid", "die", "plate", "mock", "rework", "packaging"]):
        return "PRODUCTION COSTS - ALWAYS USE:Packaging & Labeling - Always Use"
    
    if account_code == "52500" or "quality" in combined or "lab test" in combined:
        return "PRODUCTION COSTS - ALWAYS USE:Quality Testing"
    
    if account_code == "52220" or ("amazon" in combined and any(term in combined for term in ["distribution", "3pl"])):
        return "PRODUCTION COSTS - ALWAYS USE:FBA Manufacturing - Always Use"
    
    if account_code == "52270" or ("amazon" in combined and "fba fees" in combined):
        return "COS Marketplace:Amazon FBA Selling Fees"
    
    if account_code == "52320" or ("walmart" in combined and "distribution" in combined):
        return "PRODUCTION COSTS - ALWAYS USE:WMT Shipping Costs - Always Use"
    
    if account_code == "52180" or "scrap" in combined:
        return "PRODUCTION COSTS - ALWAYS USE:Scraps"
    
    return "Inventory Asset:DTC Inventory"


def map_trualchemy_account(account_code: str, combined: str) -> str:
    """Direct Insight LLC (TruAlchemy) specific mappings."""
    
    if account_code == "52130" or any(term in combined for term in ["freight", "shipping", "inbound"]):
        return "PRODUCTION COSTS - ALWAYS USE:Freight In"
    
    if account_code == "52120" or any(term in combined for term in ["3pl fulfillment", "fulfillment services"]):
        return "PRODUCTION COSTS - ALWAYS USE:Delivery Costs - Always Use"
    
    if account_code == "52140" or any(term in combined for term in ["outbound postage", "delivery costs"]):
        return "PRODUCTION COSTS - ALWAYS USE:Delivery Costs - Always Use"
    
    if account_code == "52150" or "rts" in combined or "returns postage" in combined:
        return "PRODUCTION COSTS - ALWAYS USE:Delivery Costs for RTS - Always Use"
    
    if (account_code == "52120" and "not freight" in combined) or \
       any(term in combined for term in ["pallet", "skid", "die", "plate", "mock", "rework", "packaging"]):
        return "PRODUCTION COSTS - ALWAYS USE:Packaging & Labeling - Always Use"
    
    if account_code == "52500" or "quality" in combined or "lab test" in combined:
        return "PRODUCTION COSTS - ALWAYS USE:Manufacturing - Always Use"
    
    if account_code == "52220" or ("amazon" in combined and any(term in combined for term in ["distribution", "3pl"])):
        return "PRODUCTION COSTS - ALWAYS USE:FBA Manufacturing - Always Use"
    
    if account_code == "52270" or ("amazon" in combined and "fba fees" in combined):
        return "COS Marketplace:Amazon FBA Selling Fees"
    
    if account_code == "52320" or ("walmart" in combined and "distribution" in combined):
        return "PRODUCTION COSTS - ALWAYS USE:Delivery Costs - Always Use"
    
    if account_code == "52180" or "scrap" in combined:
        return "PRODUCTION COSTS - ALWAYS USE:Scraps"
    
    return "Inventory Asset:DTC Inventory"


def map_default_account(account_code: str, combined: str) -> str:
    """Default mapping for unknown companies."""
    
    # Basic freight/inventory logic
    if "freight" in combined or account_code == "52130":
        return "PRODUCTION COSTS:Freight In"
    
    if "inventory" in combined or account_code and account_code.startswith("1321"):
        return "Inventory Asset:DTC Inventory"
    
    # Default to inventory
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
            ("write_date", ">=", since),  # Use write_date to catch re-confirmed invoices
        ]
        
        if TEST_START_DATE:
            domain.append(("write_date", ">=", TEST_START_DATE))
        
        fields = [
            "id", "name", "ref", "partner_id", "company_id",
            "invoice_date", "invoice_date_due", "date",
            "invoice_payment_term_id", "amount_total", "amount_untaxed",
            "currency_id", "invoice_line_ids", "invoice_origin", "create_date", "write_date"
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


class QuickBooksChecker:
    """Lightweight QB client just for checking if bills exist."""
    
    def __init__(self, client_id: str, client_secret: str, use_sandbox: bool = False):
        self.client_id = client_id
        self.client_secret = client_secret
        self.use_sandbox = use_sandbox
        self.base_url = "https://sandbox-quickbooks.api.intuit.com" if use_sandbox else "https://quickbooks.api.intuit.com"
        self.access_tokens: Dict[str, str] = {}  # realm_id -> access_token
        self.updated_refresh_tokens: Dict[str, str] = {}  # realm_id -> new refresh_token
    
    def get_access_token(self, refresh_token: str, realm_id: str) -> Optional[str]:
        """Get access token for a specific realm.
        
        QB refresh tokens are single-use. Every successful refresh returns a new
        refresh_token that must be persisted, or the next run will fail with 400.
        New tokens are collected in self.updated_refresh_tokens and flushed to
        Secrets Manager at the end of the run via persist_refresh_tokens().
        """
        if realm_id in self.access_tokens:
            return self.access_tokens[realm_id]
        
        try:
            resp = requests.post(
                "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer",
                auth=(self.client_id, self.client_secret),
                data={"grant_type": "refresh_token", "refresh_token": refresh_token},
                headers={"Accept": "application/json"},
                timeout=30
            )
            
            if resp.status_code == 200:
                data = resp.json()
                access_token = data.get("access_token")
                new_refresh_token = data.get("refresh_token")
                
                self.access_tokens[realm_id] = access_token
                
                # Capture the new refresh token for persistence
                if new_refresh_token and new_refresh_token != refresh_token:
                    self.updated_refresh_tokens[realm_id] = new_refresh_token
                    logger.info(f"Captured new refresh token for realm {realm_id}")
                
                return access_token
            else:
                logger.warning(f"QB token refresh failed for realm {realm_id}: {resp.status_code}")
                return None
        except Exception as e:
            logger.warning(f"QB token refresh error for realm {realm_id}: {e}")
            return None
    
    def bill_exists(self, realm_id: str, access_token: str, vendor_name: str, doc_number: str) -> tuple[bool, dict]:
        """
        Check if bill exists in QuickBooks.
        Returns (exists, details) where details contains match info for audit.
        """
        if not doc_number:
            return False, {}
        
        # Escape single quotes in doc_number
        safe_doc = doc_number.replace("'", "\\'")
        
        # Query by DocNumber only (VendorRef.Name is not queryable in QB API)
        query = f"SELECT Id, DocNumber, VendorRef, TotalAmt, TxnDate FROM Bill WHERE DocNumber = '{safe_doc}'"
        
        try:
            resp = requests.get(
                f"{self.base_url}/v3/company/{realm_id}/query",
                params={"query": query},
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json"
                },
                timeout=30
            )
            
            if resp.status_code == 200:
                data = resp.json()
                bills = data.get("QueryResponse", {}).get("Bill", [])
                
                if bills:
                    # Check ALL bills with matching DocNumber (not just first one)
                    for bill in bills:
                        qb_vendor_name = bill.get("VendorRef", {}).get("name", "")
                        
                        # Normalize vendor names for comparison
                        def normalize_vendor(name: str) -> str:
                            name = (name or "").strip()
                            return "".join(c.lower() for c in name if c.isalnum())
                        
                        if normalize_vendor(qb_vendor_name) == normalize_vendor(vendor_name):
                            # Real match - same vendor and DocNumber
                            logger.info(f"QB duplicate found: Bill ID {bill.get('Id')} for {vendor_name} doc {doc_number} in realm {realm_id}")
                            
                            return True, {
                                "qb_bill_id": bill.get("Id"),
                                "qb_doc_number": bill.get("DocNumber"),
                                "qb_vendor": qb_vendor_name,
                                "qb_realm_id": realm_id,
                                "qb_query": query
                            }
                    
                    # DocNumber exists but no vendor match - store warning info
                    qb_vendors = [bill.get("VendorRef", {}).get("name", "") for bill in bills]
                    logger.warning(f"DocNumber {doc_number} exists in QB but vendor differs: QB vendors={qb_vendors} vs Odoo vendor='{vendor_name}'")
                    
                    return False, {
                        "docnumber_exists": True,
                        "qb_vendors": qb_vendors,
                        "odoo_vendor": vendor_name,
                        "qb_bills": [bill.get("Id") for bill in bills],
                        "qb_amounts": [float(bill.get("TotalAmt", 0)) for bill in bills],
                        "qb_dates": [bill.get("TxnDate", "") for bill in bills],
                        "warning": f"DocNumber exists but vendor differs: QB={qb_vendors} vs Odoo='{vendor_name}'"
                    }
                else:
                    logger.debug(f"No QB bill found with DocNumber {doc_number} in realm {realm_id}")
                    return False, {}
            else:
                logger.error(f"QB query failed: {resp.status_code} - {resp.text[:200]}")
                raise Exception(f"QB API returned {resp.status_code}: {resp.text[:100]}")
                
        except Exception as e:
            logger.error(f"QB query error for {vendor_name} doc {doc_number}: {e}")
            raise


def compute_qb_doc_number(bill_reference: str, entry_id: str) -> str:
    """
    Compute QB DocNumber using same logic as poster to ensure consistency.
    Poster uses: (bill_reference or entry_id).replace("/", "-")[:21]
    """
    doc_number = (bill_reference or entry_id).replace("/", "-")
    return doc_number[:21]  # QB DocNumber limit is 21 characters


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


def get_qb_credentials() -> Optional[dict]:
    """Get QB credentials from Secrets Manager."""
    if not QB_SECRET_ARN:
        return None
    
    try:
        resp = secrets_client.get_secret_value(SecretId=QB_SECRET_ARN)
        return json.loads(resp["SecretString"])
    except ClientError as e:
        logger.warning(f"Failed to get QB credentials: {e}")
        return None


def init_qb_checker() -> Optional[QuickBooksChecker]:
    """Initialize QB checker if credentials available."""
    if SKIP_QB_CHECK:
        logger.info("QB duplicate check disabled via SKIP_QB_CHECK")
        return None
    
    creds = get_qb_credentials()
    if not creds:
        logger.info("No QB credentials - skipping QB duplicate check")
        return None
    
    return QuickBooksChecker(
        client_id=creds["client_id"],
        client_secret=creds["client_secret"],
        use_sandbox=creds.get("use_sandbox", QB_USE_SANDBOX)
    )


def persist_refresh_tokens(qb: QuickBooksChecker):
    """
    Write any new refresh tokens back to Secrets Manager.
    
    QB refresh tokens are single-use: each token exchange returns a new one.
    If we don't persist the new token, the next Lambda invocation will fail
    because the old token has already been consumed.
    
    This does a single read-modify-write at the end of the run to minimize
    Secrets Manager API calls.
    """
    if not qb or not qb.updated_refresh_tokens:
        return
    
    if not QB_SECRET_ARN:
        logger.warning("No QB_SECRET_ARN - cannot persist updated refresh tokens")
        return
    
    try:
        # Read current secret
        resp = secrets_client.get_secret_value(SecretId=QB_SECRET_ARN)
        secret = json.loads(resp["SecretString"])
        companies = secret.get("companies", {})
        
        updated = []
        for company_name, company_creds in companies.items():
            realm_id = company_creds.get("realm_id", "")
            if realm_id in qb.updated_refresh_tokens:
                company_creds["refresh_token"] = qb.updated_refresh_tokens[realm_id]
                updated.append(company_name)
        
        if updated:
            secret["companies"] = companies
            secrets_client.put_secret_value(
                SecretId=QB_SECRET_ARN,
                SecretString=json.dumps(secret)
            )
            logger.info(f"Persisted new refresh tokens for: {', '.join(updated)}")
        
    except Exception as e:
        # Log but don't raise - the extractor run itself succeeded
        logger.error(f"Failed to persist refresh tokens: {e}. Tokens may be stale on next run.")


def check_exists_in_qb(qb: QuickBooksChecker, qb_creds: dict, company: str, vendor_name: str, doc_number: str) -> tuple[bool, dict, str]:
    """
    Check if bill already exists in QuickBooks for the given company.
    Returns (exists, qb_details, error_message).
    If QB check fails, error_message will contain the reason.
    """
    # Use same credential structure as poster: "companies" not "credentials"
    companies = qb_creds.get("companies", {})
    company_creds = companies.get(company)
    
    if not company_creds or not company_creds.get("realm_id") or not company_creds.get("refresh_token"):
        return False, {}, f"No QB credentials for company {company}"
    
    realm_id = company_creds["realm_id"]
    refresh_token = company_creds["refresh_token"]
    
    try:
        access_token = qb.get_access_token(refresh_token, realm_id)
        if not access_token:
            return False, {}, f"Failed to get QB access token for {company}"
        
        exists, details = qb.bill_exists(realm_id, access_token, vendor_name, doc_number)
        return exists, details, ""
        
    except Exception as e:
        error_msg = f"QB duplicate check failed for {company}: {str(e)}"
        logger.error(error_msg)
        return False, {}, error_msg


def is_duplicate(entry_id: str, write_date: str = None) -> bool:
    """
    Check if entry exists in DynamoDB.
    If write_date is provided, also check if the stored version is older.
    Returns False if the invoice was updated (allowing reprocessing).
    """
    if not table:
        return False
    try:
        resp = table.get_item(Key={"entry_id": entry_id})
        if "Item" not in resp:
            return False
        
        item = resp["Item"]
        
        # If we have a write_date and the item was rejected/failed, check if it was updated
        if write_date and item.get("status") in ["REJECTED", "VALIDATION_FAILED"]:
            stored_write_date = item.get("write_date", "")
            if write_date > stored_write_date:
                # Invoice was updated in Odoo - delete old record and allow reprocessing
                table.delete_item(Key={"entry_id": entry_id})
                logger.info(f"Invoice {entry_id} was updated in Odoo (write_date: {write_date} > {stored_write_date}), reprocessing")
                return False
        
        return True
    except ClientError:
        return False


def validate_invoice(invoice_data: dict, qb: Optional[QuickBooksChecker] = None, qb_creds: Optional[dict] = None) -> Tuple[bool, List[str]]:
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
    
    # PDF check (pdf_filename is set when Odoo has an attachment; actual upload happens after validation)
    if not invoice_data.get("pdf_filename"):
        warnings.append("No PDF attachment")
    
    # Intercompany check
    vendor_lower = (invoice_data.get("vendor_name") or "").lower()
    intercompany = ["scale media", "1md", "liveconscious", "live conscious", "essential elements", "tru alchemy"]
    if any(ic in vendor_lower for ic in intercompany):
        issues.append(f"Intercompany invoice - route to Chelsea")
    
    # TBD placeholder check
    ref = (invoice_data.get("bill_reference") or "").lower()
    if "tbd" in ref or "placeholder" in ref:
        issues.append("TBD placeholder invoice")
    
    # QuickBooks duplicate check
    if qb and qb_creds and not issues:  # Only check QB if no other issues
        company = invoice_data.get("company", "Unknown")
        vendor_name = invoice_data.get("vendor_name", "")
        bill_reference = invoice_data.get("bill_reference", "")
        entry_id = invoice_data.get("entry_id", "")
        
        # Use same DocNumber format as poster for consistency
        qb_doc_number = compute_qb_doc_number(bill_reference, entry_id)
        invoice_data["qb_doc_number"] = qb_doc_number  # Store for audit
        
        if company != "Unknown" and qb_doc_number:
            exists, qb_details, error_msg = check_exists_in_qb(qb, qb_creds, company, vendor_name, qb_doc_number)
            
            if error_msg:
                # QB check failed - this is a validation failure, not a warning
                issues.append(f"QB duplicate check failed: {error_msg}")
                logger.error(f"QB check failed for {entry_id}: {error_msg}")
            elif exists:
                # Found duplicate in QB - store all details for audit
                issues.append(f"Already exists in QuickBooks ({company})")
                invoice_data["already_in_qb"] = True
                invoice_data["qb_duplicate_details"] = qb_details  # Store QB bill ID and details
                logger.warning(f"QB duplicate: {entry_id} already exists as QB Bill ID {qb_details.get('qb_bill_id')}")
            else:
                # Check if DocNumber existed but vendor differed (best-effort match info)
                if qb_details.get("docnumber_exists"):
                    # Fuzzy duplicate check: if amount and date also match, likely same bill
                    odoo_amount = invoice_data.get("amount_total", 0)
                    odoo_date = invoice_data.get("bill_date", "")
                    qb_amounts = qb_details.get("qb_amounts", [])
                    qb_dates = qb_details.get("qb_dates", [])
                    
                    is_fuzzy_dup = False
                    for qb_amt, qb_dt in zip(qb_amounts, qb_dates):
                        amount_match = abs(odoo_amount - qb_amt) <= 0.02
                        
                        # Compare dates with ±1 day tolerance (handles timezone shifts, datetime vs date, etc.)
                        date_match = False
                        if odoo_date and qb_dt:
                            try:
                                odoo_d = datetime.strptime(str(odoo_date)[:10], "%Y-%m-%d").date()
                                qb_d = datetime.strptime(str(qb_dt)[:10], "%Y-%m-%d").date()
                                date_match = abs((odoo_d - qb_d).days) <= 1
                            except (ValueError, TypeError):
                                date_match = False
                        
                        if amount_match and date_match:
                            is_fuzzy_dup = True
                            logger.warning(
                                f"Fuzzy duplicate: {entry_id} matches QB bill "
                                f"(amount ${qb_amt:.2f} ≈ ${odoo_amount:.2f}, date {qb_dt} = {odoo_date}) "
                                f"despite vendor mismatch"
                            )
                            break
                    
                    if is_fuzzy_dup:
                        issues.append(
                            f"Likely duplicate in QB: DocNumber + amount + date match "
                            f"despite vendor name difference ({qb_details.get('odoo_vendor')} vs {qb_details.get('qb_vendors')})"
                        )
                        invoice_data["already_in_qb"] = True
                        invoice_data["qb_duplicate_details"] = qb_details
                    else:
                        warnings.append(qb_details.get("warning", "DocNumber exists in QB but vendor differs"))
                        invoice_data["qb_vendor_mismatch"] = qb_details
                        logger.info(f"QB check passed for {entry_id}, DocNumber exists with different vendor but amount/date differ")
                else:
                    # Clean pass - no duplicate found
                    logger.info(f"QB duplicate check passed for {entry_id} in {company}")
        elif company == "Unknown":
            # Optional: Make Unknown company a hard failure instead of warning
            # Uncomment this line to fail on Unknown companies:
            # issues.append(f"Unknown company - cannot determine QB realm: {invoice_data.get('company_name')}")
            pass
    
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


def process_bill(odoo: OdooClient, bill: dict, qb: Optional[QuickBooksChecker] = None, qb_creds: Optional[dict] = None) -> Optional[tuple]:
    """Process single bill, validate, and return (invoice_data, pdf_data) or None."""
    entry_id = bill.get("name", f"BILL-{bill['id']}")
    write_date = bill.get("write_date", "")
    
    # Duplicate check (with write_date for reprocessing rejected invoices)
    if is_duplicate(entry_id, write_date):
        logger.info(f"Skipping {entry_id} - already exists")
        return None
    
    # Company
    company_name = ""
    if bill.get("company_id"):
        company_name = bill["company_id"][1] if isinstance(bill["company_id"], list) else str(bill["company_id"])
    company = map_company_name(company_name)
    
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
                # Strip decimal portion (52120.2 → 52120)
                account_code = parts[0].split(".")[0]
        
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
            "qb_category": map_odoo_to_qb_account(account_code, account_name, product_name, company),
        })
    
    # PDF - fetch from Odoo but don't upload yet (upload after validation)
    attachment = odoo.get_attachment("account.move", bill["id"])
    pdf_data = None
    pdf_filename = None
    
    if attachment and attachment.get("datas"):
        try:
            pdf_data = base64.b64decode(attachment["datas"])
            pdf_filename = attachment.get("name")
        except Exception as e:
            logger.error(f"PDF decode failed for {entry_id}: {e}")
    
    # PO reference
    po_number = bill.get("invoice_origin") or bill.get("ref", "")
    
    # Use invoice line items as authoritative total (not move header).
    invoice_lines_total = round(sum(l["subtotal"] for l in processed_lines), 2)
    move_header_total = float(bill.get("amount_total", 0))
    
    if abs(invoice_lines_total - move_header_total) > 0.02:
        logger.warning(
            f"{entry_id}: Invoice lines total (${invoice_lines_total:.2f}) differs from "
            f"move header (${move_header_total:.2f}). Using invoice lines total per policy."
        )
    
    # Build invoice data (purely JSON-serializable, no raw bytes)
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
        "amount_total": invoice_lines_total,
        "amount_untaxed": invoice_lines_total,  # Same since no tax on vendor bills
        "odoo_move_total": move_header_total,  # Keep original for audit trail
        "currency": bill.get("currency_id", [None, "USD"])[1] if isinstance(bill.get("currency_id"), list) else "USD",
        "line_items": processed_lines,
        "pdf_s3_key": None,
        "pdf_filename": pdf_filename,
        "write_date": write_date,
    }
    
    return invoice_data, pdf_data


def lambda_handler(event, context):
    """Main handler."""
    logger.info(f"Starting extractor. DRY_RUN={DRY_RUN}")
    
    lookback_hours = event.get("lookback_hours", 24) if event else 24
    
    processed = 0
    validation_failed = 0
    already_in_qb = 0
    skipped = 0
    errors = 0
    
    try:
        # Initialize Odoo
        creds = get_odoo_credentials()
        odoo = OdooClient(
            base_url=ODOO_API_URL,
            database=creds["database"],
            username=creds["username"],
            api_key=creds["api_key"]
        )
        
        if not odoo.authenticate():
            raise Exception("Odoo authentication failed")
        
        # Initialize QB checker
        qb = init_qb_checker()
        qb_creds = get_qb_credentials() if qb else None
        
        # Token keepalive: refresh every company's token on every run.
        # QB refresh tokens are single-use and expire after 100 days of inactivity.
        if qb and qb_creds:
            companies = qb_creds.get("companies", {})
            for comp_name, comp_creds in companies.items():
                realm_id = comp_creds.get("realm_id", "")
                refresh_token = comp_creds.get("refresh_token", "")
                if realm_id and refresh_token:
                    token = qb.get_access_token(refresh_token, realm_id)
                    if token:
                        logger.info(f"Token keepalive OK for {comp_name}")
                    else:
                        logger.warning(f"Token keepalive FAILED for {comp_name} - re-auth needed")
        
        # Get bills from Odoo
        bills = odoo.get_posted_vendor_bills(since_hours=lookback_hours)
        logger.info(f"Found {len(bills)} posted vendor bills")
        
        for bill in bills:
            try:
                result = process_bill(odoo, bill, qb, qb_creds)
                
                if not result:
                    skipped += 1
                    continue
                
                invoice_data, pdf_data = result
                
                # Validate (including QB duplicate check)
                is_valid, issues = validate_invoice(invoice_data, qb, qb_creds)
                
                # Upload PDF to S3 for valid invoices and QB duplicates (for audit trail)
                if (is_valid or invoice_data.get("already_in_qb")) and pdf_data:
                    pdf_s3_key = upload_pdf_to_s3(
                        pdf_data, invoice_data["company"], invoice_data["entry_id"]
                    )
                    invoice_data["pdf_s3_key"] = pdf_s3_key
                
                if is_valid:
                    save_to_dynamodb(invoice_data, STATUS_READY_FOR_APPROVAL)
                    processed += 1
                    logger.info(f"✓ {invoice_data['entry_id']} ready for approval")
                elif invoice_data.get("already_in_qb"):
                    save_to_dynamodb(invoice_data, STATUS_ALREADY_IN_QB)
                    already_in_qb += 1
                    logger.info(f"⊘ {invoice_data['entry_id']} already in QuickBooks")
                else:
                    save_to_dynamodb(invoice_data, STATUS_VALIDATION_FAILED)
                    validation_failed += 1
                    logger.warning(f"✗ {invoice_data['entry_id']} validation failed: {issues}")
                    
            except Exception as e:
                errors += 1
                logger.error(f"Error processing {bill.get('name')}: {e}")
        
        summary = f"Ready: {processed}, ValidationFailed: {validation_failed}, AlreadyInQB: {already_in_qb}, Skipped: {skipped}, Errors: {errors}"
        logger.info(summary)
        
        # Persist any new QB refresh tokens back to Secrets Manager
        # This MUST happen before the Lambda exits or next run's tokens will be stale
        persist_refresh_tokens(qb)
        
        # Datadog custom metrics
        emit_metric("odoo_qb.extractor.bills_found", len(bills))
        emit_metric("odoo_qb.extractor.ready", processed)
        emit_metric("odoo_qb.extractor.validation_failed", validation_failed)
        emit_metric("odoo_qb.extractor.already_in_qb", already_in_qb)
        emit_metric("odoo_qb.extractor.errors", errors)
        tag_current_span({"bills.total": len(bills), "bills.ready": processed, "bills.errors": errors})
        
        if errors > 0:
            send_alert(f"[{ENVIRONMENT}] Extractor: {errors} errors", summary)
        
        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": summary,
                "ready_for_approval": processed,
                "validation_failed": validation_failed,
                "already_in_qb": already_in_qb,
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