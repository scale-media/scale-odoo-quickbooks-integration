#!/usr/bin/env python3
"""
Local test script for Odoo extraction.
Tests the JSON-RPC API calls without needing AWS.

Usage:
  python test_odoo.py

Set your API key as environment variable:
  export ODOO_API_KEY="your_api_key_here"
"""

import os
import json
import base64
import requests
from datetime import datetime, timedelta

# Configuration
ODOO_URL = "https://scalemedia.odoo.com"
ODOO_DB = "2jaszgithub-scale-media-master-305444"
ODOO_USERNAME = "lerone.pieters@scale.tech"
ODOO_API_KEY = 'os.environ.get("ODOO_API_KEY", "")'

# Output directory for downloaded PDFs
PDF_OUTPUT_DIR = "downloaded_pdfs"

if not ODOO_API_KEY:
    print("ERROR: Set ODOO_API_KEY environment variable")
    print("  export ODOO_API_KEY='your_api_key_here'")
    exit(1)


def jsonrpc_call(service, method, args):
    """Make a JSON-RPC call to Odoo."""
    payload = {
        "jsonrpc": "2.0",
        "method": "call",
        "params": {
            "service": service,
            "method": method,
            "args": args
        },
        "id": 1
    }
    
    response = requests.post(f"{ODOO_URL}/jsonrpc", json=payload, timeout=60)
    result = response.json()
    
    if "error" in result:
        raise Exception(f"Odoo error: {result['error']}")
    
    return result.get("result")


def authenticate():
    """Authenticate and return user ID."""
    uid = jsonrpc_call("common", "authenticate", [ODOO_DB, ODOO_USERNAME, ODOO_API_KEY, {}])
    print(f"Authenticated as user ID: {uid}")
    return uid


def search_read(uid, model, domain, fields, limit=10):
    """Search and read records from Odoo."""
    return jsonrpc_call(
        "object", "execute_kw",
        [ODOO_DB, uid, ODOO_API_KEY, model, "search_read", [domain], {"fields": fields, "limit": limit}]
    )


def download_pdf(uid, bill_id, bill_name):
    """Download PDF attachment for a bill and save locally."""
    
    # Get attachment with base64 data
    attachments = search_read(
        uid,
        "ir.attachment",
        [
            ("res_model", "=", "account.move"),
            ("res_id", "=", bill_id),
            ("mimetype", "=", "application/pdf")
        ],
        ["id", "name", "datas", "file_size"],  # 'datas' contains base64 encoded content
        limit=1
    )
    
    if not attachments:
        return None, "No PDF attachment found"
    
    attachment = attachments[0]
    
    if not attachment.get("datas"):
        return None, "PDF attachment has no data"
    
    # Decode base64
    try:
        pdf_bytes = base64.b64decode(attachment["datas"])
    except Exception as e:
        return None, f"Failed to decode PDF: {e}"
    
    # Create output directory if needed
    os.makedirs(PDF_OUTPUT_DIR, exist_ok=True)
    
    # Save PDF
    safe_name = bill_name.replace("/", "-")
    filename = f"{safe_name}_{attachment['name']}"
    filepath = os.path.join(PDF_OUTPUT_DIR, filename)
    
    with open(filepath, "wb") as f:
        f.write(pdf_bytes)
    
    return filepath, f"Saved {len(pdf_bytes):,} bytes"


def main():
    print("=" * 60)
    print("ODOO EXTRACTION TEST (with PDF download)")
    print("=" * 60)
    
    # Authenticate
    print("\nAuthenticating...")
    uid = authenticate()
    
    # Get recent posted vendor bills
    print("\nFetching recent posted vendor bills...")
    since_date = (datetime.utcnow() - timedelta(hours=72)).strftime("%Y-%m-%d %H:%M:%S")
    
    bills = search_read(
        uid,
        "account.move",
        [
            ("move_type", "=", "in_invoice"),
            ("state", "=", "posted"),
            ("create_date", ">=", since_date)
        ],
        ["id", "name", "ref", "partner_id", "company_id", "invoice_date", 
         "amount_total", "invoice_payment_term_id", "invoice_line_ids", "invoice_origin"],
        limit=5
    )
    
    print(f"Found {len(bills)} bills in last 72 hours\n")
    
    downloaded_pdfs = []
    
    for bill in bills:
        print("-" * 50)
        print(f"{bill['name']}")
        print(f"   Vendor:    {bill['partner_id'][1] if bill.get('partner_id') else 'N/A'}")
        print(f"   Company:   {bill['company_id'][1] if bill.get('company_id') else 'N/A'}")
        print(f"   Reference: {bill.get('ref', 'N/A')}")
        print(f"   Date:      {bill.get('invoice_date', 'N/A')}")
        print(f"   Amount:    ${bill.get('amount_total', 0):,.2f}")
        print(f"   Terms:     {bill['invoice_payment_term_id'][1] if bill.get('invoice_payment_term_id') else 'N/A'}")
        print(f"   PO:        {bill.get('invoice_origin', 'N/A')}")
        print(f"   Lines:     {len(bill.get('invoice_line_ids', []))} line items")
        
        # Get line item details for first bill
        if bill == bills[0] and bill.get("invoice_line_ids"):
            print("\n   Line Items:")
            lines = search_read(
                uid,
                "account.move.line",
                [("id", "in", bill["invoice_line_ids"])],
                ["id", "name", "account_id", "product_id", "quantity", "price_unit", "price_subtotal"],
                limit=10
            )
            
            for line in lines:
                if line.get("price_subtotal", 0) != 0:
                    account = line["account_id"][1] if line.get("account_id") else "N/A"
                    product = line["product_id"][1][:30] if line.get("product_id") else "N/A"
                    print(f"     • {product}")
                    print(f"       Account: {account}")
                    print(f"       Qty: {line.get('quantity', 0)} × ${line.get('price_unit', 0):,.4f} = ${line.get('price_subtotal', 0):,.2f}")
        
        # Download PDF attachment
        print("\n   Downloading PDF attachment...")
        filepath, message = download_pdf(uid, bill["id"], bill["name"])
        
        if filepath:
            print(f"     {message}")
            print(f"     Saved to: {filepath}")
            downloaded_pdfs.append(filepath)
        else:
            print(f"     {message}")
        
        print()
    
    print("=" * 60)
    print("TEST COMPLETE")
    print("=" * 60)
    
    if downloaded_pdfs:
        print(f"\nDownloaded {len(downloaded_pdfs)} PDFs to ./{PDF_OUTPUT_DIR}/")
        for pdf in downloaded_pdfs:
            print(f"   • {pdf}")


if __name__ == "__main__":
    main()