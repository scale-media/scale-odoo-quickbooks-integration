"""
Lambda 3: Slack Notifier

Triggered by DynamoDB Stream when new invoices are ready for approval.
Sends Slack message with invoice details, line items with QB account mappings,
and Approve/Reject/View PDF buttons.
"""

import os
import json
import logging
from datetime import datetime
from typing import Optional

import boto3
import requests
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment
SLACK_SECRET_ARN = os.environ.get("SLACK_SECRET_ARN", "")
S3_BUCKET = os.environ.get("S3_BUCKET", "")
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "")

# AWS clients
secrets_client = boto3.client("secretsmanager")
s3_client = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")

table = dynamodb.Table(DYNAMODB_TABLE) if DYNAMODB_TABLE else None


def get_slack_config() -> dict:
    """Get Slack credentials from Secrets Manager."""
    if not SLACK_SECRET_ARN:
        return {
            "bot_token": os.environ.get("SLACK_BOT_TOKEN", ""),
            "channel_id": os.environ.get("SLACK_CHANNEL_ID", ""),
        }
    
    try:
        resp = secrets_client.get_secret_value(SecretId=SLACK_SECRET_ARN)
        return json.loads(resp["SecretString"])
    except ClientError as e:
        logger.error(f"Failed to get Slack config: {e}")
        raise


def get_presigned_url(s3_key: str, expires_in: int = 7200) -> Optional[str]:
    """Generate presigned URL for PDF. Default 2 hours."""
    if not S3_BUCKET or not s3_key:
        return None
    
    try:
        url = s3_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": S3_BUCKET, "Key": s3_key},
            ExpiresIn=expires_in
        )
        return url
    except ClientError as e:
        logger.error(f"Failed to generate presigned URL: {e}")
        return None


def format_currency(amount: float) -> str:
    """Format amount as currency."""
    return f"${amount:,.2f}"


def build_slack_message(invoice: dict) -> dict:
    """Build Slack Block Kit message for invoice approval."""
    
    entry_id = invoice.get("entry_id", "Unknown")
    vendor = invoice.get("vendor_name", "Unknown Vendor")
    company = invoice.get("company", "Unknown")
    amount = invoice.get("amount_total", 0)
    bill_ref = invoice.get("bill_reference", "N/A")
    bill_date = invoice.get("bill_date", "N/A")
    due_date = invoice.get("due_date", "N/A")
    po_number = invoice.get("po_number", "")
    payment_terms = invoice.get("payment_terms", "Net30")
    line_items = invoice.get("line_items", [])
    warnings = invoice.get("validation_warnings", [])
    pdf_key = invoice.get("pdf_s3_key", "")
    is_intercompany = invoice.get("is_intercompany", False)
    
    # Header
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"📄 Invoice Approval Required",
                "emoji": True
            }
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Vendor:*\n{vendor}"},
                {"type": "mrkdwn", "text": f"*Company:*\n{company}"},
                {"type": "mrkdwn", "text": f"*Bill #:*\n{bill_ref}"},
                {"type": "mrkdwn", "text": f"*Amount:*\n{format_currency(amount)}"},
                {"type": "mrkdwn", "text": f"*PO:*\n{po_number or 'N/A'}"},
                {"type": "mrkdwn", "text": f"*Date:*\n{bill_date}"},
                {"type": "mrkdwn", "text": f"*Due:*\n{due_date or 'N/A'}"},
                {"type": "mrkdwn", "text": f"*Terms:*\n{payment_terms}"},
            ]
        },
        {"type": "divider"},
    ]
    
    # Line items with QB account mapping
    if line_items:
        # Build line items text showing QB account mapping
        lines_text = "*Line Items → QB Account:*\n"
        for i, line in enumerate(line_items[:8]):  # Show max 8 lines
            subtotal = line.get("subtotal", 0)
            description = line.get("description", "")[:30] or line.get("product_name", "")[:30] or "Item"
            qb_category = line.get("qb_category", "Unknown")
            account_code = line.get("account_code", "")
            
            # Format: $500.00 - Description → QB: Category
            lines_text += f"• {format_currency(subtotal)} - {description}\n"
            lines_text += f"   ↳ `{account_code}` → _{qb_category}_\n"
        
        if len(line_items) > 8:
            lines_text += f"_... and {len(line_items) - 8} more lines_\n"
        
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": lines_text}
        })
        blocks.append({"type": "divider"})
    
    # Intercompany warning
    if is_intercompany:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "⚠️ *INTERCOMPANY INVOICE* - Will NOT auto-post to QuickBooks. Chelsea must enter manually as journal entry."
            }
        })
    
    # Validation warnings
    if warnings:
        warning_text = "⚠️ *Warnings:*\n" + "\n".join(f"• {w}" for w in warnings)
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": warning_text}
        })
    
    # Action buttons
    buttons = []
    
    if is_intercompany:
        # For intercompany, just acknowledge (no QB posting)
        buttons.append({
            "type": "button",
            "text": {"type": "plain_text", "text": "✓ Acknowledge", "emoji": True},
            "style": "primary",
            "action_id": "acknowledge_intercompany",
            "value": entry_id
        })
    else:
        buttons.append({
            "type": "button",
            "text": {"type": "plain_text", "text": "✅ Approve", "emoji": True},
            "style": "primary",
            "action_id": "approve_invoice",
            "value": entry_id
        })
    
    buttons.append({
        "type": "button",
        "text": {"type": "plain_text", "text": "❌ Reject", "emoji": True},
        "style": "danger",
        "action_id": "reject_invoice",
        "value": entry_id
    })
    
    # Add PDF button if available
    if pdf_key:
        pdf_url = get_presigned_url(pdf_key)
        if pdf_url:
            buttons.append({
                "type": "button",
                "text": {"type": "plain_text", "text": "📎 View PDF", "emoji": True},
                "action_id": "view_pdf",
                "url": pdf_url,
                "value": entry_id
            })
    
    blocks.append({
        "type": "actions",
        "elements": buttons
    })
    
    # Footer with entry ID
    blocks.append({
        "type": "context",
        "elements": [
            {"type": "mrkdwn", "text": f"`{entry_id}`"}
        ]
    })
    
    return {"blocks": blocks}


def send_slack_message(config: dict, message: dict) -> Optional[str]:
    """Send message to Slack and return message timestamp."""
    
    try:
        resp = requests.post(
            "https://slack.com/api/chat.postMessage",
            headers={
                "Authorization": f"Bearer {config['bot_token']}",
                "Content-Type": "application/json"
            },
            json={
                "channel": config["channel_id"],
                **message
            },
            timeout=10
        )
        
        result = resp.json()
        
        if result.get("ok"):
            return result.get("ts")
        else:
            logger.error(f"Slack API error: {result.get('error')}")
            return None
            
    except Exception as e:
        logger.error(f"Failed to send Slack message: {e}")
        return None


def update_invoice_with_slack_ts(entry_id: str, slack_ts: str):
    """Store Slack message timestamp for later updates."""
    if not table or not slack_ts:
        return
    
    try:
        table.update_item(
            Key={"entry_id": entry_id},
            UpdateExpression="SET slack_ts = :ts, notified_at = :now",
            ExpressionAttributeValues={
                ":ts": slack_ts,
                ":now": datetime.utcnow().isoformat()
            }
        )
    except ClientError as e:
        logger.error(f"Failed to update Slack TS: {e}")


def deserialize_dynamodb_item(item: dict) -> dict:
    """Convert DynamoDB stream format to regular dict."""
    result = {}
    
    for key, value in item.items():
        if "S" in value:
            result[key] = value["S"]
        elif "N" in value:
            result[key] = float(value["N"])
        elif "BOOL" in value:
            result[key] = value["BOOL"]
        elif "L" in value:
            result[key] = [deserialize_dynamodb_item({"v": v})["v"] for v in value["L"]]
        elif "M" in value:
            result[key] = deserialize_dynamodb_item(value["M"])
        elif "NULL" in value:
            result[key] = None
        else:
            result[key] = str(value)
    
    return result


def lambda_handler(event, context):
    """Handle DynamoDB stream events."""
    
    records = event.get("Records", [])
    logger.info(f"Received {len(records)} records")
    
    config = get_slack_config()
    
    for record in records:
        try:
            # Only process INSERTs with READY_FOR_APPROVAL status
            if record.get("eventName") != "INSERT":
                continue
            
            new_image = record.get("dynamodb", {}).get("NewImage", {})
            if not new_image:
                continue
            
            invoice = deserialize_dynamodb_item(new_image)
            entry_id = invoice.get("entry_id", "Unknown")
            status = invoice.get("status", "")
            
            if status != "READY_FOR_APPROVAL":
                continue
            
            logger.info(f"Processing notification for {entry_id}")
            
            # Check if intercompany (for display purposes)
            vendor_lower = (invoice.get("vendor_name") or "").lower()
            intercompany_vendors = ["scale media", "1md", "liveconscious", "live conscious", "essential elements", "tru alchemy", "digital med", "infinite focus", "new momentum", "direct insight"]
            invoice["is_intercompany"] = any(ic in vendor_lower for ic in intercompany_vendors)
            
            # Build and send message
            message = build_slack_message(invoice)
            slack_ts = send_slack_message(config, message)
            
            if slack_ts:
                update_invoice_with_slack_ts(entry_id, slack_ts)
                logger.info(f"Sent notification for {entry_id}")
            else:
                logger.error(f"Failed to notify for {entry_id}")
                
        except Exception as e:
            logger.error(f"Error processing record: {e}")
    
    return {"statusCode": 200, "body": f"Processed {len(records)} records"}