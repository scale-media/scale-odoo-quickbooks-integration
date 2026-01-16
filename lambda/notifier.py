"""
Lambda 3: Slack Notifier

Triggered by DynamoDB Stream when new records are inserted with
status=READY_FOR_APPROVAL. Sends Slack message with invoice details
and Approve/Reject buttons.
"""

import os
import json
import logging
from datetime import datetime
from typing import Optional
from urllib.parse import urlencode

import boto3
import requests
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")
SLACK_SECRET_ARN = os.environ.get("SLACK_SECRET_ARN", "")
SLACK_CHANNEL_ID = os.environ.get("SLACK_CHANNEL_ID", "")
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "")
S3_BUCKET = os.environ.get("S3_BUCKET", "")
APPROVAL_URL = os.environ.get("APPROVAL_URL", "")

# AWS clients
secrets_client = boto3.client("secretsmanager")
dynamodb = boto3.resource("dynamodb")
s3_client = boto3.client("s3")

table = dynamodb.Table(DYNAMODB_TABLE) if DYNAMODB_TABLE else None


def get_slack_config() -> dict:
    """Get Slack config from Secrets Manager or env."""
    if not SLACK_SECRET_ARN:
        return {
            "bot_token": os.environ.get("SLACK_BOT_TOKEN", ""),
            "channel_id": SLACK_CHANNEL_ID,
        }
    
    try:
        resp = secrets_client.get_secret_value(SecretId=SLACK_SECRET_ARN)
        config = json.loads(resp["SecretString"])
        config["channel_id"] = SLACK_CHANNEL_ID or config.get("channel_id", "")
        return config
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
        logger.error(f"Presigned URL generation failed: {e}")
        return None


def update_slack_message_ts(entry_id: str, message_ts: str):
    """Store Slack message timestamp for later updates."""
    if not table:
        return
    
    try:
        table.update_item(
            Key={"entry_id": entry_id},
            UpdateExpression="SET slack_message_ts = :ts, slack_channel = :ch",
            ExpressionAttributeValues={
                ":ts": message_ts,
                ":ch": SLACK_CHANNEL_ID
            }
        )
    except ClientError as e:
        logger.error(f"Failed to update message_ts: {e}")


def build_slack_message(invoice: dict) -> dict:
    """Build Slack Block Kit message with invoice details and buttons."""
    
    entry_id = invoice.get("entry_id", "Unknown")
    vendor = invoice.get("vendor_name", "Unknown")
    company = invoice.get("company", "Unknown")
    bill_ref = invoice.get("bill_reference", "N/A")
    amount = invoice.get("amount_total", 0)
    po_number = invoice.get("po_number", "N/A")
    bill_date = invoice.get("bill_date", "N/A")
    payment_terms = invoice.get("payment_terms", "N/A")
    line_items = invoice.get("line_items", [])
    pdf_key = invoice.get("pdf_s3_key")
    warnings = invoice.get("validation_warnings", [])
    
    # Line items summary
    line_summary = []
    for line in line_items[:5]:  # Show max 5 lines
        desc = line.get("product_name") or line.get("description", "Item")
        if len(desc) > 40:
            desc = desc[:37] + "..."
        subtotal = line.get("subtotal", 0)
        qb_cat = line.get("qb_category", "").split(":")[-1]  # Just the account name
        line_summary.append(f"• {desc}: ${subtotal:,.2f} → {qb_cat}")
    
    if len(line_items) > 5:
        line_summary.append(f"  _...and {len(line_items) - 5} more items_")
    
    lines_text = "\n".join(line_summary) if line_summary else "_No line items_"
    
    # Warnings section
    warnings_text = ""
    if warnings:
        warnings_text = "\n\n⚠️ *Warnings:*\n" + "\n".join(f"• {w}" for w in warnings)
    
    # PDF link
    pdf_url = get_presigned_url(pdf_key) if pdf_key else None
    
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "📄 Invoice Ready for Approval",
                "emoji": True
            }
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Vendor:*\n{vendor}"},
                {"type": "mrkdwn", "text": f"*Company:*\n{company}"},
                {"type": "mrkdwn", "text": f"*Bill #:*\n{bill_ref}"},
                {"type": "mrkdwn", "text": f"*Amount:*\n${amount:,.2f}"},
                {"type": "mrkdwn", "text": f"*PO:*\n{po_number}"},
                {"type": "mrkdwn", "text": f"*Date:*\n{bill_date}"},
                {"type": "mrkdwn", "text": f"*Terms:*\n{payment_terms}"},
                {"type": "mrkdwn", "text": f"*PDF:*\n{'✅ Attached' if pdf_key else '⚠️ Missing'}"},
            ]
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Line Items ({len(line_items)}):*\n{lines_text}{warnings_text}"
            }
        },
        {"type": "divider"},
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "✅ Approve", "emoji": True},
                    "style": "primary",
                    "action_id": "approve_invoice",
                    "value": entry_id
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "❌ Reject", "emoji": True},
                    "style": "danger",
                    "action_id": "reject_invoice",
                    "value": entry_id
                }
            ]
        }
    ]
    
    # Add PDF button if available
    if pdf_url:
        blocks[-1]["elements"].append({
            "type": "button",
            "text": {"type": "plain_text", "text": "📎 View PDF", "emoji": True},
            "url": pdf_url,
            "action_id": "view_pdf"
        })
    
    # Add context with entry ID (for reference)
    blocks.append({
        "type": "context",
        "elements": [
            {"type": "mrkdwn", "text": f"Entry ID: `{entry_id}` | {ENVIRONMENT}"}
        ]
    })
    
    return {"blocks": blocks}


def send_slack_message(config: dict, invoice: dict) -> Optional[str]:
    """Send Slack message and return message timestamp."""
    
    message = build_slack_message(invoice)
    
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
        
        if not result.get("ok"):
            logger.error(f"Slack API error: {result.get('error')}")
            return None
        
        message_ts = result.get("ts")
        logger.info(f"Sent Slack message: {message_ts}")
        return message_ts
        
    except Exception as e:
        logger.error(f"Failed to send Slack message: {e}")
        return None


def deserialize_dynamodb_item(item: dict) -> dict:
    """Convert DynamoDB stream format to regular dict."""
    from boto3.dynamodb.types import TypeDeserializer
    deserializer = TypeDeserializer()
    
    return {k: deserializer.deserialize(v) for k, v in item.items()}


def lambda_handler(event, context):
    """Handle DynamoDB Stream events."""
    logger.info(f"Received {len(event.get('Records', []))} records")
    
    config = get_slack_config()
    
    if not config.get("bot_token"):
        logger.error("Slack bot token not configured")
        return {"statusCode": 500, "body": "Missing Slack config"}
    
    processed = 0
    
    for record in event.get("Records", []):
        # Only process INSERT events (new records)
        if record.get("eventName") != "INSERT":
            continue
        
        # Get the new item
        new_image = record.get("dynamodb", {}).get("NewImage")
        if not new_image:
            continue
        
        # Deserialize
        invoice = deserialize_dynamodb_item(new_image)
        
        # Only process READY_FOR_APPROVAL status
        if invoice.get("status") != "READY_FOR_APPROVAL":
            continue
        
        entry_id = invoice.get("entry_id", "Unknown")
        logger.info(f"Processing notification for {entry_id}")
        
        # Send Slack message
        message_ts = send_slack_message(config, invoice)
        
        if message_ts:
            # Store message timestamp for later updates
            update_slack_message_ts(entry_id, message_ts)
            processed += 1
    
    return {
        "statusCode": 200,
        "body": json.dumps({"notifications_sent": processed})
    }
