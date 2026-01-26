"""
Lambda 4: Approval Handler

Lambda Function URL / API Gateway that handles Slack interactive button clicks.
Updates DynamoDB status and enqueues approved invoices to SQS.
"""

import os
import json
import hmac
import hashlib
import logging
import time
import base64
from datetime import datetime
from urllib.parse import parse_qs

import boto3
import requests
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "")
SQS_QUEUE_URL = os.environ.get("SQS_QUEUE_URL", "")
SLACK_SECRET_ARN = os.environ.get("SLACK_SECRET_ARN", "")

# Status constants
STATUS_APPROVED = "APPROVED"
STATUS_REJECTED = "REJECTED"

# Rejection reasons dropdown
REJECT_REASONS = [
    "Wrong GL account",
    "Missing PDF",
    "Intercompany - route to Chelsea",
    "Duplicate invoice",
    "Amount mismatch",
    "Wrong vendor",
    "Needs PO update",
    "Other"
]

# AWS clients
secrets_client = boto3.client("secretsmanager")
dynamodb = boto3.resource("dynamodb")
sqs_client = boto3.client("sqs")

table = dynamodb.Table(DYNAMODB_TABLE) if DYNAMODB_TABLE else None


def get_slack_config() -> dict:
    """Get Slack config from Secrets Manager."""
    if not SLACK_SECRET_ARN:
        return {
            "bot_token": os.environ.get("SLACK_BOT_TOKEN", ""),
            "signing_secret": os.environ.get("SLACK_SIGNING_SECRET", ""),
        }
    
    try:
        resp = secrets_client.get_secret_value(SecretId=SLACK_SECRET_ARN)
        return json.loads(resp["SecretString"])
    except ClientError as e:
        logger.error(f"Failed to get Slack config: {e}")
        raise


def verify_slack_signature(headers: dict, body: str, signing_secret: str) -> bool:
    """
    Verify request is from Slack using signing secret.
    
    IMPORTANT: body must be the decoded string (not base64), as Slack signs the actual payload.
    """
    
    # Skip verification if no signing secret (dev mode)
    if not signing_secret:
        logger.warning("Slack signing secret not configured - skipping verification")
        return True
    
    # Lambda Function URL / API Gateway headers are lowercase
    timestamp = headers.get("x-slack-request-timestamp", "")
    signature = headers.get("x-slack-signature", "")
    
    if not timestamp or not signature:
        logger.error(f"Missing Slack signature headers. Headers present: {list(headers.keys())}")
        return False
    
    # Check timestamp is recent (within 5 minutes)
    try:
        if abs(time.time() - int(timestamp)) > 300:
            logger.error("Slack timestamp too old")
            return False
    except ValueError:
        logger.error(f"Invalid timestamp: {timestamp}")
        return False
    
    # Compute expected signature
    sig_basestring = f"v0:{timestamp}:{body}"
    expected = "v0=" + hmac.new(
        signing_secret.encode(),
        sig_basestring.encode(),
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(expected, signature):
        logger.error("Slack signature mismatch")
        logger.debug(f"Expected: {expected[:20]}...")
        logger.debug(f"Received: {signature[:20]}...")
        return False
    
    return True


def update_invoice_status(entry_id: str, status: str, user: str, reason: str = None) -> bool:
    """
    Update invoice status in DynamoDB with conditional check.
    Only updates if current status is READY_FOR_APPROVAL (prevents double-approvals).
    """
    if not table:
        logger.warning(f"[NO DB] Would update {entry_id} to {status}")
        return True
    
    try:
        update_expr = "SET #status = :status, approved_by = :user, approved_at = :ts"
        expr_values = {
            ":status": status,
            ":user": user,
            ":ts": datetime.utcnow().isoformat(),
            ":expected_status": "READY_FOR_APPROVAL"
        }
        
        if reason:
            update_expr += ", rejection_reason = :reason"
            expr_values[":reason"] = reason
        
        table.update_item(
            Key={"entry_id": entry_id},
            UpdateExpression=update_expr,
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues=expr_values,
            ConditionExpression="#status = :expected_status"
        )
        
        logger.info(f"Updated {entry_id} to {status} by {user}")
        return True
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            logger.warning(f"Invoice {entry_id} already processed (not in READY_FOR_APPROVAL state)")
            return False
        logger.error(f"DynamoDB update failed: {e}")
        return False


def enqueue_for_posting(entry_id: str) -> bool:
    """Add approved invoice to SQS queue."""
    if not SQS_QUEUE_URL:
        logger.warning(f"[NO SQS] Would enqueue {entry_id}")
        return True
    
    try:
        params = {
            "QueueUrl": SQS_QUEUE_URL,
            "MessageBody": json.dumps({"entry_id": entry_id})
        }
        # Only add MessageGroupId for FIFO queues
        if ".fifo" in SQS_QUEUE_URL:
            params["MessageGroupId"] = "invoices"
        
        sqs_client.send_message(**params)
        logger.info(f"Enqueued {entry_id} for posting")
        return True
        
    except ClientError as e:
        logger.error(f"SQS enqueue failed: {e}")
        return False


def update_slack_message(response_url: str, entry_id: str, action: str, user: str):
    """Update the original Slack message to show approval/rejection."""
    
    if action == "approve":
        text = f"✅ *Approved* by <@{user}>"
        color = "#36a64f"
    elif action == "reject":
        text = f"❌ *Rejected* by <@{user}>"
        color = "#dc3545"
    elif action == "already_processed":
        text = f"⚠️ *Already processed* (clicked by <@{user}>)"
        color = "#ffc107"
    else:
        text = f"Unknown action: {action}"
        color = "#6c757d"
    
    # Replace original message with simpler confirmation
    payload = {
        "replace_original": True,
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{text}\n`{entry_id}`"
                }
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"Processed at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"}
                ]
            }
        ]
    }
    
    try:
        resp = requests.post(response_url, json=payload, timeout=5)
        if resp.status_code != 200:
            logger.warning(f"Slack message update failed: {resp.text}")
    except Exception as e:
        logger.error(f"Failed to update Slack message: {e}")


def update_slack_message_with_reason(response_url: str, entry_id: str, user: str, reason: str):
    """Update Slack message showing rejection with reason."""
    
    payload = {
        "replace_original": True,
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"❌ *Rejected* by <@{user}>\n`{entry_id}`"
                }
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"*Reason:* {reason}"},
                    {"type": "mrkdwn", "text": f"Processed at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"}
                ]
            }
        ]
    }
    
    try:
        resp = requests.post(response_url, json=payload, timeout=5)
        if resp.status_code != 200:
            logger.warning(f"Slack message update failed: {resp.text}")
    except Exception as e:
        logger.error(f"Failed to update Slack message: {e}")


def open_reject_modal(trigger_id: str, entry_id: str, response_url: str, bot_token: str):
    """Open modal for rejection reason selection."""
    
    modal = {
        "type": "modal",
        "callback_id": "reject_modal",
        "private_metadata": json.dumps({"entry_id": entry_id, "response_url": response_url}),
        "title": {"type": "plain_text", "text": "Reject Invoice"},
        "submit": {"type": "plain_text", "text": "Reject"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Invoice:* `{entry_id}`"
                }
            },
            {
                "type": "input",
                "block_id": "reason_block",
                "element": {
                    "type": "static_select",
                    "action_id": "reject_reason",
                    "placeholder": {"type": "plain_text", "text": "Select reason"},
                    "options": [
                        {"text": {"type": "plain_text", "text": r}, "value": r}
                        for r in REJECT_REASONS
                    ]
                },
                "label": {"type": "plain_text", "text": "Rejection Reason"}
            },
            {
                "type": "input",
                "block_id": "notes_block",
                "optional": True,
                "element": {
                    "type": "plain_text_input",
                    "action_id": "reject_notes",
                    "placeholder": {"type": "plain_text", "text": "Additional notes (optional)"},
                    "multiline": False
                },
                "label": {"type": "plain_text", "text": "Notes"}
            }
        ]
    }
    
    try:
        resp = requests.post(
            "https://slack.com/api/views.open",
            headers={
                "Authorization": f"Bearer {bot_token}",
                "Content-Type": "application/json"
            },
            json={"trigger_id": trigger_id, "view": modal},
            timeout=5
        )
        result = resp.json()
        if not result.get("ok"):
            logger.error(f"Failed to open modal: {result.get('error')}")
    except Exception as e:
        logger.error(f"Failed to open reject modal: {e}")


def handle_approval(payload: dict, bot_token: str) -> dict:
    """Handle approve/reject button clicks."""
    
    actions = payload.get("actions", [])
    if not actions:
        return {"statusCode": 400, "body": "No actions"}
    
    action = actions[0]
    action_id = action.get("action_id", "")
    entry_id = action.get("value", "")
    
    user_info = payload.get("user", {})
    user_id = user_info.get("id", "unknown")
    username = user_info.get("username", "unknown")
    
    response_url = payload.get("response_url", "")
    trigger_id = payload.get("trigger_id", "")
    
    logger.info(f"Action: {action_id} on {entry_id} by {username}")
    
    # Handle view PDF - no action needed, Slack opens URL
    if action_id == "view_pdf":
        return {"statusCode": 200, "body": ""}
    
    # Handle approval
    if action_id == "approve_invoice":
        if update_invoice_status(entry_id, STATUS_APPROVED, username):
            if enqueue_for_posting(entry_id):
                update_slack_message(response_url, entry_id, "approve", user_id)
                return {"statusCode": 200, "body": ""}
            else:
                return {"statusCode": 500, "body": "Failed to enqueue"}
        else:
            # Already processed - update Slack message anyway
            update_slack_message(response_url, entry_id, "already_processed", user_id)
            return {"statusCode": 200, "body": "Already processed"}
    
    # Handle quick rejection (no reason)
    if action_id == "quick_reject_invoice":
        if update_invoice_status(entry_id, STATUS_REJECTED, username, "Quick rejected via Slack"):
            update_slack_message(response_url, entry_id, "reject", user_id)
            return {"statusCode": 200, "body": ""}
        else:
            update_slack_message(response_url, entry_id, "already_processed", user_id)
            return {"statusCode": 200, "body": "Already processed"}
    
    # Handle rejection with reason - open modal
    if action_id == "reject_invoice":
        open_reject_modal(trigger_id, entry_id, response_url, bot_token)
        return {"statusCode": 200, "body": ""}
    
    return {"statusCode": 400, "body": f"Unknown action: {action_id}"}


def handle_modal_submit(payload: dict) -> dict:
    """Handle modal submission (rejection with reason)."""
    
    user_info = payload.get("user", {})
    user_id = user_info.get("id", "unknown")
    username = user_info.get("username", "unknown")
    
    # Get entry_id and response_url from private_metadata
    private_metadata = payload.get("view", {}).get("private_metadata", "{}")
    try:
        metadata = json.loads(private_metadata)
        entry_id = metadata.get("entry_id", "")
        response_url = metadata.get("response_url", "")
    except:
        logger.error("Failed to parse modal metadata")
        return {"statusCode": 400, "body": "Invalid metadata"}
    
    # Get selected reason from modal values
    values = payload.get("view", {}).get("state", {}).get("values", {})
    
    reason = ""
    notes = ""
    
    reason_block = values.get("reason_block", {})
    if reason_block:
        reason_data = reason_block.get("reject_reason", {})
        selected = reason_data.get("selected_option", {})
        reason = selected.get("value", "Unknown reason")
    
    notes_block = values.get("notes_block", {})
    if notes_block:
        notes_data = notes_block.get("reject_notes", {})
        notes = notes_data.get("value", "")
    
    # Combine reason and notes
    full_reason = reason
    if notes:
        full_reason = f"{reason}: {notes}"
    
    logger.info(f"Modal submit: {entry_id} rejected by {username} - {full_reason}")
    
    # Update status with reason
    if update_invoice_status(entry_id, STATUS_REJECTED, username, full_reason):
        # Update the original Slack message
        if response_url:
            update_slack_message_with_reason(response_url, entry_id, user_id, full_reason)
        return {"statusCode": 200, "body": ""}
    else:
        # Already processed
        if response_url:
            update_slack_message(response_url, entry_id, "already_processed", user_id)
        return {"statusCode": 200, "body": "Already processed"}


def lambda_handler(event, context):
    """Handle API Gateway / Lambda Function URL requests from Slack."""
    
    logger.info(f"Received request: {event.get('requestContext', {}).get('http', {}).get('method')}")
    
    # Get Slack config for verification
    config = get_slack_config()
    
    # Get body - decode if base64 encoded
    body = event.get("body", "")
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8")
    
    # Verify request is from Slack (using decoded body)
    headers = event.get("headers", {})
    if not verify_slack_signature(headers, body, config.get("signing_secret", "")):
        logger.error("Slack signature verification failed")
        return {
            "statusCode": 401,
            "body": "Invalid signature"
        }
    
    # Parse the payload (body is already decoded)
    try:
        parsed = parse_qs(body)
        payload_str = parsed.get("payload", ["{}"])[0]
        payload = json.loads(payload_str)
    except Exception as e:
        logger.error(f"Failed to parse payload: {e}")
        return {"statusCode": 400, "body": "Invalid payload"}
    
    # Handle different interaction types
    interaction_type = payload.get("type", "")
    
    if interaction_type == "block_actions":
        return handle_approval(payload, config.get("bot_token", ""))
    
    if interaction_type == "view_submission":
        # Modal submitted
        callback_id = payload.get("view", {}).get("callback_id", "")
        if callback_id == "reject_modal":
            return handle_modal_submit(payload)
    
    # Handle URL verification (for setup)
    if interaction_type == "url_verification":
        return {
            "statusCode": 200,
            "body": payload.get("challenge", "")
        }
    
    logger.warning(f"Unknown interaction type: {interaction_type}")
    return {"statusCode": 200, "body": ""}