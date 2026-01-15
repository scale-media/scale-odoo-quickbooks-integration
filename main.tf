terraform {
  required_version = ">= 1.0.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "odoo-qb-integration"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# Variables

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "prod"
}

variable "odoo_api_url" {
  description = "Odoo API base URL"
  type        = string
  default     = "https://scalemedia.odoo.com"
}

variable "alert_email" {
  description = "Email for pipeline failure alerts"
  type        = string
}

variable "schedule_rate" {
  description = "EventBridge schedule rate for Odoo polling"
  type        = string
  default     = "rate(15 minutes)"
}

variable "slack_channel_id" {
  description = "Slack channel ID for approval notifications"
  type        = string
}

variable "slack_bot_token" {
  description = "Slack Bot OAuth token (starts with xoxb-)"
  type        = string
  sensitive   = true
}

variable "slack_signing_secret" {
  description = "Slack app signing secret for request verification"
  type        = string
  sensitive   = true
}

# Odoo Credentials
variable "odoo_database" {
  description = "Odoo database name"
  type        = string
  default     = "2jaszgithub-scale-media-master-305444"
}

variable "odoo_username" {
  description = "Odoo API username (email)"
  type        = string
}

variable "odoo_api_key" {
  description = "Odoo API key"
  type        = string
  sensitive   = true
}

# QuickBooks Credentials
variable "qb_client_id" {
  description = "QuickBooks OAuth client ID"
  type        = string
}

variable "qb_client_secret" {
  description = "QuickBooks OAuth client secret"
  type        = string
  sensitive   = true
}

variable "qb_refresh_token" {
  description = "QuickBooks OAuth refresh token"
  type        = string
  sensitive   = true
}

variable "qb_realm_ids" {
  description = "QuickBooks realm IDs per company"
  type        = map(string)
  default     = {
    "1MD"              = ""
    "LiveConscious"    = ""
    "EssentialElements" = ""
    "TruAlchemy"       = ""
  }
}

variable "qb_use_sandbox" {
  description = "Use QuickBooks sandbox environment"
  type        = bool
  default     = false
}

# Data Sources

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# S3 Bucket - PDF Storage

resource "aws_s3_bucket" "invoice_pdfs" {
  bucket = "scale-media-odoo-invoices-${var.environment}"
}

resource "aws_s3_bucket_versioning" "invoice_pdfs" {
  bucket = aws_s3_bucket.invoice_pdfs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "invoice_pdfs" {
  bucket = aws_s3_bucket.invoice_pdfs.id
  
  rule {
    id     = "archive-old-invoices"
    status = "Enabled"
    
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    
    expiration {
      days = 2555  # 7 years
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "invoice_pdfs" {
  bucket = aws_s3_bucket.invoice_pdfs.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "invoice_pdfs" {
  bucket = aws_s3_bucket.invoice_pdfs.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# DynamoDB - Invoice Tracking with Streams

resource "aws_dynamodb_table" "invoices" {
  name             = "odoo-qb-invoices-${var.environment}"
  billing_mode     = "PAY_PER_REQUEST"
  hash_key         = "entry_id"
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
  
  attribute {
    name = "entry_id"
    type = "S"
  }
  
  attribute {
    name = "status"
    type = "S"
  }
  
  attribute {
    name = "company"
    type = "S"
  }
  
  global_secondary_index {
    name            = "status-index"
    hash_key        = "status"
    projection_type = "ALL"
  }
  
  global_secondary_index {
    name            = "company-status-index"
    hash_key        = "company"
    range_key       = "status"
    projection_type = "ALL"
  }
  
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
  
  point_in_time_recovery {
    enabled = true
  }
}

# SQS - Approved Invoices Queue

resource "aws_sqs_queue" "approved_invoices" {
  name                       = "odoo-approved-invoices-${var.environment}"
  visibility_timeout_seconds = 300  # 5 min (match Lambda timeout)
  message_retention_seconds  = 1209600  # 14 days
  receive_wait_time_seconds  = 20  # Long polling
  
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.poster_dlq.arn
    maxReceiveCount     = 3
  })
}

resource "aws_sqs_queue" "poster_dlq" {
  name                      = "odoo-poster-dlq-${var.environment}"
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue" "extractor_dlq" {
  name                      = "odoo-extractor-dlq-${var.environment}"
  message_retention_seconds = 1209600
}

# SNS - Alerting

resource "aws_sns_topic" "alerts" {
  name = "odoo-qb-alerts-${var.environment}"
}

resource "aws_sns_topic_subscription" "email_alert" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Secrets Manager

resource "aws_secretsmanager_secret" "odoo_credentials" {
  name        = "odoo-qb-integration/odoo-credentials-${var.environment}"
  description = "Odoo API credentials"
}

resource "aws_secretsmanager_secret_version" "odoo_credentials" {
  secret_id = aws_secretsmanager_secret.odoo_credentials.id
  secret_string = jsonencode({
    database = var.odoo_database
    username = var.odoo_username
    api_key  = var.odoo_api_key
  })
}

resource "aws_secretsmanager_secret" "qb_credentials" {
  name        = "odoo-qb-integration/quickbooks-credentials-${var.environment}"
  description = "QuickBooks OAuth credentials"
}

resource "aws_secretsmanager_secret_version" "qb_credentials" {
  secret_id = aws_secretsmanager_secret.qb_credentials.id
  secret_string = jsonencode({
    client_id      = var.qb_client_id
    client_secret  = var.qb_client_secret
    refresh_token  = var.qb_refresh_token
    realm_ids      = var.qb_realm_ids
    use_sandbox    = var.qb_use_sandbox
  })
}

resource "aws_secretsmanager_secret" "slack_config" {
  name        = "odoo-qb-integration/slack-config-${var.environment}"
  description = "Slack bot token and signing secret"
}

resource "aws_secretsmanager_secret_version" "slack_config" {
  secret_id = aws_secretsmanager_secret.slack_config.id
  secret_string = jsonencode({
    bot_token      = var.slack_bot_token
    signing_secret = var.slack_signing_secret
    channel_id     = var.slack_channel_id
  })
}

# IAM Roles

# Extractor Role
resource "aws_iam_role" "extractor_role" {
  name = "odoo-extractor-role-${var.environment}"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "extractor_policy" {
  name = "extractor-policy"
  role = aws_iam_role.extractor_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject"]
        Resource = "${aws_s3_bucket.invoice_pdfs.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query"]
        Resource = [aws_dynamodb_table.invoices.arn, "${aws_dynamodb_table.invoices.arn}/index/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.odoo_credentials.arn
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = aws_sqs_queue.extractor_dlq.arn
      }
    ]
  })
}

# Notifier Role
resource "aws_iam_role" "notifier_role" {
  name = "odoo-notifier-role-${var.environment}"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "notifier_policy" {
  name = "notifier-policy"
  role = aws_iam_role.notifier_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetRecords", "dynamodb:GetShardIterator", "dynamodb:DescribeStream", "dynamodb:ListStreams"]
        Resource = aws_dynamodb_table.invoices.stream_arn
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.invoices.arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.invoice_pdfs.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.slack_config.arn
      }
    ]
  })
}

# Approval Handler Role
resource "aws_iam_role" "approval_role" {
  name = "odoo-approval-role-${var.environment}"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "approval_policy" {
  name = "approval-policy"
  role = aws_iam_role.approval_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.invoices.arn
      },
      {
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = aws_sqs_queue.approved_invoices.arn
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.slack_config.arn
      }
    ]
  })
}

# Poster Role
resource "aws_iam_role" "poster_role" {
  name = "odoo-poster-role-${var.environment}"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "poster_policy" {
  name = "poster-policy"
  role = aws_iam_role.poster_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:DeleteObject", "s3:CopyObject", "s3:PutObject"]
        Resource = "${aws_s3_bucket.invoice_pdfs.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:UpdateItem", "dynamodb:Query"]
        Resource = [aws_dynamodb_table.invoices.arn, "${aws_dynamodb_table.invoices.arn}/index/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue"]
        Resource = aws_secretsmanager_secret.qb_credentials.arn
      },
      {
        Effect   = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource = aws_sqs_queue.approved_invoices.arn
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}

# Lambda Functions

# Lambda 1: Odoo Extractor
resource "aws_lambda_function" "extractor" {
  filename         = "${path.module}/lambda/extractor.zip"
  function_name    = "odoo-extractor-${var.environment}"
  role             = aws_iam_role.extractor_role.arn
  handler          = "extractor.lambda_handler"
  source_code_hash = filebase64sha256("${path.module}/lambda/extractor.zip")
  runtime          = "python3.12"
  timeout          = 300
  memory_size      = 512
  
  environment {
    variables = {
      ENVIRONMENT     = var.environment
      ODOO_API_URL    = var.odoo_api_url
      ODOO_SECRET_ARN = aws_secretsmanager_secret.odoo_credentials.arn
      DYNAMODB_TABLE  = aws_dynamodb_table.invoices.name
      S3_BUCKET       = aws_s3_bucket.invoice_pdfs.id
      SNS_ALERT_TOPIC = aws_sns_topic.alerts.arn
    }
  }
  
  dead_letter_config {
    target_arn = aws_sqs_queue.extractor_dlq.arn
  }
}

# Lambda 3: Slack Notifier
resource "aws_lambda_function" "notifier" {
  filename         = "${path.module}/lambda/notifier.zip"
  function_name    = "odoo-notifier-${var.environment}"
  role             = aws_iam_role.notifier_role.arn
  handler          = "notifier.lambda_handler"
  source_code_hash = filebase64sha256("${path.module}/lambda/notifier.zip")
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 256
  
  environment {
    variables = {
      ENVIRONMENT      = var.environment
      SLACK_SECRET_ARN = aws_secretsmanager_secret.slack_config.arn
      SLACK_CHANNEL_ID = var.slack_channel_id
      DYNAMODB_TABLE   = aws_dynamodb_table.invoices.name
      S3_BUCKET        = aws_s3_bucket.invoice_pdfs.id
      APPROVAL_URL     = aws_lambda_function_url.approval_handler.function_url
    }
  }
}

# DynamoDB Stream trigger for Notifier
resource "aws_lambda_event_source_mapping" "notifier_stream" {
  event_source_arn  = aws_dynamodb_table.invoices.stream_arn
  function_name     = aws_lambda_function.notifier.arn
  starting_position = "LATEST"
  batch_size        = 10
  
  filter_criteria {
    filter {
      pattern = jsonencode({
        eventName = ["INSERT"]
        dynamodb = {
          NewImage = {
            status = { S = ["READY_FOR_APPROVAL"] }
          }
        }
      })
    }
  }
}

# Lambda 4: Approval Handler (with Function URL)
resource "aws_lambda_function" "approval_handler" {
  filename         = "${path.module}/lambda/approval_handler.zip"
  function_name    = "odoo-approval-handler-${var.environment}"
  role             = aws_iam_role.approval_role.arn
  handler          = "approval_handler.lambda_handler"
  source_code_hash = filebase64sha256("${path.module}/lambda/approval_handler.zip")
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 256
  
  environment {
    variables = {
      ENVIRONMENT      = var.environment
      DYNAMODB_TABLE   = aws_dynamodb_table.invoices.name
      SQS_QUEUE_URL    = aws_sqs_queue.approved_invoices.url
      SLACK_SECRET_ARN = aws_secretsmanager_secret.slack_config.arn
    }
  }
}

# Lambda Function URL for Approval Handler
resource "aws_lambda_function_url" "approval_handler" {
  function_name      = aws_lambda_function.approval_handler.function_name
  authorization_type = "NONE"  # Slack handles auth via signing secret
}

# Lambda 2: QB Poster (SQS triggered)
resource "aws_lambda_function" "poster" {
  filename         = "${path.module}/lambda/poster.zip"
  function_name    = "odoo-poster-${var.environment}"
  role             = aws_iam_role.poster_role.arn
  handler          = "poster.lambda_handler"
  source_code_hash = filebase64sha256("${path.module}/lambda/poster.zip")
  runtime          = "python3.12"
  timeout          = 300
  memory_size      = 256
  
  environment {
    variables = {
      ENVIRONMENT     = var.environment
      QB_SECRET_ARN   = aws_secretsmanager_secret.qb_credentials.arn
      DYNAMODB_TABLE  = aws_dynamodb_table.invoices.name
      S3_BUCKET       = aws_s3_bucket.invoice_pdfs.id
      SNS_ALERT_TOPIC = aws_sns_topic.alerts.arn
    }
  }
}

# SQS trigger for Poster
resource "aws_lambda_event_source_mapping" "poster_sqs" {
  event_source_arn = aws_sqs_queue.approved_invoices.arn
  function_name    = aws_lambda_function.poster.arn
  batch_size       = 1  # Process one at a time for QB rate limits
}

# EventBridge - Scheduled Trigger

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "odoo-extractor-schedule-${var.environment}"
  description         = "Trigger Odoo extractor on schedule"
  schedule_expression = var.schedule_rate
}

resource "aws_cloudwatch_event_target" "extractor" {
  rule      = aws_cloudwatch_event_rule.schedule.name
  target_id = "OdooExtractor"
  arn       = aws_lambda_function.extractor.arn
}

resource "aws_lambda_permission" "eventbridge_invoke" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.extractor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}

# CloudWatch Alarms

resource "aws_cloudwatch_log_group" "extractor" {
  name              = "/aws/lambda/${aws_lambda_function.extractor.function_name}"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "notifier" {
  name              = "/aws/lambda/${aws_lambda_function.notifier.function_name}"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "approval" {
  name              = "/aws/lambda/${aws_lambda_function.approval_handler.function_name}"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "poster" {
  name              = "/aws/lambda/${aws_lambda_function.poster.function_name}"
  retention_in_days = 30
}

resource "aws_cloudwatch_metric_alarm" "dlq_messages" {
  alarm_name          = "odoo-qb-dlq-messages-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Messages in DLQ indicate failed processing"
  
  dimensions = {
    QueueName = aws_sqs_queue.poster_dlq.name
  }
  
  alarm_actions = [aws_sns_topic.alerts.arn]
}

# Outputs

output "approval_handler_url" {
  description = "URL for Slack button callbacks"
  value       = aws_lambda_function_url.approval_handler.function_url
}

output "s3_bucket" {
  description = "S3 bucket for invoice PDFs"
  value       = aws_s3_bucket.invoice_pdfs.id
}

output "dynamodb_table" {
  description = "DynamoDB table for invoice tracking"
  value       = aws_dynamodb_table.invoices.name
}

output "sqs_queue_url" {
  description = "SQS queue for approved invoices"
  value       = aws_sqs_queue.approved_invoices.url
}

output "secrets_to_configure" {
  description = "Secrets that need to be configured manually"
  value = {
    odoo  = aws_secretsmanager_secret.odoo_credentials.name
    qb    = aws_secretsmanager_secret.qb_credentials.name
    slack = aws_secretsmanager_secret.slack_config.name
  }
}
