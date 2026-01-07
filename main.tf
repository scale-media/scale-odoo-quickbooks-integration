terraform {
  required_version = ">= 1.0.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  
  # Uncomment for remote state
  # backend "s3" {
  #   bucket = "scale-media-terraform-state"
  #   key    = "odoo-qb-integration/terraform.tfstate"
  #   region = "us-west-2"
  # }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "odoo-qb-integration"
      Environment = var.environment
      ManagedBy   = "terraform"
      Team        = "data-engineering"
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

variable "slack_webhook_url" {
  description = "Slack webhook URL for alerts (optional)"
  type        = string
  default     = ""
  sensitive   = true
}

# Data Sources

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

##############################################################################
# S3 Bucket - PDF Storage
##############################################################################

resource "aws_s3_bucket" "invoice_pdfs" {
  bucket = "scale-media-odoo-invoices-${var.environment}"
  
  tags = {
    Name = "Odoo Invoice PDFs"
  }
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
      days = 2555  # 7 years for accounting records
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

# S3 Event Notification to trigger Lambda 2
resource "aws_s3_bucket_notification" "invoice_uploaded" {
  bucket = aws_s3_bucket.invoice_pdfs.id
  
  lambda_function {
    lambda_function_arn = aws_lambda_function.qb_poster.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "pending/"
    filter_suffix       = ".pdf"
  }
  
  depends_on = [aws_lambda_permission.s3_invoke_qb_poster]
}

##############################################################################
# DynamoDB - Invoice Metadata & Tracking
##############################################################################

resource "aws_dynamodb_table" "invoices" {
  name           = "odoo-qb-invoices-${var.environment}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "entry_id"
  
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
  
  tags = {
    Name = "Odoo QB Invoice Tracking"
  }
}

# SQS - Dead Letter Queues

resource "aws_sqs_queue" "extractor_dlq" {
  name                      = "odoo-extractor-dlq-${var.environment}"
  message_retention_seconds = 1209600 
  
  tags = {
    Name = "Odoo Extractor DLQ"
  }
}

resource "aws_sqs_queue" "poster_dlq" {
  name                      = "qb-poster-dlq-${var.environment}"
  message_retention_seconds = 1209600 
  
  tags = {
    Name = "QB Poster DLQ"
  }
}

# SNS - Alerting

resource "aws_sns_topic" "alerts" {
  name = "odoo-qb-alerts-${var.environment}"
  
  tags = {
    Name = "Odoo QB Alerts"
  }
}

resource "aws_sns_topic_subscription" "email_alert" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

##############################################################################
# Secrets Manager - Credentials
##############################################################################

resource "aws_secretsmanager_secret" "odoo_credentials" {
  name        = "odoo-qb-integration/odoo-credentials-${var.environment}"
  description = "Odoo API credentials"
  
  tags = {
    Name = "Odoo API Credentials"
  }
}

resource "aws_secretsmanager_secret" "qb_credentials" {
  name        = "odoo-qb-integration/quickbooks-credentials-${var.environment}"
  description = "QuickBooks OAuth credentials"
  
  tags = {
    Name = "QuickBooks OAuth Credentials"
  }
}

# Note: Secret values should be set manually or via separate secure process
# Odoo format: {"database": "...", "username": "...", "password": "..."}
# QB format: {"client_id": "...", "client_secret": "...", "refresh_token": "...", "realm_ids": {...}}

##############################################################################
# IAM - Lambda Execution Roles
##############################################################################

# Odoo Extractor Role
resource "aws_iam_role" "extractor_role" {
  name = "odoo-extractor-role-${var.environment}"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "extractor_policy" {
  name = "odoo-extractor-policy"
  role = aws_iam_role.extractor_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
      },
      {
        Sid    = "S3Write"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.invoice_pdfs.arn}/*"
      },
      {
        Sid    = "DynamoDB"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          aws_dynamodb_table.invoices.arn,
          "${aws_dynamodb_table.invoices.arn}/index/*"
        ]
      },
      {
        Sid    = "SecretsManager"
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.odoo_credentials.arn
      },
      {
        Sid    = "SNS"
        Effect = "Allow"
        Action = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Sid    = "SQS"
        Effect = "Allow"
        Action = ["sqs:SendMessage"]
        Resource = aws_sqs_queue.extractor_dlq.arn
      }
    ]
  })
}

# QB Poster Role
resource "aws_iam_role" "poster_role" {
  name = "qb-poster-role-${var.environment}"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "poster_policy" {
  name = "qb-poster-policy"
  role = aws_iam_role.poster_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
      },
      {
        Sid    = "S3Read"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:DeleteObject",
          "s3:CopyObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.invoice_pdfs.arn}/*"
      },
      {
        Sid    = "DynamoDB"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query"
        ]
        Resource = [
          aws_dynamodb_table.invoices.arn,
          "${aws_dynamodb_table.invoices.arn}/index/*"
        ]
      },
      {
        Sid    = "SecretsManager"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue"
        ]
        Resource = aws_secretsmanager_secret.qb_credentials.arn
      },
      {
        Sid    = "SNS"
        Effect = "Allow"
        Action = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Sid    = "SQS"
        Effect = "Allow"
        Action = ["sqs:SendMessage"]
        Resource = aws_sqs_queue.poster_dlq.arn
      }
    ]
  })
}

##############################################################################
# Lambda Functions
##############################################################################

# Lambda 1: Odoo Extractor
resource "aws_lambda_function" "odoo_extractor" {
  filename         = "${path.module}/lambda/odoo_extractor.zip"
  function_name    = "odoo-extractor-${var.environment}"
  role             = aws_iam_role.extractor_role.arn
  handler          = "odoo_extractor.lambda_handler"
  source_code_hash = filebase64sha256("${path.module}/lambda/odoo_extractor.zip")
  runtime          = "python3.12"
  timeout          = 300 
  memory_size      = 512
  
  environment {
    variables = {
      ENVIRONMENT       = var.environment
      ODOO_API_URL      = var.odoo_api_url
      ODOO_SECRET_ARN   = aws_secretsmanager_secret.odoo_credentials.arn
      DYNAMODB_TABLE    = aws_dynamodb_table.invoices.name
      S3_BUCKET         = aws_s3_bucket.invoice_pdfs.id
      SNS_ALERT_TOPIC   = aws_sns_topic.alerts.arn
      SLACK_WEBHOOK_URL = var.slack_webhook_url
    }
  }
  
  dead_letter_config {
    target_arn = aws_sqs_queue.extractor_dlq.arn
  }
  
  tags = {
    Name = "Odoo Extractor"
  }
}

# Lambda 2: QuickBooks Poster
resource "aws_lambda_function" "qb_poster" {
  filename         = "${path.module}/lambda/qb_poster.zip"
  function_name    = "qb-poster-${var.environment}"
  role             = aws_iam_role.poster_role.arn
  handler          = "qb_poster.lambda_handler"
  source_code_hash = filebase64sha256("${path.module}/lambda/qb_poster.zip")
  runtime          = "python3.12"
  timeout          = 120  
  memory_size      = 256
  
  environment {
    variables = {
      ENVIRONMENT       = var.environment
      QB_SECRET_ARN     = aws_secretsmanager_secret.qb_credentials.arn
      DYNAMODB_TABLE    = aws_dynamodb_table.invoices.name
      S3_BUCKET         = aws_s3_bucket.invoice_pdfs.id
      SNS_ALERT_TOPIC   = aws_sns_topic.alerts.arn
      SLACK_WEBHOOK_URL = var.slack_webhook_url
    }
  }
  
  dead_letter_config {
    target_arn = aws_sqs_queue.poster_dlq.arn
  }
  
  tags = {
    Name = "QuickBooks Poster"
  }
}

# Lambda Permissions
resource "aws_lambda_permission" "eventbridge_invoke_extractor" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.odoo_extractor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}

resource "aws_lambda_permission" "s3_invoke_qb_poster" {
  statement_id  = "AllowS3Invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.qb_poster.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.invoice_pdfs.arn
}

# EventBridge - Scheduled Trigger

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "odoo-extractor-schedule-${var.environment}"
  description         = "Trigger Odoo extractor on schedule"
  schedule_expression = var.schedule_rate
  
  tags = {
    Name = "Odoo Extractor Schedule"
  }
}

resource "aws_cloudwatch_event_target" "extractor" {
  rule      = aws_cloudwatch_event_rule.schedule.name
  target_id = "OdooExtractor"
  arn       = aws_lambda_function.odoo_extractor.arn
}

# CloudWatch - Monitoring & Alarms

resource "aws_cloudwatch_log_group" "extractor_logs" {
  name              = "/aws/lambda/${aws_lambda_function.odoo_extractor.function_name}"
  retention_in_days = 30
  
  tags = {
    Name = "Odoo Extractor Logs"
  }
}

resource "aws_cloudwatch_log_group" "poster_logs" {
  name              = "/aws/lambda/${aws_lambda_function.qb_poster.function_name}"
  retention_in_days = 30
  
  tags = {
    Name = "QB Poster Logs"
  }
}

# Extractor Error Alarm
resource "aws_cloudwatch_metric_alarm" "extractor_errors" {
  alarm_name          = "odoo-extractor-errors-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Odoo extractor errors detected"
  
  dimensions = {
    FunctionName = aws_lambda_function.odoo_extractor.function_name
  }
  
  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]
}

# Poster Error Alarm
resource "aws_cloudwatch_metric_alarm" "poster_errors" {
  alarm_name          = "qb-poster-errors-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "QB poster errors detected"
  
  dimensions = {
    FunctionName = aws_lambda_function.qb_poster.function_name
  }
  
  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]
}

# DLQ Message Alarms
resource "aws_cloudwatch_metric_alarm" "extractor_dlq" {
  alarm_name          = "odoo-extractor-dlq-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Messages in extractor DLQ"
  
  dimensions = {
    QueueName = aws_sqs_queue.extractor_dlq.name
  }
  
  alarm_actions = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "poster_dlq" {
  alarm_name          = "qb-poster-dlq-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Messages in poster DLQ"
  
  dimensions = {
    QueueName = aws_sqs_queue.poster_dlq.name
  }
  
  alarm_actions = [aws_sns_topic.alerts.arn]
}

# Outputs

output "s3_bucket_name" {
  description = "S3 bucket for invoice PDFs"
  value       = aws_s3_bucket.invoice_pdfs.id
}

output "dynamodb_table_name" {
  description = "DynamoDB table for invoice tracking"
  value       = aws_dynamodb_table.invoices.name
}

output "extractor_function_name" {
  description = "Odoo extractor Lambda function"
  value       = aws_lambda_function.odoo_extractor.function_name
}

output "poster_function_name" {
  description = "QB poster Lambda function"
  value       = aws_lambda_function.qb_poster.function_name
}

output "odoo_secret_arn" {
  description = "Odoo credentials secret ARN"
  value       = aws_secretsmanager_secret.odoo_credentials.arn
}

output "qb_secret_arn" {
  description = "QuickBooks credentials secret ARN"
  value       = aws_secretsmanager_secret.qb_credentials.arn
}

output "sns_topic_arn" {
  description = "SNS alerts topic ARN"
  value       = aws_sns_topic.alerts.arn
}
