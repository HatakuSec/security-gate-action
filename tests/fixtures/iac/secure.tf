# Secure Terraform Configuration
# This file follows security best practices and should produce no findings

terraform {
  required_version = ">= 1.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Backend with encryption
  backend "s3" {
    bucket         = "terraform-state-bucket"
    key            = "state/terraform.tfstate"
    region         = "eu-west-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}

provider "aws" {
  region = "eu-west-1"

  default_tags {
    tags = {
      Environment = "production"
      ManagedBy   = "terraform"
    }
  }
}

# Secure S3 bucket with encryption, versioning, and logging
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket-${random_id.bucket_suffix.hex}"

  tags = {
    Name = "Secure Bucket"
  }
}

resource "aws_s3_bucket_versioning" "secure_bucket_versioning" {
  bucket = aws_s3_bucket.secure_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_bucket_encryption" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.bucket_key.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "secure_bucket_public_access" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "secure_bucket_logging" {
  bucket = aws_s3_bucket.secure_bucket.id

  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "logs/"
}

# KMS key for encryption
resource "aws_kms_key" "bucket_key" {
  description             = "KMS key for S3 bucket encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name = "S3 Bucket Encryption Key"
  }
}

# Secure security group with specific rules
resource "aws_security_group" "secure_sg" {
  name        = "secure-sg"
  description = "Security group with specific ingress rules"
  vpc_id      = var.vpc_id

  # HTTPS only from specific CIDR
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
    description = "HTTPS from allowed networks"
  }

  # Restricted egress
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS outbound"
  }

  tags = {
    Name = "Secure Security Group"
  }
}

# Secure RDS instance
resource "aws_db_instance" "secure_rds" {
  identifier = "secure-db"

  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  max_allocated_storage = 100

  # Security settings
  storage_encrypted   = true
  kms_key_id          = aws_kms_key.rds_key.arn
  publicly_accessible = false

  # Credentials from Secrets Manager (not hardcoded)
  username               = "admin"
  manage_master_user_password = true

  # Backup and maintenance
  backup_retention_period = 30
  deletion_protection     = true
  skip_final_snapshot     = false
  final_snapshot_identifier = "secure-db-final-snapshot"

  # VPC configuration
  db_subnet_group_name   = aws_db_subnet_group.secure.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]

  tags = {
    Name = "Secure Database"
  }
}

resource "aws_kms_key" "rds_key" {
  description             = "KMS key for RDS encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

# Variables
variable "vpc_id" {
  description = "VPC ID for resources"
  type        = string
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access resources"
  type        = list(string)
  default     = ["10.0.0.0/8"]
}

# Random suffix for unique names
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# Outputs
output "bucket_name" {
  description = "Name of the secure S3 bucket"
  value       = aws_s3_bucket.secure_bucket.id
}

output "bucket_arn" {
  description = "ARN of the secure S3 bucket"
  value       = aws_s3_bucket.secure_bucket.arn
}
