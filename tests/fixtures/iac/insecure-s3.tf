# Insecure S3 Bucket Configuration
# This file contains deliberate security misconfigurations for testing

# Public S3 bucket - HIGH severity
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket"
  acl    = "public-read"

  tags = {
    Name        = "Public Bucket"
    Environment = "test"
  }
}

# S3 bucket without encryption - MEDIUM severity
resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "my-unencrypted-bucket"

  tags = {
    Name = "Unencrypted Bucket"
  }
}

# S3 bucket without versioning - LOW severity
resource "aws_s3_bucket" "no_versioning_bucket" {
  bucket = "my-no-versioning-bucket"

  tags = {
    Name = "No Versioning Bucket"
  }
}

# S3 bucket without logging - MEDIUM severity
resource "aws_s3_bucket" "no_logging_bucket" {
  bucket = "my-no-logging-bucket"

  tags = {
    Name = "No Logging Bucket"
  }
}

# Security group with wide open ingress - HIGH severity
resource "aws_security_group" "wide_open" {
  name        = "wide-open-sg"
  description = "Security group with 0.0.0.0/0 ingress"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# RDS without encryption - HIGH severity
resource "aws_db_instance" "unencrypted_rds" {
  identifier           = "unencrypted-db"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t2.micro"
  allocated_storage    = 20
  storage_encrypted    = false
  skip_final_snapshot  = true

  username = "admin"
  password = "password123"  # Hardcoded password - also bad practice
}
