variable "project" { type = string }
variable "environment" { type = string }
variable "vpc_id" { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "db_password" { type = string }

resource "aws_db_subnet_group" "main" {
  name       = "${var.project}-${var.environment}-db-subnet"
  subnet_ids = var.private_subnet_ids # IV-10 remediated: private subnets
}

# IV-02 remediated: DB SG accepts 5432 only from within the VPC CIDR.
resource "aws_security_group" "db" {
  name   = "${var.project}-${var.environment}-db-sg"
  vpc_id = var.vpc_id

  ingress {
    description = "PostgreSQL from within VPC only"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    description = "Outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# KMS key for RDS storage encryption.
resource "aws_kms_key" "rds" {
  description         = "${var.project}-${var.environment} RDS encryption"
  enable_key_rotation = true
}

resource "aws_db_instance" "auth" {
  identifier                          = "${var.project}-${var.environment}-authdb"
  engine                              = "postgres"
  engine_version                      = "14"
  instance_class                      = "db.t3.micro"
  allocated_storage                   = 20
  db_name                             = "authdb"
  username                            = "authuser"
  password                            = var.db_password
  db_subnet_group_name                = aws_db_subnet_group.main.name
  vpc_security_group_ids              = [aws_security_group.db.id]
  publicly_accessible                 = false                # CKV_AWS_17 remediated
  storage_encrypted                   = true                 # CKV_AWS_16 remediated
  kms_key_id                          = aws_kms_key.rds.arn
  skip_final_snapshot                 = false                # CKV_AWS_118 remediated
  final_snapshot_identifier           = "${var.project}-${var.environment}-authdb-final"
  deletion_protection                 = true
  backup_retention_period             = 7
  performance_insights_enabled        = true
  performance_insights_kms_key_id     = aws_kms_key.rds.arn
  enabled_cloudwatch_logs_exports     = ["postgresql", "upgrade"]
  iam_database_authentication_enabled = true
  auto_minor_version_upgrade          = true
  multi_az                            = true
  copy_tags_to_snapshot               = true
}

resource "aws_db_instance" "transactions" {
  identifier                          = "${var.project}-${var.environment}-txdb"
  engine                              = "postgres"
  engine_version                      = "14"
  instance_class                      = "db.t3.micro"
  allocated_storage                   = 20
  db_name                             = "transactiondb"
  username                            = "txuser"
  password                            = var.db_password
  db_subnet_group_name                = aws_db_subnet_group.main.name
  vpc_security_group_ids              = [aws_security_group.db.id]
  publicly_accessible                 = false
  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.rds.arn
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "${var.project}-${var.environment}-txdb-final"
  deletion_protection                 = true
  backup_retention_period             = 7
  performance_insights_enabled        = true
  performance_insights_kms_key_id     = aws_kms_key.rds.arn
  enabled_cloudwatch_logs_exports     = ["postgresql", "upgrade"]
  iam_database_authentication_enabled = true
  auto_minor_version_upgrade          = true
  multi_az                            = true
  copy_tags_to_snapshot               = true
}