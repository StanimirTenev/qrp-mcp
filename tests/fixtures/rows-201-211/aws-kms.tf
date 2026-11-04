resource "aws_rds_cluster_parameter_group" "pg18" {
  name   = "aurora-pg18-pq"
  family = "aurora-postgresql18"
  parameter {
    name  = "ssl_groups"
    value = "X25519MLKEM768:X25519"
  }
  parameter {
    name  = "ssl_min_protocol_version"
    value = "TLSv1.2"
  }
}

resource "aws_msk_cluster" "events" {
  cluster_name = "events"
  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
    }
  }
}

resource "aws_kms_key" "partner" {
  customer_master_key_spec = "ML_KEM_768"
  key_usage                = "ENCAPSULATE_DECAPSULATE"
}

resource "aws_kms_key" "archive" {
  customer_master_key_spec = "RSA_3072"
  key_usage                = "SIGN_VERIFY"
}

resource "aws_cloudfront_origin_request_policy" "tls" {
  name = "tls-details"
  headers_config {
    header_behavior = "whitelist"
    headers { items = ["CloudFront-Viewer-TLS"] }
  }
}
