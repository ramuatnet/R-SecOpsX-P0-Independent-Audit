resource "aws_s3_bucket" "artifacts" {
  bucket = "acme-artifacts"
  acl    = "public-read"
}
