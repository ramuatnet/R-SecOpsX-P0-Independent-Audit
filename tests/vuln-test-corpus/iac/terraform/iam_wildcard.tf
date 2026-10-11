resource "aws_iam_role_policy" "deployer" {
  name = "ci-deployer"
  role = aws_iam_role.ci.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["*"]
      Resource = "arn:aws:s3:::acme-artifacts/*"
    }]
  })
}
