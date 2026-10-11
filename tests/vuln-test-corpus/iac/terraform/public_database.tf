resource "aws_db_instance" "orders" {
  publicly_accessible = true
  storage_encrypted   = false
  instance_class      = "db.t3.micro"
}
