variable "prefix" {}
variable "dynamodb_table" {}
variable "vpc_id" {}
variable "private_subnets" {
  type = list(string)
}
variable "remote_state" {}
variable "mysql_secret" {}
variable "eks_cluster" {}
