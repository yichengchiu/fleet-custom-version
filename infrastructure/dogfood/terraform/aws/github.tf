data "tls_certificate" "github" {
  url = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
}

resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = [
    "sts.amazonaws.com",
  ]

  thumbprint_list = [
    data.tls_certificate.github.certificates[0].sha1_fingerprint
  ]
}

resource "aws_iam_role" "gha_role" {
  name               = "github-actions-role"
  assume_role_policy = data.aws_iam_policy_document.gha_assume_role.json
}

resource "aws_iam_policy_attachment" "gha" {
  name       = "github-actions-permissions"
  policy_arn = aws_iam_policy.gha.arn
  roles = [aws_iam_role.gha_role.name]
}

resource "aws_iam_policy" "gha" {
  policy = data.aws_iam_policy_document.gha-permissions.json
}

#####################
# AssumeRole
#
# Allow sts:AssumeRoleWithWebIdentity from GitHub via OIDC
#####################
data "aws_iam_policy_document" "gha_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type = "Federated"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"
      ]
    }
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:github.com/fleetdm/fleet"]
    }
  }
}

data "aws_iam_policy_document" "gha-permissions" {
  statement {
    effect = "Allow"
    actions = ["ecr:*"]
    resources = [data.aws_ecr_repository.test-repo.arn]
  }
}

data "aws_ecr_repository" "test-repo" {
  name = "fleet-test"
}

output "gha-iam-role" {
  value = aws_iam_role.gha_role.arn
}