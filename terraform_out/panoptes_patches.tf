# Panoptes remediation plan for AdminRole trust policy
terraform {
  required_version = ">= 1.5.0"
}

data "aws_iam_policy_document" "admin_role_trust" {
  statement {
    sid     = "PanoptesTrust"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/PanoptesBuilder"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = ["o-2a1b2c3d4e"]
    }

    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = ["panoptes-prod"]
    }

    condition {
      test     = "StringEquals"
      variable = "sts:SourceIdentity"
      values   = ["panoptes"]
    }

    condition {
      test     = "StringEqualsIfExists"
      variable = "aws:SourceVpce"
      values   = ["vpce-0f00ba11cafe12345"]
    }

    condition {
      test     = "IpAddress"
      variable = "aws:SourceIp"
      values   = ["203.0.113.0/24", "198.51.100.0/24"]
    }

    condition {
      test     = "StringEqualsIfExists"
      variable = "aws:PrincipalTag/Team"
      values   = ["Security", "Platform"]
    }

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

data "aws_iam_policy_document" "admin_role_guardrail" {
  statement {
    sid    = "DenyEscalationOpsWithoutMFAOrTag"
    effect = "Deny"
    actions = [
      "iam:AttachUserPolicy",
      "iam:AttachRolePolicy",
      "iam:CreatePolicyVersion",
      "iam:SetDefaultPolicyVersion",
      "iam:PutUserPolicy",
      "iam:PutRolePolicy",
      "iam:UpdateAssumeRolePolicy",
      "iam:PassRole",
    ]
    resources = ["*"]

    condition {
      test     = "BoolIfExists"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["false"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalTag/AllowEscalation"
      values   = ["true"]
    }
  }
}

resource "aws_iam_role" "admin_role" {
  name               = "AdminRole"
  assume_role_policy = data.aws_iam_policy_document.admin_role_trust.json

  tags = {
    PrivEscalation = "deny"
  }
}

resource "aws_iam_policy" "admin_role_guardrail" {
  name        = "panoptes-adminrole-guardrail"
  description = "Denies privileged escalation operations unless MFA and AllowEscalation tag are present."
  policy      = data.aws_iam_policy_document.admin_role_guardrail.json
}

resource "aws_iam_role_policy_attachment" "admin_role_guardrail" {
  role       = aws_iam_role.admin_role.name
  policy_arn = aws_iam_policy.admin_role_guardrail.arn
}
