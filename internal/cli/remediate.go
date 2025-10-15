package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var remOut string

var remediateCmd = &cobra.Command{
	Use:   "remediate <findings.json>",
	Short: "Generate remediation patches (stub Terraform)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		findingsPath := args[0]
		b, err := os.ReadFile(findingsPath)
		if err != nil {
			return err
		}
		var findings Findings
		if err := json.Unmarshal(b, &findings); err != nil {
			return err
		}
		if len(findings.Findings) == 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "no findings, nothing to remediate")
			return nil
		}
		if remOut == "" {
			remOut = "terraform"
		}
		if err := os.MkdirAll(remOut, 0755); err != nil {
			return err
		}
		tf := `# Panoptes remediation plan for AdminRole trust policy
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
`
		path := filepath.Join(remOut, "panoptes_patches.tf")
		mustWrite(path, []byte(tf))
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", path)
		return nil
	},
}

func init() {
	remediateCmd.Flags().StringVar(&remOut, "emit", "terraform", "output directory for patches")
}
