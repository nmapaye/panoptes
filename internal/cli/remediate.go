package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func runRemediate(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("remediate", stderr)
	outDir := fs.String("emit", "terraform_out", "output directory for remediation artifacts")
	findingsPath := ""
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		findingsPath = args[0]
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if findingsPath == "" && fs.NArg() == 1 {
		findingsPath = fs.Arg(0)
	}
	if findingsPath == "" || fs.NArg() > 1 {
		return fmt.Errorf("usage: remediate <findings.json> [--emit terraform_out]")
	}
	var findings Findings
	if err := readJSON(findingsPath, &findings); err != nil {
		return err
	}
	if len(findings.Findings) == 0 {
		_, _ = fmt.Fprintln(stdout, "no findings, nothing to remediate")
		return nil
	}
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return err
	}

	plan := RemediationPlan{
		SchemaVersion: "1.0.0",
		GeneratedAt:   time.Now().UTC(),
		Items:         make([]RemediationItem, 0, len(findings.Findings)),
	}
	hclBlocks := make([]string, 0, len(findings.Findings))
	for _, finding := range findings.Findings {
		hcl := buildTerraformPatch(finding)
		plan.Items = append(plan.Items, RemediationItem{
			FindingID: finding.ID,
			Target:    finding.Target,
			Summary:   finding.Remediation.Summary,
			Kind:      finding.Remediation.Kind,
			Steps:     append([]string(nil), finding.Remediation.Suggested...),
			HCL:       hcl,
		})
		hclBlocks = append(hclBlocks, hcl)
	}

	if err := writeJSON(defaultOutputPath(*outDir, "remediation.json"), plan); err != nil {
		return err
	}
	tf := strings.Join(hclBlocks, "\n\n")
	mustWrite(defaultOutputPath(*outDir, "panoptes_patches.tf"), []byte(tf+"\n"))
	_, _ = fmt.Fprintf(stdout, "wrote %s\n", filepath.Join(*outDir, "remediation.json"))
	_, _ = fmt.Fprintf(stdout, "wrote %s\n", filepath.Join(*outDir, "panoptes_patches.tf"))
	return nil
}

func buildTerraformPatch(finding Finding) string {
	evidence := finding.Evidence
	roleName := stringFromAny(evidence["role_name"])
	if roleName == "" {
		roleName = finding.Target
	}
	orgID := stringFromAny(evidence["org_id"])
	if orgID == "" {
		if required, ok := evidence["required_conditions"].(map[string]any); ok {
			orgID = stringFromAny(required["org_id"])
		}
	}
	trustedPrincipal := stringFromAny(evidence["trusted_principal_arn"])
	if trustedPrincipal == "" {
		trustedPrincipal = "arn:aws:iam::<account-id>:role/restricted-principal"
	}
	resourceName := sanitizeResourceName(roleName)
	return fmt.Sprintf(`# %s - %s
data "aws_iam_policy_document" "%s_trust" {
  statement {
    sid     = "PanoptesGuardrail"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [%q]
    }

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [%q]
    }
  }
}

resource "aws_iam_role" "%s" {
  name               = %q
  assume_role_policy = data.aws_iam_policy_document.%s_trust.json
}
`, finding.ID, finding.Title, resourceName, trustedPrincipal, orgID, resourceName, roleName, resourceName)
}
