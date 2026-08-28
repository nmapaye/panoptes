package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

var roleNamePattern = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{1,64}$`)

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
		SchemaVersion: "1.1.0",
		GeneratedAt:   time.Now().UTC(),
		Items:         make([]RemediationItem, 0, len(findings.Findings)),
	}
	hclBlocks := make([]string, 0, len(findings.Findings))
	for _, finding := range findings.Findings {
		hcl, hclErr := buildTerraformPatch(finding)
		item := RemediationItem{
			FindingID: finding.ID,
			Target:    finding.Target,
			Summary:   finding.Remediation.Summary,
			Kind:      finding.Remediation.Kind,
			Steps:     append([]string(nil), finding.Remediation.Suggested...),
			HCL:       hcl,
		}
		if hclErr != nil {
			item.RequiresReview = true
			item.BlockedReason = hclErr.Error()
			item.HCL = ""
		} else {
			hclBlocks = append(hclBlocks, hcl)
		}
		plan.Items = append(plan.Items, item)
	}

	planPath := defaultOutputPath(*outDir, "remediation.json")
	if err := writeJSON(planPath, plan); err != nil {
		return err
	}
	tf := strings.Join(hclBlocks, "\n\n")
	if tf == "" {
		tf = "# No applyable Terraform was generated. Review remediation.json."
	}
	tfPath := defaultOutputPath(*outDir, "panoptes_patches.tf")
	if err := os.WriteFile(tfPath, []byte(tf+"\n"), 0644); err != nil {
		return fmt.Errorf("write %s: %w", tfPath, err)
	}
	_, _ = fmt.Fprintf(stdout, "wrote %s\n", planPath)
	_, _ = fmt.Fprintf(stdout, "wrote %s\n", tfPath)
	return nil
}

func buildTerraformPatch(finding Finding) (string, error) {
	evidence := finding.Evidence
	roleName := stringFromAny(evidence["role_name"])
	orgID := stringFromAny(evidence["org_id"])
	trustedPrincipal := stringFromAny(evidence["trusted_principal_arn"])
	missing := []string{}
	if !roleNamePattern.MatchString(roleName) {
		missing = append(missing, "a valid role_name")
	}
	if !strings.HasPrefix(orgID, "o-") || len(orgID) < 4 {
		missing = append(missing, "a valid organization id")
	}
	if !strings.HasPrefix(trustedPrincipal, "arn:") || strings.Contains(trustedPrincipal, "*") {
		missing = append(missing, "a specific trusted principal ARN")
	}
	if len(missing) > 0 {
		return "", errors.New("cannot generate Terraform without " + strings.Join(missing, ", "))
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

  lifecycle {
    prevent_destroy = true
  }
}
`, finding.ID, finding.Title, resourceName, trustedPrincipal, orgID, resourceName, roleName, resourceName), nil
}
