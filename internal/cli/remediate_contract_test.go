package cli

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

func loadRemediationSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "schemas", "remediation.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	schema, err := compiler.Compile((&url.URL{Scheme: "file", Path: path}).String())
	if err != nil {
		t.Fatalf("compile remediation schema: %v", err)
	}
	return schema
}

func serializedPlan(t *testing.T, item RemediationItem) any {
	t.Helper()
	data, err := json.Marshal(RemediationPlan{
		SchemaVersion: "1.1.0",
		GeneratedAt:   time.Unix(1, 0).UTC(),
		Items:         []RemediationItem{item},
	})
	if err != nil {
		t.Fatal(err)
	}
	var document any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func TestRemediationSchemaAcceptsApplyableAndReviewOnlyItems(t *testing.T) {
	schema := loadRemediationSchema(t)
	base := RemediationItem{FindingID: "F-1", Target: "r:admin", Summary: "Restrict trust", Kind: "terraform"}

	applyable := base
	applyable.HCL = "resource \"aws_iam_role\" \"admin\" {}"
	if err := schema.Validate(serializedPlan(t, applyable)); err != nil {
		t.Fatalf("applyable plan failed validation: %v", err)
	}

	reviewOnly := base
	reviewOnly.RequiresReview = true
	reviewOnly.BlockedReason = "missing trusted principal"
	if err := schema.Validate(serializedPlan(t, reviewOnly)); err != nil {
		t.Fatalf("review-only plan failed validation: %v", err)
	}
}

func TestRemediationSchemaRejectsIncompleteAndMixedItems(t *testing.T) {
	schema := loadRemediationSchema(t)
	base := RemediationItem{FindingID: "F-1", Target: "r:admin", Summary: "Restrict trust", Kind: "terraform"}
	tests := []struct {
		name string
		item RemediationItem
	}{
		{name: "neither form", item: base},
		{name: "review without reason", item: func() RemediationItem { item := base; item.RequiresReview = true; return item }()},
		{name: "mixed form", item: func() RemediationItem {
			item := base
			item.HCL = "resource \"aws_iam_role\" \"admin\" {}"
			item.RequiresReview = true
			item.BlockedReason = "ambiguous evidence"
			return item
		}()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := schema.Validate(serializedPlan(t, tc.item)); err == nil {
				t.Fatal("expected schema validation to fail")
			}
		})
	}
}

func TestOrganizationAndTrustedPrincipalValidation(t *testing.T) {
	validPrincipals := []string{
		"arn:aws:iam::111111111111:root",
		"arn:aws-us-gov:iam::111111111111:role/security/AdminRole",
		"arn:aws-cn:iam::111111111111:user/ci-bot",
	}
	for _, principal := range validPrincipals {
		if !validTrustedPrincipalARN(principal) {
			t.Errorf("valid principal rejected: %s", principal)
		}
	}

	invalidPrincipals := []string{
		"arn:not-valid",
		"arn:aws:iam::11111111111:role/AdminRole",
		"arn:aws:s3::111111111111:role/AdminRole",
		"arn:aws:iam:us-east-1:111111111111:role/AdminRole",
		"arn:aws:iam::111111111111:group/Admins",
		"arn:aws:iam::111111111111:role/*",
		"arn:aws-iso:iam::111111111111:role/AdminRole",
	}
	for _, principal := range invalidPrincipals {
		if validTrustedPrincipalARN(principal) {
			t.Errorf("invalid principal accepted: %s", principal)
		}
	}

	validEvidence := map[string]any{
		"role_name":             "AdminRole",
		"org_id":                "o-2a1b2c3d4e",
		"trusted_principal_arn": "arn:aws:iam::111111111111:role/AdminRole",
	}
	finding := Finding{ID: "F-1", Title: "Unsafe", Evidence: validEvidence}
	if hcl, err := buildTerraformPatch(finding); err != nil || hcl == "" {
		t.Fatalf("valid evidence did not produce Terraform: %q, %v", hcl, err)
	}

	for _, orgID := range []string{"o-x", "o-UPPERCASE123", "o-123456789", "o-123456789012345678901234567890123"} {
		finding.Evidence = map[string]any{
			"role_name":             "AdminRole",
			"org_id":                orgID,
			"trusted_principal_arn": "arn:aws:iam::111111111111:role/AdminRole",
		}
		if hcl, err := buildTerraformPatch(finding); err == nil || hcl != "" {
			t.Errorf("invalid organization ID produced Terraform: %q, %v", hcl, err)
		}
	}
}
