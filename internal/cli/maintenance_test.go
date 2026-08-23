package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRuleLoadingIsStrictStableAndRejectsDuplicates(t *testing.T) {
	dir := t.TempDir()
	valid := `id: AWS-TEST-001
title: Test trust
description: Test rule
match_type: CanAssume
require_org_id: true
severity: high
remediation_kind: restrict_assume_role
remediation_steps:
  - Add an organization guard.
`
	if err := os.WriteFile(filepath.Join(dir, "b.yaml"), []byte(strings.Replace(valid, "AWS-TEST-001", "AWS-TEST-002", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	rules, err := loadRules(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{rules[0].ID, rules[1].ID}; !reflect.DeepEqual(got, []string{"AWS-TEST-001", "AWS-TEST-002"}) {
		t.Fatalf("rules not loaded by filename: %v", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "c.yaml"), []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRules(dir); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate ID error, got %v", err)
	}
	unknown := strings.Replace(valid, "severity: high", "severity: high\nunknown_field: true", 1)
	if err := os.WriteFile(filepath.Join(t.TempDir(), "bad.yaml"), []byte(unknown), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseRule(filepath.Join(filepath.Dir(filepath.Join(t.TempDir(), "unused")), "missing")); err == nil {
		t.Fatal("missing rule should fail")
	}
	badPath := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(badPath, []byte(unknown), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseRule(badPath); err == nil || !strings.Contains(err.Error(), "field unknown_field not found") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestAnalyzeHonorsDepthAvoidsCyclesAndUsesStableIDs(t *testing.T) {
	graph := Graph{
		Nodes: []GraphNode{
			{ID: "u:start", Type: "Principal", Name: "start"},
			{ID: "r:middle", Type: "Role", Name: "middle"},
			{ID: "r:admin", Type: "Role", Name: "admin", Attrs: map[string]any{"admin": true}},
		},
		Edges: []GraphEdge{
			{From: "r:middle", To: "u:start", Type: "CanAssume"},
			{From: "u:start", To: "r:middle", Type: "CanAssume"},
			{From: "r:middle", To: "r:admin", Type: "CanAssume", Attrs: map[string]any{
				"wildcard_principal":  true,
				"account_id":          "111111111111",
				"role_name":           "AdminRole",
				"required_conditions": map[string]any{},
			}},
		},
		Meta: map[string]any{"org_id": "o-example"},
	}
	rule := DetectionRule{ID: "AWS-TEST-001", Title: "Unsafe", Description: "Unsafe trust", MatchType: "CanAssume", RequireSpecificPrincipal: true, Severity: "high", RemediationKind: "restrict", RemediationSteps: []string{"Fix trust"}}
	shallow := analyzeGraph(graph, []DetectionRule{rule}, true, 1)
	deep := analyzeGraph(graph, []DetectionRule{rule}, true, 2)
	again := analyzeGraph(graph, []DetectionRule{rule}, true, 2)
	if len(shallow) != 1 || len(shallow[0].Steps) != 1 {
		t.Fatalf("depth one should include only target edge: %+v", shallow)
	}
	if len(deep) != 1 || len(deep[0].Steps) != 2 {
		t.Fatalf("depth two should include the shortest path: %+v", deep)
	}
	if deep[0].ID != again[0].ID || !reflect.DeepEqual(deep[0].Steps, again[0].Steps) {
		t.Fatal("analysis is not deterministic")
	}
}

func TestRemediationFailsClosedWithoutEvidence(t *testing.T) {
	finding := Finding{ID: "F-1", Title: "Unsafe", Target: "r:admin", Evidence: map[string]any{"role_name": "AdminRole", "org_id": "", "trusted_principal_arn": "*"}}
	if hcl, err := buildTerraformPatch(finding); err == nil || hcl != "" {
		t.Fatalf("incomplete evidence produced HCL: %q, %v", hcl, err)
	}
	dir := t.TempDir()
	findingsPath := filepath.Join(dir, "findings.json")
	finding.Remediation = RemediationRef{Kind: "restrict", Summary: "Review", Suggested: []string{"Fix trust"}}
	if err := writeJSON(findingsPath, Findings{SchemaVersion: "1.1.0", Findings: []Finding{finding}}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	if err := runRemediate([]string{findingsPath, "--emit", out}, os.Stdout, os.Stderr); err != nil {
		t.Fatal(err)
	}
	terraform, err := os.ReadFile(filepath.Join(out, "panoptes_patches.tf"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(terraform), "resource \"aws_iam_role\"") || strings.Contains(string(terraform), "<account-id>") {
		t.Fatalf("unsafe Terraform was emitted: %s", terraform)
	}
	var plan RemediationPlan
	if err := readJSON(filepath.Join(out, "remediation.json"), &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Items) != 1 || !plan.Items[0].RequiresReview || plan.Items[0].BlockedReason == "" {
		t.Fatalf("review requirement missing: %+v", plan.Items)
	}
}

func TestWriteJSONReturnsFilesystemErrors(t *testing.T) {
	if err := writeJSON(filepath.Join(t.TempDir(), "missing", "output.json"), map[string]string{"ok": "yes"}); err == nil {
		t.Fatal("expected write error")
	}
}
