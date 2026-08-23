package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadDemoState(t *testing.T) StateSnapshot {
	t.Helper()
	var snapshot StateSnapshot
	path := filepath.Join("..", "..", "fixtures", "aws", "demo_state.json")
	if err := readJSON(path, &snapshot); err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := validateState(snapshot); err != nil {
		t.Fatalf("validate fixture: %v", err)
	}
	return snapshot
}

func TestNormalizeStateBuildsDeterministicGraph(t *testing.T) {
	graph := normalizeState(loadDemoState(t), "fixtures/aws/demo_state.json")
	if len(graph.Nodes) != 4 {
		t.Fatalf("expected 4 nodes, got %d", len(graph.Nodes))
	}
	if len(graph.Edges) != 2 {
		t.Fatalf("expected 2 edges, got %d", len(graph.Edges))
	}
	if graph.Edges[0].Type != "CanAssume" {
		t.Fatalf("unexpected edge type %q", graph.Edges[0].Type)
	}
}

func TestAnalyzeGraphFindsOnlyTheUnsafeAdminTrust(t *testing.T) {
	graph := normalizeState(loadDemoState(t), "fixtures/aws/demo_state.json")
	rules, err := loadRules(filepath.Join("..", "..", "rules", "aws"))
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	findings := analyzeGraph(graph, rules, true, 6)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "AWS-TRUST-001" {
		t.Fatalf("unexpected rule id %q", findings[0].RuleID)
	}
	if findings[0].TargetName != "arn:aws:iam::111111111111:role/AdminRole" {
		t.Fatalf("unexpected target %q", findings[0].TargetName)
	}
}

func TestRemediateWritesDataDrivenTerraform(t *testing.T) {
	graph := normalizeState(loadDemoState(t), "fixtures/aws/demo_state.json")
	rules, err := loadRules(filepath.Join("..", "..", "rules", "aws"))
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	findings := Findings{
		SchemaVersion: "1.0.0",
		Findings:      analyzeGraph(graph, rules, true, 6),
	}
	if len(findings.Findings) != 1 {
		t.Fatalf("expected findings to contain 1 item")
	}

	dir := t.TempDir()
	findingsPath := filepath.Join(dir, "findings.json")
	if err := writeJSON(findingsPath, findings); err != nil {
		t.Fatalf("write findings: %v", err)
	}
	if err := runRemediate([]string{findingsPath, "--emit", dir}, os.Stdout, os.Stderr); err != nil {
		t.Fatalf("run remediate: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(dir, "panoptes_patches.tf"))
	if err != nil {
		t.Fatalf("read terraform patch: %v", err)
	}
	text := string(content)
	if !strings.Contains(text, "AdminRole") || !strings.Contains(text, "aws:PrincipalOrgID") {
		t.Fatalf("terraform patch missing expected role/org guard: %s", text)
	}
}
