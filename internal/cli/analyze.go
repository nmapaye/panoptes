package cli

import (
	"fmt"
	"io"
	"strings"
	"time"
)

func runAnalyze(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("analyze", stderr)
	rulesDir := fs.String("rules", "rules/aws", "rules directory")
	maxDepth := fs.Int("max-depth", 6, "maximum path search depth")
	includePaths := fs.Bool("paths", true, "include explicit paths in findings")
	outFile := fs.String("out", "findings.json", "output findings file")
	graphPath := ""
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		graphPath = args[0]
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if graphPath == "" && fs.NArg() == 1 {
		graphPath = fs.Arg(0)
	}
	if graphPath == "" || fs.NArg() > 1 {
		return fmt.Errorf("usage: analyze <graph.json> [--rules rules/aws] [--paths=true] [--max-depth 6] [--out findings.json]")
	}
	if *maxDepth < 1 {
		return fmt.Errorf("--max-depth must be at least 1")
	}
	var graph Graph
	if err := readJSON(graphPath, &graph); err != nil {
		return err
	}
	rules, err := loadRules(*rulesDir)
	if err != nil {
		return err
	}

	findings := Findings{
		SchemaVersion: "1.0.0",
		GeneratedAt:   time.Now().UTC(),
		Findings:      analyzeGraph(graph, rules, *includePaths),
	}
	if err := writeJSON(*outFile, findings); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "wrote %s\n", *outFile)
	return nil
}

func analyzeGraph(graph Graph, rules []DetectionRule, includePaths bool) []Finding {
	nodeLookup := map[string]GraphNode{}
	for _, node := range graph.Nodes {
		nodeLookup[node.ID] = node
	}

	findings := make([]Finding, 0)
	counter := 1
	for _, edge := range graph.Edges {
		if edge.Type != "CanAssume" {
			continue
		}
		requiredConditions, _ := edge.Attrs["required_conditions"].(map[string]any)
		wildcard := boolFromAny(edge.Attrs["wildcard_principal"])
		roleNode := nodeLookup[edge.To]
		sourceNode := nodeLookup[edge.From]
		admin := boolFromAny(roleNode.Attrs["admin"])
		for _, rule := range rules {
			if rule.MatchType != edge.Type {
				continue
			}
			var reasons []string
			if rule.RequireSpecificPrincipal && wildcard {
				reasons = append(reasons, "trust policy allows a wildcard or overly broad principal")
			}
			if rule.RequireOrgID && stringFromAny(requiredConditions["org_id"]) == "" {
				reasons = append(reasons, "trust policy is missing an aws:PrincipalOrgID restriction")
			}
			if rule.RequireMFA && !boolFromAny(requiredConditions["require_mfa"]) {
				reasons = append(reasons, "trust policy does not require MFA")
			}
			if len(reasons) == 0 {
				continue
			}

			findingID := fmt.Sprintf("F-%04d", counter)
			counter++
			steps := []string{}
			if includePaths {
				steps = append(steps, fmt.Sprintf("%s -> %s -> %s", sourceNode.Name, edge.Type, roleNode.Name))
			}
			conditions := map[string]any{}
			for key, value := range requiredConditions {
				conditions[key] = value
			}
			accountID := stringFromAny(edge.Attrs["account_id"])
			roleName := stringFromAny(edge.Attrs["role_name"])
			findings = append(findings, Finding{
				ID:         findingID,
				RuleID:     rule.ID,
				Title:      rule.Title,
				Severity:   rule.Severity,
				Steps:      steps,
				Score:      severityScore(rule.Severity, admin),
				Target:     edge.To,
				TargetName: roleNode.Name,
				Evidence: map[string]any{
					"account_id":           accountID,
					"role_name":            roleName,
					"trusted_principal_arn": sourceNode.Name,
					"wildcard_principal":   wildcard,
					"required_conditions":  conditions,
					"reason":               strings.Join(reasons, "; "),
					"org_id":               graphMetaOrgID(graph),
				},
				Remediation: RemediationRef{
					Kind:      rule.RemediationKind,
					Summary:   strings.Join(reasons, "; "),
					Suggested: append([]string(nil), rule.RemediationSteps...),
				},
			})
		}
	}
	return findings
}
