package cli

import (
	"crypto/sha256"
	"fmt"
	"io"
	"sort"
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
		SchemaVersion: "1.1.0",
		GeneratedAt:   time.Now().UTC(),
		Findings:      analyzeGraph(graph, rules, *includePaths, *maxDepth),
	}
	if err := writeJSON(*outFile, findings); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "wrote %s\n", *outFile)
	return nil
}

func analyzeGraph(graph Graph, rules []DetectionRule, includePaths bool, maxDepth int) []Finding {
	nodeLookup := map[string]GraphNode{}
	for _, node := range graph.Nodes {
		nodeLookup[node.ID] = node
	}
	edges := append([]GraphEdge(nil), graph.Edges...)
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		if edges[i].To != edges[j].To {
			return edges[i].To < edges[j].To
		}
		return edges[i].Type < edges[j].Type
	})

	findings := make([]Finding, 0)
	seen := map[string]bool{}
	for _, edge := range edges {
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
			reasons := trustReasons(rule, wildcard, requiredConditions)
			if len(reasons) == 0 {
				continue
			}
			identity := rule.ID + "\x00" + edge.From + "\x00" + edge.To + "\x00" + edge.Type
			if seen[identity] {
				continue
			}
			seen[identity] = true
			steps := []string{}
			if includePaths {
				path := shortestPathToEdge(graph.Nodes, edges, edge, maxDepth)
				steps = pathSteps(path, nodeLookup)
			}
			conditions := map[string]any{}
			for key, value := range requiredConditions {
				conditions[key] = value
			}
			findings = append(findings, Finding{
				ID:         stableFindingID(identity),
				RuleID:     rule.ID,
				Title:      rule.Title,
				Severity:   rule.Severity,
				Steps:      steps,
				Score:      severityScore(rule.Severity, admin),
				Target:     edge.To,
				TargetName: roleNode.Name,
				Evidence: map[string]any{
					"account_id":            stringFromAny(edge.Attrs["account_id"]),
					"role_name":             stringFromAny(edge.Attrs["role_name"]),
					"trusted_principal_arn": sourceNode.Name,
					"wildcard_principal":    wildcard,
					"required_conditions":   conditions,
					"reason":                strings.Join(reasons, "; "),
					"org_id":                graphMetaOrgID(graph),
				},
				Remediation: RemediationRef{
					Kind:      rule.RemediationKind,
					Summary:   strings.Join(reasons, "; "),
					Suggested: append([]string(nil), rule.RemediationSteps...),
				},
			})
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		if findings[i].Target != findings[j].Target {
			return findings[i].Target < findings[j].Target
		}
		return findings[i].ID < findings[j].ID
	})
	return findings
}

func trustReasons(rule DetectionRule, wildcard bool, conditions map[string]any) []string {
	reasons := []string{}
	if rule.RequireSpecificPrincipal && wildcard {
		reasons = append(reasons, "trust policy allows a wildcard or overly broad principal")
	}
	if rule.RequireOrgID && stringFromAny(conditions["org_id"]) == "" {
		reasons = append(reasons, "trust policy is missing an aws:PrincipalOrgID restriction")
	}
	if rule.RequireMFA && !boolFromAny(conditions["require_mfa"]) {
		reasons = append(reasons, "trust policy does not require MFA")
	}
	return reasons
}

type searchPath struct {
	node  string
	edges []GraphEdge
	seen  map[string]bool
}

func shortestPathToEdge(nodes []GraphNode, edges []GraphEdge, target GraphEdge, maxDepth int) []GraphEdge {
	if maxDepth <= 1 {
		return []GraphEdge{target}
	}
	adjacency := map[string][]GraphEdge{}
	for _, edge := range edges {
		if edge.Type == "CanAssume" && (edge.From != target.From || edge.To != target.To || edge.Type != target.Type) {
			adjacency[edge.From] = append(adjacency[edge.From], edge)
		}
	}
	roots := []string{}
	for _, node := range nodes {
		if node.Type == "Principal" {
			roots = append(roots, node.ID)
		}
	}
	sort.Strings(roots)
	queue := make([]searchPath, 0, len(roots))
	for _, root := range roots {
		queue = append(queue, searchPath{node: root, seen: map[string]bool{root: true}})
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current.node == target.From {
			return append(append([]GraphEdge(nil), current.edges...), target)
		}
		if len(current.edges)+1 >= maxDepth {
			continue
		}
		for _, edge := range adjacency[current.node] {
			if current.seen[edge.To] {
				continue
			}
			seen := make(map[string]bool, len(current.seen)+1)
			for node := range current.seen {
				seen[node] = true
			}
			seen[edge.To] = true
			queue = append(queue, searchPath{node: edge.To, edges: append(append([]GraphEdge(nil), current.edges...), edge), seen: seen})
		}
	}
	return []GraphEdge{target}
}

func pathSteps(path []GraphEdge, nodes map[string]GraphNode) []string {
	steps := make([]string, 0, len(path))
	for _, edge := range path {
		from := nodes[edge.From].Name
		if from == "" {
			from = edge.From
		}
		to := nodes[edge.To].Name
		if to == "" {
			to = edge.To
		}
		steps = append(steps, fmt.Sprintf("%s -> %s -> %s", from, edge.Type, to))
	}
	return steps
}

func stableFindingID(identity string) string {
	digest := sha256.Sum256([]byte(identity))
	return fmt.Sprintf("F-%X", digest[:6])
}
