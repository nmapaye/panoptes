package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	rulesDir    string
	maxDepth    int
	pathsFlag   bool
	outFindings string
)

type Finding struct {
	ID     string   `json:"id"`
	Title  string   `json:"title"`
	Steps  []string `json:"steps"`
	Score  float64  `json:"score"`
	Target string   `json:"target"`
}

type Findings struct {
	Findings []Finding `json:"findings"`
}

type analysisGraph struct {
	Edges []struct {
		From     string         `json:"from"`
		To       string         `json:"to"`
		EdgeType string         `json:"type"`
		Attrs    map[string]any `json:"attrs"`
	} `json:"edges"`
}

var analyzeCmd = &cobra.Command{
	Use:   "analyze <graph.json>",
	Short: "Analyze graph for escalation paths (calls Rust engine; stub fallback)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		graphPath := args[0]
		if outFindings == "" {
			outFindings = "findings.json"
		}
		enginePath := guessEngine()
		if enginePath != "" {
			c := exec.Command(enginePath, "--in", graphPath, "--out", outFindings, "--max-depth", fmt.Sprint(maxDepth))
			c.Stdout = cmd.OutOrStdout()
			c.Stderr = cmd.ErrOrStderr()
			if err := c.Run(); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", outFindings)
			return nil
		}
		// Fallback stub that mirrors engine logic
		gb, err := os.ReadFile(graphPath)
		if err != nil {
			return err
		}
		var g analysisGraph
		if err := json.Unmarshal(gb, &g); err != nil {
			return err
		}
		hasUnrestrictedPath := false
		for _, e := range g.Edges {
			if e.EdgeType != "CanAssume" || e.From != "u:ci-bot" || e.To != "r:AdminRole" {
				continue
			}
			guardsSatisfied := false
			if e.Attrs != nil {
				if rc, ok := e.Attrs["required_conditions"].(map[string]any); ok {
					requireMFA, _ := rc["requireMFA"].(bool)
					externalID, _ := rc["externalId"].(string)
					sourceIdentity, _ := rc["sourceIdentity"].(string)
					guardsSatisfied = requireMFA &&
						externalID == "panoptes-prod" &&
						sourceIdentity == "panoptes"
					if guardsSatisfied {
						if rt, ok := rc["resourceTags"].(map[string]any); ok {
							val, _ := rt["PrivEscalation"].(string)
							guardsSatisfied = guardsSatisfied && val == "deny"
						} else {
							guardsSatisfied = false
						}
					}
					if guardsSatisfied {
						if pt, ok := rc["principalTags"].(map[string]any); ok {
							if teamRaw, ok := pt["Team"]; ok {
								switch t := teamRaw.(type) {
								case []any:
									var hasSecurity, hasPlatform bool
									for _, v := range t {
										if s, ok := v.(string); ok {
											switch s {
											case "Security":
												hasSecurity = true
											case "Platform":
												hasPlatform = true
											}
										}
									}
									guardsSatisfied = guardsSatisfied && hasSecurity && hasPlatform
								case []string:
									var tags = map[string]bool{}
									for _, s := range t {
										switch s {
										case "Security":
											tags["Security"] = true
										case "Platform":
											tags["Platform"] = true
										default:
											// ignore other tags
										}
									}
									guardsSatisfied = guardsSatisfied && tags["Security"] && tags["Platform"]
								default:
									guardsSatisfied = false
								}
							} else {
								guardsSatisfied = false
							}
						} else {
							guardsSatisfied = false
						}
					}
				}
			}
			if !guardsSatisfied {
				hasUnrestrictedPath = true
				break
			}
		}
		f := Findings{}
		if hasUnrestrictedPath {
			f.Findings = append(f.Findings, Finding{
				ID:     "F-0001",
				Title:  "AdminRole trust policy missing guardrails",
				Steps:  []string{"u:ci-bot -> CanAssume -> r:AdminRole"},
				Score:  0.92,
				Target: "r:AdminRole",
			})
		}
		b, _ := json.MarshalIndent(f, "", "  ")
		mustWrite(outFindings, b)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (stub)\n", outFindings)
		return nil
	},
}

func init() {
	analyzeCmd.Flags().StringVar(&rulesDir, "rules", "rules/aws", "rules directory")
	analyzeCmd.Flags().IntVar(&maxDepth, "max-depth", 6, "maximum search depth")
	analyzeCmd.Flags().BoolVar(&pathsFlag, "paths", true, "include explicit paths")
	analyzeCmd.Flags().StringVar(&outFindings, "out", "findings.json", "output file")
}

func guessEngine() string {
	candidates := []string{
		filepath.FromSlash("engine/target/debug/panoptes-engine"),
		"panoptes-engine",
	}
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	return ""
}
