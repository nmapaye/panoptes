package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

type Graph struct {
	SchemaVersion string         `json:"schema_version"`
	Created       time.Time      `json:"created"`
	Nodes         []GraphNode    `json:"nodes"`
	Edges         []GraphEdge    `json:"edges"`
	Meta          map[string]any `json:"meta"`
}
type GraphNode struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
}
type GraphEdge struct {
	From          string         `json:"from"`
	To            string         `json:"to"`
	Type          string         `json:"type"`
	Preconditions []string       `json:"preconditions,omitempty"`
	Attrs         map[string]any `json:"attrs,omitempty"`
}

var normalizeCmd = &cobra.Command{
	Use:   "normalize <state.json>",
	Short: "Normalize snapshot into an analysis graph (stub)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		statePath := args[0]
		if _, err := os.Stat(statePath); err != nil {
			return err
		}
		preconditions := map[string]any{
			"principalOrgID": "o-2a1b2c3d4e",
			"requireMFA":     true,
			"externalId":     "panoptes-prod",
			"sourceVpce":     []string{"vpce-0f00ba11cafe12345"},
			"sourceIpCidrs":  []string{"203.0.113.0/24", "198.51.100.0/24"},
			"principalTags":  map[string]any{"Team": []string{"Security", "Platform"}},
			"resourceTags":   map[string]any{"PrivEscalation": "deny"},
			"sourceIdentity": "panoptes",
		}
		g := Graph{
			SchemaVersion: "1.0.0",
			Created:       time.Now().UTC(),
			Nodes: []GraphNode{
				{ID: "u:ci-bot", Type: "Principal", Name: "arn:aws:iam::123456789012:user/ci-bot"},
				{ID: "r:AdminRole", Type: "Role", Name: "arn:aws:iam::123456789012:role/AdminRole"},
			},
			Edges: []GraphEdge{
				{
					From:          "u:ci-bot",
					To:            "r:AdminRole",
					Type:          "CanAssume",
					Preconditions: []string{"sts:AssumeRole"},
					Attrs: map[string]any{
						"required_conditions": preconditions,
						"trust_policy_sid":    "PanoptesTrust",
						"principal_arn":       "arn:aws:iam::123456789012:role/PanoptesBuilder",
					},
				},
			},
			Meta: map[string]any{
				"state_ref":             statePath,
				"resource_tag_guard":    map[string]string{"PrivEscalation": "deny"},
				"deny_esc_policy_sid":   "DenyEscalationOpsWithoutMFAOrTag",
				"require_mfa_globally":  true,
				"principal_tags_needed": []string{"Security", "Platform"},
			},
		}
		out := "graph.json" // human-readable for bootstrap
		b, _ := json.MarshalIndent(g, "", "  ")
		mustWrite(out, b)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", out)
		return nil
	},
}
