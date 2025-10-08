package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

type Graph struct {
	Version string        `json:"version"`
	Created time.Time     `json:"created"`
	Nodes   []GraphNode   `json:"nodes"`
	Edges   []GraphEdge   `json:"edges"`
	Meta    map[string]any `json:"meta"`
}
type GraphNode struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
}
type GraphEdge struct {
	From  string         `json:"from"`
	To    string         `json:"to"`
	Type  string         `json:"type"`
	Attrs map[string]any `json:"attrs,omitempty"`
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
		g := Graph{
			Version: "0.0.1",
			Created: time.Now().UTC(),
			Nodes: []GraphNode{
				{ID: "u:alice", Type: "Principal", Name: "alice"},
				{ID: "r:AdminRole", Type: "Role", Name: "AdminRole"},
			},
			Edges: []GraphEdge{
				{From: "u:alice", To: "r:AdminRole", Type: "CanAssume", Attrs: map[string]any{"condition": "stub"}},
			},
			Meta: map[string]any{"source": statePath},
		}
		out := "graph.json" // human-readable for bootstrap
		b, _ := json.MarshalIndent(g, "", "  ")
		mustWrite(out, b)
		fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", out)
		return nil
	},
}
