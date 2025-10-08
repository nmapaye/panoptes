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
	rulesDir   string
	maxDepth   int
	pathsFlag  bool
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
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", outFindings)
			return nil
		}
		// Fallback stub
		f := Findings{Findings: []Finding{{
			ID:     "F-0001",
			Title:  "Demo path to AdminRole",
			Steps:  []string{"u:alice -> CanAssume -> r:AdminRole"},
			Score:  0.92,
			Target: "r:AdminRole",
		}}}
		b, _ := json.MarshalIndent(f, "", "  ")
		mustWrite(outFindings, b)
		fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (stub)\n", outFindings)
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
