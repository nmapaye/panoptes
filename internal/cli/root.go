package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var Version = "dev"

var rootCmd = &cobra.Command{
	Use:   "panoptes",
	Short: "Panoptes – IAM attack-path finder with auto-remediation",
}

func Execute() error { return rootCmd.Execute() }

func init() {
	rootCmd.Version = Version
	rootCmd.AddCommand(collectCmd)
	rootCmd.AddCommand(normalizeCmd)
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(showPathCmd)
	rootCmd.AddCommand(remediateCmd)
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")
}

// helpers
func mustWrite(path string, data []byte) {
	if err := os.WriteFile(path, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", path, err)
		os.Exit(1)
	}
}
