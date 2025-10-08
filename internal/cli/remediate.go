package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var remOut string

var remediateCmd = &cobra.Command{
	Use:   "remediate <findings.json>",
	Short: "Generate remediation patches (stub Terraform)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if remOut == "" {
			remOut = "terraform"
		}
		if err := os.MkdirAll(remOut, 0755); err != nil {
			return err
		}
		tf := `# stub remediation
# tighten trust policy conditions; restrict actions/resources
terraform {
  required_version = ">= 1.5.0"
}
`
		path := filepath.Join(remOut, "panoptes_patches.tf")
		mustWrite(path, []byte(tf))
		fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", path)
		return nil
	},
}

func init() {
	remediateCmd.Flags().StringVar(&remOut, "emit", "terraform", "output directory for patches")
}
