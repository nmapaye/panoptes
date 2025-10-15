package cli

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

type StateSnapshot struct {
	SchemaVersion string    `json:"schema_version"`
	Provider      string    `json:"provider"`
	OrgID         string    `json:"org_id"`
	Ts            time.Time `json:"timestamp"`
	Accounts      []string  `json:"accounts"`
	Notes         string    `json:"notes"`
}

var (
	orgID   string
	outFile string
)

var collectCmd = &cobra.Command{
	Use:   "collect",
	Short: "Collect cloud IAM inventory",
}

var collectAWS = &cobra.Command{
	Use:   "aws",
	Short: "Collect AWS Organization snapshot (stub)",
	RunE: func(cmd *cobra.Command, args []string) error {
		s := StateSnapshot{
			SchemaVersion: "1.0.0",
			Provider:      "aws",
			OrgID:         orgID,
			Ts:            time.Now().UTC(),
			Accounts:      []string{"111111111111", "222222222222"},
			Notes:         "stub snapshot for bootstrap",
		}
		b, _ := json.MarshalIndent(s, "", "  ")
		if outFile == "" {
			outFile = "state.json"
		}
		mustWrite(outFile, b)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", outFile)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(collectCmd)
	collectCmd.AddCommand(collectAWS)
	collectAWS.Flags().StringVar(&orgID, "org", "", "AWS Organization ID")
	collectAWS.Flags().StringVar(&outFile, "out", "state.json", "output state file")
	_ = collectAWS.MarkFlagRequired("org")
}
