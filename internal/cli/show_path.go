package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var showPathCmd = &cobra.Command{
	Use:   "show-path <finding_id> [findings.json]",
	Short: "Show a path by finding ID",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		in := "findings.json"
		if len(args) == 2 {
			in = args[1]
		}
		b, err := os.ReadFile(in)
		if err != nil {
			return err
		}
		var f Findings
		if err := json.Unmarshal(b, &f); err != nil {
			return err
		}
		for _, x := range f.Findings {
			if x.ID == id {
				fmt.Fprintln(cmd.OutOrStdout(), x.Title)
				for i, s := range x.Steps {
					fmt.Fprintf(cmd.OutOrStdout(), "%d) %s\n", i+1, s)
				}
				return nil
			}
		}
		return fmt.Errorf("finding %s not found", id)
	},
}
