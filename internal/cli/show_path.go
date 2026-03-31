package cli

import (
	"fmt"
	"io"
)

func runShowPath(args []string, stdout, stderr io.Writer) error {
	_ = stderr
	if len(args) < 1 || len(args) > 2 {
		return fmt.Errorf("usage: show-path <finding-id> [findings.json]")
	}
	id := args[0]
	path := "findings.json"
	if len(args) == 2 {
		path = args[1]
	}
	var findings Findings
	if err := readJSON(path, &findings); err != nil {
		return err
	}
	for _, finding := range findings.Findings {
		if finding.ID != id {
			continue
		}
		_, _ = fmt.Fprintln(stdout, finding.Title)
		if len(finding.Steps) == 0 {
			_, _ = fmt.Fprintln(stdout, "No explicit path was recorded for this finding.")
			return nil
		}
		for idx, step := range finding.Steps {
			_, _ = fmt.Fprintf(stdout, "%d) %s\n", idx+1, step)
		}
		return nil
	}
	return fmt.Errorf("finding %s not found", id)
}
