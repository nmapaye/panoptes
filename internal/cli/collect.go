package cli

import (
	"fmt"
	"io"
	"time"
)

func runCollect(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "aws" {
		return fmt.Errorf("usage: collect aws --fixture <state.json> [--org <org-id>] [--out state.json]")
	}

	fs := newFlagSet("collect aws", stderr)
	var (
		fixture string
		orgID   string
		outFile string
	)
	fs.StringVar(&fixture, "fixture", "", "fixture state snapshot to ingest")
	fs.StringVar(&orgID, "org", "", "expected AWS Organization ID")
	fs.StringVar(&outFile, "out", "state.json", "output state file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fixture == "" {
		return fmt.Errorf("collect aws currently requires --fixture")
	}

	var snapshot StateSnapshot
	if err := readJSON(fixture, &snapshot); err != nil {
		return err
	}
	if orgID != "" && snapshot.OrgID != orgID {
		return fmt.Errorf("fixture org %q does not match --org %q", snapshot.OrgID, orgID)
	}
	if orgID == "" {
		orgID = snapshot.OrgID
	}
	snapshot.OrgID = orgID
	snapshot.Timestamp = time.Now().UTC()
	if snapshot.Metadata == nil {
		snapshot.Metadata = map[string]any{}
	}
	snapshot.Metadata["collected_from_fixture"] = fixture
	if err := validateState(snapshot); err != nil {
		return err
	}
	if err := writeJSON(outFile, snapshot); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "wrote %s\n", outFile)
	return nil
}
