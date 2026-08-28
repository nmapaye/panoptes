package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var Version = "dev"

func Execute() error {
	return execute(os.Args[1:], os.Stdout, os.Stderr)
}

func execute(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stdout)
		return nil
	}

	switch args[0] {
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	case "version", "--version":
		_, err := fmt.Fprintln(stdout, Version)
		return err
	case "collect":
		return runCollect(args[1:], stdout, stderr)
	case "normalize":
		return runNormalize(args[1:], stdout, stderr)
	case "analyze":
		return runAnalyze(args[1:], stdout, stderr)
	case "show-path":
		return runShowPath(args[1:], stdout, stderr)
	case "remediate":
		return runRemediate(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Panoptes - AWS IAM attack-path MVP")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "Commands:")
	_, _ = fmt.Fprintln(w, "  collect aws --fixture <state.json> [--org <org-id>] [--out state.json]")
	_, _ = fmt.Fprintln(w, "  normalize <state.json> [--out graph.json]")
	_, _ = fmt.Fprintln(w, "  analyze <graph.json> [--rules rules/aws] [--paths=true] [--max-depth 6] [--out findings.json]")
	_, _ = fmt.Fprintln(w, "  show-path <finding-id> [findings.json]")
	_, _ = fmt.Fprintln(w, "  remediate <findings.json> [--emit terraform_out]")
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(b, '\n'), 0644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func readJSON(path string, out any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func validateState(snapshot StateSnapshot) error {
	if !strings.HasPrefix(snapshot.SchemaVersion, "1.") {
		return fmt.Errorf("unsupported state schema version %q", snapshot.SchemaVersion)
	}
	if snapshot.Provider != "aws" {
		return fmt.Errorf("unsupported provider %q", snapshot.Provider)
	}
	if !strings.HasPrefix(snapshot.OrgID, "o-") {
		return fmt.Errorf("org_id must look like an AWS organization id, got %q", snapshot.OrgID)
	}
	if len(snapshot.Accounts) == 0 {
		return errors.New("state snapshot must include at least one account")
	}
	seenAccounts := map[string]bool{}
	seenPrincipals := map[string]bool{}
	seenRoles := map[string]bool{}
	for _, account := range snapshot.Accounts {
		if account.ID == "" {
			return errors.New("account id is required")
		}
		if seenAccounts[account.ID] {
			return fmt.Errorf("duplicate account id %q", account.ID)
		}
		seenAccounts[account.ID] = true
		for _, principal := range account.Principals {
			if principal.ID == "" || principal.ARN == "" {
				return fmt.Errorf("principal in %s must include id and arn", account.ID)
			}
			if seenPrincipals[principal.ID] {
				return fmt.Errorf("duplicate principal id %q", principal.ID)
			}
			seenPrincipals[principal.ID] = true
		}
		for _, role := range account.Roles {
			if role.ID == "" || role.ARN == "" {
				return fmt.Errorf("role in %s must include id and arn", account.ID)
			}
			if seenRoles[role.ID] {
				return fmt.Errorf("duplicate role id %q", role.ID)
			}
			seenRoles[role.ID] = true
		}
	}
	return nil
}

func nodeID(prefix, raw string) string {
	return prefix + ":" + raw
}

func boolFromAny(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	default:
		return false
	}
}

func stringFromAny(value any) string {
	switch v := value.(type) {
	case string:
		return v
	default:
		return ""
	}
}

func severityScore(severity string, admin bool) float64 {
	score := map[string]float64{
		"critical": 0.98,
		"high":     0.9,
		"medium":   0.72,
		"low":      0.5,
	}[severity]
	if score == 0 {
		score = 0.65
	}
	if admin && score < 0.95 {
		score += 0.05
	}
	if score > 0.99 {
		return 0.99
	}
	return score
}

func sanitizeResourceName(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "panoptes_target"
	}
	return b.String()
}

func sortedKeys[K ~string, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}

func graphMetaOrgID(g Graph) string {
	if g.Meta == nil {
		return ""
	}
	if org, ok := g.Meta["org_id"].(string); ok {
		return org
	}
	return ""
}

func defaultOutputPath(dir, name string) string {
	if dir == "" {
		return name
	}
	return filepath.Join(dir, name)
}
