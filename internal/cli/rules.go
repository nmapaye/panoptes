package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var ruleIDPattern = regexp.MustCompile(`^[A-Z0-9][A-Z0-9_-]{2,63}$`)

func loadRules(dir string) ([]DetectionRule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	rules := make([]DetectionRule, 0, len(entries))
	seen := map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml")) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		rule, err := parseRule(path)
		if err != nil {
			return nil, err
		}
		if previous, exists := seen[rule.ID]; exists {
			return nil, fmt.Errorf("duplicate rule id %q in %s and %s", rule.ID, previous, path)
		}
		seen[rule.ID] = path
		rules = append(rules, rule)
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rule files found in %s", dir)
	}
	return rules, nil
}

func parseRule(path string) (DetectionRule, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return DetectionRule{}, err
	}

	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	decoder.KnownFields(true)
	var rule DetectionRule
	if err := decoder.Decode(&rule); err != nil {
		return DetectionRule{}, fmt.Errorf("parse rule %s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return DetectionRule{}, fmt.Errorf("rule %s contains multiple YAML documents", path)
		}
		return DetectionRule{}, fmt.Errorf("parse rule %s: %w", path, err)
	}
	if err := validateRule(rule); err != nil {
		return DetectionRule{}, fmt.Errorf("rule %s: %w", path, err)
	}
	return rule, nil
}

func validateRule(rule DetectionRule) error {
	if !ruleIDPattern.MatchString(rule.ID) {
		return errors.New("id must contain 3 to 64 uppercase letters, digits, underscores, or hyphens")
	}
	if strings.TrimSpace(rule.Title) == "" || strings.TrimSpace(rule.Description) == "" {
		return errors.New("title and description are required")
	}
	if rule.MatchType != "CanAssume" {
		return fmt.Errorf("unsupported match_type %q", rule.MatchType)
	}
	if !rule.RequireOrgID && !rule.RequireMFA && !rule.RequireSpecificPrincipal {
		return errors.New("at least one trust requirement must be enabled")
	}
	switch rule.Severity {
	case "critical", "high", "medium", "low":
	default:
		return fmt.Errorf("unsupported severity %q", rule.Severity)
	}
	if strings.TrimSpace(rule.RemediationKind) == "" || len(rule.RemediationSteps) == 0 {
		return errors.New("remediation_kind and remediation_steps are required")
	}
	for _, step := range rule.RemediationSteps {
		if strings.TrimSpace(step) == "" {
			return errors.New("remediation steps cannot be empty")
		}
	}
	return nil
}
