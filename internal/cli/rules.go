package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func loadRules(dir string) ([]DetectionRule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	rules := make([]DetectionRule, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !(strings.HasSuffix(entry.Name(), ".yaml") || strings.HasSuffix(entry.Name(), ".yml")) {
			continue
		}
		rule, err := parseRule(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rule files found in %s", dir)
	}
	return rules, nil
}

func parseRule(path string) (DetectionRule, error) {
	file, err := os.Open(path)
	if err != nil {
		return DetectionRule{}, err
	}
	defer file.Close()

	rule := DetectionRule{}
	currentList := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "- ") {
			item := strings.TrimSpace(strings.TrimPrefix(line, "- "))
			if currentList == "remediation_steps" {
				rule.RemediationSteps = append(rule.RemediationSteps, item)
			}
			continue
		}

		currentList = ""
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"`)
		switch key {
		case "id":
			rule.ID = value
		case "title":
			rule.Title = value
		case "description":
			rule.Description = value
		case "match_type":
			rule.MatchType = value
		case "require_org_id":
			rule.RequireOrgID = parseBoolString(value)
		case "require_mfa":
			rule.RequireMFA = parseBoolString(value)
		case "require_specific_principal":
			rule.RequireSpecificPrincipal = parseBoolString(value)
		case "severity":
			rule.Severity = value
		case "remediation_kind":
			rule.RemediationKind = value
		case "remediation_steps":
			currentList = key
		}
	}
	if err := scanner.Err(); err != nil {
		return DetectionRule{}, err
	}
	if rule.ID == "" || rule.Title == "" || rule.MatchType == "" {
		return DetectionRule{}, fmt.Errorf("rule %s is missing required fields", path)
	}
	if rule.Severity == "" {
		rule.Severity = "high"
	}
	if rule.RemediationKind == "" {
		rule.RemediationKind = "restrict_assume_role"
	}
	return rule, nil
}
