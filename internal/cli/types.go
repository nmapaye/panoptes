package cli

import "time"

type StateSnapshot struct {
	SchemaVersion string         `json:"schema_version"`
	Provider      string         `json:"provider"`
	OrgID         string         `json:"org_id"`
	Timestamp     time.Time      `json:"timestamp"`
	Accounts      []AWSAccount   `json:"accounts"`
	Regions       []string       `json:"regions,omitempty"`
	Notes         string         `json:"notes,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

type AWSAccount struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Principals []AWSPrincipal `json:"principals,omitempty"`
	Roles      []AWSRole      `json:"roles,omitempty"`
}

type AWSPrincipal struct {
	ID   string              `json:"id"`
	Name string              `json:"name"`
	ARN  string              `json:"arn"`
	Tags map[string][]string `json:"tags,omitempty"`
}

type AWSRole struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	ARN               string            `json:"arn"`
	Admin             bool              `json:"admin,omitempty"`
	TrustedPrincipals []string          `json:"trusted_principals"`
	Trust             TrustPolicy       `json:"trust"`
	Tags              map[string]string `json:"tags,omitempty"`
}

type TrustPolicy struct {
	WildcardPrincipal bool                `json:"wildcard_principal,omitempty"`
	AllowedOrgID      string              `json:"allowed_org_id,omitempty"`
	RequireMFA        bool                `json:"require_mfa,omitempty"`
	ExternalID        string              `json:"external_id,omitempty"`
	SourceIdentity    string              `json:"source_identity,omitempty"`
	PrincipalTags     map[string][]string `json:"principal_tags,omitempty"`
	ResourceTags      map[string]string   `json:"resource_tags,omitempty"`
	SourceVPCEs       []string            `json:"source_vpces,omitempty"`
	SourceIPCidrs     []string            `json:"source_ip_cidrs,omitempty"`
}

type Graph struct {
	SchemaVersion string         `json:"schema_version"`
	Created       time.Time      `json:"created"`
	Source        string         `json:"source,omitempty"`
	Nodes         []GraphNode    `json:"nodes"`
	Edges         []GraphEdge    `json:"edges"`
	Meta          map[string]any `json:"meta,omitempty"`
}

type GraphNode struct {
	ID    string         `json:"id"`
	Type  string         `json:"type"`
	Name  string         `json:"name,omitempty"`
	Scope string         `json:"scope,omitempty"`
	Attrs map[string]any `json:"attrs,omitempty"`
}

type GraphEdge struct {
	From          string         `json:"from"`
	To            string         `json:"to"`
	Type          string         `json:"type"`
	Preconditions []string       `json:"preconditions,omitempty"`
	Attrs         map[string]any `json:"attrs,omitempty"`
	Weight        float64        `json:"weight,omitempty"`
}

type DetectionRule struct {
	ID                       string   `yaml:"id"`
	Title                    string   `yaml:"title"`
	Description              string   `yaml:"description"`
	MatchType                string   `yaml:"match_type"`
	RequireOrgID             bool     `yaml:"require_org_id"`
	RequireMFA               bool     `yaml:"require_mfa"`
	RequireSpecificPrincipal bool     `yaml:"require_specific_principal"`
	Severity                 string   `yaml:"severity"`
	RemediationKind          string   `yaml:"remediation_kind"`
	RemediationSteps         []string `yaml:"remediation_steps"`
}

type Finding struct {
	ID          string         `json:"id"`
	RuleID      string         `json:"rule_id"`
	Title       string         `json:"title"`
	Severity    string         `json:"severity"`
	Steps       []string       `json:"steps,omitempty"`
	Score       float64        `json:"score"`
	Target      string         `json:"target"`
	TargetName  string         `json:"target_name,omitempty"`
	Evidence    map[string]any `json:"evidence,omitempty"`
	Remediation RemediationRef `json:"remediation"`
}

type Findings struct {
	SchemaVersion string    `json:"schema_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	Findings      []Finding `json:"findings"`
}

type RemediationRef struct {
	Kind      string   `json:"kind"`
	Summary   string   `json:"summary"`
	Suggested []string `json:"suggested,omitempty"`
}

type RemediationPlan struct {
	SchemaVersion string            `json:"schema_version"`
	GeneratedAt   time.Time         `json:"generated_at"`
	Items         []RemediationItem `json:"items"`
}

type RemediationItem struct {
	FindingID      string   `json:"finding_id"`
	Target         string   `json:"target"`
	Summary        string   `json:"summary"`
	Kind           string   `json:"kind"`
	Steps          []string `json:"steps,omitempty"`
	HCL            string   `json:"hcl,omitempty"`
	RequiresReview bool     `json:"requires_review,omitempty"`
	BlockedReason  string   `json:"blocked_reason,omitempty"`
}
