package cli

import (
	"fmt"
	"io"
	"time"
)

func runNormalize(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("normalize", stderr)
	outFile := fs.String("out", "graph.json", "output graph file")
	statePath := ""
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		statePath = args[0]
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if statePath == "" && fs.NArg() == 1 {
		statePath = fs.Arg(0)
	}
	if statePath == "" || fs.NArg() > 1 {
		return fmt.Errorf("usage: normalize <state.json> [--out graph.json]")
	}
	var snapshot StateSnapshot
	if err := readJSON(statePath, &snapshot); err != nil {
		return err
	}
	if err := validateState(snapshot); err != nil {
		return err
	}

	graph := normalizeState(snapshot, statePath)
	if err := writeJSON(*outFile, graph); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "wrote %s\n", *outFile)
	return nil
}

func normalizeState(snapshot StateSnapshot, statePath string) Graph {
	nodes := map[string]GraphNode{}
	edges := make([]GraphEdge, 0)
	identityLookup := map[string]GraphNode{}
	identityNames := map[string]string{}
	accountByIdentity := map[string]string{}

	for _, account := range snapshot.Accounts {
		for _, principal := range account.Principals {
			node := GraphNode{
				ID:    nodeID("u", principal.ID),
				Type:  "Principal",
				Name:  principal.ARN,
				Scope: account.ID,
				Attrs: map[string]any{"tags": principal.Tags, "account_name": account.Name},
			}
			nodes[node.ID] = node
			identityLookup[principal.ID] = node
			identityNames[node.ID] = principal.Name
			accountByIdentity[node.ID] = account.ID
		}
		for _, role := range account.Roles {
			node := GraphNode{
				ID:    nodeID("r", role.ID),
				Type:  "Role",
				Name:  role.ARN,
				Scope: account.ID,
				Attrs: map[string]any{
					"admin":        role.Admin,
					"role_name":    role.Name,
					"account_name": account.Name,
					"tags":         role.Tags,
				},
			}
			nodes[node.ID] = node
			identityLookup[role.ID] = node
			identityNames[node.ID] = role.Name
			accountByIdentity[node.ID] = account.ID
		}
	}

	for _, account := range snapshot.Accounts {
		for _, role := range account.Roles {
			roleNode := identityLookup[role.ID]
			for _, trustedPrincipal := range role.TrustedPrincipals {
				sourceNode, ok := identityLookup[trustedPrincipal]
				if !ok {
					sourceNode = GraphNode{
						ID:    nodeID("u", "external/"+trustedPrincipal),
						Type:  "Principal",
						Name:  trustedPrincipal,
						Scope: account.ID,
					}
					nodes[sourceNode.ID] = sourceNode
					identityNames[sourceNode.ID] = trustedPrincipal
					accountByIdentity[sourceNode.ID] = account.ID
				}

				edges = append(edges, GraphEdge{
					From:          sourceNode.ID,
					To:            roleNode.ID,
					Type:          "CanAssume",
					Preconditions: []string{"sts:AssumeRole"},
					Weight:        1,
					Attrs: map[string]any{
						"trusted_principal_ref": trustedPrincipal,
						"trusted_principal_arn": sourceNode.Name,
						"wildcard_principal":    role.Trust.WildcardPrincipal,
						"account_id":            account.ID,
						"role_name":             role.Name,
						"required_conditions": map[string]any{
							"org_id":          role.Trust.AllowedOrgID,
							"require_mfa":     role.Trust.RequireMFA,
							"external_id":     role.Trust.ExternalID,
							"source_identity": role.Trust.SourceIdentity,
							"principal_tags":  role.Trust.PrincipalTags,
							"resource_tags":   role.Trust.ResourceTags,
							"source_vpces":    role.Trust.SourceVPCEs,
							"source_ip_cidrs": role.Trust.SourceIPCidrs,
						},
					},
				})
			}
		}
	}

	nodeList := make([]GraphNode, 0, len(nodes))
	for _, key := range sortedKeys(nodes) {
		nodeList = append(nodeList, nodes[key])
	}

	return Graph{
		SchemaVersion: "1.1.0",
		Created:       time.Now().UTC(),
		Source:        "panoptes normalize aws",
		Nodes:         nodeList,
		Edges:         edges,
		Meta: map[string]any{
			"provider":  snapshot.Provider,
			"org_id":    snapshot.OrgID,
			"state_ref": statePath,
		},
	}
}
