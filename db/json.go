package db

import (
	"context"
	"encoding/json"
	"fmt"

	"rulehound/core"

	"gopkg.in/yaml.v3"
)

type JSONMeta struct {
	ParserName       string   `json:"parserName"`
	ParserVersion    string   `json:"parserVersion"`
	ParserAuthor     string   `json:"parserAuthor"`
	FirewallBrand    string   `json:"firewallBrand"`
	FirewallVersions []string `json:"firewallVersions"`
}

type JSONNode struct {
	ID         int                    `json:"id"`
	Type       string                 `json:"type"`
	Caption    string                 `json:"caption"`
	Properties map[string]interface{} `json:"properties"`
}

type JSONLink struct {
	Type       string                 `json:"type"`
	From       int                    `json:"from"`
	To         int                    `json:"to"`
	Properties map[string]interface{} `json:"properties"`
}

type JSONDocument struct {
	Meta  JSONMeta   `json:"meta"`
	Nodes []JSONNode `json:"nodes"`
	Links []JSONLink `json:"links"`
}

// ReadDBJSON runs ReadDB and converts its YAML document into a flat JSON
// structure suited to client-side graph rendering.
func ReadDBJSON(ctx context.Context, db *core.Database, cypher string) ([]byte, error) {
	yamlData, err := ReadDB(ctx, db, cypher)
	if err != nil {
		return nil, err
	}

	var doc core.Document

	if err := yaml.Unmarshal(yamlData, &doc); err != nil {
		return nil, fmt.Errorf("failed to convert query result: %w", err)
	}

	versions := doc.Meta.FirewallVersions
	if versions == nil {
		versions = []string{}
	}

	output := JSONDocument{
		Meta: JSONMeta{
			ParserName:       doc.Meta.ParserName,
			ParserVersion:    doc.Meta.ParserVersion,
			ParserAuthor:     doc.Meta.ParserAuthor,
			FirewallBrand:    doc.Meta.FirewallBrand,
			FirewallVersions: versions,
		},
		Nodes: make([]JSONNode, 0, len(doc.Objects)),
		Links: make([]JSONLink, 0, len(doc.Links)),
	}

	for _, entry := range doc.Objects {
		properties := entry.Object.Properties
		if properties == nil {
			properties = map[string]interface{}{}
		}

		output.Nodes = append(output.Nodes, JSONNode{
			ID:         entry.Object.ID,
			Type:       entry.Object.Type,
			Caption:    entry.Object.Caption,
			Properties: properties,
		})
	}

	for _, entry := range doc.Links {
		properties := entry.Link.Properties
		if properties == nil {
			properties = map[string]interface{}{}
		}

		output.Links = append(output.Links, JSONLink{
			Type:       entry.Link.Type,
			From:       entry.Link.From,
			To:         entry.Link.To,
			Properties: properties,
		})
	}

	data, err := json.Marshal(output)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize query result to JSON: %w", err)
	}

	return data, nil
}
