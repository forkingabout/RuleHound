package db

import (
	"fmt"
	"strings"

	"rulehound/core"

	"gopkg.in/yaml.v3"
)

func ParseObjects(data []byte) (*core.Meta, []*core.GraphNode, []core.Link, error) {
	root, err := core.ParseYAML(data)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	if len(root.Content) == 0 {
		return nil, nil, nil, fmt.Errorf("YAML document is empty")
	}

	document := root.Content[0]

	if document.Kind != yaml.MappingNode {
		return nil, nil, nil, fmt.Errorf("YAML root must be a mapping")
	}

	var metaNode *yaml.Node
	var objectsNode *yaml.Node
	var linksNode *yaml.Node

	// Find Meta, Objects and Links at the root of the YAML document.
	for i := 0; i < len(document.Content); i += 2 {
		key := document.Content[i]
		value := document.Content[i+1]

		switch key.Value {
		case "Meta":
			metaNode = value
		case "Objects":
			objectsNode = value
		case "Links":
			linksNode = value
		}
	}

	if metaNode == nil {
		return nil, nil, nil, fmt.Errorf("YAML is missing Meta")
	}

	if objectsNode == nil {
		return nil, nil, nil, fmt.Errorf("YAML is missing Objects")
	}

	meta, err := parseMeta(metaNode)
	if err != nil {
		return nil, nil, nil, err
	}

	if objectsNode.Kind != yaml.SequenceNode {
		return nil, nil, nil, fmt.Errorf("Objects must be a YAML list")
	}

	nodes := make([]*core.GraphNode, 0, len(objectsNode.Content))

	for _, objectNode := range objectsNode.Content {
		node, err := parseGraphNode(objectNode)
		if err != nil {
			return nil, nil, nil, err
		}

		nodes = append(nodes, node)
	}

	links, err := parseLinks(linksNode)
	if err != nil {
		return nil, nil, nil, err
	}

	return meta, nodes, links, nil
}

// parseMeta converts the Meta YAML node into a core.Meta.
func parseMeta(node *yaml.Node) (*core.Meta, error) {
	var meta core.Meta

	if err := node.Decode(&meta); err != nil {
		return nil, fmt.Errorf("failed to parse Meta: %w", err)
	}

	return &meta, nil
}

// findWrapped returns the value under the given key of a single-key
// wrapper mapping such as "- Object: ..." or "- Link: ...".
func findWrapped(node *yaml.Node, wrapper string) (*yaml.Node, error) {
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s entry must be a mapping (line %d)", wrapper, node.Line)
	}

	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == wrapper {
			return node.Content[i+1], nil
		}
	}

	return nil, fmt.Errorf("entry is missing %s (line %d)", wrapper, node.Line)
}

// parseGraphNode converts one Objects entry into a core.GraphNode.
func parseGraphNode(node *yaml.Node) (*core.GraphNode, error) {
	objectNode, err := findWrapped(node, "Object")
	if err != nil {
		return nil, err
	}

	var graphNode core.GraphNode

	if err := objectNode.Decode(&graphNode); err != nil {
		return nil, fmt.Errorf("failed to parse Object (line %d): %w", objectNode.Line, err)
	}

	return &graphNode, nil
}

// parseLinks converts the optional Links list into core.Links.
func parseLinks(node *yaml.Node) ([]core.Link, error) {
	// Links is optional; absent or "Links:" with no value means no relationships.
	if node == nil || (node.Kind == yaml.ScalarNode && node.Tag == "!!null") {
		return nil, nil
	}

	if node.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("Links must be a YAML list")
	}

	links := make([]core.Link, 0, len(node.Content))

	for _, entry := range node.Content {
		linkNode, err := findWrapped(entry, "Link")
		if err != nil {
			return nil, err
		}

		// Pointers so a missing From/To is distinguishable from ID 0.
		var raw struct {
			Type       string                 `yaml:"Type"`
			From       *int                   `yaml:"From"`
			To         *int                   `yaml:"To"`
			Properties map[string]interface{} `yaml:"Properties"`
		}

		if err := linkNode.Decode(&raw); err != nil {
			return nil, fmt.Errorf("failed to parse Link (line %d): %w", linkNode.Line, err)
		}

		if raw.From == nil || raw.To == nil {
			return nil, fmt.Errorf("Link at line %d must have both From and To", linkNode.Line)
		}

		linkType := strings.TrimSpace(raw.Type)
		if linkType == "" {
			linkType = core.DefaultLinkType
		}

		links = append(links, core.Link{
			Type:       linkType,
			From:       *raw.From,
			To:         *raw.To,
			Properties: raw.Properties,
		})
	}

	return links, nil
}
