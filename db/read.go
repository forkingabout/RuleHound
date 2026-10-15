package db

import (
	"context"
	"fmt"
	"time"

	"rulehound/core"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"gopkg.in/yaml.v3"
)

// QueryTimeout is the server-side limit Neo4j enforces on a user query.
const QueryTimeout = 2 * time.Minute

func readMeta(ctx context.Context, session neo4j.SessionWithContext) (core.Meta, error) {
	meta := core.Meta{}

	result, err := session.Run(
		ctx,
		"MATCH (n {id: 0}) RETURN n LIMIT 1",
		nil,
	)
	if err != nil {
		return meta, fmt.Errorf("failed to read metadata: %w", err)
	}

	if !result.Next(ctx) {
		if err := result.Err(); err != nil {
			return meta, fmt.Errorf("failed to read metadata: %w", err)
		}

		return meta, fmt.Errorf("database does not contain metadata object")
	}

	metaNode, ok := result.Record().Values[0].(neo4j.Node)
	if !ok {
		return meta, fmt.Errorf("metadata query did not return a node")
	}

	if value, ok := metaNode.Props["parserName"].(string); ok {
		meta.ParserName = value
	}

	if value, ok := metaNode.Props["parserVersion"].(string); ok {
		meta.ParserVersion = value
	}

	if value, ok := metaNode.Props["parserAuthor"].(string); ok {
		meta.ParserAuthor = value
	}

	if value, ok := metaNode.Props["firewallBrand"].(string); ok {
		meta.FirewallBrand = value
	}

	if value, ok := metaNode.Props["firewallVersions"].([]interface{}); ok {
		for _, version := range value {
			if v, ok := version.(string); ok {
				meta.FirewallVersions = append(meta.FirewallVersions, v)
			}
		}
	}

	if err := result.Err(); err != nil {
		return meta, fmt.Errorf("failed to read metadata: %w", err)
	}

	return meta, nil
}

// readLinks returns every relationship in the database whose start and
// end nodes both have an id in ids, with its type and properties.
func readLinks(ctx context.Context, session neo4j.SessionWithContext, ids []int64) ([]core.LinkEntry, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	result, err := session.Run(
		ctx,
		`
			MATCH (a)-[r]->(b)
			WHERE a.id IN $ids AND b.id IN $ids
			RETURN a.id AS from, b.id AS to, type(r) AS type, properties(r) AS properties
			ORDER BY from, to, type
		`,
		map[string]interface{}{
			"ids": ids,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to read links: %w", err)
	}

	var links []core.LinkEntry

	for result.Next(ctx) {
		record := result.Record()

		fromValue, _ := record.Get("from")
		toValue, _ := record.Get("to")
		typeValue, _ := record.Get("type")
		propertiesValue, _ := record.Get("properties")

		from, ok := fromValue.(int64)
		if !ok {
			continue
		}

		to, ok := toValue.(int64)
		if !ok {
			continue
		}

		linkType, _ := typeValue.(string)

		properties, _ := propertiesValue.(map[string]interface{})
		if len(properties) == 0 {
			properties = nil
		}

		links = append(links, core.LinkEntry{
			Link: core.Link{
				Type:       linkType,
				From:       int(from),
				To:         int(to),
				Properties: properties,
			},
		})
	}

	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("failed to read links: %w", err)
	}

	return links, nil
}

// nodeToGraphNode converts a Neo4j node into a core.GraphNode.
// Returns false for the metadata node and for nodes without an integer id.
func nodeToGraphNode(node neo4j.Node) (core.GraphNode, bool) {
	id, ok := node.Props["id"].(int64)
	if !ok || id == 0 {
		return core.GraphNode{}, false
	}

	properties := make(map[string]interface{})

	for key, value := range node.Props {
		// These are represented separately on GraphNode.
		if key == "id" || key == "caption" {
			continue
		}

		properties[key] = value
	}

	graphNode := core.GraphNode{
		ID:         int(id),
		Properties: properties,
	}

	if len(node.Labels) > 0 {
		graphNode.Type = node.Labels[0]
	}

	if caption, ok := node.Props["caption"].(string); ok {
		graphNode.Caption = caption
	}

	return graphNode, true
}

// ReadDB runs cypher and returns the result as a RuleHound YAML document.
// Cancelling ctx (for example when the HTTP client disconnects) aborts the
// query; Neo4j also terminates it on its own after QueryTimeout.
func ReadDB(ctx context.Context, db *core.Database, cypher string) ([]byte, error) {
	session := db.Driver.NewSession(ctx, neo4j.SessionConfig{})

	// Close with a fresh context so cleanup still runs after ctx is cancelled.
	defer session.Close(context.Background())

	// Always retrieve the metadata object separately.
	meta, err := readMeta(ctx, session)
	if err != nil {
		return nil, err
	}

	// Now execute the user's query.
	result, err := session.Run(ctx, cypher, nil, neo4j.WithTxTimeout(QueryTimeout))
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	var objects []core.ObjectEntry
	var ids []int64
	seen := make(map[int]bool)

	addNode := func(node neo4j.Node) {
		graphNode, ok := nodeToGraphNode(node)
		if !ok || seen[graphNode.ID] {
			return
		}

		seen[graphNode.ID] = true
		objects = append(objects, core.ObjectEntry{Object: graphNode})
		ids = append(ids, int64(graphNode.ID))
	}

	for result.Next(ctx) {
		for _, value := range result.Record().Values {
			switch v := value.(type) {
			case neo4j.Node:
				addNode(v)
			case neo4j.Path:
				for _, node := range v.Nodes {
					addNode(node)
				}
			}
		}
	}

	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("failed to read query results: %w", err)
	}

	// Collect the real relationships between the returned objects.
	links, err := readLinks(ctx, session, ids)
	if err != nil {
		return nil, err
	}

	output := core.Document{
		Meta:    meta,
		Objects: objects,
		Links:   links,
	}

	data, err := yaml.Marshal(output)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize database to YAML: %w", err)
	}

	return data, nil
}
