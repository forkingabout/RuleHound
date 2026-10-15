package db

import (
	"context"
	"fmt"
	"strings"

	"rulehound/core"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// quoteLabel backtick-quotes a node label or relationship type for Cypher.
func quoteLabel(label string) string {
	return "`" + strings.ReplaceAll(label, "`", "``") + "`"
}

func writeObject(ctx context.Context, session neo4j.SessionWithContext, obj *core.GraphNode) error {
	if obj.Type == "" {
		return fmt.Errorf("object %d has no Type", obj.ID)
	}

	if obj.ID == 0 {
		return fmt.Errorf("object of type %s has ID 0, which is reserved for metadata", obj.Type)
	}

	query := fmt.Sprintf(`
		CREATE (n:%s {id: $id, caption: $caption})
		SET n += $properties
	`, quoteLabel(obj.Type))

	properties := obj.Properties
	if properties == nil {
		properties = map[string]interface{}{}
	}

	_, err := session.Run(
		ctx,
		query,
		map[string]interface{}{
			"id":         obj.ID,
			"caption":    obj.Caption,
			"properties": properties,
		},
	)

	if err != nil {
		core.Error(fmt.Sprintf("Failed to write object %d", obj.ID))
		return fmt.Errorf("failed to write object %d: %w", obj.ID, err)
	}

	core.Success(fmt.Sprintf("Wrote %s object %d", obj.Type, obj.ID))

	return nil
}

func createLink(ctx context.Context, session neo4j.SessionWithContext, link core.Link) error {
	linkType := link.Type
	if linkType == "" {
		linkType = core.DefaultLinkType
	}

	if link.From == 0 || link.To == 0 {
		return fmt.Errorf("cannot create %s link %d -> %d: ID 0 is reserved for metadata", linkType, link.From, link.To)
	}

	properties := link.Properties
	if properties == nil {
		properties = map[string]interface{}{}
	}

	// Relationship types cannot be parameterised in Cypher, so the type is
	// quoted into the query text; everything else is passed as parameters.
	query := fmt.Sprintf(`
		MATCH (a {id: $from}), (b {id: $to})
		CREATE (a)-[r:%s]->(b)
		SET r += $properties
		RETURN count(r) AS created
	`, quoteLabel(linkType))

	result, err := session.Run(
		ctx,
		query,
		map[string]interface{}{
			"from":       link.From,
			"to":         link.To,
			"properties": properties,
		},
	)

	if err != nil {
		core.Error(fmt.Sprintf("Failed to create %s link %d -> %d", linkType, link.From, link.To))
		return fmt.Errorf("failed to create %s link %d -> %d: %w", linkType, link.From, link.To, err)
	}

	record, err := result.Single(ctx)
	if err != nil {
		return fmt.Errorf("failed to read link result %d -> %d: %w", link.From, link.To, err)
	}

	created, _ := record.Values[0].(int64)
	if created == 0 {
		core.Error(fmt.Sprintf("Cannot create %s link %d -> %d: object not found", linkType, link.From, link.To))
		return fmt.Errorf("cannot create %s link %d -> %d: one or both objects do not exist", linkType, link.From, link.To)
	}

	core.Success(fmt.Sprintf("Linked object %d -[%s]-> %d", link.From, linkType, link.To))

	return nil
}

func writeMeta(ctx context.Context, session neo4j.SessionWithContext, meta *core.Meta) error {
	// ID 0 is reserved for the metadata object.
	result, err := session.Run(
		ctx,
		"MATCH (n {id: 0}) RETURN n LIMIT 1",
		nil,
	)

	if err != nil {
		return fmt.Errorf("failed to check for existing metadata: %w", err)
	}

	if result.Next(ctx) {
		core.Error("Database already contains metadata object")
		return fmt.Errorf("database already contains metadata object")
	}

	if err := result.Err(); err != nil {
		return fmt.Errorf("failed to check metadata result: %w", err)
	}

	query := `
		CREATE (n:Meta {
			id: $id,
			parserName: $parserName,
			parserVersion: $parserVersion,
			parserAuthor: $parserAuthor,
			firewallBrand: $firewallBrand,
			firewallVersions: $firewallVersions
		})
	`

	_, err = session.Run(
		ctx,
		query,
		map[string]interface{}{
			"id":               0,
			"parserName":       meta.ParserName,
			"parserVersion":    meta.ParserVersion,
			"parserAuthor":     meta.ParserAuthor,
			"firewallBrand":    meta.FirewallBrand,
			"firewallVersions": meta.FirewallVersions,
		},
	)

	if err != nil {
		core.Error("Failed to write metadata object")
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	core.Success("Wrote database metadata")

	return nil
}

func WriteObject(db *core.Database, obj *core.GraphNode) error {
	ctx := context.Background()

	session := db.Driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	return writeObject(ctx, session, obj)
}

// CreateLink creates a relationship of the given type, with the given
// properties, from the object with ID fromID to the object with ID toID.
// An empty linkType uses core.DefaultLinkType; properties may be nil.
func CreateLink(db *core.Database, fromID int, toID int, linkType string, properties map[string]interface{}) error {
	ctx := context.Background()

	session := db.Driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	return createLink(ctx, session, core.Link{
		Type:       linkType,
		From:       fromID,
		To:         toID,
		Properties: properties,
	})
}

func WriteMeta(db *core.Database, meta *core.Meta) error {
	ctx := context.Background()

	session := db.Driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	return writeMeta(ctx, session, meta)
}

func WriteObjects(db *core.Database, data []byte) error {
	meta, objects, links, err := ParseObjects(data)
	if err != nil {
		core.Error(fmt.Sprintf("Failed to parse objects: %v", err))
		return err
	}

	ctx := context.Background()

	session := db.Driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	if err := writeMeta(ctx, session, meta); err != nil {
		return err
	}

	// Create every node first so links can reference any object.
	for _, object := range objects {
		if err := writeObject(ctx, session, object); err != nil {
			return err
		}
	}

	// Then instantiate each Link as a real, typed relationship.
	for _, link := range links {
		if err := createLink(ctx, session, link); err != nil {
			return err
		}
	}

	core.Success(fmt.Sprintf(
		"Successfully wrote %d objects and %d links",
		len(objects),
		len(links),
	))

	return nil
}
