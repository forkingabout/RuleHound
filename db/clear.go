package db

import (
	"context"
	"fmt"

	"rulehound/core"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func ClearDB(db *core.Database) error {
	core.Warn("Clearing Neo4j database")

	ctx := context.Background()

	session := db.Driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	_, err := session.Run(
		ctx,
		"MATCH (n) DETACH DELETE n",
		nil,
	)

	if err != nil {
		core.Error("Failed to clear Neo4j database")
		return fmt.Errorf("failed to clear database: %w", err)
	}

	core.Success("Neo4j database cleared")

	return nil
}
