package client

import (
	"context"
	"fmt"

	"rulehound/core"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func Query(query *string, config *core.Config) (string, error) {
	if query == nil {
		return "", fmt.Errorf("query is nil")
	}

	if config == nil {
		return "", fmt.Errorf("config is nil")
	}

	driver, err := neo4j.NewDriverWithContext(
		fmt.Sprintf(
			"neo4j://%s:%d",
			config.Database.Host,
			config.Database.BoltPort,
		),
		neo4j.BasicAuth(
			config.Database.Username,
			config.Database.Password,
			"",
		),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create Neo4j driver: %w", err)
	}
	defer driver.Close(context.Background())

	ctx := context.Background()

	session := driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: config.Database.Database,
	})
	defer session.Close(ctx)

	result, err := session.Run(ctx, *query, nil)
	if err != nil {
		return "", fmt.Errorf("query failed: %w", err)
	}

	record, err := result.Single(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get query result: %w", err)
	}

	if len(record.Values) == 0 {
		return "", fmt.Errorf("query returned no value")
	}

	value := record.Values[0]

	valueString, ok := value.(string)
	if !ok {
		return "", fmt.Errorf(
			"query returned %T instead of string",
			value,
		)
	}

	return valueString, nil
}
