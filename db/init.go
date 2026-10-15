package db

import (
	"context"
	"fmt"

	"rulehound/core"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func TestDBConn(cfg *core.DatabaseConfig) error {
	core.Success(
		fmt.Sprintf(
			"Testing Neo4j connection to %s:%d",
			cfg.Host,
			cfg.BoltPort,
		),
	)

	uri := fmt.Sprintf(
		"bolt://%s:%d",
		cfg.Host,
		cfg.BoltPort,
	)

	driver, err := neo4j.NewDriverWithContext(
		uri,
		neo4j.BasicAuth(
			cfg.Username,
			cfg.Password,
			"",
		),
	)

	if err != nil {
		core.Error("Failed to create Neo4j driver")
		return fmt.Errorf("failed to create Neo4j driver: %w", err)
	}

	defer driver.Close(context.Background())

	ctx := context.Background()

	if err := driver.VerifyConnectivity(ctx); err != nil {
		core.Error(
			fmt.Sprintf("Failed to connect to Neo4j at %s", uri),
		)

		return fmt.Errorf(
			"failed to connect to Neo4j at %s: %w",
			uri,
			err,
		)
	}

	core.Success(
		fmt.Sprintf(
			"Successfully connected to Neo4j at %s",
			uri,
		),
	)

	return nil
}

func GetDBConn(cfg *core.DatabaseConfig) (*core.Database, error) {
	uri := fmt.Sprintf(
		"bolt://%s:%d",
		cfg.Host,
		cfg.BoltPort,
	)

	core.Success(fmt.Sprintf(
		"Connecting to Neo4j at %s",
		uri,
	))

	driver, err := neo4j.NewDriverWithContext(
		uri,
		neo4j.BasicAuth(
			cfg.Username,
			cfg.Password,
			"",
		),
	)

	if err != nil {
		core.Error("Failed to create Neo4j driver")
		return nil, fmt.Errorf("failed to create Neo4j driver: %w", err)
	}

	ctx := context.Background()

	if err := driver.VerifyConnectivity(ctx); err != nil {
		core.Error(fmt.Sprintf(
			"Failed to connect to Neo4j at %s",
			uri,
		))

		driver.Close(ctx)

		return nil, fmt.Errorf("failed to connect to Neo4j: %w", err)
	}

	core.Success("Neo4j connection established")

	return &core.Database{
		Driver: driver,
	}, nil
}
