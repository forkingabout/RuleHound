package main

import (
	"flag"
	"os"
	"rulehound/core"
	"rulehound/db"
	"rulehound/web"
	"strconv"
)

func LoadConfig(configFile *string) *core.Config {

	core.Debug("Using configuration file: " + *configFile)

	cfg, err := core.LoadConfig(*configFile)
	if err != nil {
		core.Error(err.Error())
		os.Exit(1)
	}

	return cfg
}

func main() {
	core.Banner()
	core.Success("RuleHound starting")

	configFile := flag.String(
		"config-file",
		"./config/RuleHound.yaml",
		"Path to the RuleHound configuration file",
	)

	flag.Parse()

	config := LoadConfig(configFile)
	core.Success("Configuration loaded successfully")
	core.Success(
		"Neo4j: bolt://" +
			config.Database.Host + ":" + strconv.Itoa(config.Database.BoltPort),
	)

	db.TestDBConn(&config.Database)

	conn, err := db.GetDBConn(&config.Database)

	if err != nil {
		core.Error(err.Error())
		os.Exit(1)
	}

	web.InitWebServer(config, conn)
}
