package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"rulehound/analyser"
	"rulehound/client"
	"rulehound/core"
	"rulehound/db"
	"rulehound/reporter"
)

type Args struct {
	Mode        string
	SubMode     string
	ConfigFile  string
	DockerInit  string
	DBHost      string
	DBPort      int
	DBUsername  string
	DBPassword  string
	WebHost     string
	WebPort     int
	Query       string
	AnalyseFile string
	Report      string
	ReportHTML  string
	ReportMD    string
	ReportCSV   string
	ReportJSON  string
	ReportYAML  string
	IngestYAML  string
}

// reportOutput is one --report-* output file and the writer that produces it.
type reportOutput struct {
	Flag  string
	Label string
	Path  string
	Write func([]*reporter.Finding, string) error
}

// reportOutputs returns the --report-* outputs that were given, in a fixed
// order.
func (a *Args) reportOutputs() []reportOutput {
	all := []reportOutput{
		{"report-html", "HTML", a.ReportHTML, reporter.WriteHTML},
		{"report-md", "Markdown", a.ReportMD, reporter.WriteMarkdown},
		{"report-csv", "CSV", a.ReportCSV, reporter.WriteCSV},
		{"report-json", "JSON", a.ReportJSON, reporter.WriteJSON},
		{"report-yaml", "YAML", a.ReportYAML, reporter.WriteYAML},
	}

	var given []reportOutput
	for _, out := range all {
		if out.Path != "" {
			given = append(given, out)
		}
	}
	return given
}

// samePathKey normalises a path so "./out.md" and "out.md" compare equal.
func samePathKey(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return filepath.Clean(path)
}

func LoadConfig(configFile string) (*core.Config, error) {
	core.Debug("Using configuration file: " + configFile)

	cfg, err := core.LoadConfig(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	return cfg, nil
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func parseArgs() (*Args, error) {
	args := &Args{}

	// Database mode arguments.
	flag.StringVar(&args.ConfigFile, "config-file", "", "Path to configuration file")
	flag.StringVar(&args.DockerInit, "docker-init", "", "Path to Docker configuration file")
	flag.StringVar(&args.DBHost, "db-host", "", "Neo4j database host")
	flag.IntVar(&args.DBPort, "db-port", 0, "Neo4j database port")
	flag.StringVar(&args.DBUsername, "db-username", "", "Neo4j database username")
	flag.StringVar(&args.DBPassword, "db-password", "", "Neo4j database password")

	// Web mode arguments.
	flag.StringVar(&args.WebHost, "web-host", "", "RuleHound web server host")
	flag.IntVar(&args.WebPort, "web-port", 0, "RuleHound web server port")

	// Submode arguments.
	flag.StringVar(&args.Query, "query", "", "Cypher query to execute")
	flag.StringVar(&args.AnalyseFile, "analyse-file", "", "Firewall configuration file to analyse")
	flag.StringVar(&args.Report, "report", "", "Path to report findings YAML file")
	flag.StringVar(&args.IngestYAML, "ingest-yaml", "", "Path to firewall YAML file to POST to the web server")

	// Report output arguments (only with --report).
	flag.StringVar(&args.ReportHTML, "report-html", "", "Write an HTML report to this path (with --report)")
	flag.StringVar(&args.ReportMD, "report-md", "", "Write a Markdown report to this path (with --report)")
	flag.StringVar(&args.ReportCSV, "report-csv", "", "Write a CSV report to this path (with --report)")
	flag.StringVar(&args.ReportJSON, "report-json", "", "Write a JSON report to this path (with --report)")
	flag.StringVar(&args.ReportYAML, "report-yaml", "", "Write a YAML report to this path (with --report)")

	flag.Parse()

	// 1. Determine the submode first. Exactly one submode flag may be set.
	submodes := map[string]string{
		"query":        args.Query,
		"analyse-file": args.AnalyseFile,
		"report":       args.Report,
		"ingest-yaml":  args.IngestYAML,
	}

	selected := 0
	for mode, value := range submodes {
		if value != "" {
			args.SubMode = mode
			selected++
		}
	}

	if selected != 1 {
		return nil, fmt.Errorf(
			"specify exactly one of --query, --analyse-file, --report or --ingest-yaml",
		)
	}

	// 2. Report outputs: only valid with --report, and no two output files
	// (or an output and the --report input) may share a path.
	outputs := args.reportOutputs()

	if len(outputs) > 0 && args.SubMode != "report" {
		flags := make([]string, 0, len(outputs))
		for _, out := range outputs {
			flags = append(flags, "--"+out.Flag)
		}
		return nil, fmt.Errorf(
			"%s can only be used with --report",
			strings.Join(flags, ", "),
		)
	}

	if args.SubMode == "report" {
		seen := map[string]string{samePathKey(args.Report): "report"}
		for _, out := range outputs {
			key := samePathKey(out.Path)
			if prev, ok := seen[key]; ok {
				return nil, fmt.Errorf(
					"--%s and --%s must not use the same path: %s",
					prev, out.Flag, out.Path,
				)
			}
			seen[key] = out.Flag
		}
	}

	// 3. Identify which submodes require a database or web connection.
	requireDBConn := []string{
		"query",
		"report",
	}

	requireWebConn := []string{
		"ingest-yaml",
	}

	needsDB := contains(requireDBConn, args.SubMode)
	needsWeb := contains(requireWebConn, args.SubMode)

	// 4. Analyse-file doesn't require a database, web server or main mode.
	if !needsDB && !needsWeb {
		return args, nil
	}

	configMode := args.ConfigFile != ""
	dockerMode := args.DockerInit != ""
	dbFlagsProvided := args.DBHost != "" ||
		args.DBPort != 0 ||
		args.DBUsername != "" ||
		args.DBPassword != ""
	dbArgsProvided := configMode || dockerMode || dbFlagsProvided
	webArgsProvided := args.WebHost != "" || args.WebPort != 0

	// 5. Web mode: web args only, never alongside database args.
	if needsWeb {
		if dbArgsProvided {
			return nil, fmt.Errorf(
				"--%s uses web mode and cannot be combined with "+
					"--config-file, --docker-init or --db-* arguments",
				args.SubMode,
			)
		}
		if args.WebHost == "" || args.WebPort <= 0 || args.WebPort > 65535 {
			return nil, fmt.Errorf(
				"--%s requires --web-host and a valid --web-port",
				args.SubMode,
			)
		}

		args.Mode = "web"
		return args, nil
	}

	// 6. Database mode: database args only, never alongside web args.
	if webArgsProvided {
		return nil, fmt.Errorf(
			"--%s uses database mode and cannot be combined with "+
				"--web-host or --web-port",
			args.SubMode,
		)
	}

	switch {
	case configMode && !dockerMode && !dbFlagsProvided:
		args.Mode = "config-file"

	case !configMode && dockerMode:
		args.Mode = "docker-init"

	case !configMode && !dockerMode &&
		args.DBHost != "" && args.DBPort > 0:
		args.Mode = "database"

	default:
		return nil, fmt.Errorf(
			"specify one connection mode: " +
				"--config-file, --db-host with --db-port, or --docker-init",
		)
	}

	// 7. Validate and apply database settings.
	switch args.Mode {
	case "config-file":
		// Database settings and credentials come from the config file.

	case "database":
		if args.DBUsername == "" {
			args.DBUsername = "neo4j"
		}
		if args.DBPassword == "" {
			args.DBPassword = "password"
		}

	case "docker-init":
		if args.DBHost == "" {
			args.DBHost = "localhost"
		}
		if args.DBPort == 0 {
			args.DBPort = 7687
		}
		if args.DBUsername == "" {
			args.DBUsername = "neo4j"
		}
		if args.DBPassword == "" {
			args.DBPassword = "password"
		}
	}

	return args, nil
}

// ingestYAML reads the file at path and POSTs its contents as the request
// body to http://{host}:{port}/api/ingest/yaml.
func ingestYAML(host string, port int, path string) error {
	core.Debug("Reading YAML file: " + path)

	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read YAML file: %w", err)
	}

	url := "http://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/api/ingest/yaml"
	core.Debug("POST " + url)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to build ingest request: %w", err)
	}
	req.Header.Set("Content-Type", "application/yaml; charset=utf-8")

	httpClient := &http.Client{Timeout: 5 * time.Minute}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("ingest request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := strings.TrimSpace(string(respBody))
		if msg == "" {
			return fmt.Errorf("ingest failed: %s", resp.Status)
		}
		return fmt.Errorf("ingest failed: %s: %s", resp.Status, msg)
	}

	core.Success("Ingesting " + path + " (" + resp.Status + ")" + "\n\nThis could take a while...")
	return nil
}

func main() {
	core.Banner()

	args, err := parseArgs()
	if err != nil {
		core.Error(err.Error())
		flag.Usage()
		os.Exit(1)
	}

	// Execute submodes that don't require a database first.
	switch args.SubMode {
	case "analyse-file":
		// TODO: Call your firewall analysis function.
		// Use args.AnalyseFile as the input file path.
		core.Debug("Analysing file: " + args.AnalyseFile)
		result, err := analyser.Analyse(&args.AnalyseFile)
		if err != nil {
			os.Exit(1)
		}
		result.PrettyPrint()
		return

	case "ingest-yaml":
		if err := ingestYAML(args.WebHost, args.WebPort, args.IngestYAML); err != nil {
			core.Error(err.Error())
			os.Exit(1)
		}
		return
	}

	// All remaining submodes require a database connection.
	var config core.Config

	switch args.Mode {
	case "config-file":
		cfg, err := LoadConfig(args.ConfigFile)
		if err != nil {
			core.Error(err.Error())
			os.Exit(1)
		}
		config = *cfg
		core.Success("Configuration loaded successfully")

	case "database":
		config.Database = core.DatabaseConfig{
			Host:     args.DBHost,
			BoltPort: args.DBPort,
			Username: args.DBUsername,
			Password: args.DBPassword,
			Database: "neo4j",
		}

	case "docker-init":
		// TODO: Initialize Docker using args.DockerInit if required.
		config.Database = core.DatabaseConfig{
			Host:     args.DBHost,
			BoltPort: args.DBPort,
			Username: args.DBUsername,
			Password: args.DBPassword,
			Database: "neo4j",
		}
	}

	core.Success(
		"Neo4j: " +
			config.Database.Host + ":" +
			strconv.Itoa(config.Database.BoltPort),
	)

	if err := db.TestDBConn(&config.Database); err != nil {
		core.Error(err.Error())
		os.Exit(1)
	}

	switch args.SubMode {
	case "query":
		result, err := client.Query(&args.Query, &config)
		if err != nil {
			core.Error(err.Error())
			os.Exit(1)
		}

		fmt.Println(result)

	case "report":
		core.Debug("Using report file: " + args.Report)

		// AuditFile logs each error via core.Error itself.
		findings := reporter.AuditFile(args.Report, &config)

		failed := false
		for _, out := range args.reportOutputs() {
			if err := out.Write(findings, out.Path); err != nil {
				core.Error("--" + out.Flag + ": " + err.Error())
				failed = true
				continue
			}
			core.Success("Wrote " + out.Label + " report: " + out.Path)
		}

		if failed {
			os.Exit(1)
		}
	}
}
