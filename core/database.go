package core

import "github.com/neo4j/neo4j-go-driver/v5/neo4j"

// DefaultLinkType is used when a Link in the YAML has no Type.
const DefaultLinkType = "LINKS_TO"

type Database struct {
	Driver neo4j.DriverWithContext
}

type GraphNode struct {
	Type       string                 `yaml:"Type"`
	Caption    string                 `yaml:"Caption"`
	ID         int                    `yaml:"ID"`
	Properties map[string]interface{} `yaml:"Properties"`
}

type Link struct {
	Type       string                 `yaml:"Type"`
	From       int                    `yaml:"From"`
	To         int                    `yaml:"To"`
	Properties map[string]interface{} `yaml:"Properties,omitempty"`
}

type Meta struct {
	ParserName       string   `yaml:"ParserName"`
	ParserVersion    string   `yaml:"ParserVersion"`
	ParserAuthor     string   `yaml:"ParserAuthor"`
	FirewallBrand    string   `yaml:"FirewallBrand"`
	FirewallVersions []string `yaml:"FirewallVersions"`
}

// ObjectEntry is the "- Object:" wrapper used in the Objects list.
type ObjectEntry struct {
	Object GraphNode `yaml:"Object"`
}

// LinkEntry is the "- Link:" wrapper used in the Links list.
type LinkEntry struct {
	Link Link `yaml:"Link"`
}

// Document is the complete RuleHound YAML structure.
type Document struct {
	Meta    Meta          `yaml:"Meta"`
	Objects []ObjectEntry `yaml:"Objects"`
	Links   []LinkEntry   `yaml:"Links"`
}
