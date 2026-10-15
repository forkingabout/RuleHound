package reporter

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"rulehound/core"
)

type reportConfig struct {
	Meta          *Meta           `yaml:"Meta"`
	SoloFindings  []*SoloFinding  `yaml:"SoloFindings"`
	BatchFindings []*BatchFinding `yaml:"BatchFindings"`
}

type Meta struct {
	Vendor               string   `yaml:"Vendor"`
	Model                string   `yaml:"Model"`
	Firmware             string   `yaml:"Firmware"`
	OSVersion            string   `yaml:"OS Version"`
	KnownCompatability   []string `yaml:"KnownCompatability"`
	KnownIncompatability []string `yaml:"KnownIncompatability"`
	AuditfileVersion     string   `yaml:"AuditfileVersion"`
}

type Var struct {
	Name  string `yaml:"Name"`
	Query string `yaml:"Query"`
}

type Cue struct {
	Message string `yaml:"Message"`
	Query   string `yaml:"Query"`
}

type Text struct {
	Singular string `yaml:"Singular"`
	Plural   string `yaml:"Plural"`
}

// Pick returns Singular when n == 1, otherwise Plural.
func (t *Text) Pick(n int) string {
	if t == nil {
		return ""
	}
	if n == 1 {
		return t.Singular
	}
	return t.Plural
}

type SoloFinding struct {
	Name     string         `yaml:"Name"`
	Severity float64        `yaml:"Severity"`
	Audit    string         `yaml:"Audit"`
	Flag     []*Cue         `yaml:"Flag"`
	Vars     []*Var         `yaml:"Vars"`
	Sections []*SoloSection `yaml:"Sections"`
}

type SoloSection struct {
	Name string `yaml:"Name"`
	Text *Text  `yaml:"Text"`
}

type BatchFinding struct {
	Name           string        `yaml:"Name"`
	Intro          *Text         `yaml:"Intro"`
	Severity       float64       `yaml:"Severity"`
	CumulativeRisk bool          `yaml:"CumulativeRisk"`
	GlobalVars     []*Var        `yaml:"GlobalVars"`
	Subs           []*SubFinding `yaml:"Subs"`
}

type SubFinding struct {
	Name               string        `yaml:"Name"`
	Audit              string        `yaml:"Audit"`
	SoloSeverity       float64       `yaml:"SoloSeverity"`
	CumulativeSeverity float64       `yaml:"CumulativeSeverity"`
	Flag               []*Cue        `yaml:"Flag"`
	Vars               []*Var        `yaml:"Vars"`
	Sections           []*SubSection `yaml:"Sections"`
}

type SubSection struct {
	Name      string `yaml:"Name"`
	SoloText  *Text  `yaml:"SoloText"`
	BatchText *Text  `yaml:"BatchText"`
}

// ValidateFile reads the report config at path and passes its contents to
// Validate.
func ValidateFile(path string) ([]*SoloFinding, []*BatchFinding, []error) {
	b, err := os.ReadFile(path)
	if err != nil {
		errs := []error{fmt.Errorf("reading report config: %w", err)}
		logErrors(errs)
		return nil, nil, errs
	}
	return Validate(string(b))
}

// Validate decodes a report config YAML string strictly (unknown keys are
// errors), checks that required pieces are present, logs every error via
// core.Error and returns the findings. On a decode error the finding slices
// are nil; on validation errors they are returned alongside the errors.
func Validate(yamlStr string) ([]*SoloFinding, []*BatchFinding, []error) {
	var cfg reportConfig
	dec := yaml.NewDecoder(strings.NewReader(yamlStr))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		errs := decodeErrors(err)
		logErrors(errs)
		return nil, nil, errs
	}

	var errs []error
	if cfg.Meta == nil {
		errs = append(errs, errors.New("missing Meta"))
	}
	for i, s := range cfg.SoloFindings {
		if s.Name == "" {
			errs = append(errs, fmt.Errorf("SoloFindings[%d]: missing Name", i))
		}
		if s.Audit == "" {
			errs = append(errs, fmt.Errorf("SoloFindings[%d] %q: missing Audit", i, s.Name))
		}
		for j, sec := range s.Sections {
			if sec.Text == nil {
				errs = append(errs, fmt.Errorf("SoloFindings[%d] %q Sections[%d]: missing Text", i, s.Name, j))
			}
		}
	}
	for i, b := range cfg.BatchFindings {
		if b.Name == "" {
			errs = append(errs, fmt.Errorf("BatchFindings[%d]: missing Name", i))
		}
		if b.Intro == nil {
			errs = append(errs, fmt.Errorf("BatchFindings[%d] %q: missing Intro", i, b.Name))
		}
		for j, sub := range b.Subs {
			if sub.Audit == "" {
				errs = append(errs, fmt.Errorf("BatchFindings[%d].Subs[%d] %q: missing Audit", i, j, sub.Name))
			}
			for k, sec := range sub.Sections {
				if sec.SoloText == nil || sec.BatchText == nil {
					errs = append(errs, fmt.Errorf("BatchFindings[%d].Subs[%d] %q Sections[%d]: needs both SoloText and BatchText", i, j, sub.Name, k))
				}
			}
		}
	}

	logErrors(errs)
	return cfg.SoloFindings, cfg.BatchFindings, errs
}

// decodeErrors splits a yaml.TypeError (one entry per bad field, e.g. each
// unknown key) into separate errors so each is logged on its own.
func decodeErrors(err error) []error {
	var te *yaml.TypeError
	if errors.As(err, &te) {
		errs := make([]error, 0, len(te.Errors))
		for _, e := range te.Errors {
			errs = append(errs, errors.New(e))
		}
		return errs
	}
	return []error{err}
}

func logErrors(errs []error) {
	for _, err := range errs {
		core.Error(err.Error())
	}
}
