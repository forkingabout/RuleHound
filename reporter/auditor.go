package reporter

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"rulehound/core"
)

const queryTimeout = 60 * time.Second

// placeholderRe matches {name} in section text.
var placeholderRe = regexp.MustCompile(`\{([^{}]+)\}`)

// queryRunner runs one Cypher query and returns all of its rows.
type queryRunner func(query string) (*neo4j.EagerResult, error)

// failFunc logs an error via core.Error and records it.
type failFunc func(format string, a ...any)

// newFail returns a failFunc that appends every message to *errors.
func newFail(errors *[]string) failFunc {
	return func(format string, a ...any) {
		msg := fmt.Sprintf(format, a...)
		core.Error(msg)
		*errors = append(*errors, msg)
	}
}

// openRunner creates a Neo4j driver for db and returns a queryRunner bound to
// it, plus a function that closes the driver.
func openRunner(db *core.Config) (queryRunner, func(), error) {
	ctx := context.Background()
	uri := "bolt://" + db.Database.Host + ":" + strconv.Itoa(db.Database.BoltPort)

	driver, err := neo4j.NewDriverWithContext(
		uri,
		neo4j.BasicAuth(db.Database.Username, db.Database.Password, ""),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Neo4j driver for %s: %w", uri, err)
	}

	run := func(query string) (*neo4j.EagerResult, error) {
		qctx, cancel := context.WithTimeout(ctx, queryTimeout)
		defer cancel()
		return neo4j.ExecuteQuery(
			qctx, driver, query, nil,
			neo4j.EagerResultTransformer,
			neo4j.ExecuteQueryWithDatabase(db.Database.Database),
			neo4j.ExecuteQueryWithReadersRouting(),
		)
	}

	return run, func() { driver.Close(ctx) }, nil
}

// ---------------------------------------------------------------------------
// Solo findings
// ---------------------------------------------------------------------------

// ValidateSoloFinding runs each SoloFinding's Audit query against Neo4j and
// builds a Finding for every one that returns rows. Every error is logged via
// core.Error and returned in the errors slice; a failing finding is skipped
// but the rest are still processed.
func ValidateSoloFinding(soloFindings []*SoloFinding, isPlural bool, db *core.Config) ([]*Finding, []string) {
	var errors []string
	fail := newFail(&errors)

	run, closeRunner, err := openRunner(db)
	if err != nil {
		fail("%v", err)
		return nil, errors
	}
	defer closeRunner()

	return validateSoloFindings(run, soloFindings, isPlural, fail), errors
}

func validateSoloFindings(run queryRunner, soloFindings []*SoloFinding, isPlural bool, fail failFunc) []*Finding {
	var findings []*Finding

	for _, sf := range soloFindings {
		// 1. Audit query: 0 rows means the config passes.
		auditResult, err := run(sf.Audit)
		if err != nil {
			fail("%q: Audit query failed: %v", sf.Name, err)
			continue
		}
		if len(auditResult.Records) == 0 {
			core.Debug(fmt.Sprintf("%q: Audit returned 0 rows, not affected", sf.Name))
			continue
		}

		finding := &Finding{
			Name:     sf.Name,
			Severity: sf.Severity,
			Sections: make(map[string]string, len(sf.Sections)),
			Flags:    []string{},
		}

		// 2. Vars: each query returns a single string value.
		vars := resolveVars(run, sf.Name, sf.Vars, fail)

		// 3. Sections: pick Singular/Plural, then fill {var} placeholders.
		for _, sec := range sf.Sections {
			finding.Sections[sec.Name] = fillTemplate(pickText(sec.Text, isPlural), vars)
		}

		// 4. Flags: any rows means the cue applies.
		finding.Flags = append(finding.Flags, runFlags(run, sf.Name, sf.Flag, fail)...)

		findings = append(findings, finding)
	}

	return findings
}

// ---------------------------------------------------------------------------
// Batch findings
// ---------------------------------------------------------------------------

// ValidateBatchFinding runs every SubFinding's Audit query for each
// BatchFinding and builds at most one Finding per BatchFinding:
//
//   - no subs hit:  nothing is produced
//   - one sub hits: a Finding for that sub alone, using its SoloText sections
//     and SoloSeverity
//   - several hit:  one merged Finding named after the BatchFinding, whose
//     sections are the union of the hit subs' section names, each built from
//     "## {sub name}\n\n{BatchText}" blocks. The BatchFinding's Intro is
//     prepended to the first section (the first section of the first hit
//     sub, in YAML order). Severity is the sum of the hit subs'
//     CumulativeSeverity when the BatchFinding sets CumulativeRisk, else the
//     BatchFinding's Severity.
//
// In all cases GlobalVars take precedence over a sub's Vars of the same name.
// Every error is logged via core.Error and returned in the errors slice.
func ValidateBatchFinding(batchFindings []*BatchFinding, isPlural bool, db *core.Config) ([]*Finding, []string) {
	var errors []string
	fail := newFail(&errors)

	run, closeRunner, err := openRunner(db)
	if err != nil {
		fail("%v", err)
		return nil, errors
	}
	defer closeRunner()

	return validateBatchFindings(run, batchFindings, isPlural, fail), errors
}

func validateBatchFindings(run queryRunner, batchFindings []*BatchFinding, isPlural bool, fail failFunc) []*Finding {
	var findings []*Finding

	for _, bf := range batchFindings {
		// 1. Audit every sub; keep the ones that return rows, in YAML order.
		var hits []*SubFinding
		for _, sub := range bf.Subs {
			result, err := run(sub.Audit)
			if err != nil {
				fail("%q / %q: Audit query failed: %v", bf.Name, sub.Name, err)
				continue
			}
			if len(result.Records) > 0 {
				hits = append(hits, sub)
			}
		}

		if len(hits) == 0 {
			core.Debug(fmt.Sprintf("%q: no Audit queries returned rows, not affected", bf.Name))
			continue
		}

		// 2. GlobalVars, resolved once per BatchFinding.
		globals := resolveVars(run, bf.Name, bf.GlobalVars, fail)

		// 3a. Exactly one sub hit: standalone Finding from its SoloText.
		if len(hits) == 1 {
			sub := hits[0]
			owner := bf.Name + " / " + sub.Name
			vars := mergeVars(resolveVars(run, owner, sub.Vars, fail), globals)

			finding := &Finding{
				Name:     sub.Name,
				Severity: sub.SoloSeverity,
				Sections: make(map[string]string, len(sub.Sections)),
				Flags:    []string{},
			}
			for _, sec := range sub.Sections {
				finding.Sections[sec.Name] = fillTemplate(pickText(sec.SoloText, isPlural), vars)
			}
			finding.Flags = append(finding.Flags, runFlags(run, owner, sub.Flag, fail)...)

			findings = append(findings, finding)
			continue
		}

		// 3b. Several subs hit: one merged Finding from their BatchText.
		finding := &Finding{
			Name:     bf.Name,
			Sections: make(map[string]string),
			Flags:    []string{},
		}

		// The first section created (first section of the first hit sub)
		// receives the Intro once all blocks are in place.
		firstSection := ""

		for _, sub := range hits {
			owner := bf.Name + " / " + sub.Name
			vars := mergeVars(resolveVars(run, owner, sub.Vars, fail), globals)

			for _, sec := range sub.Sections {
				block := "## " + sub.Name + "\n\n" + fillTemplate(pickText(sec.BatchText, isPlural), vars)
				if existing, ok := finding.Sections[sec.Name]; ok {
					finding.Sections[sec.Name] = existing + "\n\n" + block
				} else {
					finding.Sections[sec.Name] = block
					if firstSection == "" {
						firstSection = sec.Name
					}
				}
			}

			if bf.CumulativeRisk {
				finding.Severity += sub.CumulativeSeverity
			}

			finding.Flags = append(finding.Flags, runFlags(run, owner, sub.Flag, fail)...)
		}

		if !bf.CumulativeRisk {
			finding.Severity = bf.Severity
		}

		if firstSection != "" {
			intro := fillTemplate(pickText(bf.Intro, isPlural), globals)
			finding.Sections[firstSection] = intro + "\n\n" + finding.Sections[firstSection]
		}

		findings = append(findings, finding)
	}

	return findings
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// resolveVars runs each Var query and maps the var name to the string in the
// first column of the first row. Failures are reported and the var skipped.
func resolveVars(run queryRunner, owner string, vars []*Var, fail failFunc) map[string]string {
	resolved := make(map[string]string, len(vars))
	for _, v := range vars {
		result, err := run(v.Query)
		if err != nil {
			fail("%q: Var %q query failed: %v", owner, v.Name, err)
			continue
		}
		if len(result.Records) == 0 || len(result.Records[0].Values) == 0 {
			fail("%q: Var %q query returned no value", owner, v.Name)
			continue
		}
		value, ok := result.Records[0].Values[0].(string)
		if !ok {
			fail("%q: Var %q query returned %T, expected string", owner, v.Name, result.Records[0].Values[0])
			continue
		}
		resolved[v.Name] = value
	}
	return resolved
}

// runFlags returns the Message of every cue whose query returns rows.
func runFlags(run queryRunner, owner string, cues []*Cue, fail failFunc) []string {
	var flags []string
	for _, cue := range cues {
		result, err := run(cue.Query)
		if err != nil {
			fail("%q: Flag query for %q failed: %v", owner, cue.Message, err)
			continue
		}
		if len(result.Records) > 0 {
			flags = append(flags, cue.Message)
		}
	}
	return flags
}

// mergeVars combines local and global vars; globals win on a name clash.
func mergeVars(local, global map[string]string) map[string]string {
	merged := make(map[string]string, len(local)+len(global))
	for k, v := range local {
		merged[k] = v
	}
	for k, v := range global {
		merged[k] = v
	}
	return merged
}

// pickText returns Plural when isPlural, otherwise Singular.
func pickText(t *Text, isPlural bool) string {
	if t == nil {
		return ""
	}
	if isPlural {
		return t.Plural
	}
	return t.Singular
}

// fillTemplate replaces {name} with vars[name] in a single pass. Placeholders
// with no matching var are left as-is, and substituted values are never
// re-scanned, so braces inside query results are safe.
func fillTemplate(text string, vars map[string]string) string {
	return placeholderRe.ReplaceAllStringFunc(text, func(match string) string {
		if value, ok := vars[match[1:len(match)-1]]; ok {
			return value
		}
		return match
	})
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

// AuditFile loads the report config at filePath, audits every finding
// against the database and returns the affected findings (solo first, then
// batch). Report files are written by the caller.
func AuditFile(filePath string, db *core.Config) []*Finding {
	soloFindings, batchFindings, errs := ValidateFile(filePath)
	if len(errs) > 0 {
		os.Exit(1)
	}

	core.Success(
		"Report config loaded: " +
			strconv.Itoa(len(soloFindings)) + " solo findings, " +
			strconv.Itoa(len(batchFindings)) + " batch findings",
	)

	// One RuleHound database holds one firewall config, i.e. one asset.
	isPlural := false

	soloResults, _ := ValidateSoloFinding(soloFindings, isPlural, db)
	batchResults, _ := ValidateBatchFinding(batchFindings, isPlural, db)

	findings := append(soloResults, batchResults...)

	PrettyPrintFindings(findings)
	core.Success(
		strconv.Itoa(len(findings)) + " findings affected (" +
			strconv.Itoa(len(soloResults)) + " solo, " +
			strconv.Itoa(len(batchResults)) + " batch)",
	)
	return findings
}
