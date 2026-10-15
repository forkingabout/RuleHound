package reporter

import (
	"fmt"
	"sort"
	"strings"
)

type Finding struct {
	Name     string
	Severity float64
	Sections map[string]string
	Flags    []string
}

// PrettyPrint prints a single Finding: name and severity, every section
// (sorted by name, multi-line values indented), then any flags.
func (f *Finding) PrettyPrint() {
	if f == nil {
		return
	}

	rule := strings.Repeat("=", 72)
	fmt.Println(rule)
	fmt.Printf("%s  [Severity %.1f]\n", f.Name, f.Severity)
	fmt.Println(strings.Repeat("-", 72))

	names := make([]string, 0, len(f.Sections))
	for name := range f.Sections {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		fmt.Printf("%s:\n", name)
		fmt.Printf("  %s\n\n", strings.ReplaceAll(f.Sections[name], "\n", "\n  "))
	}

	if len(f.Flags) > 0 {
		fmt.Println("Flags:")
		for _, flag := range f.Flags {
			fmt.Printf("  ! %s\n", flag)
		}
		fmt.Println()
	}
}

// PrettyPrintFindings prints every Finding in the slice using PrettyPrint.
func PrettyPrintFindings(findings []*Finding) {
	if len(findings) == 0 {
		fmt.Println("No findings.")
		return
	}

	fmt.Printf("%d finding(s)\n\n", len(findings))
	for _, f := range findings {
		f.PrettyPrint()
	}
}
