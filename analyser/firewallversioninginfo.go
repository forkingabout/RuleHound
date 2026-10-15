package analyser

import (
	"fmt"
	"strings"
)

type FirewallVersioningInfo struct {
	Vendor       string `json:"vendor"`
	Model        string `json:"model"`
	Firmware     string `json:"firmware"`
	SerialNumber string `json:"serial_number"`
	OSVersion    string `json:"os_version"`
}

// PrettyPrint outputs the firewall metadata inside a beautifully decorated box frame.
func (f *FirewallVersioningInfo) PrettyPrint() {
	if f == nil {
		fmt.Println("┌────────────────────────────────────────┐")
		fmt.Println("│  No firewall metadata available.       │")
		fmt.Println("└────────────────────────────────────────┘")
		return
	}

	// 1. Prepare data and track the longest line to dynamic-size the box width
	kvPairs := [][2]string{
		{"Vendor", getOrDefault(f.Vendor)},
		{"Model", getOrDefault(f.Model)},
		{"Firmware", getOrDefault(f.Firmware)},
		{"Serial Number", getOrDefault(f.SerialNumber)},
	}

	labelWidth := 15 // Fixed column spacing for labels
	maxContentWidth := 0

	for _, pair := range kvPairs {
		lineLen := labelWidth + len(pair[1])
		if lineLen > maxContentWidth {
			maxContentWidth = lineLen
		}
	}

	// Set overall inside width with comfortable margins
	boxWidth := maxContentWidth + 4
	if boxWidth < 36 {
		boxWidth = 36 // Establish a baseline visual width
	}

	// 2. Render Top Border & Header Banner
	headerText := " FIREWALL CONFIG DETECTED "
	sideBarLen := (boxWidth - len(headerText)) / 2

	// Adjust slightly if the split isn't clean
	leftBar := strings.Repeat("═", sideBarLen)
	rightBar := strings.Repeat("═", boxWidth-len(headerText)-sideBarLen)

	fmt.Printf("╔%s%s%s╗\n", leftBar, headerText, rightBar)
	fmt.Printf("║%s║\n", strings.Repeat(" ", boxWidth)) // Empty spacer line

	// 3. Render Contents Body
	for _, pair := range kvPairs {
		label := pair[0] + ":"
		value := pair[1]

		// Format string: left-align label within spacing, then drop value
		leftPart := fmt.Sprintf("  %-*s %s", labelWidth, label, value)
		paddingNeeded := boxWidth - len(leftPart)

		// Print line framed with box walls
		if paddingNeeded > 0 {
			fmt.Printf("║%s%s║\n", leftPart, strings.Repeat(" ", paddingNeeded))
		} else {
			fmt.Printf("║%s║\n", leftPart)
		}
	}

	// 4. Render Bottom Border
	fmt.Printf("║%s║\n", strings.Repeat(" ", boxWidth)) // Empty spacer line
	fmt.Printf("╚%s╝\n", strings.Repeat("═", boxWidth))
}

// Helper to keep the output tidy if a specific field is unpopulated
func getOrDefault(val string) string {
	if strings.TrimSpace(val) == "" {
		return "N/A"
	}
	return val
}
