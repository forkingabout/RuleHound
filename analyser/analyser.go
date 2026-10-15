package analyser

import (
	"fmt"
	"io"
	"os"
	"rulehound/core"
)

type DetectorFunc func([]byte) *FirewallVersioningInfo

var detectorPipeline = []DetectorFunc{
	DetectSonicWall,
}

func Analyse(filePath *string) (*FirewallVersioningInfo, error) {
	if filePath == nil || *filePath == "" {
		core.Error("Error: File path is nil or empty")
		return &FirewallVersioningInfo{}, fmt.Errorf("Empty config path")
	}

	file, err := os.Open(*filePath)
	if err != nil {
		core.Error("Error opening or reading file")
		return &FirewallVersioningInfo{}, fmt.Errorf("Error opening file")
	}
	defer file.Close()

	// Read the entire file content into bytes.
	// (Note: If configs grow past hundreds of MBs, consider parsing an initial chunk instead)
	fileBytes, err := io.ReadAll(file)
	if err != nil {
		core.Error("Error reading file contents")
		return &FirewallVersioningInfo{}, fmt.Errorf("Error reading file")
	}

	// Initialize the target metadata struct as nil
	var detectedInfo *FirewallVersioningInfo = nil

	// Loop through registered vendors sequentially
	for _, detect := range detectorPipeline {
		detectedInfo = detect(fileBytes)
		if detectedInfo != nil {
			// Found a match! Break out early.
			break
		}
	}

	// Evaluate pipeline result
	if detectedInfo != nil {
		fmt.Printf("Successfully Matched Vendor!\n")
		fmt.Printf("Vendor:        %s\n", detectedInfo.Vendor)
		fmt.Printf("Model:         %s\n", detectedInfo.Model)
		fmt.Printf("Firmware:      %s\n", detectedInfo.Firmware)
		fmt.Printf("Serial Number: %s\n", detectedInfo.SerialNumber)
		return detectedInfo, nil
	} else {
		fmt.Printf("Unknown Config: Could not map '%s' to any known firewall signature.\n", *filePath)
		return detectedInfo, fmt.Errorf("Unknown config")
	}
}
