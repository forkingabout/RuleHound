package analyser

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"net/url"
	"regexp"
	"strings"
)

// SonicWall .exp exports are Base64-encoded preference dumps. Once decoded
// they are "&"-separated key=value pairs with URL-encoded values, e.g.
// "...&shortProdName=NSA%202700&firmwareVersion=SonicOS%207.3.3-7015-R9691&...".
// Key names have varied between SonicOS releases, so each field is looked up
// from a list of known candidates (case-insensitive, first non-empty wins).
var (
	sonicWallModelKeys = []string{
		"shortProdName", "model", "productName", "prodName", "sysModel", "modelName",
	}
	sonicWallFirmwareKeys = []string{
		"firmwareVersion", "fw_version", "firmware", "sysFirmwareVersion", "fwVersion", "currentFirmwareVersion",
	}
	sonicWallSerialKeys = []string{
		"serialNumber", "sn", "serial", "sysSerialNumber", "serialNum",
	}
)

// sonicOSBuildRe matches a SonicOS build string such as 7.3.3-7015-R9691 or
// 6.5.4.4-44n inside a longer firmware value.
var sonicOSBuildRe = regexp.MustCompile(`\d+\.\d+\.\d+(?:\.\d+)?-[0-9A-Za-z]+(?:-R?[0-9A-Za-z]+)?`)

// DetectSonicWall identifies a SonicWall .exp configuration export (including
// SonicOS 7 exports from NSA 2700 appliances) and extracts the model,
// firmware build, serial number and SonicOS major version.
func DetectSonicWall(data []byte) *FirewallVersioningInfo {
	decoded := decodeSonicWallExport(data)
	if decoded == nil {
		return nil
	}

	values := parseSonicWallPrefs(decoded)
	if len(values) == 0 {
		return nil
	}

	model := lookupFirst(values, sonicWallModelKeys)
	firmwareRaw := lookupFirst(values, sonicWallFirmwareKeys)
	serialNumber := lookupFirst(values, sonicWallSerialKeys)

	// Require at least one identifying field.
	if model == "" && firmwareRaw == "" && serialNumber == "" {
		return nil
	}

	// Normalise "SonicOS 7.3.3-7015-R9691" style values to the bare build,
	// and derive the OS version ("SonicOS 7") from its major number.
	firmware := firmwareRaw
	osVersion := ""
	if build := sonicOSBuildRe.FindString(firmwareRaw); build != "" {
		firmware = build
		major, _, _ := strings.Cut(build, ".")
		osVersion = "SonicOS " + major
	}

	return &FirewallVersioningInfo{
		Vendor:       "SonicWall",
		Model:        model,
		Firmware:     firmware,
		SerialNumber: serialNumber,
		OSVersion:    osVersion,
	}
}

// decodeSonicWallExport returns the decoded preference text, or nil if data
// is not a SonicWall export. It mirrors `base64 -d -i`: every character
// outside the Base64 alphabet (line breaks, stray whitespace, a trailing "&")
// is ignored. Gzip-compressed payloads are unpacked, and an export that is
// already plain key=value text is accepted as-is.
func decodeSonicWallExport(data []byte) []byte {
	text := strings.TrimSpace(string(data))
	if text == "" {
		return nil
	}

	// Already-decoded export (someone ran base64 -d first).
	if looksLikePrefs(text) {
		return []byte(text)
	}

	// Keep only Base64 alphabet characters, accepting URL-safe variants.
	var b strings.Builder
	b.Grow(len(text))
	for _, r := range text {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '+', r == '/':
			b.WriteRune(r)
		case r == '-':
			b.WriteRune('+')
		case r == '_':
			b.WriteRune('/')
		}
	}
	clean := b.String()

	// A single leftover character can never decode; drop it like base64 -i.
	if len(clean)%4 == 1 {
		clean = clean[:len(clean)-1]
	}

	decoded, err := base64.RawStdEncoding.DecodeString(clean)
	if err != nil || len(decoded) == 0 {
		return nil
	}

	// Some exports are gzip-compressed before encoding.
	if len(decoded) > 2 && decoded[0] == 0x1f && decoded[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(decoded))
		if err != nil {
			return nil
		}
		defer zr.Close()
		unzipped, err := io.ReadAll(zr)
		if err != nil {
			return nil
		}
		decoded = unzipped
	}

	if !looksLikePrefs(string(decoded)) {
		return nil
	}
	return decoded
}

// looksLikePrefs reports whether text has the shape of a SonicWall
// preference dump: several "&"-separated key=value pairs.
func looksLikePrefs(text string) bool {
	sample := text
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	return strings.Count(sample, "&") >= 3 && strings.Count(sample, "=") >= 3
}

// parseSonicWallPrefs splits the decoded export into key/value pairs,
// matching: sed 's/&/\n/g'. Keys are stored lower-cased for lookup; values
// stay raw until read.
func parseSonicWallPrefs(decoded []byte) map[string]string {
	values := make(map[string]string)

	for _, entry := range strings.FieldsFunc(string(decoded), func(r rune) bool {
		return r == '&' || r == '\n' || r == '\r'
	}) {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			continue
		}
		// Keep the first occurrence; later duplicates are table rows.
		if _, seen := values[key]; !seen {
			values[key] = value
		}
	}

	return values
}

// lookupFirst returns the first non-empty, URL-decoded value among keys.
func lookupFirst(values map[string]string, keys []string) string {
	for _, k := range keys {
		raw, ok := values[strings.ToLower(k)]
		if !ok {
			continue
		}
		v := raw
		if unescaped, err := url.QueryUnescape(raw); err == nil {
			v = unescaped
		}
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}
