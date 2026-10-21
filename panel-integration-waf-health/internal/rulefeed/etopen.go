// Package rulefeed builds reviewed, offline IDS rule artifacts. It does not
// download sources, modify a panel, enable capture or certify native syntax.
package rulefeed

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	SourceURL     = "https://rules.emergingthreats.net/open/suricata-8.0.7/emerging.rules.tar.gz"
	maxCompressed = 16 << 20
	maxExpanded   = 192 << 20
	maxFile       = 32 << 20
	maxLine       = 64 << 10
	maxRules      = 65536
	maxInventory  = 100000
	maxArtifact   = 8 << 20
	// Exact, independently reviewed notices. A changed notice needs a new legal
	// review, not a substring test or the distribution index's license label.
	licenseDigest = "03ecce62500a3fbc131dc41b99b3e69632101542e3fc9a303698ef8578c4d4b3"
	bsdDigest     = "2fba5e256c061fd24855c2a46d2ecf9f4eed7869cdf3b5a22d53fc26578ae906"
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var memberPattern = regexp.MustCompile(`^rules/[A-Za-z0-9_.-]{1,120}$`)
var keywordPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
var bitPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,160}$`)
var variablePattern = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)`)

type Rule struct {
	SID                    uint32 `json:"sid"`
	Revision               uint32 `json:"revision"`
	Category               string `json:"category"`
	Disabled               bool   `json:"upstream_disabled"`
	Text                   string `json:"-"`
	action, excluded       string
	classification         string
	sets, needs, variables []string
	references             []string
}

type Source struct {
	archiveSHA256       string
	archiveBytes        int
	license, bsdLicense []byte
	rules               []Rule
	inactive            map[string]int
	categoryNames       map[string]bool
	classifications     map[string]int
	inventoryCount      int
}

// ReadETOpen reads a complete bounded container, checking its digest before
// interpreting it. expectedSHA256 is a caller's independently obtained binding,
// NOT a publisher signature. No archive member is extracted to the filesystem.
func ReadETOpen(ctx context.Context, input io.Reader, expectedSHA256 string) (*Source, error) {
	if !digestPattern.MatchString(expectedSHA256) {
		return nil, errors.New("rule source requires a canonical SHA-256 binding")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	compressed, err := io.ReadAll(io.LimitReader(input, maxCompressed+1))
	if err != nil || len(compressed) == 0 || len(compressed) > maxCompressed {
		return nil, errors.New("rule source compressed budget or read failure")
	}
	if fmt.Sprintf("%x", sha256.Sum256(compressed)) != expectedSHA256 {
		return nil, errors.New("rule source digest mismatch")
	}
	remaining := bytes.NewReader(compressed)
	decoder, err := gzip.NewReader(remaining)
	if err != nil {
		return nil, errors.New("rule source is not a valid gzip container")
	}
	defer decoder.Close()
	decoder.Multistream(false)
	bounded := &io.LimitedReader{R: decoder, N: maxExpanded + 1}
	archive := tar.NewReader(bounded)
	source := &Source{archiveSHA256: expectedSHA256, archiveBytes: len(compressed), inactive: map[string]int{}, categoryNames: map[string]bool{}}
	names := map[string]bool{}
	ids := map[uint32]bool{}
	count := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.New("rule source TAR structure is damaged")
		}
		count++
		name := header.Name
		if count > 256 || bounded.N <= 0 || header.Size < 0 || header.Size > maxFile || names[name] || len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 || header.Linkname != "" {
			return nil, errors.New("rule source member identity, type or budget is invalid")
		}
		names[name] = true
		if header.Typeflag == tar.TypeDir && (name == "rules" || name == "rules/") && header.Size == 0 {
			continue
		}
		if header.Typeflag != tar.TypeReg || !memberPattern.MatchString(name) || path.Clean(name) != name {
			return nil, errors.New("rule source member path or type is not allowed")
		}
		selected := name == "rules/LICENSE" || name == "rules/BSD-License.txt" || name == "rules/classification.config" || strings.HasSuffix(name, ".rules")
		if !selected {
			continue
		}
		if (name == "rules/LICENSE" || name == "rules/BSD-License.txt") && header.Size > 128<<10 {
			return nil, errors.New("rule license notice exceeds its budget")
		}
		data, err := io.ReadAll(io.LimitReader(archive, header.Size+1))
		if err != nil || int64(len(data)) != header.Size {
			return nil, errors.New("rule source member read is incomplete")
		}
		switch name {
		case "rules/LICENSE":
			source.license = data
		case "rules/BSD-License.txt":
			source.bsdLicense = data
		case "rules/classification.config":
			classes, err := readClassifications(data)
			if err != nil {
				return nil, err
			}
			source.classifications = classes
		default:
			if err := readRules(ctx, name, data, source, ids); err != nil {
				return nil, err
			}
		}
	}
	// A TAR end marker must not hide a second archive. Consume only zero padding
	// and reach gzip EOF to verify its checksum; reject concatenated gzip members.
	padding := make([]byte, 4096)
	totalPadding := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, readErr := bounded.Read(padding)
		totalPadding += n
		if bounded.N <= 0 || totalPadding > 64<<10 {
			return nil, errors.New("rule source expansion or trailing padding exceeds budget")
		}
		for _, value := range padding[:n] {
			if value != 0 {
				return nil, errors.New("rule source has nonzero bytes after its TAR end")
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, errors.New("rule source gzip trailer is damaged")
		}
	}
	if remaining.Len() != 0 {
		return nil, errors.New("rule source has concatenated gzip members or trailing bytes")
	}
	if fmt.Sprintf("%x", sha256.Sum256(source.license)) != licenseDigest || fmt.Sprintf("%x", sha256.Sum256(source.bsdLicense)) != bsdDigest {
		return nil, errors.New("rule source license notice differs from the reviewed binding")
	}
	if len(source.rules) == 0 {
		return nil, errors.New("rule source contains no rule inventory")
	}
	sort.Slice(source.rules, func(i, j int) bool { return source.rules[i].SID < source.rules[j].SID })
	return source, nil
}

func readRules(ctx context.Context, name string, data []byte, source *Source, ids map[uint32]bool) error {
	category := strings.TrimSuffix(strings.TrimPrefix(name, "rules/"), ".rules")
	source.categoryNames[category] = true
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return errors.New("rule file is not bounded UTF-8 text")
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxLine)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if err := ctx.Err(); err != nil {
			return err
		}
		line := strings.TrimSpace(scanner.Text())
		disabled := false
		if strings.HasPrefix(line, "#") {
			disabled = true
			line = strings.TrimSpace(strings.TrimPrefix(line, "#"))
		}
		if !looksLikeRule(line) {
			if !disabled && line != "" {
				return fmt.Errorf("unexpected rule text at %s:%d", name, lineNumber)
			}
			continue
		}
		source.inventoryCount++
		if source.inventoryCount > maxInventory {
			return errors.New("rule source active/inactive inventory exceeds budget")
		}
		// Disabled and archived text is never exported, evaluated for identity,
		// or considered a dependency producer. Old deleted rules can contain
		// historically invalid syntax; counting them is not enabling them.
		if category == "emerging-deleted" || category == "emerging-retired" {
			source.inactive["retired-category"]++
			continue
		}
		if disabled {
			source.inactive["upstream-disabled"]++
			continue
		}
		rule, err := parseRule(line)
		if err != nil {
			return fmt.Errorf("invalid rule at %s:%d: %w", name, lineNumber, err)
		}
		if len(source.rules) >= maxRules || ids[rule.SID] {
			return errors.New("rule SID duplicate or inventory budget exhausted")
		}
		ids[rule.SID] = true
		rule.Category = category
		rule.Disabled = disabled
		source.rules = append(source.rules, rule)
	}
	if scanner.Err() != nil {
		return errors.New("rule file line exceeds its budget or cannot be read")
	}
	return nil
}

func looksLikeRule(line string) bool {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false
	}
	action, _, _ := strings.Cut(strings.ToLower(fields[0]), ":")
	switch action {
	case "alert", "drop", "pass", "reject", "rejectsrc", "rejectdst", "rejectboth", "accept", "config":
		return true
	}
	return false
}

// Mirror Suricata 8.0.7 SigParseOptions: a semicolon terminates an option unless
// its immediately preceding byte is a backslash, including inside quotes.
// Quotes inside PCRE character classes are not option delimiters. A regex for
// "sid:" would instead mistake literal option values for a license scope.
func parseRule(line string) (Rule, error) {
	rule := Rule{Text: line, Revision: 1}
	if len(line) >= maxLine || !utf8.ValidString(line) {
		return rule, errors.New("rule text exceeds its budget")
	}
	for _, r := range line {
		if r < 32 && r != '\t' || r == 127 {
			return rule, errors.New("rule contains control characters")
		}
	}
	open := strings.IndexByte(line, '(')
	if open < 0 || !strings.HasSuffix(line, ")") {
		return rule, errors.New("rule option enclosure missing")
	}
	header := strings.TrimSpace(line[:open])
	fields := strings.Fields(header)
	if len(fields) < 7 || strings.ContainsAny(header, `";)\`) {
		return rule, errors.New("rule header is ambiguous")
	}
	rule.action = strings.ToLower(fields[0])
	for _, match := range variablePattern.FindAllStringSubmatch(header, -1) {
		rule.variables = append(rule.variables, match[1])
	}
	options := line[open+1 : len(line)-1]
	start := 0
	seen := map[string]bool{}
	optionCount := 0
	for i := 0; i < len(options); i++ {
		c := options[i]
		if c == ';' && (i == 0 || options[i-1] != '\\') {
			optionCount++
			if optionCount > 256 {
				return rule, errors.New("rule option count exhausted")
			}
			raw := strings.TrimSpace(options[start:i])
			start = i + 1
			key, value, hasValue := strings.Cut(raw, ":")
			// Suricata 8.0.7 SigTableGet uses strcasecmp for both names and
			// aliases. Normalize for identity and policy checks, not rule text.
			key = strings.ToLower(strings.TrimSpace(key))
			value = strings.TrimSpace(value)
			if !keywordPattern.MatchString(key) {
				return rule, errors.New("rule option keyword is invalid")
			}
			switch key {
			case "msg", "content", "pcre":
				literal := strings.TrimSpace(strings.TrimPrefix(value, "!"))
				if !hasValue || len(literal) < 2 || literal[0] != '"' || literal[len(literal)-1] != '"' {
					return rule, errors.New("quoted option value incomplete")
				}
			case "sid", "rev", "gid":
				if seen[key] || !hasValue {
					return rule, errors.New("rule identity option duplicate or missing")
				}
				seen[key] = true
				n, e := strconv.ParseUint(value, 10, 32)
				if e != nil || n == 0 || strconv.FormatUint(n, 10) != value {
					return rule, errors.New("rule identity is not canonical")
				}
				if key == "sid" {
					rule.SID = uint32(n)
				}
				if key == "rev" {
					rule.Revision = uint32(n)
				}
				if key == "gid" && n != 1 {
					rule.excluded = "nonstandard-generator"
				}
			case "classtype":
				if seen[key] || !hasValue || !keywordPattern.MatchString(value) {
					return rule, errors.New("rule classification ambiguous")
				}
				seen[key] = true
				rule.classification = value
			case "reference":
				system, identifier, ok := strings.Cut(value, ",")
				if !hasValue || !ok || !keywordPattern.MatchString(system) || identifier == "" {
					return rule, errors.New("rule reference identity ambiguous")
				}
				rule.references = append(rule.references, system)
			case "lua", "luajit", "dataset", "iprep", "filestore", "file.store", "filemd5", "filesha1", "filesha256", "filemagic", "tag", "logto", "replace", "bypass":
				rule.excluded = "external-or-active-capability"
			case "xbits", "flowint", "flowvar", "pktvar":
				rule.excluded = "unsupported-state-dependency"
			case "flowbits":
				if !hasValue || !parseFlowbits(&rule, value) {
					rule.excluded = "unsupported-flowbits"
				}
			}
		}
	}
	if strings.TrimSpace(options[start:]) != "" || !seen["sid"] {
		return rule, errors.New("rule options incomplete or SID missing")
	}
	rule.sets = uniqueNames(rule.sets)
	rule.needs = uniqueNames(rule.needs)
	rule.variables = uniqueNames(rule.variables)
	rule.references = uniqueNames(rule.references)
	return rule, nil
}

func readClassifications(data []byte) (map[string]int, error) {
	if len(data) > 128<<10 || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return nil, errors.New("rule classification text invalid or over budget")
	}
	result := map[string]int{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > 4096 || !strings.HasPrefix(line, "config classification:") {
			return nil, errors.New("rule classification directive invalid")
		}
		parts := strings.Split(strings.TrimPrefix(line, "config classification:"), ",")
		if len(parts) != 3 {
			return nil, errors.New("rule classification fields invalid")
		}
		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[2])
		priority, err := strconv.Atoi(value)
		if !keywordPattern.MatchString(name) || len(result) >= 128 || result[name] != 0 || err != nil || priority < 1 || priority > 4 || strconv.Itoa(priority) != value {
			return nil, errors.New("rule classification name or priority ambiguous")
		}
		result[name] = priority
	}
	if len(result) == 0 {
		return nil, errors.New("rule classification file empty")
	}
	return result, nil
}

func uniqueNames(names []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(names))
	for _, name := range names {
		if !seen[name] {
			seen[name] = true
			result = append(result, name)
		}
	}
	return result
}

func parseFlowbits(rule *Rule, value string) bool {
	parts := strings.Split(value, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	if len(parts) == 1 {
		return parts[0] == "noalert"
	}
	if len(parts) != 2 {
		return false
	}
	bits := strings.Split(strings.ReplaceAll(parts[1], "&", "|"), "|")
	if len(bits) == 0 || len(bits) > 32 {
		return false
	}
	for _, bit := range bits {
		if !bitPattern.MatchString(bit) {
			return false
		}
	}
	switch parts[0] {
	case "set":
		if len(bits) != 1 {
			return false
		}
		rule.sets = append(rule.sets, bits[0])
	case "isset":
		rule.needs = append(rule.needs, bits...)
	case "unset", "isnotset":
		if len(bits) != 1 {
			return false
		}
	default:
		return false
	}
	return true
}

// Categories exposes only a copy of inventory names, not mutable source rules.
func (source *Source) Categories() []string {
	if source == nil {
		return nil
	}
	set := map[string]bool{}
	for category := range source.categoryNames {
		set[category] = true
	}
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
