package rulefeed

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Profile requires an explicit bounded category choice. Empty selection never
// means "enable everything". Variables must be supplied by closed native YAML.
type Profile struct {
	Categories []string
	Variables  []string
	MaxEnabled int
}

type Manifest struct {
	Format                     int               `json:"format"`
	SourceURL                  string            `json:"source_url"`
	SourceSHA256               string            `json:"source_sha256"`
	SourceBytes                int               `json:"source_bytes"`
	License                    string            `json:"license"`
	EngineMajor                int               `json:"engine_major"`
	Categories                 []string          `json:"categories"`
	RequiredVariables          []string          `json:"required_variables"`
	SourceRuleCount            int               `json:"source_rule_count"`
	EnabledRuleCount           int               `json:"enabled_rule_count"`
	DependencyRuleCount        int               `json:"dependency_rule_count"`
	Excluded                   map[string]int    `json:"excluded"`
	Files                      map[string]string `json:"files_sha256"`
	NativeSyntaxVerified       bool              `json:"native_syntax_verified"`
	PublisherSignatureVerified bool              `json:"publisher_signature_verified"`
}

type Bundle struct {
	Manifest Manifest
	Files    map[string][]byte
	Rules    []Rule
}

// Build preserves upstream disabled/deleted/retired rules, never rewrites an
// action, and excludes non-BSD or external/active capabilities. Dependencies
// may add eligible enabled setters outside the selected category, but cannot
// silently turn on a disabled rule or import a different license range.
func Build(source *Source, profile Profile) (*Bundle, error) {
	if source == nil || !digestPattern.MatchString(source.archiveSHA256) || fmt.Sprintf("%x", sha256.Sum256(source.license)) != licenseDigest || fmt.Sprintf("%x", sha256.Sum256(source.bsdLicense)) != bsdDigest || len(source.rules) == 0 || len(source.rules) > maxRules {
		return nil, errors.New("rule source has no reviewed closed inventory")
	}
	if len(profile.Categories) == 0 || len(profile.Categories) > 54 || len(profile.Variables) > 64 || profile.MaxEnabled < 1 || profile.MaxEnabled > 8192 {
		return nil, errors.New("explicit rule profile or resource budget invalid")
	}
	categories := map[string]bool{}
	knownCategories := map[string]bool{}
	for category := range source.categoryNames {
		knownCategories[category] = true
	}
	for _, category := range profile.Categories {
		if categories[category] || !knownCategories[category] || category == "emerging-deleted" || category == "emerging-retired" {
			return nil, errors.New("rule category duplicate, unknown or retired")
		}
		categories[category] = true
	}
	variables := map[string]bool{}
	for _, name := range profile.Variables {
		if !bitPattern.MatchString(name) || variables[name] {
			return nil, errors.New("rule variable profile ambiguous")
		}
		variables[name] = true
	}
	eligible := make([]bool, len(source.rules))
	reasons := make([]string, len(source.rules))
	setters := map[string][]int{}
	for i, rule := range source.rules {
		reason := rule.excluded
		if rule.SID < 2000000 || rule.SID > 2799999 {
			reason = "outside-reviewed-BSD-range"
		} else if rule.Disabled {
			reason = "upstream-disabled"
		} else if rule.Category == "emerging-deleted" || rule.Category == "emerging-retired" {
			reason = "retired-category"
		} else if rule.action != "alert" {
			reason = "non-passive-action"
		} else if reason == "" {
			for _, variable := range rule.variables {
				if !variables[variable] {
					reason = "undefined-native-variable"
					break
				}
			}
		}
		reasons[i] = reason
		if reason != "" {
			continue
		}
		eligible[i] = true
		for _, bit := range rule.sets {
			setters[bit] = append(setters[bit], i)
		}
	}
	// Queue-based pruning propagates missing setters without an O(N²) fixed-
	// point scan. Conservatively require every OR operand's producer to remain;
	// never report a partial OR dependency as full profile coverage.
	reverse := map[string][]int{}
	producerCounts := map[string]int{}
	for bit, list := range setters {
		producerCounts[bit] = len(list)
	}
	queue := []int{}
	for i, rule := range source.rules {
		if !eligible[i] {
			continue
		}
		missing := false
		for _, bit := range rule.needs {
			reverse[bit] = append(reverse[bit], i)
			if producerCounts[bit] == 0 {
				missing = true
			}
		}
		if missing {
			queue = append(queue, i)
		}
	}
	for head := 0; head < len(queue); head++ {
		i := queue[head]
		if !eligible[i] {
			continue
		}
		eligible[i] = false
		reasons[i] = "unresolved-state-dependency"
		for _, bit := range source.rules[i].sets {
			producerCounts[bit]--
			if producerCounts[bit] == 0 {
				queue = append(queue, reverse[bit]...)
			}
		}
	}
	selected := make([]bool, len(source.rules))
	// Reject dependency-only cycles too: having a nominal setter does not make
	// state reachable if every setter first requires that same unset state.
	reachable := make([]bool, len(source.rules))
	needed := make([]int, len(source.rules))
	bitQueue := []string{}
	bitReached := map[string]bool{}
	addBits := func(rule Rule) {
		for _, bit := range rule.sets {
			if !bitReached[bit] {
				bitReached[bit] = true
				bitQueue = append(bitQueue, bit)
			}
		}
	}
	for i, rule := range source.rules {
		if eligible[i] {
			needed[i] = len(rule.needs)
			if needed[i] == 0 {
				reachable[i] = true
				addBits(rule)
			}
		}
	}
	for head := 0; head < len(bitQueue); head++ {
		for _, i := range reverse[bitQueue[head]] {
			if eligible[i] && !reachable[i] {
				needed[i]--
				if needed[i] == 0 {
					reachable[i] = true
					addBits(source.rules[i])
				}
			}
		}
	}
	for i := range eligible {
		if eligible[i] && !reachable[i] {
			eligible[i] = false
			reasons[i] = "unreachable-state-dependency"
		}
	}
	selection := []int{}
	for i, rule := range source.rules {
		if eligible[i] && categories[rule.Category] {
			selected[i] = true
			selection = append(selection, i)
		}
	}
	for head := 0; head < len(selection); head++ {
		for _, bit := range source.rules[selection[head]].needs {
			for _, producer := range setters[bit] {
				if eligible[producer] && !selected[producer] {
					selected[producer] = true
					selection = append(selection, producer)
				}
			}
		}
	}
	if len(selection) == 0 || len(selection) > profile.MaxEnabled {
		return nil, errors.New("selected rule profile empty or above resource budget; not truncated")
	}
	bundle := &Bundle{Files: map[string][]byte{}, Manifest: Manifest{Format: 1, SourceURL: SourceURL, SourceSHA256: source.archiveSHA256, SourceBytes: source.archiveBytes, License: "BSD-3-Clause; reviewed ET SID range 2000000-2799999 only", EngineMajor: 8, Categories: append([]string(nil), profile.Categories...), SourceRuleCount: len(source.rules), Excluded: map[string]int{}, Files: map[string]string{}}}
	required := map[string]bool{}
	bundle.Manifest.RequiredVariables = []string{}
	for reason, count := range source.inactive {
		bundle.Manifest.Excluded[reason] = count
		bundle.Manifest.SourceRuleCount += count
	}
	for i, rule := range source.rules {
		if selected[i] {
			bundle.Rules = append(bundle.Rules, rule)
			for _, v := range rule.variables {
				required[v] = true
			}
			if !categories[rule.Category] {
				bundle.Manifest.DependencyRuleCount++
			}
		} else {
			reason := reasons[i]
			if reason == "" {
				reason = "unselected-category"
			}
			bundle.Manifest.Excluded[reason]++
		}
	}
	sort.Slice(bundle.Rules, func(i, j int) bool { return bundle.Rules[i].SID < bundle.Rules[j].SID })
	sort.Strings(bundle.Manifest.Categories)
	for v := range required {
		bundle.Manifest.RequiredVariables = append(bundle.Manifest.RequiredVariables, v)
	}
	sort.Strings(bundle.Manifest.RequiredVariables)
	var rules strings.Builder
	usedClasses := map[string]int{}
	usedReferences := map[string]bool{}
	rules.WriteString("# Reviewed ET Open BSD subset; see LICENSE and BSD-License.txt.\n# No publisher signature or native syntax proof is implied by this artifact.\n")
	for _, rule := range bundle.Rules {
		if rules.Len()+len(rule.Text)+1 > maxArtifact {
			return nil, errors.New("selected rule artifact exceeds 8 MiB; not truncated")
		}
		for _, system := range rule.references {
			if referencePrefixes[system] == "" {
				return nil, errors.New("selected rule reference system has no reviewed fixed mapping: " + system)
			}
			usedReferences[system] = true
		}
		if rule.classification != "" {
			priority := source.classifications[rule.classification]
			if priority == 0 {
				return nil, errors.New("selected rule has an undefined native classification")
			}
			usedClasses[rule.classification] = priority
		}
		rules.WriteString(rule.Text)
		rules.WriteByte('\n')
	}
	bundle.Manifest.EnabledRuleCount = len(bundle.Rules)
	bundle.Files["et-open.rules"] = []byte(rules.String())
	bundle.Files["LICENSE"] = append([]byte(nil), source.license...)
	bundle.Files["BSD-License.txt"] = append([]byte(nil), source.bsdLicense...)
	classNames := make([]string, 0, len(usedClasses))
	for name := range usedClasses {
		classNames = append(classNames, name)
	}
	sort.Strings(classNames)
	var classifications strings.Builder
	classifications.WriteString("# Generated labels; identifiers and priority facts from the reviewed source.\n")
	for _, name := range classNames {
		fmt.Fprintf(&classifications, "config classification: %s,IDS classification %s,%d\n", name, name, usedClasses[name])
	}
	bundle.Files["classification.config"] = []byte(classifications.String())
	referenceNames := make([]string, 0, len(usedReferences))
	for name := range usedReferences {
		referenceNames = append(referenceNames, name)
	}
	sort.Strings(referenceNames)
	var references strings.Builder
	references.WriteString("# Fixed informational reference prefixes; never fetched by this builder or engine.\n")
	for _, name := range referenceNames {
		fmt.Fprintf(&references, "config reference: %s %s\n", name, referencePrefixes[name])
	}
	bundle.Files["reference.config"] = []byte(references.String())
	for name, data := range bundle.Files {
		bundle.Manifest.Files[name] = fmt.Sprintf("%x", sha256.Sum256(data))
	}
	manifest, err := json.MarshalIndent(bundle.Manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	bundle.Files["manifest.json"] = append(manifest, '\n')
	return bundle, nil
}

// Reference identifiers and URL prefixes are factual mappings, not copied
// upstream descriptions. Legacy database links are retained as historical
// references only; this package performs no requests to these destinations.
var referencePrefixes = map[string]string{
	"url": "http://", "cve": "https://www.cve.org/CVERecord?id=CVE-",
	"md5": "https://www.virustotal.com/gui/file/", "sha1": "https://www.virustotal.com/gui/file/", "sha256": "https://www.virustotal.com/gui/file/",
	"bugtraq": "https://www.securityfocus.com/bid/", "bid": "https://www.securityfocus.com/bid/", "nessus": "https://www.tenable.com/plugins/nessus/", "osvdb": "http://osvdb.org/",
	"mcafee": "http://vil.nai.com/vil/content/v_", "arachnids": "http://www.whitehats.com/info/IDS", "msb": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/",
}
