package rulefeed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

// VerifyBundle requires expectedManifestSHA256 from a separately verified
// signing authority, never directly from an untrusted browser request. It
// verifies closed data/capability/notice bindings, NOT native engine success,
// upstream publisher authenticity, freshness or installed-file ownership.
func VerifyBundle(ctx context.Context, files map[string][]byte, expectedManifestSHA256 string) (*Bundle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	expected := map[string]int{"manifest.json": 32 << 10, "LICENSE": 128 << 10, "BSD-License.txt": 128 << 10, "et-open.rules": maxArtifact, "classification.config": 128 << 10, "reference.config": 128 << 10}
	if len(files) != len(expected) || !digestPattern.MatchString(expectedManifestSHA256) {
		return nil, errors.New("rule artifact file set or trusted binding invalid")
	}
	for name, limit := range expected {
		data, ok := files[name]
		if !ok || len(data) == 0 || len(data) > limit || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
			return nil, errors.New("rule artifact missing, over budget or not text: " + name)
		}
	}
	if fmt.Sprintf("%x", sha256.Sum256(files["manifest.json"])) != expectedManifestSHA256 {
		return nil, errors.New("rule artifact manifest digest mismatch")
	}
	var manifest Manifest
	if err := decodeManifest(files["manifest.json"], &manifest); err != nil {
		return nil, err
	}
	if manifest.Format != 1 || manifest.EngineMajor != 8 || manifest.SourceURL != SourceURL || !digestPattern.MatchString(manifest.SourceSHA256) || manifest.SourceBytes < 1 || manifest.SourceBytes > maxCompressed || manifest.License != "BSD-3-Clause; reviewed ET SID range 2000000-2799999 only" || manifest.NativeSyntaxVerified || manifest.PublisherSignatureVerified {
		return nil, errors.New("rule artifact identity, license or proof scope invalid")
	}
	if manifest.SourceRuleCount < 1 || manifest.SourceRuleCount > maxInventory || manifest.EnabledRuleCount < 1 || manifest.EnabledRuleCount > 8192 || manifest.DependencyRuleCount < 0 || manifest.DependencyRuleCount > manifest.EnabledRuleCount || len(manifest.Categories) < 1 || len(manifest.Categories) > 54 || len(manifest.RequiredVariables) > 64 || len(manifest.Excluded) > 16 || len(manifest.Files) != len(expected)-1 {
		return nil, errors.New("rule artifact count or profile budget invalid")
	}
	seen := map[string]bool{}
	for _, category := range manifest.Categories {
		if !memberPattern.MatchString("rules/"+category+".rules") || seen[category] || category == "emerging-deleted" || category == "emerging-retired" {
			return nil, errors.New("rule artifact category invalid")
		}
		seen[category] = true
	}
	if !sort.StringsAreSorted(manifest.Categories) || !sort.StringsAreSorted(manifest.RequiredVariables) {
		return nil, errors.New("rule artifact profile not canonical")
	}
	allowedReasons := map[string]bool{"outside-reviewed-BSD-range": true, "upstream-disabled": true, "retired-category": true, "non-passive-action": true, "undefined-native-variable": true, "nonstandard-generator": true, "external-or-active-capability": true, "unsupported-state-dependency": true, "unsupported-flowbits": true, "unresolved-state-dependency": true, "unreachable-state-dependency": true, "unselected-category": true}
	total := manifest.EnabledRuleCount
	for reason, count := range manifest.Excluded {
		if !allowedReasons[reason] || count < 1 || count > maxInventory {
			return nil, errors.New("rule artifact exclusion summary invalid")
		}
		total += count
	}
	if total != manifest.SourceRuleCount {
		return nil, errors.New("rule artifact inventory accounting mismatch")
	}
	for name, limit := range expected {
		if name == "manifest.json" {
			continue
		}
		digest, ok := manifest.Files[name]
		if !ok || !digestPattern.MatchString(digest) || fmt.Sprintf("%x", sha256.Sum256(files[name])) != digest || len(files[name]) > limit {
			return nil, errors.New("rule artifact member binding mismatch: " + name)
		}
	}
	if manifest.Files["LICENSE"] != licenseDigest || manifest.Files["BSD-License.txt"] != bsdDigest {
		return nil, errors.New("rule artifact reviewed copyright notice changed")
	}
	classes, err := readClassificationsAllowEmpty(files["classification.config"])
	if err != nil {
		return nil, err
	}
	source := &Source{archiveSHA256: manifest.SourceSHA256, archiveBytes: manifest.SourceBytes, license: files["LICENSE"], bsdLicense: files["BSD-License.txt"], inactive: map[string]int{}, categoryNames: map[string]bool{}, classifications: classes}
	if err := readRules(ctx, "rules/selected.rules", files["et-open.rules"], source, map[uint32]bool{}); err != nil {
		return nil, err
	}
	if len(source.inactive) != 0 || len(source.rules) != manifest.EnabledRuleCount {
		return nil, errors.New("rule artifact has disabled or miscounted rules")
	}
	rebuilt, err := Build(source, Profile{Categories: []string{"selected"}, Variables: manifest.RequiredVariables, MaxEnabled: 8192})
	if err != nil {
		return nil, err
	}
	// Rebuilding proves passive BSD identities, reachable dependencies, canonical
	// SID ordering, the exact generated configuration set and variable coverage.
	for _, name := range []string{"et-open.rules", "classification.config", "reference.config"} {
		if !bytes.Equal(files[name], rebuilt.Files[name]) {
			return nil, errors.New("rule artifact contains noncanonical or excluded data: " + name)
		}
	}
	if strings.Join(rebuilt.Manifest.RequiredVariables, "\x00") != strings.Join(manifest.RequiredVariables, "\x00") {
		return nil, errors.New("rule artifact required variables do not match its rules")
	}
	closed := map[string][]byte{}
	for name, data := range files {
		closed[name] = append([]byte(nil), data...)
	}
	return &Bundle{Manifest: manifest, Files: closed, Rules: rebuilt.Rules}, nil
}

func readClassificationsAllowEmpty(data []byte) (map[string]int, error) {
	if bytes.Equal(data, []byte("# Generated labels; identifiers and priority facts from the reviewed source.\n")) {
		return map[string]int{}, nil
	}
	return readClassifications(data)
}

func decodeManifest(data []byte, out *Manifest) error {
	if len(data) > 32<<10 || !utf8.Valid(data) {
		return errors.New("rule manifest exceeds text budget")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 8 {
			return errors.New("rule manifest nesting exceeds budget")
		}
		token, err := decoder.Token()
		if err != nil || token == nil {
			return errors.New("rule manifest incomplete or contains null")
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				seen := map[string]bool{}
				for decoder.More() {
					key, err := decoder.Token()
					name, ok := key.(string)
					if err != nil || !ok || seen[strings.ToLower(name)] {
						return errors.New("rule manifest has duplicate or ambiguous keys")
					}
					seen[strings.ToLower(name)] = true
					if err := value(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				if depth == 0 {
					return errors.New("rule manifest root must be an object")
				}
				for decoder.More() {
					if err := value(depth + 1); err != nil {
						return err
					}
				}
			default:
				return errors.New("rule manifest unexpected delimiter")
			}
			end, err := decoder.Token()
			if err != nil || delimiter == '{' && end != json.Delim('}') || delimiter == '[' && end != json.Delim(']') {
				return errors.New("rule manifest container incomplete")
			}
		} else if depth == 0 {
			return errors.New("rule manifest root must be an object")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("rule manifest contains trailing data")
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}
	names := []string{"format", "source_url", "source_sha256", "source_bytes", "license", "engine_major", "categories", "required_variables", "source_rule_count", "enabled_rule_count", "dependency_rule_count", "excluded", "files_sha256", "native_syntax_verified", "publisher_signature_verified"}
	if len(keys) != len(names) {
		return errors.New("rule manifest field set incomplete or extended")
	}
	for _, name := range names {
		if _, ok := keys[name]; !ok {
			return errors.New("rule manifest field not canonical: " + name)
		}
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}
