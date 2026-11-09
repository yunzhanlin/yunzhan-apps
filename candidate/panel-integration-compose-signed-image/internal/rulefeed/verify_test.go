package rulefeed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func verificationFixture(t *testing.T) *Bundle {
	t.Helper()
	source := readFixture(t, map[string]string{"emerging-fixture": ruleLine(2000001, "reference:url,own.invalid;") + "\n" + ruleLine(2000002, "flowbits:set,own;flowbits:noalert;") + "\n" + ruleLine(2000003, "flowbits:isset,own;")})
	bundle, err := Build(source, profile("emerging-fixture"))
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}
func bindFiles(t *testing.T, files map[string][]byte, manifest Manifest) string {
	t.Helper()
	for name := range manifest.Files {
		manifest.Files[name] = fmt.Sprintf("%x", sha256.Sum256(files[name]))
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	files["manifest.json"] = append(data, '\n')
	return fmt.Sprintf("%x", sha256.Sum256(files["manifest.json"]))
}

func TestClosedArtifactVerificationCopiesAndDoesNotCertifyNative(t *testing.T) {
	built := verificationFixture(t)
	digest := fmt.Sprintf("%x", sha256.Sum256(built.Files["manifest.json"]))
	verified, err := VerifyBundle(context.Background(), built.Files, digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(verified.Rules) != 3 || verified.Manifest.NativeSyntaxVerified || verified.Manifest.PublisherSignatureVerified {
		t.Fatal("wrong proof scope")
	}
	old := append([]byte(nil), verified.Files["et-open.rules"]...)
	built.Files["et-open.rules"][0] = 'x'
	if !bytes.Equal(old, verified.Files["et-open.rules"]) {
		t.Fatal("verified files alias mutable inputs")
	}
}

func TestClosedArtifactRejectsExtraMissingUnboundAndChangedLicense(t *testing.T) {
	for _, scenario := range []string{"extra", "missing", "wrong-binding", "changed-member", "changed-notice"} {
		t.Run(scenario, func(t *testing.T) {
			bundle := verificationFixture(t)
			digest := fmt.Sprintf("%x", sha256.Sum256(bundle.Files["manifest.json"]))
			switch scenario {
			case "extra":
				bundle.Files["run.sh"] = []byte("must never execute")
			case "missing":
				delete(bundle.Files, "reference.config")
			case "wrong-binding":
				digest = strings.Repeat("0", 64)
			case "changed-member":
				bundle.Files["et-open.rules"] = append(bundle.Files["et-open.rules"], byte('\n'))
			case "changed-notice":
				bundle.Files["LICENSE"] = bytes.Replace(bundle.Files["LICENSE"], []byte("2003-2026"), []byte("2003-2025"), 1)
				digest = bindFiles(t, bundle.Files, bundle.Manifest)
			}
			if _, err := VerifyBundle(context.Background(), bundle.Files, digest); err == nil {
				t.Fatal("open or unreviewed artifact accepted")
			}
		})
	}
}

func TestClosedArtifactRejectsAmbiguousManifestEvenWithMatchingDigest(t *testing.T) {
	for _, scenario := range []string{"duplicate", "case-shadow", "escaped-key", "null-array", "null-member", "noncanonical-case", "unknown-field", "trailing", "wrong-total", "fake-native", "fake-upstream-signature", "duplicate-variable", "retired-category", "unknown-exclusion"} {
		t.Run(scenario, func(t *testing.T) {
			bundle := verificationFixture(t)
			data := bundle.Files["manifest.json"]
			manifest := bundle.Manifest
			switch scenario {
			case "duplicate":
				data = bytes.Replace(data, []byte(`"format": 1`), []byte(`"format": 1,"format": 1`), 1)
			case "case-shadow":
				data = bytes.Replace(data, []byte(`"format": 1`), []byte(`"format": 1,"FORMAT": 1`), 1)
			case "escaped-key":
				data = bytes.Replace(data, []byte(`"format": 1`), []byte(`"format": 1,"\u0066ormat": 1`), 1)
			case "null-array":
				data = bytes.Replace(data, []byte("\"required_variables\": [\n    \"HOME_NET\"\n  ]"), []byte(`"required_variables":null`), 1)
			case "null-member":
				data = bytes.Replace(data, []byte(`"native_syntax_verified": false`), []byte(`"native_syntax_verified":null`), 1)
			case "noncanonical-case":
				data = bytes.Replace(data, []byte(`"format"`), []byte(`"Format"`), 1)
			case "unknown-field":
				data = bytes.Replace(data, []byte(`"format": 1`), []byte(`"format": 1,"run":"unreviewed"`), 1)
			case "trailing":
				data = append(data, []byte("{}")...)
			case "wrong-total":
				manifest.SourceRuleCount++
				bindFiles(t, bundle.Files, manifest)
				data = bundle.Files["manifest.json"]
			case "fake-native":
				manifest.NativeSyntaxVerified = true
				bindFiles(t, bundle.Files, manifest)
				data = bundle.Files["manifest.json"]
			case "fake-upstream-signature":
				manifest.PublisherSignatureVerified = true
				bindFiles(t, bundle.Files, manifest)
				data = bundle.Files["manifest.json"]
			case "duplicate-variable":
				manifest.RequiredVariables = []string{"HOME_NET", "HOME_NET"}
				bindFiles(t, bundle.Files, manifest)
				data = bundle.Files["manifest.json"]
			case "retired-category":
				manifest.Categories = []string{"emerging-retired"}
				bindFiles(t, bundle.Files, manifest)
				data = bundle.Files["manifest.json"]
			case "unknown-exclusion":
				manifest.Excluded["silently-dropped"] = 1
				manifest.SourceRuleCount++
				bindFiles(t, bundle.Files, manifest)
				data = bundle.Files["manifest.json"]
			}
			bundle.Files["manifest.json"] = data
			digest := fmt.Sprintf("%x", sha256.Sum256(data))
			if _, err := VerifyBundle(context.Background(), bundle.Files, digest); err == nil {
				t.Fatal("ambiguous manifest accepted", scenario)
			}
		})
	}
}

func TestClosedArtifactRechecksNativeCapabilitiesAndStateGraph(t *testing.T) {
	for _, scenario := range []string{"active-action", "non-BSD", "file-reader", "disabled", "missing-state", "missing-variable", "noncanonical-reference", "noncanonical-classification", "wrong-rule-count", "duplicate-SID"} {
		t.Run(scenario, func(t *testing.T) {
			bundle := verificationFixture(t)
			rules := bundle.Files["et-open.rules"]
			switch scenario {
			case "active-action":
				rules = bytes.Replace(rules, []byte("alert http"), []byte("reject http"), 1)
			case "non-BSD":
				rules = bytes.Replace(rules, []byte("sid:2000001"), []byte("sid:2800001"), 1)
			case "file-reader":
				rules = bytes.Replace(rules, []byte("sid:2000001"), []byte("filesha256:/etc/passwd;sid:2000001"), 1)
			case "disabled":
				rules = bytes.Replace(rules, []byte("alert http"), []byte("# alert http"), 1)
			case "missing-state":
				rules = bytes.Replace(rules, []byte("flowbits:set,own"), []byte("flowbits:set,different"), 1)
			case "missing-variable":
				bundle.Manifest.RequiredVariables = []string{}
			case "noncanonical-reference":
				bundle.Files["reference.config"] = append(bundle.Files["reference.config"], []byte("config reference: private https://own.invalid/\n")...)
			case "noncanonical-classification":
				bundle.Files["classification.config"] = append(bundle.Files["classification.config"], []byte("config classification: extra,External display text,3\n")...)
			case "wrong-rule-count":
				bundle.Manifest.EnabledRuleCount++
				bundle.Manifest.SourceRuleCount++
			case "duplicate-SID":
				rules = bytes.Replace(rules, []byte("sid:2000002"), []byte("sid:2000001"), 1)
			}
			bundle.Files["et-open.rules"] = rules
			digest := bindFiles(t, bundle.Files, bundle.Manifest)
			if _, err := VerifyBundle(context.Background(), bundle.Files, digest); err == nil {
				t.Fatal("rebound unsafe data accepted", scenario)
			}
		})
	}
}
