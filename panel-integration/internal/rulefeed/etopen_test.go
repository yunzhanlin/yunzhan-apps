package rulefeed

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func notice(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func ruleLine(sid int, extra string) string {
	return fmt.Sprintf(`alert http any any -> $HOME_NET any (msg:"fixture\; sid:2800001\; lua:evil"; %s sid:%d; rev:1;)`, extra, sid)
}
func sourceFixture(t *testing.T, extras []*tar.Header, data []string) []byte {
	t.Helper()
	var raw bytes.Buffer
	writer := tar.NewWriter(&raw)
	for _, name := range []string{"LICENSE", "BSD-License.txt"} {
		body := notice(t, name)
		if err := writer.WriteHeader(&tar.Header{Name: "rules/" + name, Mode: 0644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		writer.Write(body)
	}
	for i, header := range extras {
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA {
			writer.Write([]byte(data[i]))
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var result bytes.Buffer
	compressed := gzip.NewWriter(&result)
	compressed.Write(raw.Bytes())
	compressed.Close()
	return result.Bytes()
}
func ruleMember(name, body string) (*tar.Header, string) {
	return &tar.Header{Name: "rules/" + name + ".rules", Mode: 0644, Typeflag: tar.TypeReg, Size: int64(len(body))}, body
}
func readFixture(t *testing.T, members map[string]string) *Source {
	t.Helper()
	headers := []*tar.Header{}
	data := []string{}
	for name, body := range members {
		h, d := ruleMember(name, body)
		headers = append(headers, h)
		data = append(data, d)
	}
	raw := sourceFixture(t, headers, data)
	source, err := ReadETOpen(context.Background(), bytes.NewReader(raw), fmt.Sprintf("%x", sha256.Sum256(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return source
}
func profile(categories ...string) Profile {
	return Profile{Categories: categories, Variables: []string{"HOME_NET"}, MaxEnabled: 128}
}

func TestRuleIdentityOutsideQuotesAndEscapes(t *testing.T) {
	for _, extra := range []string{`content:"sid:2800001\; lua:evil";`, `msg:"escaped quote \" and escaped semicolon \; sid:2800001";`, `pcre:"/sid:2800001\; lua:evil/";`, `pcre:"/^["']?post/Ri";`} {
		rule, err := parseRule(ruleLine(2000001, extra))
		if err != nil || rule.SID != 2000001 || rule.excluded != "" {
			t.Fatalf("literal text changed identity/capability: %+v %v", rule, err)
		}
	}
	for _, line := range []string{ruleLine(2000001, "sid:2800001;"), ruleLine(2000001, "rev:2;"), ruleLine(2000001, "gid:1;gid:1;"), strings.Replace(ruleLine(2000001, ""), "sid:2000001;", "sid:02000001;", 1), strings.Replace(ruleLine(2000001, ""), "sid:2000001;", "sid:0;", 1), `alert tcp any any -> any any (msg:"unterminated; sid:2000001;)`, `alert tcp any any -> any any (sid:2000001)`, ruleLine(2000001, string([]byte{0}))} {
		if _, err := parseRule(line); err == nil {
			t.Fatal("ambiguous identity accepted", line)
		}
	}
}

func TestReviewedLicenseAndBSDRangePreserved(t *testing.T) {
	source := readFixture(t, map[string]string{"emerging-web_server": ruleLine(2000001, "") + "\n" + ruleLine(2800001, "") + "\n" + ruleLine(123, "") + "\n"})
	bundle, err := Build(source, profile("emerging-web_server"))
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Rules) != 1 || bundle.Rules[0].SID != 2000001 || bundle.Manifest.Excluded["outside-reviewed-BSD-range"] != 2 || !bytes.Equal(bundle.Files["LICENSE"], notice(t, "LICENSE")) || !bytes.Equal(bundle.Files["BSD-License.txt"], notice(t, "BSD-License.txt")) {
		t.Fatal("license boundary or notice changed")
	}
	if bundle.Manifest.NativeSyntaxVerified || bundle.Manifest.PublisherSignatureVerified {
		t.Fatal("offline assembly falsely claims native/publisher proof")
	}
	for name, digest := range bundle.Manifest.Files {
		if fmt.Sprintf("%x", sha256.Sum256(bundle.Files[name])) != digest {
			t.Fatal("artifact binding mismatch", name)
		}
	}
	var manifest Manifest
	if err := json.Unmarshal(bundle.Files["manifest.json"], &manifest); err != nil || manifest.EnabledRuleCount != 1 {
		t.Fatal("manifest invalid", err)
	}
}

func TestRuleContainerRejectsDigestLicenseDuplicateAndLink(t *testing.T) {
	h, d := ruleMember("emerging-scan", ruleLine(2000001, ""))
	valid := sourceFixture(t, []*tar.Header{h}, []string{d})
	if _, err := ReadETOpen(context.Background(), bytes.NewReader(valid), strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong digest accepted")
	}
	if _, err := ReadETOpen(context.Background(), bytes.NewReader(valid), strings.ToUpper(fmt.Sprintf("%x", sha256.Sum256(valid)))); err == nil {
		t.Fatal("noncanonical binding accepted")
	}
	for _, header := range []*tar.Header{{Name: "rules/../evil.rules", Mode: 0644, Size: 1, Typeflag: tar.TypeReg}, {Name: "/rules/evil.rules", Mode: 0644, Size: 1, Typeflag: tar.TypeReg}, {Name: "rules/evil.rules", Mode: 0644, Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink}, {Name: "rules/evil.rules", Mode: 0644, Size: 1, Typeflag: tar.TypeReg, PAXRecords: map[string]string{"comment": "hidden"}}, {Name: "rules/LICENSE", Mode: 0644, Size: 1, Typeflag: tar.TypeReg}} {
		raw := sourceFixture(t, []*tar.Header{h, header}, []string{d, "x"})
		if _, err := ReadETOpen(context.Background(), bytes.NewReader(raw), fmt.Sprintf("%x", sha256.Sum256(raw))); err == nil {
			t.Fatal("unsafe member accepted", header.Name)
		}
	}
	raw := sourceFixture(t, []*tar.Header{h, h}, []string{d, d})
	if _, err := ReadETOpen(context.Background(), bytes.NewReader(raw), fmt.Sprintf("%x", sha256.Sum256(raw))); err == nil {
		t.Fatal("duplicate archive member accepted")
	}
	other, body := ruleMember("emerging-other", d)
	raw = sourceFixture(t, []*tar.Header{h, other}, []string{d, body})
	if _, err := ReadETOpen(context.Background(), bytes.NewReader(raw), fmt.Sprintf("%x", sha256.Sum256(raw))); err == nil {
		t.Fatal("duplicate SID accepted")
	}
	for _, raw := range [][]byte{append(append([]byte(nil), valid...), valid...), append(append([]byte(nil), valid...), 0), valid[:len(valid)-1]} {
		if _, err := ReadETOpen(context.Background(), bytes.NewReader(raw), fmt.Sprintf("%x", sha256.Sum256(raw))); err == nil {
			t.Fatal("gzip trailing/truncated source accepted")
		}
	}
}

func TestPassivePolicyDisabledRulesAndUnresolvedDependencies(t *testing.T) {
	lines := []string{ruleLine(2000001, ""), "# " + ruleLine(2000002, ""), ruleLine(2000003, "lua:evil.lua;"), ruleLine(2000004, "filestore;"), ruleLine(2000005, "dataset:isset,private;"), ruleLine(2000006, "xbits:isset,other,track ip_src;"), strings.Replace(ruleLine(2000007, ""), "alert ", "reject ", 1), ruleLine(2000008, "flowbits:isset,missing;"), ruleLine(2000009, "flowbits:isset,loop;flowbits:set,loop;"), strings.Replace(ruleLine(2000010, ""), "$HOME_NET", "$UNDEFINED", 1), ruleLine(2000011, "flowbits:isset,a||b;")}
	source := readFixture(t, map[string]string{"emerging-scan": strings.Join(lines, "\n")})
	bundle, err := Build(source, profile("emerging-scan"))
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Rules) != 1 || bundle.Rules[0].SID != 2000001 || bundle.Manifest.Excluded["upstream-disabled"] != 1 || bundle.Manifest.Excluded["unresolved-state-dependency"] != 1 || bundle.Manifest.Excluded["unreachable-state-dependency"] != 1 {
		t.Fatalf("unsafe/dead rule admitted: %+v", bundle.Manifest)
	}
}

func TestCrossCategoryDependenciesAreReachableAndDeterministic(t *testing.T) {
	source := readFixture(t, map[string]string{"emerging-target": ruleLine(2000003, "flowbits:isset,b;"), "emerging-support": ruleLine(2000001, "flowbits:set,a;flowbits:noalert;") + "\n" + ruleLine(2000002, "flowbits:isset,a;flowbits:set,b;")})
	bundle, err := Build(source, profile("emerging-target"))
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Rules) != 3 || bundle.Manifest.DependencyRuleCount != 2 {
		t.Fatal("cross-category dependency omitted")
	}
	for i, rule := range bundle.Rules {
		if rule.SID != uint32(2000001+i) {
			t.Fatal("nondeterministic SID order")
		}
	}
	second, err := Build(source, profile("emerging-target"))
	if err != nil || !bytes.Equal(second.Files["manifest.json"], bundle.Files["manifest.json"]) || !bytes.Equal(second.Files["et-open.rules"], bundle.Files["et-open.rules"]) {
		t.Fatal("unstable artifact")
	}
	for _, invalid := range []Profile{{MaxEnabled: 128}, {Categories: []string{"unknown"}, MaxEnabled: 128}, {Categories: []string{"emerging-target", "emerging-target"}, MaxEnabled: 128}, {Categories: []string{"emerging-target"}, Variables: []string{"HOME_NET"}, MaxEnabled: 2}} {
		if _, err := Build(source, invalid); err == nil {
			t.Fatal("empty/ambiguous/over-budget profile accepted", invalid)
		}
	}
}

func TestRuleSourceCancellationAndLineBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReadETOpen(ctx, bytes.NewReader(nil), strings.Repeat("0", 64)); err == nil {
		t.Fatal("cancelled source accepted")
	}
	h, d := ruleMember("emerging-scan", strings.Repeat("#", maxLine+1))
	raw := sourceFixture(t, []*tar.Header{h}, []string{d})
	if _, err := ReadETOpen(context.Background(), bytes.NewReader(raw), fmt.Sprintf("%x", sha256.Sum256(raw))); err == nil {
		t.Fatal("oversize line accepted")
	}
}

func TestInactiveMalformedTextCannotBlockOrBecomeDependency(t *testing.T) {
	broken := `alert tcp any any -> $HOME_NET any (pcre:"/broken"quote/";sid:2000009;)`
	source := readFixture(t, map[string]string{"emerging-deleted": "# " + broken, "emerging-retired": broken, "emerging-target": ruleLine(2000001, "") + "\n# " + broken + "\n# " + ruleLine(2000002, "flowbits:set,disabled;") + "\n" + ruleLine(2000003, "flowbits:isset,disabled;")})
	bundle, err := Build(source, profile("emerging-target"))
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Rules) != 1 || bundle.Manifest.Excluded["upstream-disabled"] != 2 || bundle.Manifest.Excluded["retired-category"] != 2 || bundle.Manifest.Excluded["unresolved-state-dependency"] != 1 || bundle.Manifest.SourceRuleCount != 6 {
		t.Fatal("inactive rule text treated as active", bundle.Manifest)
	}
}

func TestNativeCaseInsensitiveKeywordPolicyCannotBeBypassed(t *testing.T) {
	line := strings.ReplaceAll(ruleLine(2000001, "Content:\"literal\";"), "sid:", "SID:")
	rule, err := parseRule(line)
	if err != nil || rule.SID != 2000001 {
		t.Fatal("native case-insensitive syntax rejected", err)
	}
	source := readFixture(t, map[string]string{"emerging-target": line + "\n" + ruleLine(2000002, "LuA:evil.lua;") + "\n" + strings.ReplaceAll(ruleLine(2000003, ""), "alert ", "REJECT ")})
	bundle, err := Build(source, profile("emerging-target"))
	if err != nil || len(bundle.Rules) != 1 || bundle.Manifest.Excluded["external-or-active-capability"] != 1 || bundle.Manifest.Excluded["non-passive-action"] != 1 {
		t.Fatal("case-insensitive unsafe keyword/action admitted", err)
	}
}

func TestClassificationFactsPreservePrioritiesWithoutCopyingDescriptions(t *testing.T) {
	classes, err := readClassifications([]byte("# source notice\nconfig classification: attempted-recon,Source description not redistributed,2\n"))
	if err != nil || classes["attempted-recon"] != 2 {
		t.Fatal("classification priority not parsed", err)
	}
	source := readFixture(t, map[string]string{"emerging-target": ruleLine(2000001, "classtype:attempted-recon;")})
	source.classifications = classes
	bundle, err := Build(source, profile("emerging-target"))
	if err != nil || !strings.Contains(string(bundle.Files["classification.config"]), "attempted-recon,IDS classification attempted-recon,2") || bytes.Contains(bundle.Files["classification.config"], []byte("Source description")) {
		t.Fatal("classification semantics or notice derivation wrong", err)
	}
	source.classifications = nil
	if _, err := Build(source, profile("emerging-target")); err == nil {
		t.Fatal("missing native classification ignored")
	}
	for _, bad := range []string{"config classification: same,x,1\nconfig classification: same,x,2", "config classification: name,x,0", "config classification: name,x,01", "config classification: name,x,5", "include: /etc/passwd", "config classification: name,x,y,2"} {
		if _, err := readClassifications([]byte(bad)); err == nil {
			t.Fatal("invalid classification accepted")
		}
	}
}

func TestReferenceMappingsAreFixedBoundAndNeverInvented(t *testing.T) {
	source := readFixture(t, map[string]string{"emerging-target": ruleLine(2000001, "reference:url,owned-fixture.invalid;reference:cve,2026-1234;reference:md5,00000000000000000000000000000000;")})
	bundle, err := Build(source, profile("emerging-target"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mapping := range []string{"config reference: url http://", "config reference: cve https://www.cve.org/CVERecord?id=CVE-", "config reference: md5 https://www.virustotal.com/gui/file/"} {
		if !strings.Contains(string(bundle.Files["reference.config"]), mapping) {
			t.Fatal("missing reference mapping")
		}
	}
	source = readFixture(t, map[string]string{"emerging-target": ruleLine(2000001, "reference:unreviewed,anything;")})
	if _, err := Build(source, profile("emerging-target")); err == nil {
		t.Fatal("unknown reference silently invented or ignored")
	}
}
