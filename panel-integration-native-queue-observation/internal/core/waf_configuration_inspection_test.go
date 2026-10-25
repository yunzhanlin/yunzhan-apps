package core

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func wafInspectionFixture() WAFConfigurationInspection {
	return WAFConfigurationInspection{Format: 1, ReadOnly: true, InstalledVersion: "2.0.1", PolicyRevision: "11", SemanticRecordSHA: strings.Repeat("a", 64), Differences: []WAFConfigurationDifference{{Scope: "http-rules", ActualExists: true, ExpectedExists: true, ActualSHA: strings.Repeat("b", 64), ExpectedSHA: strings.Repeat("c", 64), ActualMode: 0640, ExpectedMode: 0640, ActualBytes: 10, ExpectedBytes: 20}}}
}
func TestWAFConfigurationInspectionClosedCompleteMetadataOnly(t *testing.T) {
	v := wafInspectionFixture()
	raw, _ := json.Marshal(v)
	if got, err := DecodeWAFConfigurationInspection(raw); err != nil || !reflect.DeepEqual(got, v) {
		t.Fatal(got, err)
	}
	for _, change := range []func(*WAFConfigurationInspection){
		func(v *WAFConfigurationInspection) { v.Format = 2 }, func(v *WAFConfigurationInspection) { v.ReadOnly = false }, func(v *WAFConfigurationInspection) { v.EnforcementVerified = true }, func(v *WAFConfigurationInspection) { v.FilesystemMatches = true }, func(v *WAFConfigurationInspection) { v.InstalledVersion = "2.5.3" }, func(v *WAFConfigurationInspection) { v.PolicyRevision = "-1" }, func(v *WAFConfigurationInspection) { v.SemanticRecordSHA = strings.Repeat("A", 64) }, func(v *WAFConfigurationInspection) { v.Differences = nil }, func(v *WAFConfigurationInspection) { v.Differences = append(v.Differences, v.Differences[0]) }, func(v *WAFConfigurationInspection) { v.Differences[0].Scope = "/etc/shadow" }, func(v *WAFConfigurationInspection) { v.Differences[0].SiteID = ID() }, func(v *WAFConfigurationInspection) { v.Differences[0].ActualMode = 04777 }, func(v *WAFConfigurationInspection) { v.Differences[0].ExpectedSHA = v.Differences[0].ActualSHA }, func(v *WAFConfigurationInspection) { v.Differences[0].ActualExists = false }, func(v *WAFConfigurationInspection) { v.Differences[0].ExpectedBytes = 8 << 20 }, func(v *WAFConfigurationInspection) {
			v.Differences[0].Scope = "site"
			v.Differences[0].SiteID = "../other"
		},
	} {
		x := wafInspectionFixture()
		change(&x)
		b, _ := json.Marshal(x)
		if _, err := DecodeWAFConfigurationInspection(b); err == nil {
			t.Fatal("hostile metadata accepted", string(b))
		}
	}
	for _, bad := range []string{string(raw) + " {}", strings.Replace(string(raw), `"read_only":true`, `"read_only":null`, 1), strings.Replace(string(raw), `"read_only":true`, `"Read_only":true`, 1), strings.Replace(string(raw), `"read_only":true`, `"read_only":true,"read_only":true`, 1), strings.Replace(string(raw), `"scope":"http-rules"`, `"scope":"http-rules","content":"secret"`, 1), strings.Replace(string(raw), `"actual_exists":true`, `"actual_exists":true,"actual\u005fexists":true`, 1)} {
		if _, err := DecodeWAFConfigurationInspection([]byte(bad)); err == nil {
			t.Fatal("ambiguous response", bad)
		}
	}
	v.Differences = []WAFConfigurationDifference{}
	v.FilesystemMatches = true
	raw, _ = json.Marshal(v)
	if got, err := DecodeWAFConfigurationInspection(raw); err != nil || !got.FilesystemMatches || got.EnforcementVerified {
		t.Fatal("matching bytes are not enforcement", got, err)
	}
}
func TestWAFConfigurationInspectionActualCoreAuthorityAndNoQueue(t *testing.T) {
	store, a, login := wafTaskTestServer(t)
	calls := 0
	value := wafInspectionFixture()
	raw, _ := json.Marshal(value)
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/v1/software/nginx-waf/config-inspection" || r.URL.RawQuery != "" || r.Body != nil {
			t.Fatal("new authority", r.Method, r.URL)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(raw))), Request: r}, nil
	})}}
	route := "/api/software/nginx-waf/config-inspection"
	if w := wafTaskTestRead(a, route, nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	for _, user := range []string{"audit-admin", "runtime-admin", "reader", "operator"} {
		if w := wafTaskTestRead(a, route, login(user)); w.Code != 403 {
			t.Fatal(user, w.Code)
		}
	}
	if calls != 0 {
		t.Fatal("denied user reached executor")
	}
	cookie := login("waf-admin")
	before := replayCounts(t, store)
	for _, q := range []string{"?", "?path=/etc/shadow", "?version=2.5.2", "?repair=1"} {
		if w := wafTaskTestRead(a, route+q, cookie); w.Code != 400 {
			t.Fatal("query accepted", q, w.Code)
		}
	}
	if calls != 0 {
		t.Fatal("query reached executor")
	}
	w := wafTaskTestRead(a, route, cookie)
	var got WAFConfigurationInspection
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(w.Body.Bytes(), &got) != nil || !reflect.DeepEqual(got, value) || calls != 1 {
		t.Fatal("actual inspection", w.Code, w.Body.String())
	}
	raw = []byte(`{"read_only":true,"content":"unreviewed private output"}`)
	if w := wafTaskTestRead(a, route, cookie); w.Code != 503 || strings.Contains(w.Body.String(), "private output") {
		t.Fatal("unclosed response relayed", w.Code, w.Body.String())
	}
	if after := replayCounts(t, store); !reflect.DeepEqual(before, after) {
		t.Fatal("GET created authority or tasks", before, after)
	}
}
