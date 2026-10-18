package core

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func wafInventoryCoreFixture() WAFBackupInventory {
	return WAFBackupInventory{Available: true, Entries: []WAFBackupInventoryRow{{ID: strings.Repeat("1", 32), CreatedAt: "2026-10-11T00:00:00Z", Files: 5, Bytes: 123, SHA: strings.Repeat("a", 64)}}, Bytes: 123, CountMax: 100, ScanMax: 128 << 20, ReadOnly: true, Message: "verified fixture, not native inventory"}
}

func TestWAFBackupInventoryDecodeClosedBoundedDTO(t *testing.T) {
	value := wafInventoryCoreFixture()
	raw, _ := json.Marshal(value)
	out, err := DecodeWAFBackupInventory(raw)
	if err != nil || out.Bytes != 123 || len(out.Entries) != 1 || out.Message == value.Message {
		t.Fatal("closed DTO", out, err)
	}
	for _, change := range []func(*WAFBackupInventory){
		func(v *WAFBackupInventory) { v.Available = false }, func(v *WAFBackupInventory) { v.ReadOnly = false }, func(v *WAFBackupInventory) { v.CountMax = 101 }, func(v *WAFBackupInventory) { v.ScanMax++ }, func(v *WAFBackupInventory) { v.Bytes++ }, func(v *WAFBackupInventory) { v.Entries[0].Files = 4 }, func(v *WAFBackupInventory) { v.Entries[0].SHA = strings.Repeat("A", 64) }, func(v *WAFBackupInventory) { v.Entries[0].CreatedAt = "bad" }, func(v *WAFBackupInventory) { v.Entries = append(v.Entries, v.Entries[0]); v.Bytes *= 2 }, func(v *WAFBackupInventory) { v.Message = strings.Repeat("x", 1025) },
	} {
		v := wafInventoryCoreFixture()
		change(&v)
		bad, _ := json.Marshal(v)
		if _, err := DecodeWAFBackupInventory(bad); err == nil {
			t.Fatal("invalid bound accepted", string(bad))
		}
	}
	for _, bad := range []string{
		strings.Replace(string(raw), `"available":true`, `"available":null`, 1),
		strings.Replace(string(raw), `"bytes":123`, `"bytes":null`, 1),
		strings.Replace(string(raw), `"files":5`, `"files":null`, 1),
		strings.Replace(string(raw), `"available":true`, `"Available":true`, 1),
		strings.Replace(string(raw), `"available":true`, `"available":true,"available":true`, 1),
		strings.Replace(string(raw), `"files":5`, `"files":5,"fi\u006ces":5`, 1),
		strings.Replace(string(raw), `"files":5`, `"files":5,"source":"/private"`, 1),
		`{"secret":"private",` + string(raw[1:]), string(raw) + ` {}`,
	} {
		if _, err := DecodeWAFBackupInventory([]byte(bad)); err == nil {
			t.Fatal("ambiguous DTO accepted", bad)
		}
	}
	value.Available = false
	value.Entries = []WAFBackupInventoryRow{}
	value.Bytes = 0
	raw, _ = json.Marshal(value)
	if out, err := DecodeWAFBackupInventory(raw); err != nil || out.Available || !strings.Contains(out.Message, "未宣称库存为空") {
		t.Fatal("unavailable != empty", out, err)
	}
}

func TestWAFBackupInventoryActualAuthorizationAndNoOtherAuthority(t *testing.T) {
	s, a, login := wafTaskTestServer(t)
	calls := 0
	value := wafInventoryCoreFixture()
	raw, _ := json.Marshal(value)
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/v1/software/nginx-waf/config-backups" || r.URL.RawQuery != "" || r.Body != nil {
			t.Fatal("unexpected executor authority", r.Method, r.URL)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(raw))), Request: r}, nil
	})}}
	path := "/api/software/nginx-waf/config-backups"
	if w := wafTaskTestRead(a, path, nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	for _, user := range []string{"audit-admin", "runtime-admin", "reader", "operator"} {
		if w := wafTaskTestRead(a, path, login(user)); w.Code != 403 {
			t.Fatal("authorization expanded", user, w.Code)
		}
	}
	if calls != 0 {
		t.Fatal("denied user reached executor")
	}
	cookie := login("waf-admin")
	for _, query := range []string{"?", "?path=/etc/shadow", "?page=1&page=2"} {
		if w := wafTaskTestRead(a, path+query, cookie); w.Code != 400 {
			t.Fatal("unknown query", w.Code)
		}
	}
	if calls != 0 {
		t.Fatal("invalid query reached executor")
	}
	var beforeJobs, beforeAudit int
	if err := s.DB.QueryRow(`SELECT count(*) FROM runtime_jobs`).Scan(&beforeJobs); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(`SELECT count(*) FROM audit_logs`).Scan(&beforeAudit); err != nil {
		t.Fatal(err)
	}
	w := wafTaskTestRead(a, path, cookie)
	var out WAFBackupInventory
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Bytes != 123 || calls != 1 {
		t.Fatal("actual scoped read", w.Code)
	}
	for _, global := range []string{"/api/sites", "/api/jobs/" + ID(), "/api/sites/" + ID() + "/files"} {
		if w := wafTaskTestRead(a, global, cookie); w.Code != 403 {
			t.Fatal("broader access granted", global, w.Code)
		}
	}
	var afterJobs, afterAudit int
	if err := s.DB.QueryRow(`SELECT count(*) FROM runtime_jobs`).Scan(&afterJobs); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(`SELECT count(*) FROM audit_logs`).Scan(&afterAudit); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual([]int{beforeJobs, beforeAudit}, []int{afterJobs, afterAudit}) {
		t.Fatal("GET mutated tasks or audit")
	}
}

func TestWAFBackupInventoryNeverRelaysUnverifiedOrPrivateExecutorResponse(t *testing.T) {
	_, a, login := wafTaskTestServer(t)
	cookie := login("waf-admin")
	value := wafInventoryCoreFixture()
	raw, _ := json.Marshal(value)
	for _, test := range []struct {
		body    string
		status  int
		failure error
	}{
		{`{"error":"/private/config secret SQL"}`, 409, nil},
		{`{"secret":"/private/config",` + string(raw[1:]), 200, nil},
		{strings.Replace(string(raw), `"bytes":123`, `"bytes":124`, 1), 200, nil},
		{"", 0, errors.New("private socket/path")},
	} {
		a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if test.failure != nil {
				return nil, test.failure
			}
			return &http.Response{StatusCode: test.status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(test.body)), Request: r}, nil
		})}}
		w := wafTaskTestRead(a, "/api/software/nginx-waf/config-backups", cookie)
		if w.Code != 503 || strings.Contains(w.Body.String(), "/private") || strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), `"entries"`) {
			t.Fatal("unverified/private response relayed", w.Code, w.Body.String())
		}
	}
}

func TestWAFBackupSnapshotClosedMetadataAndFixedActualAuthorization(t *testing.T) {
	_, a, login := wafTaskTestServer(t)
	row := wafInventoryCoreFixture().Entries[0]
	raw, _ := json.Marshal(row)
	if got, err := DecodeWAFBackupSnapshot(raw); err != nil || !reflect.DeepEqual(got, row) {
		t.Fatal(got, err)
	}
	calls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/v1/software/nginx-waf/config-backups/"+row.ID || r.URL.RawQuery != "" || r.Body != nil {
			t.Fatal("unreviewed snapshot authority", r.URL)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(raw))), Request: r}, nil
	})}}
	path := "/api/software/nginx-waf/config-backups/" + row.ID
	if w := wafTaskTestRead(a, path, nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	for _, name := range []string{"audit-admin", "runtime-admin", "reader", "operator"} {
		if w := wafTaskTestRead(a, path, login(name)); w.Code != 403 {
			t.Fatal(name, w.Code)
		}
	}
	cookie := login("waf-admin")
	for _, bad := range []string{path + "?", path + "?source=/etc/shadow", "/api/software/nginx-waf/config-backups/BAD"} {
		if w := wafTaskTestRead(a, bad, cookie); w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	if calls != 0 {
		t.Fatal("unauthorized or invalid read reached executor")
	}
	w := wafTaskTestRead(a, path, cookie)
	var got WAFBackupInventoryRow
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(w.Body.Bytes(), &got) != nil || !reflect.DeepEqual(got, row) || calls != 1 || strings.Contains(w.Body.String(), "available") || strings.Contains(w.Body.String(), "entries") {
		t.Fatal("selected row presented as whole inventory", w.Code, w.Body.String())
	}
	for _, bad := range []string{string(raw) + " {}", strings.Replace(string(raw), `"files":5`, `"files":5,"source":"/private"`, 1), strings.Replace(string(raw), `"files":5`, `"files":null`, 1), strings.Replace(string(raw), `"files":5`, `"files":5,"fi\u006ces":5`, 1), strings.Replace(string(raw), row.ID, strings.Repeat("2", 32), 1)} {
		raw = []byte(bad)
		w := wafTaskTestRead(a, path, cookie)
		if w.Code != 503 || strings.Contains(w.Body.String(), "/private") || strings.Contains(w.Body.String(), `"id"`) {
			t.Fatal("private, ambiguous or wrong snapshot relayed", w.Code, w.Body.String())
		}
	}
}
