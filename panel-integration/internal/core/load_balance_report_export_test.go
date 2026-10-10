package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func exportReceipt(t *testing.T, a *Server, u identity, action string, value any, now time.Time) LoadBalanceReportExportReceipt {
	t.Helper()
	out, ok := a.withLoadBalanceReportExport(u, action, value, now).(map[string]any)
	if !ok {
		t.Fatal("report was not an object")
	}
	receipt, ok := out["report_export"].(LoadBalanceReportExportReceipt)
	if !ok {
		t.Fatal("actual result did not receive a snapshot", out)
	}
	return receipt
}

func TestLoadBalanceReportExportSnapshotExactImmutableAndNotClientUploaded(t *testing.T) {
	a := &Server{}
	u := identity{ID: "admin-id", CSRF: "first-login"}
	now := time.Now()
	value := map[string]any{"entries": []any{map[string]any{"domain": "actual.example.test", "revision": uint64(9007199254740993)}}, "message": "actual <decoded> response"}
	receipt := exportReceipt(t, a, u, "run", value, now)
	entry := a.reportExports[receipt.ID]
	digest := sha256.Sum256(entry.Body)
	if receipt.Format != 1 || receipt.Module != "load-balance" || receipt.Action != "run" || !lowerHex(receipt.ID, 32) || receipt.SHA256 != hex.EncodeToString(digest[:]) || receipt.Bytes != len(entry.Body) || !entry.Expires.Equal(now.Add(loadBalanceExportTTL)) || !strings.HasSuffix(string(entry.Body), "\n") {
		t.Fatal("receipt does not bind actual response bytes", receipt)
	}
	if !strings.Contains(string(entry.Body), "9007199254740993") || strings.Contains(string(entry.Body), "report_export") {
		t.Fatal("snapshot rounded original integer or exported its own metadata", string(entry.Body))
	}
	value["message"] = "changed later"
	value["entries"].([]any)[0].(map[string]any)["domain"] = "other.example.test"
	second := exportReceipt(t, a, u, "run", value, now.Add(time.Second))
	if second.ID == receipt.ID || second.SHA256 == receipt.SHA256 || !bytes.Equal(entry.Body, a.reportExports[receipt.ID].Body) || strings.Contains(string(entry.Body), "changed later") {
		t.Fatal("later result replaced the original download")
	}
	if loadBalanceExportOwner(u) == loadBalanceExportOwner(identity{ID: u.ID, CSRF: "other-login"}) {
		t.Fatal("separate login sessions share downloads")
	}
	a.expireLoadBalanceExportsLocked(now.Add(loadBalanceExportTTL))
	if _, ok := a.reportExports[receipt.ID]; ok {
		t.Fatal("expiry boundary retained original ticket")
	}
}

func TestLoadBalanceReportExportSecretsInvalidStructureAndMissingIdentityRejected(t *testing.T) {
	u := identity{ID: "admin", CSRF: "session"}
	now := time.Now()
	deep := any("leaf")
	for i := 0; i < 20; i++ {
		deep = map[string]any{"child": deep}
	}
	values := []any{nil, []any{}, "document", deep, map[string]any{"padding": strings.Repeat("x", loadBalanceExportMaxBody)}, map[string]any{"report_export": map[string]any{"id": "client-invented"}}}
	for _, key := range []string{"token", "PASSWORD", "secret", "private_key", "remote_private_key", "environment", "environment_patch"} {
		values = append(values, map[string]any{"nested": []any{map[string]any{key: "private"}}})
	}
	for _, value := range values {
		a := &Server{}
		out := a.withLoadBalanceReportExport(u, "run", value, now)
		if len(a.reportExports) != 0 {
			t.Fatal("unsupported report minted snapshot", out)
		}
	}
	for _, test := range []struct {
		u      identity
		action string
	}{{identity{ID: "admin"}, "run"}, {identity{CSRF: "session"}, "run"}, {u, "shell"}, {u, "../run"}} {
		a := &Server{}
		a.withLoadBalanceReportExport(test.u, test.action, map[string]any{"entries": []any{}}, now)
		if len(a.reportExports) != 0 {
			t.Fatal("unbound identity/action accepted", test)
		}
	}
	for _, s := range []string{"", strings.Repeat("A", 32), strings.Repeat("g", 32), strings.Repeat("0", 31), "../" + strings.Repeat("a", 29), strings.Repeat(":", 32)} {
		if lowerHex(s, 32) {
			t.Fatal("unsafe identity accepted", s)
		}
	}
}

func TestLoadBalanceReportExportConcurrentSessionGlobalByteAndExpiryBudgets(t *testing.T) {
	a := &Server{}
	now := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 96; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := identity{ID: "admin", CSRF: "session-" + strconv.Itoa(i%6)}
			a.withLoadBalanceReportExport(u, "run", map[string]any{"counter": i}, now)
		}(i)
	}
	wg.Wait()
	a.reportExportMu.Lock()
	counts := map[string]int{}
	totalBytes := 0
	for _, entry := range a.reportExports {
		counts[entry.Owner]++
		totalBytes += len(entry.Body)
	}
	for _, count := range counts {
		if count > loadBalanceExportPerSession {
			t.Fatal("per-session cache unbounded", count)
		}
	}
	if len(a.reportExports) > loadBalanceExportMaxTickets || totalBytes != a.reportExportBytes || totalBytes > loadBalanceExportMaxBytes {
		t.Fatal("global cache unbounded", len(a.reportExports), totalBytes, a.reportExportBytes)
	}
	a.reportExportMu.Unlock()
	for i := 0; i < 24; i++ {
		exportReceipt(t, a, identity{ID: "admin", CSRF: "large-" + strconv.Itoa(i)}, "run", map[string]any{"padding": strings.Repeat("x", 700000)}, now.Add(time.Second))
	}
	if a.reportExportBytes > loadBalanceExportMaxBytes || len(a.reportExports) > loadBalanceExportMaxTickets {
		t.Fatal("large snapshots exceeded byte budget")
	}
	a.expireLoadBalanceExportsLocked(now.Add(loadBalanceExportTTL + time.Second))
	if len(a.reportExports) != 0 || a.reportExportBytes != 0 {
		t.Fatal("expired payloads retained", len(a.reportExports), a.reportExportBytes)
	}
}

func TestLoadBalanceReportExportHTTPAuthorizationReceiptExpiryAndNoExecutorOnDownload(t *testing.T) {
	store := testStore(t)
	master := accessUser(t, store, "lb-export-master", "", nil)
	other := accessUser(t, store, "lb-export-other", "", nil)
	viewer := accessUser(t, store, "lb-export-viewer", "viewer", nil)
	operator := accessUser(t, store, "lb-export-operator", "operator", nil)
	a, err := NewServer(store, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	marker := "original-actual-query"
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		body := `{"status":{"installed":true},"report":{"action":"run","result":{"entries":[],"marker":"` + marker + `"}}}`
		if r.Method == "POST" {
			body = `{"entries":[],"marker":"` + marker + `"}`
		} else if strings.Contains(r.URL.Path, "/history") {
			body = `{"events":[],"total":0,"limit":50,"offset":0}`
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	request := func(method, path, body, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.Config.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	login := func(name string) (*http.Cookie, string) {
		w := request("POST", "/api/login", `{"username":"`+name+`","password":"access-test-password-long"}`, "", nil)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var session accountSession
		if json.Unmarshal(w.Body.Bytes(), &session) != nil {
			t.Fatal("invalid session")
		}
		return w.Result().Cookies()[0], session.CSRF
	}
	admin, csrf := login(master.Username)
	parseReceipt := func(body []byte) LoadBalanceReportExportReceipt {
		var row struct {
			Receipt LoadBalanceReportExportReceipt `json:"report_export"`
		}
		if json.Unmarshal(body, &row) != nil || !lowerHex(row.Receipt.ID, 32) {
			t.Fatal("real HTTP result omitted snapshot", string(body))
		}
		return row.Receipt
	}
	w := request("POST", "/api/app-modules/load-balance/run", "{}", csrf, admin)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	receipt := parseReceipt(w.Body.Bytes())
	url := "/api/app-modules/load-balance/report-export/" + receipt.ID + "?sha256=" + receipt.SHA256
	before := calls
	download := request("GET", url, "", "", admin)
	digest := sha256.Sum256(download.Body.Bytes())
	if download.Code != 200 || calls != before || download.Header().Get("X-Content-SHA256") != receipt.SHA256 || receipt.SHA256 != hex.EncodeToString(digest[:]) || download.Header().Get("Content-Disposition") != `attachment; filename="load-balance-run-report.json"` || download.Header().Get("Content-Length") != strconv.Itoa(receipt.Bytes) || download.Header().Get("Cache-Control") != "no-store, private" || download.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(download.Body.String(), marker) || strings.Contains(download.Body.String(), "report_export") {
		t.Fatal("attachment does not bind the actual prior result", download.Code, download.Header(), download.Body.String())
	}
	marker = "later-query"
	if w := request("POST", "/api/app-modules/load-balance/run", "{}", csrf, admin); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if again := request("GET", url, "", "", admin); again.Code != 200 || !bytes.Equal(again.Body.Bytes(), download.Body.Bytes()) {
		t.Fatal("later query replaced a prior attachment")
	}
	w = request("GET", "/api/app-modules/load-balance", "", "", admin)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var module struct {
		Report struct {
			Result json.RawMessage `json:"result"`
		} `json:"report"`
	}
	if json.Unmarshal(w.Body.Bytes(), &module) != nil {
		t.Fatal("module report invalid")
	}
	parseReceipt(module.Report.Result)
	w = request("GET", "/api/app-modules/load-balance/history?limit=50&offset=0", "", "", admin)
	if w.Code != 200 || parseReceipt(w.Body.Bytes()).Action != "history" {
		t.Fatal("actual history export absent", w.Code, w.Body.String())
	}
	before = calls
	if got := request("POST", "/api/app-modules/load-balance/report-export", `{"entries":[],"report_export":{"id":"client-invented"}}`, csrf, admin); got.Code != 400 || calls != before {
		t.Fatal("client report upload created an export", got.Code)
	}
	foreign := httptest.NewRequest("GET", url, nil)
	foreign.AddCookie(admin)
	foreign.Header.Set("Origin", "https://foreign.invalid")
	denied := httptest.NewRecorder()
	a.ServeHTTP(denied, foreign)
	if denied.Code != 403 || calls != before {
		t.Fatal("foreign origin gained an attachment", denied.Code)
	}
	if head := request("HEAD", url, "", "", admin); head.Code != 200 || head.Header().Get("X-Content-SHA256") != receipt.SHA256 || calls != before {
		t.Fatal("authenticated HEAD changed or lost the snapshot", head.Code)
	}
	for _, test := range []struct {
		path   string
		status int
	}{{strings.Replace(url, receipt.SHA256, strings.Repeat("0", 64), 1), 409}, {url + "&sha256=" + receipt.SHA256, 400}, {url + "&path=/etc/shadow", 400}, {url + "&%zz", 400}, {strings.Replace(url, receipt.ID, strings.Repeat("A", 32), 1), 400}, {strings.Replace(url, "load-balance", "other", 1), 404}, {strings.Replace(url, receipt.ID, strings.Repeat("c", 32), 1), 410}} {
		if got := request("GET", test.path, "", "", admin); got.Code != test.status || calls != before {
			t.Fatal("closed attachment contract accepted wrong identity", test.path, got.Code, calls-before)
		}
	}
	if got := request("GET", url, "", "", nil); got.Code != 401 {
		t.Fatal("unauthenticated download", got.Code)
	}
	for _, name := range []string{viewer.Username, operator.Username, other.Username, master.Username} {
		cookie, _ := login(name)
		want := 403
		if name == other.Username || name == master.Username {
			want = 410
		}
		if got := request("GET", url, "", "", cookie); got.Code != want || calls != before {
			t.Fatal("another identity/session gained snapshot", name, got.Code, calls-before)
		}
	}
	if _, err = store.DB.Exec(`INSERT INTO app_user_menus(user_id,menu_ids,revision) VALUES(?,'["overview"]',1)`, master.ID); err != nil {
		t.Fatal(err)
	}
	if got := request("GET", url, "", "", admin); got.Code != 403 || calls != before {
		t.Fatal("menu revocation did not close old attachment", got.Code)
	}
	if _, err = store.DB.Exec(`DELETE FROM app_user_menus WHERE user_id=?`, master.ID); err != nil {
		t.Fatal(err)
	}
	a.reportExportMu.Lock()
	entry := a.reportExports[receipt.ID]
	entry.Expires = time.Now().Add(-time.Second)
	a.reportExports[receipt.ID] = entry
	a.reportExportMu.Unlock()
	if got := request("GET", url, "", "", admin); got.Code != 410 || calls != before {
		t.Fatal("expired attachment remained available", got.Code)
	}
	if got := request("POST", "/api/logout", "{}", csrf, admin); got.Code != 200 {
		t.Fatal("logout failed", got.Code)
	}
	if got := request("GET", url, "", "", admin); got.Code != 401 || calls != before {
		t.Fatal("logout did not invalidate attachment", got.Code)
	}
}
