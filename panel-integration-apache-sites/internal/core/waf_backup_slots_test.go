package core

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestWAFBackupSlotsNeverClaimContentVerificationAndRetainAuthorization(t *testing.T) {
	value := WAFBackupSlots{Available: true, IDs: []string{strings.Repeat("1", 32)}, CountMax: 100, ReadOnly: true, ContentsVerified: false, Message: "closed fixture"}
	raw, _ := json.Marshal(value)
	out, err := DecodeWAFBackupSlots(raw)
	if err != nil || !out.Available || out.ContentsVerified || len(out.IDs) != 1 || !strings.Contains(out.Message, "尚未核验") {
		t.Fatal(out, err)
	}
	for _, bad := range []string{
		strings.Replace(string(raw), `"contents_verified":false`, `"contents_verified":true`, 1),
		strings.Replace(string(raw), `"available":true`, `"available":null`, 1),
		strings.Replace(string(raw), `"ids":["`+value.IDs[0]+`"]`, `"ids":null`, 1),
		strings.Replace(string(raw), `"count_max":100`, `"count_max":101`, 1),
		strings.Replace(string(raw), `"available":true`, `"available":true,"available":true`, 1),
		strings.Replace(string(raw), `"message":`, `"source":"/private","message":`, 1),
	} {
		if _, err := DecodeWAFBackupSlots([]byte(bad)); err == nil {
			t.Fatal("unreviewed slot shape accepted", bad)
		}
	}
	_, a, login := wafTaskTestServer(t)
	calls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/v1/software/nginx-waf/config-backup-slots" || r.URL.RawQuery != "" || r.Body != nil {
			t.Fatal("wrong metadata authority", r.URL)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(raw))), Request: r}, nil
	})}}
	path := "/api/software/nginx-waf/config-backup-slots"
	if w := wafTaskTestRead(a, path, nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	for _, user := range []string{"audit-admin", "runtime-admin", "reader", "operator"} {
		if w := wafTaskTestRead(a, path, login(user)); w.Code != 403 {
			t.Fatal(user, w.Code)
		}
	}
	cookie := login("waf-admin")
	for _, query := range []string{"?", "?page=1", "?path=/etc/shadow"} {
		if w := wafTaskTestRead(a, path+query, cookie); w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	if calls != 0 {
		t.Fatal("denied or malformed metadata request reached executor")
	}
	w := wafTaskTestRead(a, path, cookie)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), `"entries"`) || !strings.Contains(w.Body.String(), `"contents_verified":false`) {
		t.Fatal("slots became a content verified inventory", w.Code, w.Body.String())
	}
	raw = []byte(strings.Replace(string(raw), `"contents_verified":false`, `"contents_verified":true`, 1))
	w = wafTaskTestRead(a, path, cookie)
	if w.Code != 503 || strings.Contains(w.Body.String(), `"ids"`) {
		t.Fatal("unverified metadata relayed", w.Code, w.Body.String())
	}
}
