//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"local/panel/internal/core"
)

func lbAlertNativeRead(t *testing.T, s *Service, query string, want int) core.LoadBalanceAlertFeed {
	t.Helper()
	mux := http.NewServeMux()
	s.moduleAlertRoutes(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/v1/load-balance-alert-events"+query, nil))
	if w.Code != want {
		t.Fatal("unexpected feed status", w.Code, w.Body.String())
	}
	var feed core.LoadBalanceAlertFeed
	if want == 200 && json.Unmarshal(w.Body.Bytes(), &feed) != nil {
		t.Fatal("malformed alert feed")
	}
	return feed
}
func lbAlertNativeInstall(t *testing.T, s *Service, version string) {
	t.Helper()
	if err := moduleWrite(s.moduleDir("load-balance")+"/installed.json", map[string]any{"id": "load-balance", "version": version, "installed_at": core.Now(), "updated_at": core.Now(), "settings": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
}
func TestLoadBalanceAlertNativeReadUsesRealThresholdHistoryWithoutProbeOrMutation(t *testing.T) {
	var calls atomic.Int32
	s, in := lbHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(200)
		w.Write([]byte("READY-private-response"))
	})
	if old := lbAlertNativeRead(t, s, "", 200); old.Available || len(old.Entries) != 0 {
		t.Fatal("old implementation falsely advertises alerts")
	}
	lbAlertNativeInstall(t, s, "1.8.3")
	initial := lbAlertNativeRead(t, s, "", 200)
	if !initial.Available || len(initial.Entries) != 1 || initial.Entries[0].Sequence != 0 || len(initial.Entries[0].Transitions) != 0 || calls.Load() != 0 {
		t.Fatal("empty source was probed or invented")
	}
	if initial.Entries[0].ID != core.Hash("load-balance-alert-entry:" + in.Domain)[:32] {
		t.Fatal("unstable alert identity")
	}
	lbHTTPCheck(t, s, in)
	lbHTTPCheck(t, s, in)
	before, err := os.ReadFile(s.loadBalanceHealthPath(in.Domain))
	if err != nil {
		t.Fatal(err)
	}
	observed := calls.Load()
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		t.Error("read-only feed invoked system command")
		return "", nil
	}
	feed := lbAlertNativeRead(t, s, "", 200)
	if len(feed.Entries) != 1 || feed.Entries[0].Sequence != 2 || len(feed.Entries[0].Transitions) != 2 {
		t.Fatal("actual threshold history missing")
	}
	raw, _ := json.Marshal(feed)
	for _, private := range []string{in.Domain, in.Nodes[0].Address, in.Nodes[1].Address, "READY-private-response", "/ready", "body_contains", "ca_pem"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("feed leaked source evidence", private)
		}
	}
	after, err := os.ReadFile(s.loadBalanceHealthPath(in.Domain))
	if err != nil || !bytes.Equal(before, after) || calls.Load() != observed {
		t.Fatal("reading source changed records or probed")
	}
	restarted := New(s.Config)
	again := lbAlertNativeRead(t, restarted, "", 200)
	data, _ := json.Marshal(again)
	if !bytes.Equal(raw, data) {
		t.Fatal("restart lost canonical source identity")
	}
	lbAlertNativeRead(t, s, "?domain=arbitrary.example.test", 400)
}
func TestLoadBalanceAlertNativeRefusesUnknownInstalledIdentityAndUnsafeFiles(t *testing.T) {
	s, in := lbHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("READY")) })
	lbAlertNativeInstall(t, s, "1.8.3")
	lbHTTPCheck(t, s, in)
	path := s.loadBalanceHealthPath(in.Domain)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	lbAlertNativeRead(t, s, "", 409)
	current, err := os.ReadFile(path)
	info, e := os.Stat(path)
	if err != nil || e != nil || !bytes.Equal(original, current) || info.Mode().Perm() != 0644 {
		t.Fatal("unsafe source silently repaired")
	}
	// Restore only this owned fixture mode; production never performs this repair.
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	lbAlertNativeInstall(t, s, "1.8.5")
	lbAlertNativeRead(t, s, "", 409)
	lbAlertNativeInstall(t, s, "1.8.2")
	if feed := lbAlertNativeRead(t, s, "", 200); feed.Available {
		t.Fatal("historical version guessed new capability")
	}
	lbAlertNativeInstall(t, s, "1.8.3")
	if err = atomicWrite(path, []byte("corrupt-retained-fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	lbAlertNativeRead(t, s, "", 409)
	current, _ = os.ReadFile(path)
	if string(current) != "corrupt-retained-fixture\n" {
		t.Fatal("corrupt health evidence overwritten")
	}
}
func TestLoadBalanceAlertNativePendingConfigurationBlocksFeedWithoutRecovery(t *testing.T) {
	s, _ := lbHTTPFixture(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("READY")) })
	lbAlertNativeInstall(t, s, "1.8.3")
	path := s.loadBalancePendingPath()
	if err := atomicWrite(path, []byte("retained-pending-fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	lbAlertNativeRead(t, s, "", 409)
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "retained-pending-fixture\n" {
		t.Fatal("read recovered/deleted pending configuration")
	}
}
