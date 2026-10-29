//go:build linux

package executor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestCountryTaskDispatchControllerCallsNativeStartAtMostOnceAfterDurableIntent(t *testing.T) {
	s, request, _, dir := countryTaskPreparedFixture(t)
	calls := 0
	start := func(ctx context.Context, id string) error {
		calls++
		marker, err := countryTaskReadDispatch(dir.Root, request)
		if err != nil || marker.JobID != id || marker.RequestSHA != countryTaskRequestDigest(request) {
			t.Fatal("native start preceded durable whole-request intent", marker, err)
		}
		return errors.New("explicit lost native start acknowledgement fixture")
	}
	if err := dispatchWAFCountryOriginal(context.Background(), s, request, countryFixtureBoot, start); err == nil || calls != 1 {
		t.Fatal("original unknown start disappeared", calls, err)
	}
	before, err := dir.Lstat("dispatch.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, boot := range []string{countryFixtureBoot, "11234567-89ab-cdef-0123-456789abcdef"} {
		if err := dispatchWAFCountryOriginal(context.Background(), s, request, boot, start); err != nil || calls != 1 {
			t.Fatal("lost acknowledgement/reboot repeated native start", calls, err)
		}
	}
	after, err := dir.Lstat("dispatch.json")
	if err != nil || !geoStoreStableInfo(before, after) {
		t.Fatal("read-only old dispatch changed its immutable identity")
	}
}

func TestCountryTaskDispatchCrashCancelledAndRevokedOriginalNeverStartReplacement(t *testing.T) {
	for _, kind := range []string{"after-intent", "cancelled", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			s, request, _, _ := countryTaskPreparedFixture(t)
			calls := 0
			start := func(context.Context, string) error { calls++; return nil }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "after-intent":
				s.fault = func(point string) error {
					if point == "after-dispatch-write" {
						return errors.New("explicit crash after durable intent")
					}
					return nil
				}
			case "cancelled":
				cancel()
			case "revoked":
				s.guard = func() error { return errors.New("explicit revoked actor fixture") }
			}
			if err := dispatchWAFCountryOriginal(ctx, s, request, countryFixtureBoot, start); err == nil || calls != 0 {
				t.Fatal("interrupted/cancelled/revoked dispatch started a worker", calls, err)
			}
			if kind == "after-intent" {
				s.fault = nil
				if err := dispatchWAFCountryOriginal(ctx, s, request, countryFixtureBoot, start); err != nil || calls != 0 {
					t.Fatal("original after-intent interruption automatically replayed", calls, err)
				}
			}
		})
	}
}

func TestCountryTaskUnitPolicyRejectsUnknownOverridesReloadsAndInventedIdleState(t *testing.T) {
	id := core.ID()
	good := "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nFragmentPath=/etc/systemd/system/panel-waf-country@.service\nDropInPaths=\nTransient=no\nNeedDaemonReload=no\n"
	if !countryTaskLoadedPolicy(good, id) {
		t.Fatal("complete closed unit policy rejected")
	}
	for _, bad := range []string{"", good + "LoadState=loaded\n", good + "Unknown=no\n", strings.Replace(good, "ActiveState=inactive", "ActiveState=active", 1), strings.Replace(good, "MainPID=0", "MainPID=2", 1), strings.Replace(good, "SubState=dead", "SubState=running", 1), strings.Replace(good, "DropInPaths=\n", "DropInPaths=/etc/systemd/system/panel-waf-country@.service.d/custom.conf\n", 1), strings.Replace(good, "Transient=no", "Transient=yes", 1), strings.Replace(good, "NeedDaemonReload=no", "NeedDaemonReload=yes", 1), strings.Replace(good, "/etc/systemd/system/", "/run/systemd/system/", 1), strings.Replace(good, "DropInPaths=\n", "", 1)} {
		if countryTaskLoadedPolicy(bad, id) {
			t.Fatal("unknown/overridden/running native unit was accepted", bad)
		}
	}
}

func TestCountryUnitTemplateMatchesCompiledFixedSupervisor(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "dev", "panel-waf-country@.service"))
	if err != nil || string(raw) != countryTaskUnitBody {
		t.Fatal("release template differs from independently checked compiled source", err)
	}
}

func TestCountryTaskHTTPRejectsMalformedInputBeforeHostReadsOrAnyExecution(t *testing.T) {
	s := New(Config{SystemRoot: t.TempDir(), SecurityDir: filepath.Join(t.TempDir(), "untouched")})
	mux := http.NewServeMux()
	s.wafCountryRoutes(mux)
	id := core.ID()
	for _, request := range []struct{ method, path, body string }{
		{"GET", "/v1/waf/country?source=anything", ""},
		{"GET", "/v1/waf/country/jobs/" + id, ""},
		{"GET", "/v1/waf/country/jobs/" + id + "?actor_id=" + core.ID() + "&actor_id=" + core.ID() + "&payload_sha256=" + core.Hash("test"), ""},
		{"POST", "/v1/waf/country/jobs/not-an-id", "{}"},
		{"POST", "/v1/waf/country/jobs/" + id + "?source=anything", "{}"},
		{"POST", "/v1/waf/country/jobs/" + id, "{}"},
		{"POST", "/v1/waf/country/jobs/" + id, `{"actor_id":"` + core.ID() + `","actor_id":"` + core.ID() + `"}`},
	} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(request.method, request.path, strings.NewReader(request.body)))
		if w.Code != 400 {
			t.Fatal("malformed country request reached host work", request.method, request.path, w.Code, w.Body.String())
		}
	}
	if _, err := os.Lstat(s.Config.SecurityDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid request initialized/changed security state", err)
	}
}
