//go:build linux

package executor

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestAnalyticsHTMLLoadedProbeRejectsStaleUnknownOversizedOrCookieReplies(t *testing.T) {
	// Linux Unix paths are bounded to 108 bytes; Go's descriptive TempDir
	// names can exceed that limit. This short private root is fixture-owned.
	root, err := os.MkdirTemp(os.TempDir(), "ahp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	s := New(Config{SystemRoot: root})
	socket := s.systemPath(analyticsHTMLHealthSocket)
	if err := s.wafOwnedDirectory(filepath.Dir(socket), true); err != nil {
		t.Fatal(err)
	}
	identity := analyticsHTMLEngineIdentity{JobID: core.ID(), ProgramSHA: analyticsHTMLProgramSHA}
	body := fmt.Sprintf(`{"protocol":"yunzhan-analytics-html-v1","job_id":"%s","program_sha256":"%s"}`, identity.JobID, identity.ProgramSHA)
	for _, tc := range []struct {
		name, body string
		cookie     bool
		code       int
		want       bool
	}{
		{"current", body, false, 200, true},
		{"stale", strings.Replace(body, identity.JobID, core.ID(), 1), false, 200, false},
		{"program", strings.Replace(body, identity.ProgramSHA, strings.Repeat("a", 64), 1), false, 200, false},
		{"unknown", strings.TrimSuffix(body, "}") + `,"untrusted":true}`, false, 200, false},
		{"oversized", body + strings.Repeat(" ", 1100), false, 200, false},
		{"cookie", body, true, 200, false}, {"error", body, false, 503, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/health" || r.Method != "GET" || r.Header.Get("Cookie") != "" {
					t.Error("nonfixed probe request")
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				if tc.cookie {
					w.Header().Set("Set-Cookie", "not-allowed")
				}
				w.WriteHeader(tc.code)
				fmt.Fprint(w, tc.body)
			})}
			go server.Serve(listener)
			err = s.probeAnalyticsHTMLLoaded(context.Background(), identity)
			server.Close()
			listener.Close()
			if (err == nil) != tc.want {
				t.Fatal("loaded fingerprint result", err)
			}
		})
	}
	absent, err := s.analyticsHTMLListenerAbsent(context.Background())
	if err != nil || !absent {
		t.Fatal("removed socket still loaded", err)
	}
	if err := os.Symlink("/tmp/unknown", socket); err != nil {
		t.Fatal(err)
	}
	if s.probeAnalyticsHTMLLoaded(context.Background(), identity) == nil {
		t.Fatal("symlink substituted for owned socket")
	}
}
