//go:build linux

package executor

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestMemcachedUnixWorkspaceInvalidTransportNeverTouchesOriginalNamespace(t *testing.T) {
	for _, kind := range []string{"invalid-project", "query", "unsigned", "duplicate", "alias", "extra", "foreign-project", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			project := strings.Repeat("a", 32)
			raw := []byte("{\"format\":1,\"project_id\":\"" + project + "\",\"actor_id\":\"" + strings.Repeat("b", 32) + "\",\"action\":\"inspect\"}")
			path := "/v1/memcached-unix/projects/" + project + "/workspace"
			want := 400
			switch kind {
			case "invalid-project":
				path = "/v1/memcached-unix/projects/no/workspace"
				want = 404
			case "query":
				path += "?retry=true"
				want = 404
			case "unsigned":
				want = 409
			case "duplicate":
				raw = append([]byte("{\"format\":1,"), raw[1:]...)
			case "alias":
				raw = bytes.Replace(raw, []byte("\"actor_id\""), []byte("\"Actor_ID\""), 1)
			case "extra":
				raw = append([]byte("{\"verified\":true,"), raw[1:]...)
			case "foreign-project":
				raw = bytes.Replace(raw, []byte(project), []byte(strings.Repeat("c", 32)), 1)
			case "oversize":
				raw = bytes.Repeat([]byte(" "), core.MaxMemcachedUnixWorkspaceBytes+1)
			}
			before, be := os.Lstat(memcachedUnixInstallJobsRoot)
			mux := http.NewServeMux()
			New(Config{}).memcachedUnixWorkspaceRoutes(mux)
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw)))
			after, ae := os.Lstat(memcachedUnixInstallJobsRoot)
			if response.Code != want || os.IsNotExist(be) != os.IsNotExist(ae) || be == nil && (ae != nil || !geoStoreStableInfo(before, after)) {
				t.Fatal("workspace transport changed installation state", kind, response.Code, response.Body.String())
			}
		})
	}
	for _, ctx := range []context.Context{nil, func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }()} {
		if _, err := runMemcachedUnixWorkspace(ctx, core.MemcachedUnixWorkspaceRequest{}); err == nil {
			t.Fatal("invalid context became mutation authority")
		}
	}
}
