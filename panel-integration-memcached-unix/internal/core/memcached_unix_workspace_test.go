package core

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"local/panel/internal/appcatalog"
)

func TestMemcachedUnixWorkspaceNativeRequestCannotBorrowWireOrIdentity(t *testing.T) {
	in := MemcachedUnixWorkspaceRequest{Format: 1, ProjectID: strings.Repeat("a", 32), ActorID: strings.Repeat("b", 32), Action: "cache", Cache: &MemcachedUnixCacheInput{Action: "get", KeyBase64: base64.StdEncoding.EncodeToString([]byte("binary\x00key\r\n"))}}
	raw, _ := json.Marshal(in)
	if got, err := DecodeMemcachedUnixWorkspaceRequest(raw); err != nil || got.ActorID != in.ActorID || got.Cache.KeyBase64 != in.Cache.KeyBase64 {
		t.Fatal("canonical request", err)
	}
	for _, kind := range []string{"duplicate", "alias", "extra", "actor", "null-cache", "missing-cache", "command", "native-path", "trailing", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			b := bytes.Clone(raw)
			switch kind {
			case "duplicate":
				b = append([]byte("{\"action\":\"inspect\","), b[1:]...)
			case "alias":
				b = bytes.Replace(b, []byte("\"actor_id\""), []byte("\"Actor_ID\""), 1)
			case "extra":
				b = append([]byte("{\"verified\":true,"), b[1:]...)
			case "actor":
				b = bytes.Replace(b, []byte(in.ActorID), []byte("root"), 1)
			case "null-cache":
				b, _ = json.Marshal(MemcachedUnixWorkspaceRequest{Format: 1, ProjectID: in.ProjectID, ActorID: in.ActorID, Action: "cache"})
			case "missing-cache":
				b = bytes.Replace(b, []byte("\"action\":\"cache\""), []byte("\"action\":\"inspect\""), 1)
			case "command":
				b = bytes.Replace(b, []byte("\"action\":\"get\""), []byte("\"action\":\"flush_all\""), 1)
			case "native-path":
				b = bytes.Replace(b, []byte("\"cache\":{"), []byte("\"cache\":{\"path\":\"/tmp/foreign\","), 1)
			case "trailing":
				b = append(b, '\n')
			case "oversize":
				b = bytes.Repeat([]byte(" "), MaxMemcachedUnixWorkspaceBytes+1)
			}
			if _, err := DecodeMemcachedUnixWorkspaceRequest(b); err == nil {
				t.Fatal("noncanonical native authority accepted", kind)
			}
		})
	}
}
func TestMemcachedUnixWorkspaceBrowserJSONIsClosedButNotOrderDependent(t *testing.T) {
	good := []string{
		"{\"action\":\"inspect\"}",
		" { \"cache\": { \"key_base64\":\"aw==\", \"action\":\"get\" }, \"action\":\"cache\" } ",
	}
	for _, raw := range good {
		if _, err := decodeMemcachedUnixWorkspaceInput([]byte(raw)); err != nil {
			t.Fatal("valid browser order/whitespace", err)
		}
	}
	for _, raw := range []string{
		"null", "[]", "{}", "{\"action\":null}", "{\"action\":\"inspect\",\"cache\":null}",
		"{\"action\":\"inspect\",\"action\":\"cache\"}", "{\"action\":\"inspect\",\"Action\":\"inspect\"}",
		"{\"Action\":\"inspect\"}", "{\"action\":\"inspect\",\"actor_id\":\"root\"}",
		"{\"action\":\"cache\",\"cache\":{\"action\":\"get\",\"key_base64\":\"aw==\",\"key_base64\":\"Yg==\"}}",
		"{\"action\":\"cache\",\"cache\":{\"action\":\"get\",\"Key_Base64\":\"aw==\"}}",
		"{\"action\":\"cache\",\"cache\":{\"action\":\"get\",\"key_base64\":null}}",
		"{\"action\":\"cache\",\"cache\":{\"action\":\"get\",\"pid\":1}}",
		"{\"action\":\"inspect\"}{}",
	} {
		if _, err := decodeMemcachedUnixWorkspaceInput([]byte(raw)); err == nil {
			t.Fatal("ambiguous browser object accepted", raw)
		}
	}
}
func TestMemcachedUnixWorkspaceHTTPUsesFreshAuthenticatedActorOneBoundedCallAndNoStorage(t *testing.T) {
	for _, kind := range []string{"inspect", "stopped", "cache-get", "cache-cas", "revoke", "scoped", "limited-menu", "viewer", "csrf", "extra-actor", "duplicate", "nested-duplicate", "alias", "query", "bad-project", "oversize", "root-fork", "root-unhealthy", "root-address", "root-resource", "root-version", "root-cache-action", "root-unknown", "root-error", "redirect"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			role := "admin"
			var menus []string
			if kind == "viewer" {
				role = "viewer"
			}
			if kind == "limited-menu" {
				menus = []string{"software"}
			}
			actor := accessUser(t, s, "workspace-admin", role, menus)
			token := Token()
			if _, err := s.DB.Exec("INSERT INTO sessions(token_hash,user_id,csrf,expires_at,last_activity_at) VALUES(?,?,?,?,?)", Hash(token), actor.ID, "workspace-csrf", time.Now().Add(time.Hour).Unix(), time.Now().Unix()); err != nil {
				t.Fatal(err)
			}
			project := strings.Repeat("a", 32)
			body := []byte("{\"action\":\"inspect\"}")
			out := MemcachedUnixWorkspace{Format: 1, ProjectID: project, Name: "own-cache", Version: appcatalog.MemcachedUnixVersion, State: "running", StateKnown: true, Healthy: true, CacheMB: 128, MemoryLimitMB: 192, ItemLimitMB: 4, EditorLimitBytes: MemcachedUnixConsoleValueBytes, NetworkMode: "none", RuntimeSHA256: strings.Repeat("c", 64)}
			directory, _ := MemcachedUnixDirectory(project, "")
			out.SocketPath = directory + "/cache.sock"
			want, calls := 200, 0
			switch kind {
			case "stopped":
				out.State = "stopped"
				out.Healthy = false
			case "cache-get", "cache-cas", "root-cache-action":
				cache := MemcachedUnixCacheInput{Action: "get", KeyBase64: "aw=="}
				if kind == "cache-cas" {
					cache.Action = "cas"
					cache.CAS = "18446744073709551615"
					cache.ValueBase64 = "dmFsdWUA"
					cache.TTLSeconds = 2
				}
				body, _ = json.Marshal(memcachedUnixWorkspaceInput{Action: "cache", Cache: &cache})
				out.Cache = &MemcachedUnixCacheResult{Action: cache.Action, TTLRemaining: -2}
				if kind == "root-cache-action" {
					out.Cache.Action = "delete"
					want = 409
				}
			case "revoke":
				s.DB.Exec("UPDATE app_user_roles SET role='viewer' WHERE user_id=?", actor.ID)
				want = 403
			case "scoped":
				s.DB.Exec("UPDATE app_user_roles SET site_ids=? WHERE user_id=?", "[\""+strings.Repeat("b", 32)+"\"]", actor.ID)
				want = 403
			case "limited-menu", "viewer", "csrf":
				want = 403
			case "extra-actor":
				body = []byte("{\"action\":\"inspect\",\"actor_id\":\"root\"}")
				want = 400
			case "duplicate":
				body = []byte("{\"action\":\"cache\",\"action\":\"inspect\"}")
				want = 400
			case "nested-duplicate":
				body = []byte("{\"action\":\"cache\",\"cache\":{\"action\":\"get\",\"key_base64\":\"aw==\",\"key_base64\":\"Yg==\"}}")
				want = 400
			case "alias":
				body = []byte("{\"Action\":\"inspect\"}")
				want = 400
			case "query", "bad-project":
				want = 404
			case "oversize":
				body = bytes.Repeat([]byte(" "), MaxMemcachedUnixWorkspaceBytes+1)
				want = 400
			case "root-fork":
				out.ProjectID = strings.Repeat("f", 32)
				want = 409
			case "root-unhealthy":
				out.Healthy = false
				want = 409
			case "root-address":
				out.SocketPath = "/tmp/foreign.sock"
				want = 409
			case "root-resource":
				out.MemoryLimitMB = 0
				want = 409
			case "root-version":
				out.Version = "1.6.45-compat2"
				want = 409
			case "root-unknown":
				out.StateKnown = false
				want = 409
			case "root-error", "redirect":
				want = 409
			}
			e := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodPost || r.URL.Path != "/v1/memcached-unix/projects/"+project+"/workspace" || r.Header.Get("Cookie") != "" {
					t.Error("workspace leaked credentials, redirected, or changed original route")
				}
				var transfer MemcachedUnixWorkspaceRequest
				if json.NewDecoder(r.Body).Decode(&transfer) != nil || transfer.ActorID != actor.ID || transfer.ProjectID != project || ValidateMemcachedUnixWorkspaceRequest(transfer) != nil {
					t.Error("authenticated actor not supplied by Core")
				}
				if kind == "root-error" {
					http.Error(w, "lost original response", 500)
					return
				}
				if kind == "redirect" {
					w.Header().Set("Location", "/unexpected-retry")
					w.WriteHeader(307)
					return
				}
				json.NewEncoder(w).Encode(out)
			})
			a := &Server{Store: s, Executor: e}
			mux := http.NewServeMux()
			a.memcachedUnixWorkspaceRoutes(mux)
			path := "/api/app-registry/memcached/instances/" + project + "/workspace"
			if kind == "query" {
				path += "?retry=true"
			}
			if kind == "bad-project" {
				path = "/api/app-registry/memcached/instances/not-an-id/workspace"
			}
			r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
			r.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: token})
			r.Header.Set("X-CSRF-Token", "workspace-csrf")
			if kind == "csrf" {
				r.Header.Set("X-CSRF-Token", "foreign")
			}
			before := memcachedStoreCounts(t, s)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != want || memcachedStoreCounts(t, s) != before {
				t.Fatal("unexpected permission/state/storage result", kind, w.Code, w.Body.String())
			}
			expectedCalls := 0
			if want == 200 || strings.HasPrefix(kind, "root-") || kind == "redirect" {
				expectedCalls = 1
			}
			if calls != expectedCalls {
				t.Fatal("workspace POST was retried or untrusted request reached Root", calls, expectedCalls)
			}
			if want == 200 && w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("cache values may be cached")
			}
		})
	}
}
