package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMemcachedRegistryPreviewUsesLivePermissionAndNeverQueuesOrExposesExecutorErrors(t *testing.T) {
	for _, scenario := range []string{"ok", "no-session", "revoked-menu", "expired-session", "other-app", "invalid-project", "wrong-project-reply", "changed-reply", "executor-error", "post-is-not-update"} {
		t.Run(scenario, func(t *testing.T) {
			_, _, plan := memcachedPlanFixture(t)
			s := testStore(t)
			actor := accessUser(t, s, "plan-reader", "admin", []string{"runtimes"})
			token := Token()
			if _, err := s.DB.Exec(`INSERT INTO sessions(token_hash,user_id,csrf,expires_at,last_activity_at) VALUES(?,?,?,?,?)`, Hash(token), actor.ID, "fixture-csrf", time.Now().Add(time.Hour).Unix(), time.Now().Unix()); err != nil {
				t.Fatal(err)
			}
			calls := 0
			executor := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "GET" || r.URL.Path != "/v1/docker/projects/"+plan.ProjectID+"/app-update-plan" || r.URL.RawQuery != "" {
					t.Error("preview widened the native operation")
				}
				reply := plan
				if scenario == "executor-error" {
					w.WriteHeader(409)
					_, _ = w.Write([]byte(`{"error":"private-executor-do-not-reflect"}`))
					return
				}
				if scenario == "wrong-project-reply" {
					reply.ProjectID = strings.Repeat("f", 32)
				}
				if scenario == "changed-reply" {
					reply.HostPort++
				}
				_ = json.NewEncoder(w).Encode(reply)
			})
			a := &Server{Store: s, Executor: executor}
			mux := http.NewServeMux()
			a.memcachedRegistryPlanRoutes(mux)
			path := "/api/app-registry/memcached/instances/" + plan.ProjectID + "/update-plan"
			method := "GET"
			want := 200
			switch scenario {
			case "no-session":
				want = 401
			case "revoked-menu":
				if _, err := s.DB.Exec(`UPDATE app_user_menus SET menu_ids='[]',revision=revision+1 WHERE user_id=?`, actor.ID); err != nil {
					t.Fatal(err)
				}
				want = 403
			case "expired-session":
				if _, err := s.DB.Exec(`UPDATE sessions SET expires_at=1`); err != nil {
					t.Fatal(err)
				}
				want = 401
			case "other-app":
				path = strings.Replace(path, "/memcached/", "/mongodb/", 1)
				want = 404
			case "invalid-project":
				path = strings.Replace(path, plan.ProjectID, "not-a-project", 1)
				want = 404
			case "wrong-project-reply", "changed-reply", "executor-error":
				want = 409
			case "post-is-not-update":
				method = "POST"
				want = 405
			}
			before := installReplayCounts(t, s)
			r := httptest.NewRequest(method, path, nil)
			if scenario != "no-session" {
				r.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: token})
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != want || strings.Contains(w.Body.String(), "do-not-reflect") || !reflect.DeepEqual(before, installReplayCounts(t, s)) {
				t.Fatal("preview status, privacy or read-only contract", w.Code, w.Body.String())
			}
			if want == 200 {
				var out MemcachedUpdatePlan
				if json.Unmarshal(w.Body.Bytes(), &out) != nil || out != plan || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("unbound preview response")
				}
			}
			if want == 200 || scenario == "wrong-project-reply" || scenario == "changed-reply" || scenario == "executor-error" {
				if calls != 1 {
					t.Fatal("expected exactly one native read", calls)
				}
			} else if calls != 0 {
				t.Fatal("unauthorized or invalid request reached executor", calls)
			}
		})
	}
}

func TestMemcachedUpdatePlanTransportCannotBeChangedOrUsedAsAuthority(t *testing.T) {
	_, _, p := memcachedPlanFixture(t)
	if err := ValidateMemcachedUpdatePlan(p, p.ProjectID); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"project", "format", "app", "hash", "port", "runtime-hash", "cache-warning", "pinned-claim", "target"} {
		changed := p
		switch scenario {
		case "project":
			changed.ProjectID = strings.Repeat("1", 32)
		case "format":
			changed.Format = 2
		case "app":
			changed.AppID = "mongodb"
		case "hash":
			changed.ProjectSHA256 = strings.Repeat("2", 64)
		case "port":
			changed.HostPort++
		case "runtime-hash":
			changed.RuntimeConfigSHA256 = strings.Repeat("3", 64)
		case "cache-warning":
			changed.CacheMayBeCleared = false
		case "pinned-claim":
			changed.AlreadyPinned = true
		case "target":
			changed.TargetImage = "memcached:latest"
		}
		if ValidateMemcachedUpdatePlan(changed, p.ProjectID) == nil {
			t.Fatal("changed preview accepted", scenario)
		}
	}
}
