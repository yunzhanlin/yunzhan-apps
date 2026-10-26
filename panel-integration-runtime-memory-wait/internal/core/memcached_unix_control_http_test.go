package core

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestMemcachedUnixControlClosureDoesNotReplayDaemonAndRetainsOriginalIdentity(t *testing.T) {
	s, actor, op := memcachedUnixControlFixture(t)
	if _, _, err := s.reserveMemcachedUnixControl(t.Context(), op); err != nil {
		t.Fatal(err)
	}
	if s.finishMemcachedUnixControl(t.Context(), op, nil) != nil {
		t.Fatal("original unknown fixture")
	}
	token := Token()
	if _, err := s.DB.Exec("INSERT INTO sessions(token_hash,user_id,csrf,expires_at,last_activity_at) VALUES(?,?,?,?,?)", Hash(token), actor.ID, "control-csrf", time.Now().Add(time.Hour).Unix(), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	calls := 0
	e := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/memcached-unix/projects/"+op.ProjectID+"/controls/"+op.RequestID+"/close" {
			t.Error("closure invoked a daemon action")
		}
		var original MemcachedUnixControlOperation
		if json.NewDecoder(r.Body).Decode(&original) != nil || original != op {
			t.Error("closure changed original actor or input")
		}
		json.NewEncoder(w).Encode(MemcachedUnixControlResult{Format: 1, RequestID: op.RequestID, ProjectID: op.ProjectID, OperationSHA256: MemcachedUnixControlSHA(op), State: "refused"})
	})
	a := &Server{Store: s, Executor: e}
	mux := http.NewServeMux()
	a.memcachedUnixControlRoutes(mux)
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest(http.MethodPost, "/api/app-registry/memcached/instances/"+op.ProjectID+"/controls/"+op.RequestID+"/close", strings.NewReader("{}"))
		r.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: token})
		r.Header.Set("X-CSRF-Token", "control-csrf")
		out := httptest.NewRecorder()
		mux.ServeHTTP(out, r)
		if out.Code != 200 {
			t.Fatal(out.Code, out.Body.String())
		}
	}
	if calls != 1 {
		t.Fatal("terminal closure was reissued", calls)
	}
	row, fresh, err := s.reserveMemcachedUnixControl(t.Context(), op)
	if err != nil || fresh || row.Result == nil || row.Result.State != "refused" {
		t.Fatal("late original command can be requeued", err)
	}
}
func TestMemcachedUnixInstallJobObserverBindsActualOwnerVersionAndOriginalReadOnlyRoute(t *testing.T) {
	s, actor, original, item := memcachedUnixStoreFixture(t)
	token := Token()
	if _, err := s.DB.Exec("INSERT INTO sessions(token_hash,user_id,csrf,expires_at,last_activity_at) VALUES(?,?,?,?,?)", Hash(token), actor.ID, "control-csrf", time.Now().Add(time.Hour).Unix(), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	calls := 0
	e := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet || r.URL.Path != "/v1/docker/memcached-unix/installs/"+original.JobID {
			t.Error("observer borrowed old TCP mutation or wrong original")
		}
		json.NewEncoder(w).Encode(DockerJobResult{JobID: original.JobID, ProjectID: original.ProjectID, Kind: "compose", State: "succeeded"})
	})
	a := &Server{Store: s, Executor: e}
	mux := http.NewServeMux()
	a.memcachedUnixControlRoutes(mux)
	before := installReplayCounts(t, s)
	r := httptest.NewRequest(http.MethodGet, "/api/app-registry/memcached/installs/"+original.JobID, nil)
	r.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: token})
	out := httptest.NewRecorder()
	mux.ServeHTTP(out, r)
	var result registryRequestOutcome
	if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &result) != nil || !result.StateKnown || result.State != "succeeded" || result.JobID != original.JobID || result.Version != item.Version || calls != 1 {
		t.Fatal("original installation observer", out.Code, out.Body.String())
	}
	after := installReplayCounts(t, s)
	if !slices.Equal(before, after) {
		t.Fatal("read-only installation query changed receipt, job or request state")
	}
}

func TestMemcachedUnixControlHTTPNeverRepostsOriginalUnknownOrCompleted(t *testing.T) {
	for _, kind := range []string{"fresh", "native-refused", "lost-response", "forked-response", "native-unknown", "original-reserved", "original-unknown", "original-completed", "changed-original", "bad-ack", "duplicate", "alias", "extra-actor", "csrf", "query", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			s, actor, op := memcachedUnixControlFixture(t)
			ctx := t.Context()
			token := Token()
			if _, err := s.DB.Exec("INSERT INTO sessions(token_hash,user_id,csrf,expires_at,last_activity_at) VALUES(?,?,?,?,?)", Hash(token), actor.ID, "control-csrf", time.Now().Add(time.Hour).Unix(), time.Now().Unix()); err != nil {
				t.Fatal(err)
			}
			result := MemcachedUnixControlResult{Format: 1, RequestID: op.RequestID, ProjectID: op.ProjectID, OperationSHA256: MemcachedUnixControlSHA(op), State: "completed", FinalState: "stopped", RuntimeSHA256: strings.Repeat("b", 64)}
			want, calls := 200, 0
			if strings.HasPrefix(kind, "original-") || kind == "changed-original" {
				if _, _, err := s.reserveMemcachedUnixControl(ctx, op); err != nil {
					t.Fatal(err)
				}
				if kind == "original-unknown" {
					if s.finishMemcachedUnixControl(ctx, op, nil) != nil {
						t.Fatal("unknown fixture")
					}
				}
				if kind == "original-completed" {
					if s.finishMemcachedUnixControl(ctx, op, &result) != nil {
						t.Fatal("terminal fixture")
					}
				}
			}
			in := op.Input
			switch kind {
			case "native-refused":
				result.State = "refused"
				result.FinalState = ""
				result.RuntimeSHA256 = ""
			case "lost-response", "forked-response", "native-unknown":
				want = 202
			case "changed-original":
				in.Action = "restart"
				want = 409
			case "bad-ack":
				in.AcknowledgeCacheLoss = false
				want = 400
			case "duplicate", "alias", "extra-actor":
				want = 400
			case "csrf":
				want = 403
			case "query":
				want = 404
			case "revoked":
				s.DB.Exec("UPDATE app_user_roles SET role='viewer' WHERE user_id=?", actor.ID)
				want = 403
			}
			e := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodPost || r.URL.Path != "/v1/memcached-unix/projects/"+op.ProjectID+"/controls/"+op.RequestID || r.Header.Get("Cookie") != "" {
					t.Error("incorrect/redirected original Root control route")
				}
				var received MemcachedUnixControlOperation
				if json.NewDecoder(r.Body).Decode(&received) != nil || received != op {
					t.Error("Core borrowed caller actor or changed original")
				}
				if kind == "lost-response" {
					http.Error(w, "unknown", 500)
					return
				}
				if kind == "forked-response" {
					result.OperationSHA256 = strings.Repeat("f", 64)
				}
				if kind == "native-unknown" {
					result.State = "unknown"
					result.FinalState = ""
					result.RuntimeSHA256 = ""
				}
				json.NewEncoder(w).Encode(result)
			})
			a := &Server{Store: s, Executor: e}
			mux := http.NewServeMux()
			a.memcachedUnixControlRoutes(mux)
			body, _ := json.Marshal(in)
			switch kind {
			case "duplicate":
				body = append([]byte("{\"action\":\"start\","), body[1:]...)
			case "alias":
				body = bytes.Replace(body, []byte("\"action\""), []byte("\"Action\""), 1)
			case "extra-actor":
				body = append([]byte("{\"actor_id\":\"root\","), body[1:]...)
			}
			path := "/api/app-registry/memcached/instances/" + op.ProjectID + "/controls"
			if kind == "query" {
				path += "?retry=true"
			}
			r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
			r.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: token})
			r.Header.Set("X-CSRF-Token", "control-csrf")
			r.Header.Set("Idempotency-Key", op.RequestID)
			if kind == "csrf" {
				r.Header.Set("X-CSRF-Token", "foreign")
			}
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, r)
			if response.Code != want {
				t.Fatal(kind, response.Code, response.Body.String())
			}
			expected := 0
			switch kind {
			case "fresh", "native-refused", "lost-response", "forked-response", "native-unknown":
				expected = 1
			}
			if calls != expected {
				t.Fatal("Root mutation was reissued", calls, expected)
			}
			if expected == 1 {
				row, found, err := s.memcachedUnixControlForActor(ctx, actor.ID, op.RequestID)
				if err != nil || !found || want == 202 && row.State != "unknown" || want == 200 && row.State != "completed" {
					t.Fatal("first native outcome lost", err, row.State)
				}
			}
		})
	}
}
func TestMemcachedUnixControlObserverUsesGETOnlyForTheSameOriginalOperation(t *testing.T) {
	s, actor, op := memcachedUnixControlFixture(t)
	ctx := t.Context()
	if _, _, err := s.reserveMemcachedUnixControl(ctx, op); err != nil {
		t.Fatal(err)
	}
	if s.finishMemcachedUnixControl(ctx, op, nil) != nil {
		t.Fatal("original unknown")
	}
	token := Token()
	if _, err := s.DB.Exec("INSERT INTO sessions(token_hash,user_id,csrf,expires_at,last_activity_at) VALUES(?,?,?,?,?)", Hash(token), actor.ID, "control-csrf", time.Now().Add(time.Hour).Unix(), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	calls := 0
	e := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet || r.URL.Path != "/v1/memcached-unix/projects/"+op.ProjectID+"/controls/"+op.RequestID || r.URL.RawQuery != "actor_id="+actor.ID {
			t.Error("observer reissued/moved original control")
		}
		json.NewEncoder(w).Encode(MemcachedUnixControlResult{Format: 1, RequestID: op.RequestID, ProjectID: op.ProjectID, OperationSHA256: MemcachedUnixControlSHA(op), State: "completed", FinalState: "stopped", RuntimeSHA256: strings.Repeat("c", 64)})
	})
	a := &Server{Store: s, Executor: e}
	mux := http.NewServeMux()
	a.memcachedUnixControlRoutes(mux)
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest(http.MethodGet, "/api/app-registry/memcached/instances/"+op.ProjectID+"/controls/"+op.RequestID, nil)
		r.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: token})
		out := httptest.NewRecorder()
		mux.ServeHTTP(out, r)
		if out.Code != 200 {
			t.Fatal(out.Code, out.Body.String())
		}
	}
	if calls != 1 {
		t.Fatal("completed original observer queried or mutated again", calls)
	}
}
