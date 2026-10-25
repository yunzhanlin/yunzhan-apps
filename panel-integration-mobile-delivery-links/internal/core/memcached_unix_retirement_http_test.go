package core

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// HTTP/SQL models only. No real executor, daemon or application is changed.
func TestMemcachedUnixRetirementHTTPRequiresClosedConfirmationAndNeverReplays(t *testing.T) {
	for _, kind := range []string{"fresh", "lost", "unknown", "wrong-final", "fork", "original-completed", "changed-original", "missing-ack", "false-ack", "cache-loss", "duplicate", "alias", "null", "extra-CID", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			s, actor, op := memcachedUnixControlFixture(t)
			op.Input = MemcachedUnixControlInput{Action: "retire", ExpectedRuntimeSHA256: op.Input.ExpectedRuntimeSHA256, AcknowledgeRemoval: true, ConfirmName: "own-cache"}
			result := MemcachedUnixControlResult{Format: 1, RequestID: op.RequestID, ProjectID: op.ProjectID, OperationSHA256: MemcachedUnixControlSHA(op), State: "completed", FinalState: "retired", RuntimeSHA256: strings.Repeat("b", 64)}
			token := Token()
			if _, err := s.DB.Exec("INSERT INTO sessions(token_hash,user_id,csrf,expires_at,last_activity_at) VALUES(?,?,?,?,?)", Hash(token), actor.ID, "retire-csrf", time.Now().Add(time.Hour).Unix(), time.Now().Unix()); err != nil {
				t.Fatal(err)
			}
			want, calls, expected := 200, 0, 1
			in := op.Input
			switch kind {
			case "original-completed", "changed-original":
				if _, _, e := s.reserveMemcachedUnixControl(t.Context(), op); e != nil {
					t.Fatal(e)
				}
				expected = 0
				if kind == "original-completed" {
					if s.finishMemcachedUnixControl(t.Context(), op, &result) != nil {
						t.Fatal("original result")
					}
				} else {
					in.ConfirmName = "other-cache"
					want = 409
				}
			case "lost", "unknown", "wrong-final", "fork":
				want = 202
			case "missing-ack", "false-ack", "cache-loss", "duplicate", "alias", "null", "extra-CID":
				want, expected = 400, 0
			case "revoked":
				s.DB.Exec("UPDATE app_user_roles SET role='viewer' WHERE user_id=?", actor.ID)
				want, expected = 403, 0
			}
			e := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				var received MemcachedUnixControlOperation
				if r.Method != http.MethodPost || r.URL.Path != "/v1/memcached-unix/projects/"+op.ProjectID+"/controls/"+op.RequestID || r.Header.Get("Cookie") != "" || json.NewDecoder(r.Body).Decode(&received) != nil || received != op {
					t.Error("retirement transport changed identity or leaked session")
				}
				if kind == "lost" {
					http.Error(w, "lost result", 500)
					return
				}
				v := result
				switch kind {
				case "unknown":
					v.State, v.FinalState, v.RuntimeSHA256 = "unknown", "", ""
				case "wrong-final":
					v.FinalState = "stopped"
				case "fork":
					v.OperationSHA256 = strings.Repeat("f", 64)
				}
				json.NewEncoder(w).Encode(v)
			})
			a := &Server{Store: s, Executor: e}
			mux := http.NewServeMux()
			a.memcachedUnixControlRoutes(mux)
			body, _ := json.Marshal(in)
			switch kind {
			case "missing-ack":
				body = bytes.Replace(body, []byte(",\"acknowledge_removal\":true"), nil, 1)
			case "false-ack":
				body = bytes.Replace(body, []byte("\"acknowledge_removal\":true"), []byte("\"acknowledge_removal\":false"), 1)
			case "cache-loss":
				body = bytes.Replace(body, []byte("\"acknowledge_cache_loss\":false"), []byte("\"acknowledge_cache_loss\":true"), 1)
			case "duplicate":
				body = append([]byte("{\"acknowledge_removal\":true,"), body[1:]...)
			case "alias":
				body = bytes.Replace(body, []byte("\"confirm_name\""), []byte("\"Confirm_Name\""), 1)
			case "null":
				body = bytes.Replace(body, []byte("\"confirm_name\":\"own-cache\""), []byte("\"confirm_name\":null"), 1)
			case "extra-CID":
				body = append([]byte("{\"container_id\":\"foreign\","), body[1:]...)
			}
			dispatch := func() *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodPost, "/api/app-registry/memcached/instances/"+op.ProjectID+"/controls", bytes.NewReader(body))
				r.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: token})
				r.Header.Set("X-CSRF-Token", "retire-csrf")
				r.Header.Set("Idempotency-Key", op.RequestID)
				out := httptest.NewRecorder()
				mux.ServeHTTP(out, r)
				return out
			}
			out := dispatch()
			if out.Code != want || calls != expected {
				t.Fatal("first retirement outcome", out.Code, out.Body.String(), calls, expected)
			}
			if want == 200 || want == 202 {
				out = dispatch()
				if out.Code != 200 || calls != expected || out.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("same original command was replayed", out.Code, out.Body.String(), calls)
				}
				var row memcachedUnixControlRow
				if json.Unmarshal(out.Body.Bytes(), &row) != nil || row.Operation != op || want == 202 && row.State != "unknown" || want == 200 && (row.Result == nil || row.Result.FinalState != "retired") {
					t.Fatal("original identity or unknown was lost", out.Body.String())
				}
			}
		})
	}
}
