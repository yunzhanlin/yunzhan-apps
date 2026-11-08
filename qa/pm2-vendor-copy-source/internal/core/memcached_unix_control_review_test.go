package core

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func memcachedUnixPendingReviewFixture(t *testing.T) (*Store, identity, identity, MemcachedUnixControlOperation) {
	t.Helper()
	s, owner, op := memcachedUnixControlFixture(t)
	if _, _, err := s.reserveMemcachedUnixControl(t.Context(), op); err != nil {
		t.Fatal(err)
	}
	if s.finishMemcachedUnixControl(t.Context(), op, nil) != nil {
		t.Fatal("unknown fixture")
	}
	reviewer := accessUser(t, s, "socket-reviewer", "admin", nil)
	if _, err := s.DB.Exec("UPDATE app_user_roles SET role='viewer' WHERE user_id=?", owner.ID); err != nil {
		t.Fatal(err)
	}
	return s, owner, reviewer, op
}
func TestMemcachedUnixControlReviewCanonicalWireSeparatesCurrentReviewerFromOriginalActor(t *testing.T) {
	_, owner, reviewer, op := memcachedUnixPendingReviewFixture(t)
	in := MemcachedUnixControlReviewRequest{Format: 1, Operation: op, ReviewerID: reviewer.ID}
	raw, _ := json.Marshal(in)
	got, err := DecodeMemcachedUnixControlReviewRequest(raw)
	if err != nil || got.Operation != op || got.ReviewerID == owner.ID || got.Input != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"alias", "duplicate", "extra-command", "null-input", "trailing", "bad-reviewer", "bad-original", "bad-ack", "bad-hash"} {
		t.Run(kind, func(t *testing.T) {
			changed := in
			wire := bytes.Clone(raw)
			switch kind {
			case "alias":
				wire = bytes.Replace(wire, []byte("\"reviewer_id\""), []byte("\"Reviewer_ID\""), 1)
			case "duplicate":
				wire = append([]byte("{\"format\":1,"), wire[1:]...)
			case "extra-command":
				wire = append([]byte("{\"command\":\"restart\","), wire[1:]...)
			case "null-input":
				wire = append(wire[:len(wire)-1], []byte(",\"input\":null}")...)
			case "trailing":
				wire = append(wire, '\n')
			case "bad-reviewer":
				changed.ReviewerID = "root"
				wire, _ = json.Marshal(changed)
			case "bad-original":
				changed.Operation.ActorID = "root"
				wire, _ = json.Marshal(changed)
			case "bad-ack":
				changed.Input = &MemcachedUnixControlReviewInput{ExpectedRuntimeSHA256: strings.Repeat("a", 64)}
				wire, _ = json.Marshal(changed)
			case "bad-hash":
				changed.Input = &MemcachedUnixControlReviewInput{ExpectedRuntimeSHA256: "bad", AcknowledgeOriginalUnknown: true}
				wire, _ = json.Marshal(changed)
			}
			if _, err := DecodeMemcachedUnixControlReviewRequest(wire); err == nil {
				t.Fatal("foreign review wire accepted", kind)
			}
		})
	}
}
func TestMemcachedUnixControlReviewCurrentOtherAdministratorCannotBecomeOriginalCommandIssuer(t *testing.T) {
	s, owner, reviewer, op := memcachedUnixPendingReviewFixture(t)
	ctx := t.Context()
	in := MemcachedUnixControlReviewRequest{Format: 1, Operation: op, ReviewerID: reviewer.ID}
	before := installReplayCounts(t, s)
	original, err := s.MemcachedUnixControlReviewBinding(ctx, reviewer.ID, op.RequestID)
	if err != nil || original != op || original.ActorID != owner.ID || s.CheckMemcachedUnixControlReview(ctx, in, true) != nil {
		t.Fatal("current other administrator review refused", err)
	}
	if s.CheckMemcachedUnixControl(ctx, op) == nil {
		t.Fatal("revoked issuer got a new native grant")
	}
	var oldRaw string
	s.DB.QueryRow("SELECT operation FROM memcached_unix_controls WHERE request_id=?", op.RequestID).Scan(&oldRaw)
	if _, err := s.MemcachedUnixControlReviewBinding(ctx, owner.ID, op.RequestID); err == nil {
		t.Fatal("revoked original issuer retained review authority")
	}
	changed := in
	changed.Operation.ActorID = reviewer.ID
	if s.CheckMemcachedUnixControlReview(ctx, changed, true) == nil {
		t.Fatal("reviewer borrowed original actor identity")
	}
	if got := installReplayCounts(t, s); !reflect.DeepEqual(got, before) {
		t.Fatal("review reserved an installation")
	}
	if _, err := s.DB.Exec("UPDATE app_user_roles SET role='viewer' WHERE user_id=?", reviewer.ID); err != nil {
		t.Fatal(err)
	}
	if s.CheckMemcachedUnixControlReview(ctx, in, true) == nil {
		t.Fatal("review ignored current revoke")
	}
	result := MemcachedUnixControlResult{Format: 1, RequestID: op.RequestID, ProjectID: op.ProjectID, OperationSHA256: MemcachedUnixControlSHA(op), State: "observed", FinalState: "running", RuntimeSHA256: strings.Repeat("e", 64), ReviewerID: reviewer.ID, ObservedAt: "2026-10-24T12:00:00Z"}
	if s.finishMemcachedUnixControlReview(ctx, reviewer.ID, op, result) == nil {
		t.Fatal("revoked reviewer settled queue")
	}
	s.DB.Exec("UPDATE app_user_roles SET role='admin' WHERE user_id=?", reviewer.ID)
	for i := 0; i < 2; i++ {
		if err := s.finishMemcachedUnixControlReview(ctx, reviewer.ID, op, result); err != nil {
			t.Fatal(err)
		}
	}
	var afterRaw string
	var audits int
	s.DB.QueryRow("SELECT operation FROM memcached_unix_controls WHERE request_id=?", op.RequestID).Scan(&afterRaw)
	s.DB.QueryRow("SELECT count(*)FROM audit_logs WHERE action='app.memcached.unix.review' AND target=?", op.RequestID).Scan(&audits)
	if oldRaw != afterRaw || audits != 1 {
		t.Fatal("original actor/payload changed or repeated review audit")
	}
	if s.CheckMemcachedUnixControl(ctx, op) == nil {
		t.Fatal("historical observation redispatched original command")
	}
	fork := result
	fork.RuntimeSHA256 = strings.Repeat("f", 64)
	if s.finishMemcachedUnixControlReview(ctx, reviewer.ID, op, fork) == nil {
		t.Fatal("historical observation overwritten")
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.MemcachedUnixControlReviewBinding(cancelCtx, reviewer.ID, op.RequestID); err == nil {
		t.Fatal("canceled review authorized")
	}
}
func TestMemcachedUnixControlReviewHTTPPreviewNeverWritesAndExplicitSettlementNeverCallsNativeControl(t *testing.T) {
	for _, kind := range []string{"preview", "preview-historical", "confirm", "lost-reply", "revoke-on-reply", "forked-view", "query", "wrong-project", "bad-ack", "extra-actor", "duplicate", "csrf", "revoked-reviewer"} {
		t.Run(kind, func(t *testing.T) {
			s, _, reviewer, op := memcachedUnixPendingReviewFixture(t)
			token := Token()
			s.DB.Exec("INSERT INTO sessions(token_hash,user_id,csrf,expires_at,last_activity_at)VALUES(?,?,?,?,?)", Hash(token), reviewer.ID, "review-csrf", time.Now().Add(time.Hour).Unix(), time.Now().Unix())
			digest := strings.Repeat("e", 64)
			result := MemcachedUnixControlResult{Format: 1, RequestID: op.RequestID, ProjectID: op.ProjectID, OperationSHA256: MemcachedUnixControlSHA(op), State: "observed", FinalState: "running", RuntimeSHA256: digest, ReviewerID: reviewer.ID, ObservedAt: "2026-10-24T12:00:00Z"}
			calls := 0
			native := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodPost || r.URL.Path != "/v1/memcached-unix/projects/"+op.ProjectID+"/controls/"+op.RequestID+"/review" || r.Header.Get("Cookie") != "" {
					t.Error("review called a native control or leaked session")
				}
				raw, _ := io.ReadAll(r.Body)
				in, err := DecodeMemcachedUnixControlReviewRequest(raw)
				if err != nil || in.Operation != op || in.ReviewerID != reviewer.ID {
					t.Error("review changed original actor or used browser identity", err)
				}
				if kind == "lost-reply" {
					http.Error(w, "unknown response", 500)
					return
				}
				if kind == "revoke-on-reply" {
					s.DB.Exec("UPDATE app_user_roles SET role='viewer' WHERE user_id=?", reviewer.ID)
				}
				out := MemcachedUnixControlReviewView{Format: 1, RequestID: op.RequestID, ProjectID: op.ProjectID, OperationSHA256: MemcachedUnixControlSHA(op), OriginalOutcome: "unknown"}
				if in.Input == nil && kind != "preview-historical" {
					out.CurrentState = "running"
					out.RuntimeSHA256 = digest
				} else {
					out.Observation = &result
				}
				if kind == "forked-view" {
					out.OperationSHA256 = strings.Repeat("f", 64)
				}
				json.NewEncoder(w).Encode(out)
			})
			a := &Server{Store: s, Executor: native}
			mux := http.NewServeMux()
			a.memcachedUnixControlRoutes(mux)
			method, want := http.MethodPost, 200
			if strings.HasPrefix(kind, "preview") {
				method = http.MethodGet
			}
			input := []byte("{\"expected_runtime_sha256\":\"" + digest + "\",\"acknowledge_original_unknown\":true}")
			switch kind {
			case "lost-reply", "revoke-on-reply", "forked-view":
				want = 409
			case "query":
				want = 404
			case "wrong-project", "csrf", "revoked-reviewer":
				want = 403
			case "bad-ack", "extra-actor", "duplicate":
				want = 400
			}
			if kind == "bad-ack" {
				input = bytes.Replace(input, []byte("true"), []byte("false"), 1)
			}
			if kind == "extra-actor" {
				input = append([]byte("{\"reviewer_id\":\"root\","), input[1:]...)
			}
			if kind == "duplicate" {
				input = append([]byte("{\"acknowledge_original_unknown\":true,"), input[1:]...)
			}
			project := op.ProjectID
			if kind == "wrong-project" {
				project = ID()
			}
			path := "/api/app-registry/memcached/instances/" + project + "/controls/" + op.RequestID + "/review"
			if kind == "query" {
				path += "?retry=true"
			}
			if kind == "revoked-reviewer" {
				s.DB.Exec("UPDATE app_user_roles SET role='viewer' WHERE user_id=?", reviewer.ID)
			}
			request := httptest.NewRequest(method, path, bytes.NewReader(input))
			request.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: token})
			request.Header.Set("X-CSRF-Token", "review-csrf")
			if kind == "csrf" {
				request.Header.Set("X-CSRF-Token", "foreign")
			}
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)
			if response.Code != want {
				t.Fatal(kind, response.Code, response.Body.String())
			}
			expected := 0
			if kind == "preview" || kind == "preview-historical" || kind == "confirm" || kind == "lost-reply" || kind == "revoke-on-reply" || kind == "forked-view" {
				expected = 1
			}
			if calls != expected {
				t.Fatal("review replayed or dispatched a native command", calls, expected)
			}
			row, found, err := readMemcachedUnixControl(t.Context(), s.DB, op.RequestID)
			if err != nil || !found || row.Operation != op {
				t.Fatal(err)
			}
			var audits int
			s.DB.QueryRow("SELECT count(*)FROM audit_logs WHERE action='app.memcached.unix.review'").Scan(&audits)
			if kind == "confirm" {
				if row.State != "completed" || row.Result == nil || row.Result.State != "observed" || audits != 1 {
					t.Fatal("separate observation missing")
				}
			} else if row.State != "unknown" || row.Result != nil || audits != 0 {
				t.Fatal("preview or refusal rewrote original unknown")
			}
		})
	}
}
