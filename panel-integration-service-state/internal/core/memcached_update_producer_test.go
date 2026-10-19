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

func TestMemcachedProducerOriginalReplayIsSQLOnlyEvenOfflineOrUnknown(t *testing.T) {
	for _, scenario := range []string{"reserved", "unknown", "committed", "different-input", "other-project", "other-user", "revoked", "duplicate-key", "duplicate-body", "missing-ack", "oversize"} {
		t.Run(scenario, func(t *testing.T) {
			s, actor, seed := memcachedStoreFixture(t)
			memcachedStoreReserve(t, s, actor, seed)
			if scenario == "unknown" {
				if err := s.markMemcachedUpdateUnknown(t.Context(), actor.ID, seed.Dispatch.RequestID); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "committed" {
				if _, err := s.reconcileMemcachedUpdate(t.Context(), seed.Dispatch.RequestID, memcachedStoreChain(t, seed, "pull_started", "image_verified", "apply_started", "applied", "committed")); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "other-user" {
				actor = accessUser(t, s, "different-original-owner", "admin", nil)
			}
			token := Token()
			if _, err := s.DB.Exec(`INSERT INTO sessions(token_hash,user_id,csrf,expires_at,last_activity_at) VALUES(?,?,?,?,?)`, Hash(token), actor.ID, "fixture-csrf", time.Now().Add(time.Hour).Unix(), time.Now().Unix()); err != nil {
				t.Fatal(err)
			}
			a := &Server{Store: s}
			mux := http.NewServeMux()
			a.memcachedUpdateProducerRoutes(mux)
			input := seed.Dispatch.Input
			project := seed.Dispatch.ProjectID
			want := 202
			switch scenario {
			case "different-input":
				input.ExpectedSHA256 = strings.Repeat("f", 64)
				want = 409
			case "other-project":
				project = strings.Repeat("f", 32)
				want = 409
			case "other-user":
				want = 403
			case "revoked":
				if _, err := s.DB.Exec(`UPDATE app_user_roles SET role='viewer' WHERE user_id=?`, actor.ID); err != nil {
					t.Fatal(err)
				}
				want = 403
			case "duplicate-key", "duplicate-body", "missing-ack", "oversize":
				want = 400
			}
			if scenario == "missing-ack" {
				input.AcknowledgeCacheLoss = false
			}
			body, _ := json.Marshal(input)
			if scenario == "duplicate-body" {
				body = append([]byte(`{"acknowledge_cache_loss":false,`), body[1:]...)
			}
			if scenario == "oversize" {
				body = bytes.Repeat([]byte(" "), MaxMemcachedUpdateInputBytes+1)
			}
			r := httptest.NewRequest(http.MethodPost, "/api/app-registry/memcached/instances/"+project+"/updates", bytes.NewReader(body))
			r.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: token})
			r.Header.Set("X-CSRF-Token", "fixture-csrf")
			r.Header.Set("Idempotency-Key", seed.Dispatch.RequestID)
			if scenario == "duplicate-key" {
				r.Header.Add("Idempotency-Key", seed.Dispatch.RequestID)
			}
			before := memcachedStoreCounts(t, s)
			receipt := memcachedStoreReceipt(t, s, seed.Dispatch.ProjectID)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != want || memcachedStoreCounts(t, s) != before || memcachedStoreReceipt(t, s, seed.Dispatch.ProjectID) != receipt {
				t.Fatal("original replay changed store or called unavailable dependencies", w.Code, w.Body.String())
			}
			if want == 202 {
				var out memcachedUpdateStatus
				if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.JobID != seed.Dispatch.JobID || out.RequestID != seed.Dispatch.RequestID {
					t.Fatal("original identity changed")
				}
			}
		})
	}
}

func TestMemcachedObserverMissingOrForkedNativeReplyNeverPostsOrRequeues(t *testing.T) {
	for _, scenario := range []string{"missing", "forked", "prepared", "committed"} {
		t.Run(scenario, func(t *testing.T) {
			s, actor, seed := memcachedStoreFixture(t)
			memcachedStoreReserve(t, s, actor, seed)
			calls := 0
			e := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodGet || r.URL.Path != "/v1/docker/projects/"+seed.Dispatch.ProjectID+"/app-updates/"+seed.Dispatch.JobID {
					t.Fatal("observer issued a mutation or changed original identity")
				}
				if scenario == "missing" {
					http.Error(w, "missing original", 404)
					return
				}
				chain := []MemcachedUpdateRecord{seed}
				if scenario == "committed" {
					chain = memcachedStoreChain(t, seed, "pull_started", "image_verified", "apply_started", "applied", "committed")
				}
				if scenario == "forked" {
					chain[0].Dispatch.JobID = strings.Repeat("f", 32)
					chain[0].DispatchSHA256 = MemcachedUpdateDispatchSHA(chain[0].Dispatch)
					var err error
					chain[0], err = SealMemcachedUpdateRecord(chain[0])
					if err != nil {
						t.Fatal(err)
					}
				}
				_ = json.NewEncoder(w).Encode(MemcachedUpdateSnapshot{Format: 1, Records: chain})
			})
			before := memcachedStoreReceipt(t, s, seed.Dispatch.ProjectID)
			observeMemcachedUpdates(t.Context(), s, e)
			if calls != 1 {
				t.Fatal("missing original was retried", calls)
			}
			row, found, err := s.memcachedUpdateForActor(t.Context(), actor.ID, seed.Dispatch.RequestID)
			if err != nil || !found {
				t.Fatal(err)
			}
			if scenario == "missing" || scenario == "forked" {
				if row.State != "reserved" || len(row.Chain) != 0 {
					t.Fatal("uncertain result adopted or original request discarded")
				}
			}
			if scenario != "committed" && memcachedStoreReceipt(t, s, seed.Dispatch.ProjectID) != before {
				t.Fatal("observer prematurely advanced version")
			}
			if scenario == "committed" && row.State != "committed" {
				t.Fatal("complete bound original chain was not reconciled")
			}
		})
	}
}
