package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStatisticsGeoOriginalRequestReadOnlyRecoveryNeverQueuesOrCallsExecutor(t *testing.T) {
	for _, scenario := range []string{"queued", "running", "succeeded", "failed", "needs_attention", "missing", "foreign-actor", "missing-audit", "duplicate-audit", "orphan-audit", "revoked", "changed-payload"} {
		t.Run(scenario, func(t *testing.T) {
			s := testStore(t)
			actor := accessUser(t, s, "geo-original-reader", "admin", nil)
			key := strings.Repeat("a", 32)
			in := statisticsGeoSelectionFixture()
			job, err := s.QueueStatisticsGeo(in, key, actor.ID)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "queued", "running", "succeeded", "failed", "needs_attention":
				_, err = s.DB.Exec(`UPDATE runtime_jobs SET state=? WHERE id=?`, scenario, job)
			case "missing":
				key = strings.Repeat("b", 32)
			case "foreign-actor":
				actor = accessUser(t, s, "geo-other-reader", "admin", nil)
			case "missing-audit":
				_, err = s.DB.Exec(`DELETE FROM audit_logs WHERE action='statistics.geodata.queue'`)
			case "duplicate-audit":
				_, err = s.DB.Exec(`INSERT INTO audit_logs(actor,action,target,result,created_at) SELECT actor,action,target,result,created_at FROM audit_logs WHERE action='statistics.geodata.queue'`)
			case "orphan-audit":
				_, err = s.DB.Exec(`DELETE FROM runtime_jobs WHERE id=?`, job)
			case "revoked":
				_, err = s.DB.Exec(`UPDATE app_user_roles SET role='viewer' WHERE user_id=?`, actor.ID)
			case "changed-payload":
				_, err = s.DB.Exec(`UPDATE runtime_jobs SET payload='{}' WHERE id=?`, job)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := geoRequestCounts(t, s)
			out, err := s.statisticsGeoRequestState(t.Context(), key, actor.ID)
			if geoRequestCounts(t, s) != before {
				t.Fatal("read-only lookup changed jobs/audits/receipts")
			}
			if scenario == "missing" {
				if err != nil || out.StateKnown || out.State != "unknown" || out.JobID != "" || out.Selection != nil {
					t.Fatal("absence adopted as non-submission", out, err)
				}
				return
			}
			if scenario == "queued" || scenario == "running" || scenario == "succeeded" || scenario == "failed" || scenario == "needs_attention" {
				if err != nil || out.RequestID != key || out.JobID != job || out.Selection == nil || *out.Selection != in || out.State != scenario || !out.StateKnown {
					t.Fatal("original identity changed", out, err)
				}
			} else if err == nil {
				t.Fatal("unbound/corrupt/revoked request adopted", out)
			}
		})
	}
}

func geoRequestCounts(t *testing.T, s *Store) [3]int {
	t.Helper()
	var out [3]int
	if err := s.DB.QueryRow(`SELECT (SELECT count(*) FROM runtime_jobs),(SELECT count(*) FROM audit_logs),(SELECT count(*) FROM app_registry_receipts)`).Scan(&out[0], &out[1], &out[2]); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestStatisticsGeoRetainedOrphanAuditCannotCreateAReplacementRequest(t *testing.T) {
	s := testStore(t)
	actor := accessUser(t, s, "geo-orphan-owner", "admin", nil)
	in := statisticsGeoSelectionFixture()
	key := strings.Repeat("c", 32)
	job, err := s.QueueStatisticsGeo(in, key, actor.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`DELETE FROM runtime_jobs WHERE id=?`, job); err != nil {
		t.Fatal(err)
	}
	before := geoRequestCounts(t, s)
	for _, next := range []string{key, strings.Repeat("d", 32)} {
		if id, err := s.QueueStatisticsGeo(in, next, actor.ID); err == nil || id != "" || geoRequestCounts(t, s) != before {
			t.Fatal("retained uncertainty replaced original task", id, err)
		}
	}
}

func TestStatisticsGeoUncertainOriginalCannotBeBypassedWithAnotherKey(t *testing.T) {
	s := testStore(t)
	actor := accessUser(t, s, "geo-uncertain-owner", "admin", nil)
	in := statisticsGeoSelectionFixture()
	key := strings.Repeat("a", 32)
	job, err := s.QueueStatisticsGeo(in, key, actor.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`UPDATE runtime_jobs SET state='needs_attention' WHERE id=?`, job); err != nil {
		t.Fatal(err)
	}
	before := geoRequestCounts(t, s)
	if same, err := s.QueueStatisticsGeo(in, key, actor.ID); err != nil || same != job {
		t.Fatal("original SQL-only key lookup lost", same, err)
	}
	if next, err := s.QueueStatisticsGeo(in, strings.Repeat("b", 32), actor.ID); err == nil || next != "" {
		t.Fatal("fresh key bypassed uncertain original", next, err)
	}
	if geoRequestCounts(t, s) != before {
		t.Fatal("uncertain original changed queue/audit/receipt")
	}
}

func TestStatisticsGeoRequestHTTPRequiresCurrentActorAndRejectsAliasesWithoutExecutor(t *testing.T) {
	s := testStore(t)
	actor := accessUser(t, s, "geo-http-original", "admin", nil)
	key := strings.Repeat("e", 32)
	in := statisticsGeoSelectionFixture()
	job, err := s.QueueStatisticsGeo(in, key, actor.ID)
	if err != nil {
		t.Fatal(err)
	}
	token := Token()
	if _, err = s.DB.Exec(`INSERT INTO sessions(token_hash,user_id,csrf,expires_at,last_activity_at) VALUES(?,?,?,?,?)`, Hash(token), actor.ID, "fixture-csrf", time.Now().Add(time.Hour).Unix(), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	a := &Server{Store: s}
	mux := http.NewServeMux()
	a.statisticsGeoRequestRoutes(mux)
	for _, scenario := range []string{"original", "missing", "no-session", "query", "invalid-key", "post-not-recovery"} {
		t.Run(scenario, func(t *testing.T) {
			path := "/api/software/website-statistics-v2/geodata/requests/" + key
			method := http.MethodGet
			want := 200
			switch scenario {
			case "missing":
				path = strings.Replace(path, key, strings.Repeat("f", 32), 1)
			case "no-session":
				want = 401
			case "query":
				path += "?retry=1"
				want = 400
			case "invalid-key":
				path = strings.Replace(path, key, "not-an-original-id", 1)
				want = 400
			case "post-not-recovery":
				method = http.MethodPost
				want = 405
			}
			r := httptest.NewRequest(method, path, nil)
			if scenario != "no-session" {
				r.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: token})
			}
			before := geoRequestCounts(t, s)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != want || geoRequestCounts(t, s) != before {
				t.Fatal("recovery queued/mutated or authority changed", w.Code, w.Body.String())
			}
			if want == 200 {
				var out statisticsGeoRequestOutcome
				if json.Unmarshal(w.Body.Bytes(), &out) != nil || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("unbound cacheable outcome")
				}
				if scenario == "original" && out.JobID != job || scenario == "missing" && (out.StateKnown || out.JobID != "") {
					t.Fatal("missing request became success or replacement", out)
				}
			}
		})
	}
}
