package core

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"local/panel/internal/appcatalog"
)

// Real SQLite/access/worker paths; the executor is a declared transport fixture.
// This does not claim provider downloads or native application acceptance.
func TestStatisticsGeoWorkerRejectsRevokedOrUnboundOriginalBeforeDispatch(t *testing.T) {
	for _, action := range []string{"install", "rollback", "archive", "restore"} {
		for _, mutation := range []string{"role", "menus", "deleted", "missing-audit", "duplicate-audit", "changed-payload", "terminal", "cancelled-context"} {
			t.Run(action+"/"+mutation, func(t *testing.T) {
				s := testStore(t)
				u := accessUser(t, s, "original-geo-worker", "admin", nil)
				in := statisticsGeoSelectionFixture()
				in.Action = action
				id, err := s.QueueStatisticsGeo(in, "original-geo-worker", u.ID)
				if err != nil {
					t.Fatal(err)
				}
				job, err := s.nextRuntimeInstallJob()
				if err != nil || job.ID != id {
					t.Fatal(job, err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				statement, args := "", []any{u.ID}
				switch mutation {
				case "role":
					statement = "UPDATE app_user_roles SET role='viewer' WHERE user_id=?"
				case "menus":
					statement = "INSERT INTO app_user_menus VALUES(?,'[\"runtimes\"]',1)"
				case "deleted":
					statement = "DELETE FROM users WHERE id=?"
				case "missing-audit":
					statement, args = "DELETE FROM audit_logs WHERE target=? AND action='statistics.geodata.queue'", []any{id}
				case "duplicate-audit":
					statement, args = "INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'statistics.geodata.queue',?,'queued',?)", []any{u.ID, id, Now()}
				case "changed-payload":
					statement, args = "UPDATE runtime_jobs SET payload='{}' WHERE id=?", []any{id}
				case "terminal":
					statement, args = "UPDATE runtime_jobs SET state='failed',error='original administrator cancellation' WHERE id=?", []any{id}
				case "cancelled-context":
					cancel()
				}
				if statement != "" {
					if _, err = s.DB.Exec(statement, args...); err != nil {
						t.Fatal(err)
					}
				}
				calls := 0
				e := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					body, _ := json.Marshal(StatisticsGeoOperation{JobID: id, Selection: in, State: "succeeded", Steps: []Step{}})
					return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
				})}}
				runStatisticsGeoJob(ctx, s, e, job, appcatalog.Default())
				var state, detail string
				if err = s.DB.QueryRow("SELECT state,error FROM runtime_jobs WHERE id=?", id).Scan(&state, &detail); err != nil {
					t.Fatal(err)
				}
				if calls != 0 || state == "succeeded" || mutation == "terminal" && detail != "original administrator cancellation" || mutation == "cancelled-context" && state != "running" {
					t.Fatal("revoked, corrupt or cancelled original dispatched or evidence overwritten", calls, state, detail)
				}
			})
		}
	}
}

func TestStatisticsGeoQueueRejectsCurrentRevokedAuthorityAtomically(t *testing.T) {
	for _, kind := range []string{"viewer", "operator", "missing-runtimes", "missing-sites", "deleted"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			role, menus := "admin", []string(nil)
			if kind == "viewer" || kind == "operator" {
				role = kind
			} else if kind == "missing-runtimes" {
				menus = []string{"sites"}
			} else if kind == "missing-sites" {
				menus = []string{"runtimes"}
			}
			u := accessUser(t, s, "revoked-geo-queue", role, menus)
			if kind == "deleted" {
				if _, err := s.DB.Exec("DELETE FROM users WHERE id=?", u.ID); err != nil {
					t.Fatal(err)
				}
			}
			id, err := s.QueueStatisticsGeo(statisticsGeoSelectionFixture(), "revoked-geo-queue", u.ID)
			if err == nil || id != "" {
				t.Fatal("revoked account committed a data job", id, err)
			}
			for _, query := range []string{"SELECT count(*) FROM runtime_jobs", "SELECT count(*) FROM audit_logs WHERE action='statistics.geodata.queue'"} {
				var count int
				if err = s.DB.QueryRow(query).Scan(&count); err != nil || count != 0 {
					t.Fatal("failed authorization left partial queue/audit", count, err)
				}
			}
		})
	}
}

func TestStatisticsGeoDispatchRechecksAfterPreparationForEveryAction(t *testing.T) {
	for _, action := range []string{"install", "rollback", "archive", "restore"} {
		t.Run(action, func(t *testing.T) {
			s := testStore(t)
			u := accessUser(t, s, "geo-prepare-admin", "admin", nil)
			in := statisticsGeoSelectionFixture()
			in.Action = action
			if _, err := s.QueueStatisticsGeo(in, "prepared-original", u.ID); err != nil {
				t.Fatal(err)
			}
			job, err := s.nextRuntimeInstallJob()
			if err != nil {
				t.Fatal(err)
			}
			if already, err := s.statisticsGeoDispatchBoundary(context.Background(), job, false); err != nil || already {
				t.Fatal("initial authorization", already, err)
			}
			// Represents revocation while signed catalogue preparation is in flight.
			if _, err = s.DB.Exec("UPDATE app_user_roles SET role='viewer' WHERE user_id=?", u.ID); err != nil {
				t.Fatal(err)
			}
			if _, err = s.statisticsGeoDispatchBoundary(context.Background(), job, true); err == nil {
				t.Fatal("stale initial permission accepted after preparation")
			}
			var count int
			if err = s.DB.QueryRow("SELECT count(*) FROM audit_logs WHERE action='statistics.geodata.dispatch'").Scan(&count); err != nil || count != 0 {
				t.Fatal("revocation saved a dispatch intent", count, err)
			}
		})
	}
}

func TestStatisticsGeoDispatchIntentIsSingleDurableActorPayloadBinding(t *testing.T) {
	s := testStore(t)
	u := accessUser(t, s, "geo-single-admin", "admin", nil)
	in := statisticsGeoSelectionFixture()
	if _, err := s.QueueStatisticsGeo(in, "single-original", u.ID); err != nil {
		t.Fatal(err)
	}
	job, err := s.nextRuntimeInstallJob()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan bool, 8)
	errors := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			already, err := s.statisticsGeoDispatchBoundary(context.Background(), job, true)
			results <- already
			errors <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	newIntents := 0
	for already := range results {
		if !already {
			newIntents++
		}
	}
	var count int
	var actor, digest string
	if err = s.DB.QueryRow("SELECT count(*),min(actor),min(result) FROM audit_logs WHERE action='statistics.geodata.dispatch' AND target=?", job.ID).Scan(&count, &actor, &digest); err != nil || count != 1 || actor != u.ID || digest != Hash(job.Payload) || newIntents != 1 {
		t.Fatal("dispatch intent duplicated or lost original binding", count, newIntents, actor, digest, err)
	}
	// Close/reopen the real store: this marker is durable, not an in-memory flag.
	var dbPath string
	var sequence int
	if err = s.DB.QueryRow("SELECT seq,name,file FROM pragma_database_list WHERE name='main'").Scan(&sequence, &actor, &dbPath); err != nil {
		t.Fatal(err)
	}
	if err = s.DB.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.DB.Close()
	if err = reopened.Recover(); err != nil {
		t.Fatal(err)
	}
	recovered, err := reopened.nextRuntimeInstallJob()
	if err != nil || recovered.ID != job.ID || recovered.Payload != job.Payload {
		t.Fatal("normal startup recovery changed original identity", recovered, err)
	}
	if already, err := reopened.statisticsGeoDispatchBoundary(context.Background(), recovered, true); err != nil || !already {
		t.Fatal("cold reopen lost original intent", already, err)
	}
}

func TestStatisticsGeoCorruptDispatchIntentNeverPostsOrOverwritesIt(t *testing.T) {
	for _, mutation := range []string{"actor", "digest", "duplicate", "queue-actor"} {
		t.Run(mutation, func(t *testing.T) {
			s := testStore(t)
			u := accessUser(t, s, "geo-corrupt-admin", "admin", nil)
			in := statisticsGeoSelectionFixture()
			in.Action = "rollback"
			if _, err := s.QueueStatisticsGeo(in, "corrupt-original", u.ID); err != nil {
				t.Fatal(err)
			}
			job, err := s.nextRuntimeInstallJob()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.statisticsGeoDispatchBoundary(context.Background(), job, true); err != nil {
				t.Fatal(err)
			}
			statement, args := "", []any{job.ID}
			switch mutation {
			case "actor":
				statement = "UPDATE audit_logs SET actor='eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' WHERE action='statistics.geodata.dispatch' AND target=?"
			case "digest":
				statement = "UPDATE audit_logs SET result='changed-digest' WHERE action='statistics.geodata.dispatch' AND target=?"
			case "duplicate":
				statement = "INSERT INTO audit_logs(actor,action,target,result,created_at) SELECT actor,action,target,result,created_at FROM audit_logs WHERE action='statistics.geodata.dispatch' AND target=?"
			case "queue-actor":
				statement = "UPDATE audit_logs SET actor='eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' WHERE action='statistics.geodata.queue' AND target=?"
			}
			if _, err = s.DB.Exec(statement, args...); err != nil {
				t.Fatal(err)
			}
			calls := 0
			e := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				return nil, io.ErrUnexpectedEOF
			})}}
			runStatisticsGeoJob(context.Background(), s, e, job, appcatalog.Default())
			var state string
			var count int
			if err = s.DB.QueryRow("SELECT state FROM runtime_jobs WHERE id=?", job.ID).Scan(&state); err != nil || state != "needs_attention" || calls != 0 {
				t.Fatal("corrupt dispatch binding accepted", calls, state, err)
			}
			want := 1
			if mutation == "duplicate" {
				want = 2
			}
			if err = s.DB.QueryRow("SELECT count(*) FROM audit_logs WHERE action='statistics.geodata.dispatch' AND target=?", job.ID).Scan(&count); err != nil || count != want {
				t.Fatal("original broken intent was repaired or replaced", count, err)
			}
		})
	}
}

func TestStatisticsGeoExistingIntentOnlyObservesEvenAfterRevocation(t *testing.T) {
	for _, action := range []string{"install", "rollback", "archive", "restore"} {
		t.Run(action, func(t *testing.T) {
			s := testStore(t)
			u := accessUser(t, s, "geo-observe-admin", "admin", nil)
			in := statisticsGeoSelectionFixture()
			in.Action = action
			if _, err := s.QueueStatisticsGeo(in, "observe-original", u.ID); err != nil {
				t.Fatal(err)
			}
			job, err := s.nextRuntimeInstallJob()
			if err != nil {
				t.Fatal(err)
			}
			if already, err := s.statisticsGeoDispatchBoundary(context.Background(), job, true); err != nil || already {
				t.Fatal(already, err)
			}
			if _, err = s.DB.Exec("DELETE FROM users WHERE id=?", u.ID); err != nil {
				t.Fatal(err)
			}
			gets := 0
			e := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != "GET" || r.URL.Path != "/v1/statistics/geodata/jobs/"+job.ID || r.URL.RawQuery != "" {
					t.Fatal("durable intent was resubmitted", r.Method, r.URL)
				}
				gets++
				body, _ := json.Marshal(StatisticsGeoOperation{JobID: job.ID, Selection: in, State: "failed", Error: "original native failure", Steps: []Step{}})
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
			})}}
			// Empty catalogue configuration must never be touched for observation.
			runStatisticsGeoJob(context.Background(), s, e, job, &appcatalog.Client{})
			var state, detail, payload string
			if err = s.DB.QueryRow("SELECT state,error,payload FROM runtime_jobs WHERE id=?", job.ID).Scan(&state, &detail, &payload); err != nil || state != "failed" || detail != "original native failure" || payload != job.Payload || gets != 1 {
				t.Fatal("original observation/evidence changed", state, detail, gets, err)
			}
		})
	}
}

func TestStatisticsGeoFailedIntentAuditNeverCallsExecutor(t *testing.T) {
	s := testStore(t)
	u := accessUser(t, s, "geo-audit-admin", "admin", nil)
	in := statisticsGeoSelectionFixture()
	in.Action = "rollback"
	if _, err := s.QueueStatisticsGeo(in, "audit-original", u.ID); err != nil {
		t.Fatal(err)
	}
	job, err := s.nextRuntimeInstallJob()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec("CREATE TRIGGER refuse_geo_intent BEFORE INSERT ON audit_logs WHEN NEW.action='statistics.geodata.dispatch' BEGIN SELECT RAISE(ABORT,'owned audit failure fixture'); END"); err != nil {
		t.Fatal(err)
	}
	calls := 0
	e := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return nil, io.ErrUnexpectedEOF
	})}}
	runStatisticsGeoJob(context.Background(), s, e, job, appcatalog.Default())
	var state, payload string
	var count int
	if err = s.DB.QueryRow("SELECT state,payload FROM runtime_jobs WHERE id=?", job.ID).Scan(&state, &payload); err != nil || state != "needs_attention" || payload != job.Payload || calls != 0 {
		t.Fatal("failed audit dispatched or replaced original", state, calls, err)
	}
	if err = s.DB.QueryRow("SELECT count(*) FROM audit_logs WHERE action='statistics.geodata.dispatch'").Scan(&count); err != nil || count != 0 {
		t.Fatal("partial dispatch intent retained", count, err)
	}
}
