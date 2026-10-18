package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"local/panel/internal/appcatalog"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func nativeRetryFixture(t *testing.T, s *Store, kind string) Job {
	t.Helper()
	j := Job{ID: ID(), TargetID: runtimecatalog.Apache[0].ID, Kind: kind, Payload: "{}"}
	if kind == "install_php_extension" {
		j.TargetID = runtimecatalog.PHP[0].ID
		if err := s.RecordInstallation(runtimecatalog.PHP[0], "amd64"); err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(ExtensionJobPayload{ExtensionID: runtimecatalog.Extensions[0].ID})
		if err != nil {
			t.Fatal(err)
		}
		j.Payload = string(b)
	}
	if _, err := s.DB.Exec(`INSERT INTO runtime_jobs(id,target_id,kind,state,payload,idempotency_key,created_at,updated_at) VALUES(?,?,?,'queued',?,?,?,?)`, j.ID, j.TargetID, j.Kind, j.Payload, ID(), Now(), Now()); err != nil {
		t.Fatal(err)
	}
	return j
}

func TestNativeRetryGrantIsExplicitOneShotAndSurvivesRecovery(t *testing.T) {
	for _, kind := range []string{"install_runtime", "install_php_extension"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			original := nativeRetryFixture(t, s, kind)
			j, err := s.nextRuntimeInstallJob()
			if err != nil || j.ID != original.ID {
				t.Fatal(err)
			}
			if retry, err := s.takeRuntimeNativeRetry(j); err != nil || retry {
				t.Fatal("first dispatch automatically retries", retry, err)
			}
			if err := s.FinishRuntime(j, "private synthetic failed attempt", nil); err != nil {
				t.Fatal(err)
			}
			if err := s.RetryRuntime(j.ID, "private-admin"); err != nil {
				t.Fatal(err)
			}
			j, err = s.nextRuntimeInstallJob()
			if err != nil {
				t.Fatal(err)
			}
			if retry, err := s.takeRuntimeNativeRetry(j); err != nil || !retry {
				t.Fatal("explicit grant not consumed", retry, err)
			}
			if retry, err := s.takeRuntimeNativeRetry(j); err != nil || retry {
				t.Fatal("grant consumed twice", retry, err)
			}
			if err := s.Recover(); err != nil {
				t.Fatal(err)
			}
			j, err = s.nextRuntimeInstallJob()
			if err != nil || j.ID != original.ID || j.Payload != original.Payload {
				t.Fatal("recovery changed original task", j, err)
			}
			if retry, err := s.takeRuntimeNativeRetry(j); err != nil || retry {
				t.Fatal("restart restored consumed human authorization", retry, err)
			}
			var actor string
			var consumed sql.NullString
			if err := s.DB.QueryRow(`SELECT actor,consumed_at FROM runtime_native_retry_grants WHERE job_id=?`, j.ID).Scan(&actor, &consumed); err != nil || actor != "private-admin" || !consumed.Valid {
				t.Fatal("durable retry authority lost", actor, consumed, err)
			}
			// A later explicit human retry is a new grant, not automatic recovery.
			if err := s.FinishRuntime(j, "private second failure", nil); err != nil {
				t.Fatal(err)
			}
			if err := s.RetryRuntime(j.ID, "second-admin"); err != nil {
				t.Fatal(err)
			}
			j, err = s.nextRuntimeInstallJob()
			if err != nil {
				t.Fatal(err)
			}
			if retry, err := s.takeRuntimeNativeRetry(j); err != nil || !retry {
				t.Fatal("new explicit retry lost", retry, err)
			}
		})
	}
}

func TestNativeRetryGrantRejectsIdentityStateAndConcurrentReuse(t *testing.T) {
	s := testStore(t)
	j := nativeRetryFixture(t, s, "install_runtime")
	if err := s.RetryRuntime(j.ID, "admin"); err == nil {
		t.Fatal("queued task admitted retry")
	}
	if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state='failed' WHERE id=?`, j.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RetryRuntime(j.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	for _, variant := range []Job{j, {ID: j.ID, TargetID: "other", Kind: j.Kind, Payload: j.Payload}, {ID: j.ID, TargetID: j.TargetID, Kind: "software_install", Payload: j.Payload}} {
		if retry, err := s.takeRuntimeNativeRetry(variant); err == nil || retry {
			t.Fatal("queued or foreign identity consumed grant", variant, retry, err)
		}
	}
	j, err := s.nextRuntimeInstallJob()
	if err != nil {
		t.Fatal(err)
	}
	changed := j
	changed.Payload = `{"unbound":true}`
	if retry, err := s.takeRuntimeNativeRetry(changed); err == nil || retry {
		t.Fatal("unbound payload consumed grant", retry, err)
	}
	var group sync.WaitGroup
	results := make(chan bool, 8)
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			retry, err := s.takeRuntimeNativeRetry(j)
			if err != nil {
				t.Error(err)
			}
			results <- retry
		}()
	}
	group.Wait()
	close(results)
	consumed := 0
	for retry := range results {
		if retry {
			consumed++
		}
	}
	if consumed != 1 {
		t.Fatal("explicit retry was not exactly one grant", consumed)
	}
}

func TestNativeRetryDoesNotChangeSignedRegistryPayloadBinding(t *testing.T) {
	s := testStore(t)
	actor, key := ID(), ID()
	target := runtimecatalog.Apache[0].ID
	item := appcatalog.CatalogItem{ID: "apache", Provider: "runtime", Target: target, Version: "1.0.0", SHA256: strings.Repeat("a", 64)}
	in := registryInstallInput{ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256}
	id, err := s.queueInstallBound(target, key, "admin", s.bindRegistryInstall(item, target, key, actor, in))
	if err != nil {
		t.Fatal(err)
	}
	before, found, err := s.registryInstallReplay(item.ID, actor, key, in)
	if err != nil || !found {
		t.Fatal(before, found, err)
	}
	var payload, boundHash string
	if err := s.DB.QueryRow(`SELECT j.payload,r.job_payload_sha256 FROM runtime_jobs j JOIN app_registry_install_requests r ON r.job_id=j.id WHERE j.id=?`, id).Scan(&payload, &boundHash); err != nil || Hash(payload) != boundHash {
		t.Fatal("original registry binding unavailable", err)
	}
	if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state='needs_attention' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	if err := s.RetryRuntime(id, "admin"); err != nil {
		t.Fatal(err)
	}
	j, err := s.nextRuntimeInstallJob()
	if err != nil {
		t.Fatal(err)
	}
	if retry, err := s.takeRuntimeNativeRetry(j); err != nil || !retry || j.Payload != payload || Hash(j.Payload) != boundHash {
		t.Fatal("retry mutated signed request parameters", j, retry, err)
	}
	after, found, err := s.registryInstallReplay(item.ID, actor, key, in)
	if err != nil || !found || !reflect.DeepEqual(before, after) {
		t.Fatal("original signed request identity changed", before, after, found, err)
	}
}

// Synthetic HTTP only checks the Core dispatch/recovery contract. Genuine
// PID1/unit behavior is separately verified in private native Linux fixtures.
func TestNativeRetryWorkerDispatchesFalseTrueFalseAcrossRecovery(t *testing.T) {
	for _, kind := range []string{"install_runtime", "install_php_extension"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			original := nativeRetryFixture(t, s, kind)
			for round, want := range []bool{false, true, false} {
				if round == 1 {
					if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state='failed' WHERE id=?`, original.ID); err != nil {
						t.Fatal(err)
					}
					if err := s.RetryRuntime(original.ID, "admin"); err != nil {
						t.Fatal(err)
					}
				}
				if round == 2 {
					if err := s.Recover(); err != nil {
						t.Fatal(err)
					}
				}
				j, err := s.nextRuntimeInstallJob()
				if err != nil || j.ID != original.ID {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				requests := make(chan map[string]any, 2)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var in map[string]any
					if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&in) != nil {
						t.Error("unexpected synthetic operation", r.Method, r.URL.Path)
					}
					requests <- in
					cancel() // interruption after dispatch, before any completion
				}))
				client := &ExecutorClient{Client: &http.Client{Transport: rewriteExecutorTransport{base: http.DefaultTransport, url: server.URL}}}
				runRuntimeJob(ctx, s, client, j)
				cancel()
				server.Close()
				select {
				case in := <-requests:
					if in["retry"] != want || in["job_id"] != j.ID || in["release_id"] != j.TargetID {
						t.Fatal("incorrect native restart authority", round, in, want)
					}
				default:
					t.Fatal("native dispatch missing")
				}
				if len(requests) != 0 {
					t.Fatal("worker automatically dispatched again")
				}
				var state, payload string
				if err := s.DB.QueryRow(`SELECT state,payload FROM runtime_jobs WHERE id=?`, j.ID).Scan(&state, &payload); err != nil || state != "running" || payload != original.Payload {
					t.Fatal("interruption falsely completed or mutated task", state, payload, err)
				}
			}
		})
	}
}

func TestNativeRetryAdditiveSchemaReopenPreservesExistingRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	j := nativeRetryFixture(t, s, "install_runtime")
	// Model a pre-grant schema, using only this private test database.
	if _, err := s.DB.Exec(`DROP TABLE runtime_native_retry_grants`); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	var payload string
	if err := s.DB.QueryRow(`SELECT payload FROM runtime_jobs WHERE id=?`, j.ID).Scan(&payload); err != nil || payload != j.Payload {
		t.Fatal("additive upgrade lost original task", payload, err)
	}
	if _, err := s.DB.Exec(`INSERT INTO runtime_native_retry_grants(job_id,actor,granted_at) VALUES(?,'admin',?)`, ID(), Now()); err == nil {
		t.Fatal("retry grant admitted nonexistent task")
	}
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM runtime_native_retry_grants`).Scan(&count); err != nil || count != 0 {
		t.Fatal("schema upgrade fabricated retry authorization", count, err)
	}
}
