package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/appcatalog"
)

func signedVersionFixture(t *testing.T, target, version, queued string) (*Store, identity, Job) {
	t.Helper()
	s := testStore(t)
	u := accessUser(t, s, "version-admin", "admin", nil)
	item := appcatalog.CatalogItem{ID: softwareRegistryAppID(target), Target: target, Provider: "panel-module", Version: version, SHA256: strings.Repeat("a", 64)}
	in := registryInstallInput{ExpectedVersion: version, ExpectedSHA256: item.SHA256}
	id, err := s.queueSoftwareActionBound(target, "install", nil, queued, "original-signed-version", u.Username, s.bindRegistryInstall(item, target, "original-signed-version", u.ID, in))
	if err != nil {
		t.Fatal(err)
	}
	j := Job{ID: id}
	if err = s.DB.QueryRow(`SELECT target_id,kind,payload FROM runtime_jobs WHERE id=?`, id).Scan(&j.TargetID, &j.Kind, &j.Payload); err != nil {
		t.Fatal(err)
	}
	return s, u, j
}

func originalSignedVersionBytes(t *testing.T, s *Store, j Job) []string {
	t.Helper()
	out := make([]string, 3)
	queries := []string{
		`SELECT json_object('id',id,'target',target_id,'kind',kind,'state',state,'error',error,'steps',steps,'payload',payload,'key',idempotency_key,'created',created_at,'updated',updated_at) FROM runtime_jobs WHERE id=?`,
		`SELECT json_object('key',idempotency_key,'actor',actor_id,'app',app_id,'request',request_sha256,'version',version,'digest',sha256,'provider',provider,'scope',scope,'target',target,'job',job_id,'runtime_job',runtime_job_id,'payload',job_payload_sha256,'created',created_at) FROM app_registry_install_requests WHERE job_id=?`,
		`SELECT json_group_array(json_object('job',job_id,'app',app_id,'scope',scope,'version',version,'digest',sha256,'target',target,'provider',provider,'created',created_at)) FROM app_registry_pending WHERE job_id=?`,
	}
	for n, query := range queries {
		if err := s.DB.QueryRow(query, j.ID).Scan(&out[n]); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestSignedInstallVersionAllDeclaredModulesKeepExactIdentity(t *testing.T) {
	// Deliberately derive this domain from the actual compiled catalog; it must
	// grow with the implementation instead of testing a hand-picked short list.
	for _, app := range SoftwareAppCatalog() {
		t.Run(app.ID, func(t *testing.T) {
			s, _, j := signedVersionFixture(t, app.ID, app.Version, app.Version)
			before := originalSignedVersionBytes(t, s, j)
			got, err := softwareInstallExecutionVersion(s.DB, j, app.Version)
			if err != nil || got != app.Version || !reflect.DeepEqual(before, originalSignedVersionBytes(t, s, j)) {
				t.Fatal("selected package identity lost or original rewritten", app.ID, got, err)
			}
		})
	}
}

func TestSignedInstallLegacyEmptyVersionOriginalIsResolvedWithoutMutation(t *testing.T) {
	for _, version := range []string{"1.0", "1.0-compat1", "1.1.0", "1.2.0", "1.3.0", NativeMobileAppVersion} {
		for _, state := range []string{"queued", "failed", "needs_attention", "succeeded"} {
			t.Run(version+"/"+state, func(t *testing.T) {
				s, _, j := signedVersionFixture(t, "mobile-pwa", version, "")
				if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state=?,error='retained original outcome' WHERE id=?`, state, j.ID); err != nil {
					t.Fatal(err)
				}
				if state == "succeeded" {
					if _, err := s.DB.Exec(`DELETE FROM app_registry_pending WHERE job_id=?`, j.ID); err != nil {
						t.Fatal(err)
					}
				}
				before := originalSignedVersionBytes(t, s, j)
				got, err := softwareInstallExecutionVersion(s.DB, j, "")
				if err != nil || got != version || !reflect.DeepEqual(before, originalSignedVersionBytes(t, s, j)) {
					t.Fatal("read-only original resolution changed retained evidence", got, err)
				}
			})
		}
	}
}

func TestSignedInstallVersionRejectsBorrowedOrChangedOriginalBeforeDispatch(t *testing.T) {
	for _, scenario := range []string{"provider", "app", "actor", "scope", "target", "version", "digest", "request-digest", "payload-digest", "key", "payload", "unbound-native", "revoked-native", "mismatched-selection", "different-job", "different-kind"} {
		t.Run(scenario, func(t *testing.T) {
			s, _, j := signedVersionFixture(t, "mobile-pwa", NativeMobileAppVersion, NativeMobileAppVersion)
			query := map[string]string{
				"provider":       `UPDATE app_registry_install_requests SET provider='runtime'`,
				"app":            `UPDATE app_registry_install_requests SET app_id='daily-report'`,
				"actor":          `UPDATE app_registry_install_requests SET actor_id='foreign'`,
				"scope":          `UPDATE app_registry_install_requests SET scope='task-manager'`,
				"target":         `UPDATE app_registry_install_requests SET target='task-manager'`,
				"version":        `UPDATE app_registry_install_requests SET version='1.3.0'`,
				"digest":         `UPDATE app_registry_install_requests SET sha256=upper(sha256)`,
				"request-digest": `UPDATE app_registry_install_requests SET request_sha256='invalid'`,
				"payload-digest": `UPDATE app_registry_install_requests SET job_payload_sha256=upper(job_payload_sha256)`,
				"key":            `UPDATE runtime_jobs SET idempotency_key='another-key'`,
				"payload":        `UPDATE runtime_jobs SET payload='{"settings":{"enabled":true},"version":"1.3.2"}'`,
				"unbound-native": `DELETE FROM app_registry_install_requests`,
				"revoked-native": `UPDATE app_user_roles SET role='viewer'`,
			}[scenario]
			if query != "" {
				if _, err := s.DB.Exec(query); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "different-job" {
				j.ID = ID()
			}
			if scenario == "different-kind" {
				j.Kind = "software_update"
			}
			if scenario == "mismatched-selection" {
				if got, err := softwareInstallExecutionVersion(s.DB, j, "1.3.0"); err == nil || got != "" {
					t.Fatal("borrowed different requested version", got, err)
				}
				return
			}
			if got, err := softwareInstallExecutionVersion(s.DB, j, NativeMobileAppVersion); err == nil || got != "" {
				t.Fatal("changed or unbound signed identity executed", scenario, got, err)
			}
			var calls int
			e := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				t.Error("untrusted original reached privileged executor")
				http.Error(w, "excluded", 500)
			})
			runRuntimeJob(context.Background(), s, e, j)
			if calls != 0 {
				t.Fatal("refusal happened after executor call")
			}
		})
	}
}

func TestSignedInstallWorkerUsesRetainedVersionOnlyInExecutionEnvelope(t *testing.T) {
	s, _, original := signedVersionFixture(t, "mobile-pwa", "1.3.0", "")
	var boundBefore string
	if err := s.DB.QueryRow(`SELECT job_payload_sha256 FROM app_registry_install_requests WHERE job_id=?`, original.ID).Scan(&boundBefore); err != nil {
		t.Fatal(err)
	}
	var calls int
	e := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		var in struct {
			Settings map[string]any `json:"settings"`
			Version  string         `json:"version"`
		}
		if r.Method != "POST" || r.URL.Path != "/v1/software/mobile-pwa/install" || json.NewDecoder(r.Body).Decode(&in) != nil || in.Version != "1.3.0" || in.Settings == nil {
			t.Error("dispatch lost legacy signed package version")
			http.Error(w, "excluded", 500)
			return
		}
		json.NewEncoder(w).Encode(ApplyResult{Status: "installed"})
	})
	j, err := s.NextRuntimeJob()
	if err != nil || j.ID != original.ID {
		t.Fatal(err)
	}
	runRuntimeJob(context.Background(), s, e, j)
	var payload, binding, state string
	if err := s.DB.QueryRow(`SELECT j.payload,i.job_payload_sha256,j.state FROM runtime_jobs j JOIN app_registry_install_requests i ON i.job_id=j.id WHERE j.id=?`, j.ID).Scan(&payload, &binding, &state); err != nil || calls != 1 || payload != original.Payload || binding != boundBefore || Hash(payload) != binding || state != "succeeded" {
		t.Fatal("dispatcher rewrote original payload or binding", calls, state, err)
	}
}

func TestNativeMobileCannotBorrowUnsignedNoopForeignOrRevokedQueueBinding(t *testing.T) {
	for _, action := range []string{"install", "update"} {
		for _, scenario := range []string{"signed", "nil", "noop", "foreign", "revoked"} {
			t.Run(action+"/"+scenario, func(t *testing.T) {
				s := testStore(t)
				u := accessUser(t, s, "native-admin", "admin", nil)
				item := appcatalog.CatalogItem{ID: "mobile", Target: "mobile-pwa", Provider: "panel-module", Version: NativeMobileAppVersion, SHA256: strings.Repeat("b", 64)}
				if scenario == "foreign" {
					item.ID = "daily-report"
				}
				var bind func(*sql.Tx, string, bool) error
				if scenario == "noop" {
					bind = func(*sql.Tx, string, bool) error { return nil }
				} else if scenario != "nil" {
					if action == "install" {
						bind = s.bindRegistryInstall(item, item.Target, "native-mobile-original", u.ID, registryInstallInput{ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256})
					} else {
						bind = s.bindRegistryUpdate(item, item.Target, "native-mobile-original", u.ID)
					}
				}
				if scenario == "revoked" {
					if _, err := s.DB.Exec(`UPDATE app_user_roles SET role='viewer'`); err != nil {
						t.Fatal(err)
					}
				}
				job, err := s.queueSoftwareActionBound("mobile-pwa", action, nil, NativeMobileAppVersion, "native-mobile-original", u.Username, bind)
				if scenario != "signed" {
					if err == nil || job != "" {
						t.Fatal("unsigned native delivery queued", job, err)
					}
					for _, table := range []string{"runtime_jobs", "app_registry_install_requests", "app_registry_update_requests", "app_registry_pending", "audit_logs"} {
						var count int
						if e := s.DB.QueryRow("SELECT count(*)FROM " + table).Scan(&count); e != nil || count != 0 {
							t.Fatal("partial native request", table, count, e)
						}
					}
					return
				}
				if err != nil || !ValidID(job) {
					t.Fatal(job, err)
				}
				if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state='succeeded' WHERE id=?`, job); err != nil {
					t.Fatal(err)
				}
				if _, err := s.DB.Exec(`DELETE FROM app_registry_pending WHERE job_id=?`, job); err != nil {
					t.Fatal(err)
				}
				again, err := s.queueSoftwareActionBound("mobile-pwa", action, nil, NativeMobileAppVersion, "native-mobile-original", u.Username, bind)
				if err != nil || again != job {
					t.Fatal("completed native request adopted or changed", again, err)
				}
				var count int
				if err := s.DB.QueryRow(`SELECT count(*)FROM app_registry_pending`).Scan(&count); err != nil || count != 0 {
					t.Fatal("completed pending recreated", count, err)
				}
			})
		}
	}
}
