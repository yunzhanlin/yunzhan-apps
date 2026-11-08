//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

// Isolated actual Root SQLite/WAL only. This fixture does not call a production
// account creator, service, real panel DB or application installation endpoint.
func streamInstallAuthorityNativeFixture(t *testing.T, action string) (string, *core.Store, core.LoadBalanceStreamInstallAuthority) {
	t.Helper()
	streamAuthorityNativeAnchor(t)
	return streamInstallAuthorityNativeFixtureChecked(t, action)
}

// Caller has already validated its distinct original Root-only native case.
// No production code or RPC can use this test fixture constructor.
func streamInstallAuthorityNativeFixtureChecked(t *testing.T, action string) (string, *core.Store, core.LoadBalanceStreamInstallAuthority) {
	t.Helper()
	base := filepath.Join(t.TempDir(), "core")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	writer, err := core.OpenStore(filepath.Join(base, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { writer.DB.Close() })
	writer.DB.SetMaxOpenConns(1)
	const definition = "CREATE TABLE IF NOT EXISTS load_balance_stream_install_requests(job_id TEXT PRIMARY KEY NOT NULL,actor_id TEXT NOT NULL,access_revision INTEGER NOT NULL CHECK(access_revision>0),actor_observation_sha256 TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('software_install','software_update')),payload_sha256 TEXT NOT NULL,manifest_sha256 TEXT NOT NULL,request_sha256 TEXT NOT NULL,key_sha256 TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL,CHECK(length(job_id)=32 AND length(actor_id)=32 AND length(actor_observation_sha256)=64 AND length(payload_sha256)=64 AND length(manifest_sha256)=64 AND length(request_sha256)=64 AND length(key_sha256)=64))"
	job, actor, key, now := core.ID(), core.ID(), core.ID(), core.Now()
	manifest := strings.Repeat("1", 64)
	payload := `{"settings":{},"version":"` + loadbalancestream.AppVersion + `"}`
	if action == "update" {
		payload = `{"settings":null,"version":"` + loadbalancestream.AppVersion + `"}`
	}
	for _, q := range []struct {
		text string
		args []any
	}{
		{definition, nil},
		{`INSERT INTO users(id,username,password_hash,created_at)VALUES(?,'isolated-original-installer',X'00',?)`, []any{actor, now}},
		{`INSERT INTO app_user_roles(user_id,role,site_ids)VALUES(?,'admin','[]')`, []any{actor}},
		{`INSERT INTO runtime_jobs(id,target_id,kind,state,payload,idempotency_key,created_at,updated_at)VALUES(?,'load-balance',?,'running',?,?,?,?)`, []any{job, "software_" + action, payload, key, now, now}},
		{`INSERT INTO app_registry_pending(job_id,app_id,scope,version,sha256,target,provider,created_at)VALUES(?,'load-balance','load-balance',?,?,'load-balance','panel-module',?)`, []any{job, loadbalancestream.AppVersion, manifest, now}},
	} {
		if _, err = writer.DB.Exec(q.text, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	var requestHash string
	if action == "install" {
		request := struct {
			Settings map[string]any `json:"settings"`
			Name     string         `json:"name"`
			HostPort int            `json:"host_port"`
			Version  string         `json:"expected_version"`
			SHA      string         `json:"expected_sha256"`
		}{map[string]any{}, "", 0, loadbalancestream.AppVersion, manifest}
		raw, e := json.Marshal(request)
		if e != nil {
			t.Fatal(e)
		}
		requestHash = core.Hash(string(raw))
		_, err = writer.DB.Exec(`INSERT INTO app_registry_install_requests(idempotency_key,actor_id,app_id,request_sha256,version,sha256,provider,scope,target,job_id,runtime_job_id,job_payload_sha256,created_at)VALUES(?,?,'load-balance',?,?,?,'panel-module','load-balance','load-balance',?,?,?,?)`, key, actor, requestHash, loadbalancestream.AppVersion, manifest, job, job, core.Hash(payload), now)
	} else {
		_, err = writer.DB.Exec(`INSERT INTO app_registry_update_requests(idempotency_key,actor_id,app_id,version,sha256,provider,scope,job_id,created_at)VALUES(?,?,'load-balance',?,?,'panel-module','load-balance',?,?)`, key, actor, loadbalancestream.AppVersion, manifest, job, now)
		raw, e := json.Marshal([]string{actor, "load-balance", key, job, loadbalancestream.AppVersion, manifest, "panel-module", "load-balance", payload, now})
		if e != nil {
			t.Fatal(e)
		}
		requestHash = core.Hash(string(raw))
	}
	if err != nil {
		t.Fatal(err)
	}
	access, err := writer.UserAccess(actor)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(access)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.DB.Exec(`INSERT INTO load_balance_stream_install_requests(job_id,actor_id,access_revision,actor_observation_sha256,kind,payload_sha256,manifest_sha256,request_sha256,key_sha256,created_at)VALUES(?,?,?,?,?,?,?,?,?,?)`, job, actor, access.Revision, core.Hash(string(raw)), "software_"+action, core.Hash(payload), manifest, requestHash, core.Hash(key), now); err != nil {
		t.Fatal(err)
	}
	// Force a live uncheckpointed WAL record before opening the Root reader.
	if _, err = writer.DB.Exec("UPDATE users SET username='isolated-original-live-wal'"); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		file := filepath.Join(base, "panel.db"+suffix)
		if _, err := os.Lstat(file); os.IsNotExist(err) {
			continue
		}
		if err := os.Chmod(file, 0600); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := writer.LoadBalanceStreamInstallAuthority(context.Background(), job)
	if err != nil {
		t.Fatal("actual private original grant", err)
	}
	return base, writer, expected
}

func TestLoadBalanceStreamCoreAuthorityNativeOriginalInstallGrantSelectOnly(t *testing.T) {
	for _, action := range []string{"install", "update"} {
		t.Run(action, func(t *testing.T) {
			base, _, expected := streamInstallAuthorityNativeFixture(t, action)
			source, err := openMemcachedUpdateCoreAuthorityAt(context.Background(), base, 0)
			if err != nil {
				t.Fatal(err)
			}
			r := &loadBalanceStreamCoreAuthority{source: source}
			defer r.close()
			if r.checkInstall(context.Background(), expected) != nil {
				t.Fatal("original live-WAL installation prerequisite refused")
			}
			if _, err := source.db.Exec("DELETE FROM load_balance_stream_install_requests"); err == nil {
				t.Fatal("Root authority reader could write original grants")
			}
			for _, fault := range []string{"actor", "revision", "manifest", "key", "payload", "request", "action", "version", "job"} {
				t.Run(fault, func(t *testing.T) {
					changed := expected
					switch fault {
					case "actor":
						changed.ActorID = core.ID()
					case "revision":
						changed.AccessRevision++
					case "manifest":
						changed.ManifestSHA256 = strings.Repeat("9", 64)
					case "key":
						changed.KeySHA256 = strings.Repeat("9", 64)
					case "payload":
						changed.PayloadSHA256 = strings.Repeat("9", 64)
					case "request":
						changed.OriginalRequestSHA256 = strings.Repeat("9", 64)
					case "action":
						changed.Action = "configure"
					case "version":
						changed.AppVersion = "1.8.5"
					case "job":
						changed.JobID = core.ID()
					}
					if r.checkInstall(context.Background(), changed) == nil {
						t.Fatal("foreign claimed original installation binding accepted", fault)
					}
				})
			}
		})
	}
}

func TestLoadBalanceStreamCoreAuthorityNativeInstallOriginalRevisionWALRevocation(t *testing.T) {
	for _, action := range []string{"install", "update"} {
		t.Run(action, func(t *testing.T) {
			base, writer, expected := streamInstallAuthorityNativeFixture(t, action)
			source, err := openMemcachedUpdateCoreAuthorityAt(context.Background(), base, 0)
			if err != nil {
				t.Fatal(err)
			}
			r := &loadBalanceStreamCoreAuthority{source: source}
			defer r.close()
			if r.checkInstall(context.Background(), expected) != nil {
				t.Fatal("original prerequisite refused")
			}
			if _, err = writer.DB.Exec("UPDATE app_user_roles SET role='viewer'"); err != nil {
				t.Fatal(err)
			}
			if r.checkInstall(context.Background(), expected) == nil {
				t.Fatal("live WAL revoke ignored")
			}
			// Restored full access is a NEW synthetic revision, not restoration of
			// the original once-issued native install grant.
			if _, err = writer.DB.Exec("UPDATE app_user_roles SET role='admin'"); err != nil {
				t.Fatal(err)
			}
			if _, err = writer.DB.Exec("INSERT INTO app_user_menus VALUES(?,'null',3)", expected.ActorID); err != nil {
				t.Fatal(err)
			}
			if r.checkInstall(context.Background(), expected) == nil {
				t.Fatal("restored role silently renewed the original grant")
			}
			var revision int64
			if source.db.QueryRow("SELECT access_revision FROM load_balance_stream_install_requests WHERE job_id=?", expected.JobID).Scan(&revision) != nil || revision != expected.AccessRevision {
				t.Fatal("refusal rewrote original authorization history")
			}
		})
	}
}

func TestLoadBalanceStreamCoreAuthorityNativeMissingInstallHistoryNotAdopted(t *testing.T) {
	for _, action := range []string{"install", "update"} {
		t.Run(action, func(t *testing.T) {
			base, writer, expected := streamInstallAuthorityNativeFixture(t, action)
			source, err := openMemcachedUpdateCoreAuthorityAt(context.Background(), base, 0)
			if err != nil {
				t.Fatal(err)
			}
			r := &loadBalanceStreamCoreAuthority{source: source}
			defer r.close()
			if r.checkInstall(context.Background(), expected) != nil {
				t.Fatal("original prerequisite refused")
			}
			if _, err = writer.DB.Exec("DROP TABLE load_balance_stream_install_requests"); err != nil {
				t.Fatal(err)
			}
			if r.checkInstall(context.Background(), expected) == nil {
				t.Fatal("remaining signed job/pending row adopted missing original authorization")
			}
			var count int
			if writer.DB.QueryRow("SELECT count(*)FROM sqlite_master WHERE tbl_name='load_balance_stream_install_requests'").Scan(&count) != nil || count != 0 {
				t.Fatal("Root read-only observation recreated history")
			}
		})
	}
}
