package core

import (
	"context"
	"strings"
	"testing"
)

func TestLoadBalanceStreamInstallUpgradeOriginalLiveGrantOnly(t *testing.T) {
	for _, action := range []string{"install", "update"} {
		t.Run(action, func(t *testing.T) {
			s, _, job, _ := streamInstallFixture(t, action, true)
			ctx := context.Background()
			grant, err := s.LoadBalanceStreamInstallAuthority(ctx, job)
			if err != nil {
				t.Fatal(err)
			}
			before := streamInstallSnapshot(t, s)
			if _, err = s.LoadBalanceStreamInstallUpgradeJobs(ctx, nil); err == nil {
				t.Fatal("pending native request disappeared")
			}
			jobs, err := s.LoadBalanceStreamInstallUpgradeJobs(ctx, &grant)
			if err != nil || len(jobs) != 1 || jobs[0].Authority != grant || jobs[0].State != "running" {
				t.Fatal("exact original live grant refused", err)
			}
			for _, corrupt := range []func(*LoadBalanceStreamInstallAuthority){
				func(v *LoadBalanceStreamInstallAuthority) { v.JobID = ID() },
				func(v *LoadBalanceStreamInstallAuthority) { v.AccessRevision++ },
				func(v *LoadBalanceStreamInstallAuthority) { v.ManifestSHA256 = strings.Repeat("2", 64) },
				func(v *LoadBalanceStreamInstallAuthority) { v.ActorObservationSHA256 = strings.Repeat("3", 64) },
			} {
				v := grant
				corrupt(&v)
				if _, err = s.LoadBalanceStreamInstallUpgradeJobs(ctx, &v); err == nil {
					t.Fatal("caller supplied skip authority accepted")
				}
			}
			if before != streamInstallSnapshot(t, s) {
				t.Fatal("SELECT-only census changed original records")
			}
		})
	}
}

func TestLoadBalanceStreamInstallUpgradeUncertainAndRevokedNeverEmpty(t *testing.T) {
	for _, mutation := range []string{
		"UPDATE load_balance_stream_install_requests SET access_revision=access_revision+1",
		"DELETE FROM load_balance_stream_install_requests",
		"DROP TABLE load_balance_stream_install_requests",
		"DELETE FROM app_registry_pending",
		"DELETE FROM app_registry_update_requests",
		"DELETE FROM audit_logs WHERE action='app.load-balance.stream.install-request'",
		"UPDATE runtime_jobs SET state='needs_attention'",
		"UPDATE runtime_jobs SET state='queued'",
		"UPDATE runtime_jobs SET payload='{\"version\":\"1.9.0\",\"settings\":null}'",
		"UPDATE load_balance_stream_install_requests SET created_at=printf('%4096s','x')",
	} {
		t.Run(mutation, func(t *testing.T) {
			s, _, job, _ := streamInstallFixture(t, "update", true)
			ctx := context.Background()
			grant, err := s.LoadBalanceStreamInstallAuthority(ctx, job)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.DB.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			if _, err = s.LoadBalanceStreamInstallUpgradeJobs(ctx, &grant); err == nil {
				t.Fatal("uncertainty admitted with claimed original")
			}
			if _, err = s.LoadBalanceStreamInstallUpgradeJobs(ctx, nil); err == nil {
				t.Fatal("uncertainty treated as empty")
			}
		})
	}
}

func TestLoadBalanceStreamInstallUpgradeTerminalStillRequiresRootClosure(t *testing.T) {
	for _, state := range []string{"failed", "cancelled", "succeeded"} {
		t.Run(state, func(t *testing.T) {
			s, _, job, _ := streamInstallFixture(t, "update", true)
			ctx := context.Background()
			grant, err := s.LoadBalanceStreamInstallAuthority(ctx, job)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.DB.Exec("UPDATE runtime_jobs SET state=? WHERE id=?", state, job); err != nil {
				t.Fatal(err)
			}
			if _, err = s.DB.Exec("DELETE FROM app_registry_pending WHERE job_id=?", job); err != nil {
				t.Fatal(err)
			}
			if state == "succeeded" {
				if _, err = s.LoadBalanceStreamInstallUpgradeJobs(ctx, nil); err == nil {
					t.Fatal("success label without registry receipt accepted")
				}
				if _, err = s.DB.Exec("INSERT INTO app_registry_receipts VALUES('load-balance','load-balance',?,?,'load-balance',?)", grant.AppVersion, grant.ManifestSHA256, Now()); err != nil {
					t.Fatal(err)
				}
			}
			jobs, err := s.LoadBalanceStreamInstallUpgradeJobs(ctx, nil)
			if err != nil || len(jobs) != 1 || jobs[0].State != state || jobs[0].Authority != grant {
				t.Fatal("terminal history was dropped, not returned for independent Root proof", err)
			}
			if _, err = s.LoadBalanceStreamInstallUpgradeJobs(ctx, &grant); err == nil {
				t.Fatal("terminal job became live authority")
			}
		})
	}
}

func TestLoadBalanceStreamInstallUpgradeEmptyOldSchemaOnly(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	for _, absent := range []bool{false, true} {
		if absent {
			if _, err := s.DB.Exec("DROP TABLE load_balance_stream_install_requests"); err != nil {
				t.Fatal(err)
			}
		}
		jobs, err := s.LoadBalanceStreamInstallUpgradeJobs(ctx, nil)
		if err != nil || len(jobs) != 0 {
			t.Fatal("unactivated empty schema refused", err)
		}
	}
	if _, err := s.DB.Exec("INSERT INTO runtime_jobs(id,target_id,kind,state,payload,idempotency_key,created_at,updated_at)VALUES(?,'load-balance','software_install','failed',?, ?,?,?)", ID(), `{"settings":{},"version":"1.9.0"}`, ID(), Now(), Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadBalanceStreamInstallUpgradeJobs(ctx, nil); err == nil {
		t.Fatal("lost grant after historical native job treated as old empty schema")
	}
}

func TestLoadBalanceStreamInstallUpgradeMissingSchemaCannotHideOtherPendingVersions(t *testing.T) {
	for _, payload := range []string{`{"settings":{},"version":"1.8.5"}`, `{"settings":{},"version":"1.9.1"}`, `{"settings":{},"version":"2.0.0"}`, `{"version":`, strings.Repeat("x", 2048)} {
		t.Run(payload[:min(len(payload), 70)], func(t *testing.T) {
			s := testStore(t)
			if _, err := s.DB.Exec("DROP TABLE load_balance_stream_install_requests"); err != nil {
				t.Fatal(err)
			}
			job := ID()
			if _, err := s.DB.Exec("INSERT INTO runtime_jobs(id,target_id,kind,state,payload,idempotency_key,created_at,updated_at)VALUES(?,'load-balance','software_install','queued',?,?,?,?)", job, payload, ID(), Now(), Now()); err != nil {
				t.Fatal(err)
			}
			if _, err := s.LoadBalanceStreamInstallUpgradeJobs(context.Background(), nil); err == nil {
				t.Fatal("missing native schema hid another pending version/payload")
			}
			var state string
			if s.DB.QueryRow("SELECT state FROM runtime_jobs WHERE id=?", job).Scan(&state) != nil || state != "queued" {
				t.Fatal("read-only fence edited queued original work")
			}
		})
	}
}
