package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"local/panel/internal/runtimecatalog"
)

// Core fixtures only, not native stopped-service or installation acceptance.
func TestRuntimeFailedUpgradeRequiresOriginalMatchingClosedFailure(t *testing.T) {
	for _, mutation := range []string{"original", "running", "queued", "uncertain", "success", "wrong-kind", "wrong-target", "changed-error", "changed-steps", "empty-error", "pending-retry", "missing-audit", "duplicate-audit", "missing-result-audit", "duplicate-result-audit", "future", "reversed", "before-create", "missing-job", "cancelled", "unknown-release", "docker", "invalid-id"} {
		t.Run(mutation, func(t *testing.T) {
			s := testStore(t)
			id, err := s.QueueInstall(runtimecatalog.Nginx[0].ID, ID(), "fixture-admin")
			if err != nil {
				t.Fatal(err)
			}
			in := RuntimeFailedInstallEvidence{JobID: id, ReleaseID: runtimecatalog.Nginx[0].ID, Error: "synthetic retained compile failure", Steps: []Step{{Time: Now(), Message: "synthetic retained compile failure"}}}
			if err := s.FinishRuntime(Job{ID: id, TargetID: in.ReleaseID, Kind: "install_runtime"}, in.Error, in.Steps); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			exec := func(query string, args ...any) {
				t.Helper()
				if _, err := s.DB.Exec(query, args...); err != nil {
					t.Fatal(err)
				}
			}
			switch mutation {
			case "running", "queued", "success":
				state := mutation
				if state == "success" {
					state = "succeeded"
				}
				exec("UPDATE runtime_jobs SET state=? WHERE id=?", state, id)
			case "uncertain":
				exec("UPDATE runtime_jobs SET state='needs_attention' WHERE id=?", id)
			case "wrong-kind":
				exec("UPDATE runtime_jobs SET kind='install_php_extension' WHERE id=?", id)
			case "wrong-target":
				exec("UPDATE runtime_jobs SET target_id='nginx-1.30.4' WHERE id=?", id)
			case "changed-error":
				exec("UPDATE runtime_jobs SET error='different' WHERE id=?", id)
			case "changed-steps":
				exec("UPDATE runtime_jobs SET steps='[]' WHERE id=?", id)
			case "empty-error":
				in.Error = ""
			case "pending-retry":
				exec("INSERT INTO runtime_native_retry_grants(job_id,actor,granted_at,consumed_at) VALUES(?,?,?,NULL)", id, "fixture-admin", Now())
			case "missing-audit":
				exec("DELETE FROM audit_logs WHERE action='runtime.install'")
			case "duplicate-audit":
				exec("INSERT INTO audit_logs(actor,action,target,result,created_at) SELECT actor,action,target,result,created_at FROM audit_logs WHERE action='runtime.install'")
			case "missing-result-audit":
				exec("DELETE FROM audit_logs WHERE action='install_runtime'")
			case "duplicate-result-audit":
				exec("INSERT INTO audit_logs(actor,action,target,result,created_at) SELECT actor,action,target,result,created_at FROM audit_logs WHERE action='install_runtime'")
			case "future":
				exec("UPDATE runtime_jobs SET updated_at=? WHERE id=?", time.Now().UTC().Add(time.Hour).Format(time.RFC3339), id)
			case "reversed":
				exec("UPDATE runtime_jobs SET updated_at='2026-01-01T00:00:00Z' WHERE id=?", id)
			case "before-create":
				in.Steps[0].Time = "2026-01-01T00:00:00Z"
				raw, _ := json.Marshal(in.Steps)
				exec("UPDATE runtime_jobs SET steps=? WHERE id=?", string(raw), id)
			case "missing-job":
				exec("DELETE FROM runtime_jobs WHERE id=?", id)
			case "cancelled":
				cancel()
			case "unknown-release":
				in.ReleaseID = "nginx-latest"
			case "docker":
				in.ReleaseID = "docker-29.0.2"
			case "invalid-id":
				in.JobID = "../" + id
			}
			var before string
			if err := s.DB.QueryRow("SELECT coalesce(group_concat(id||state||error||steps||payload,''),'') FROM runtime_jobs").Scan(&before); err != nil {
				t.Fatal(err)
			}
			digest, err := s.ValidateRuntimeFailedInstall(ctx, in)
			if mutation == "original" {
				if err != nil || len(digest) != 64 || strings.Trim(digest, "0123456789abcdef") != "" {
					t.Fatal(digest, err)
				}
			} else if err == nil || digest != "" {
				t.Fatal("unbound/active failure accepted", mutation, digest, err)
			}
			var after string
			if err := s.DB.QueryRow("SELECT coalesce(group_concat(id||state||error||steps||payload,''),'') FROM runtime_jobs").Scan(&after); err != nil || before != after {
				t.Fatal("validation changed original jobs", err)
			}
			var installations int
			if err := s.DB.QueryRow("SELECT count(*) FROM runtime_installations WHERE id=?", in.ReleaseID).Scan(&installations); err != nil || installations != 0 {
				t.Fatal("failed installation was published", installations, err)
			}
		})
	}
}
