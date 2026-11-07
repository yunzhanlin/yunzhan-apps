package core

import (
	"context"
	"testing"

	"local/panel/internal/runtimecatalog"
)

func TestRuntimeFailedPHPExtensionUpgradeBindsOriginalPayloadAndAudits(t *testing.T) {
	for _, mutation := range []string{"original", "missing-extension", "unknown-extension", "wrong-family", "wrong-kind", "different-payload", "extra-payload", "duplicate-payload", "spaced-payload", "pending-retry", "queued", "running", "uncertain", "succeeded", "missing-queued-audit", "duplicate-queued-audit", "wrong-queued-target", "missing-result-audit", "duplicate-result-audit", "wrong-result-kind", "changed-steps", "changed-error", "cancelled"} {
		t.Run(mutation, func(t *testing.T) {
			s := testStore(t)
			r, _ := runtimecatalog.Find("php-8.5.12")
			if err := s.RecordInstallation(r, "arm64"); err != nil {
				t.Fatal(err)
			}
			id, err := s.QueuePHPExtension(r.ID, "redis-6.3.0", ID(), "fixture-admin")
			if err != nil {
				t.Fatal(err)
			}
			j, err := s.NextRuntimeJob()
			if err != nil || j.ID != id {
				t.Fatal(j, err)
			}
			in := RuntimeFailedInstallEvidence{JobID: id, ReleaseID: r.ID, ExtensionID: "redis-6.3.0", Error: "WAF 源码构建需至少 1 GiB 可用空间，未开始修改", Steps: []Step{{Time: Now(), Message: "核对固定版本目录，等待源码构建锁"}, {Time: Now(), Message: "WAF 源码构建需至少 1 GiB 可用空间，未开始修改"}}}
			if err = s.FinishRuntime(j, in.Error, in.Steps); err != nil {
				t.Fatal(err)
			}
			exec := func(query string, args ...any) {
				t.Helper()
				if _, err := s.DB.Exec(query, args...); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mutation {
			case "missing-extension":
				in.ExtensionID = ""
			case "unknown-extension":
				in.ExtensionID = "redis-latest"
			case "wrong-family":
				in.ReleaseID = "nginx-1.30.6"
			case "wrong-kind":
				exec("UPDATE runtime_jobs SET kind='install_runtime' WHERE id=?", id)
			case "different-payload":
				exec("UPDATE runtime_jobs SET payload='{}' WHERE id=?", id)
			case "extra-payload":
				exec(`UPDATE runtime_jobs SET payload='{"extension_id":"redis-6.3.0","source":"foreign"}' WHERE id=?`, id)
			case "duplicate-payload":
				exec(`UPDATE runtime_jobs SET payload='{"extension_id":"redis-6.3.0","extension_id":"redis-6.3.0"}' WHERE id=?`, id)
			case "spaced-payload":
				exec(`UPDATE runtime_jobs SET payload='{"extension_id": "redis-6.3.0"}' WHERE id=?`, id)
			case "pending-retry":
				exec("INSERT INTO runtime_native_retry_grants(job_id,actor,granted_at,consumed_at) VALUES(?,?,?,NULL)", id, "fixture-admin", Now())
			case "queued", "running", "succeeded":
				exec("UPDATE runtime_jobs SET state=? WHERE id=?", mutation, id)
			case "uncertain":
				exec("UPDATE runtime_jobs SET state='needs_attention' WHERE id=?", id)
			case "missing-queued-audit":
				exec("DELETE FROM audit_logs WHERE action='php.extension.install'")
			case "duplicate-queued-audit":
				exec("INSERT INTO audit_logs(actor,action,target,result,created_at) SELECT actor,action,target,result,created_at FROM audit_logs WHERE action='php.extension.install'")
			case "wrong-queued-target":
				exec("UPDATE audit_logs SET target=? WHERE action='php.extension.install'", r.ID)
			case "missing-result-audit":
				exec("DELETE FROM audit_logs WHERE action='install_php_extension'")
			case "duplicate-result-audit":
				exec("INSERT INTO audit_logs(actor,action,target,result,created_at) SELECT actor,action,target,result,created_at FROM audit_logs WHERE action='install_php_extension'")
			case "wrong-result-kind":
				exec("UPDATE audit_logs SET action='install_runtime' WHERE action='install_php_extension'")
			case "changed-steps":
				exec("UPDATE runtime_jobs SET steps='[]' WHERE id=?", id)
			case "changed-error":
				exec("UPDATE runtime_jobs SET error='other' WHERE id=?", id)
			case "cancelled":
				cancel()
			}
			var before, after string
			if err = s.DB.QueryRow("SELECT state||error||steps||payload||idempotency_key FROM runtime_jobs WHERE id=?", id).Scan(&before); err != nil {
				t.Fatal(err)
			}
			digest, err := s.ValidateRuntimeFailedInstall(ctx, in)
			if mutation == "original" {
				if err != nil || len(digest) != 64 {
					t.Fatal(digest, err)
				}
			} else if err == nil || digest != "" {
				t.Fatal("unbound extension failure accepted", mutation, digest, err)
			}
			if err = s.DB.QueryRow("SELECT state||error||steps||payload||idempotency_key FROM runtime_jobs WHERE id=?", id).Scan(&after); err != nil || before != after {
				t.Fatal("original failed request changed", err)
			}
			var installed int
			if err = s.DB.QueryRow("SELECT count(*) FROM php_extensions").Scan(&installed); err != nil || installed != 0 {
				t.Fatal("failure published an extension", installed, err)
			}
		})
	}
}
