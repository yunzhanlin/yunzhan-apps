package core

import (
	"context"
	"local/panel/internal/appcatalog"
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

func TestLoadBalanceStreamLegacyPreflightRetainsOriginalHistory(t *testing.T) {
	const prefix = "TCP/UDP 原安装没有可核对的完整原生完成回执；保留原任务，只允许观察，不重新派发；执行服务：TCP/UDP 安装阶段[系统前置条件]: TCP/UDP 安装阶段["
	const suffix = "]: TCP/UDP 独立服务的完整两代配置、专用身份、内核隔离或可用资源无法核对；未启动或重载服务"
	failure := strings.TrimSuffix(prefix, "TCP/UDP 安装阶段[系统前置条件]: TCP/UDP 安装阶段[")
	for detail, want := range map[string]string{
		prefix + "资源余量" + suffix:      LoadBalanceStreamInstallMemory,
		prefix + "Nginx 运行时" + suffix: LoadBalanceStreamInstallNginx,
		failure + "TCP/UDP 安装阶段[已有原生任务]: native program operation is active, failed or transitional; upgrade refused": LoadBalanceStreamRetainedQueueRefusal,
		failure + "TCP/UDP 安装阶段[原生父进程启动与退出]: TCP/UDP 原始私有事务文件、持有描述符或运行租约无法核对；保留原始结果，不重放或修复":                           LoadBalanceStreamRetainedParentExit,
	} {
		t.Run(want, func(t *testing.T) {
			s, _, id, _ := streamInstallFixture(t, "install", true)
			ctx := context.Background()
			grant, err := s.LoadBalanceStreamInstallAuthority(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			job := Job{ID: id, TargetID: "load-balance", Kind: "software_install", Payload: `{"settings":{},"version":"1.9.0"}`}
			if err = s.finishRuntime(job, detail, nil, true); err != nil {
				t.Fatal(err)
			}
			if _, err = s.LoadBalanceStreamInstallUpgradeJobs(ctx, nil); err == nil {
				t.Fatal("still-pending original receipt accepted")
			}
			if err = (&Server{Store: s}).reconcileRegistryReceipts(ctx); err != nil {
				t.Fatal(err)
			}
			before := streamInstallSnapshot(t, s)
			jobs, err := s.LoadBalanceStreamInstallUpgradeJobs(ctx, nil)
			if err != nil || len(jobs) != 1 || jobs[0].Authority != grant || jobs[0].State != "needs_attention" || jobs[0].RetainedRefusal != want {
				t.Fatal("exact retained refusal missing from independent Root census", jobs, err)
			}
			if _, err = s.LoadBalanceStreamInstallUpgradeJobs(ctx, &grant); err == nil {
				t.Fatal("historical refusal obtained live dispatch grant")
			}
			if err = s.RetryRuntime(id, "admin"); err == nil || streamInstallSnapshot(t, s) != before {
				t.Fatal("read-only reconciliation or denied retry changed history")
			}
		})
	}
}

func TestLoadBalanceStreamLegacyPreflightRefusesIncompleteEvidence(t *testing.T) {
	for name, mutation := range map[string]string{
		"extra error":     "UPDATE runtime_jobs SET error=error||' additional detail'",
		"wrong stage":     "UPDATE runtime_jobs SET error=replace(error,'Nginx 运行时','系统身份源')",
		"start attempted": "UPDATE runtime_jobs SET steps='[]'",
		"missing audit":   "DELETE FROM audit_logs WHERE actor='executor'",
		"duplicate audit": "INSERT INTO audit_logs(actor,action,target,result,created_at) SELECT actor,action,target,result,created_at FROM audit_logs WHERE actor='executor'",
		"wrong timestamp": "UPDATE audit_logs SET created_at='2026-01-01T00:00:00Z' WHERE actor='executor'",
		"absent binding":  "DELETE FROM load_balance_stream_install_requests",
		"false success":   "INSERT INTO app_registry_receipts VALUES('load-balance','load-balance','1.9.0',printf('%064d',1),'load-balance','2026-01-01T00:00:00Z')",
	} {
		t.Run(name, func(t *testing.T) {
			s, _, id, _ := streamInstallFixture(t, "install", true)
			ctx := context.Background()
			job := Job{ID: id, TargetID: "load-balance", Kind: "software_install", Payload: `{"settings":{},"version":"1.9.0"}`}
			const old = "TCP/UDP 原安装没有可核对的完整原生完成回执；保留原任务，只允许观察，不重新派发；执行服务：TCP/UDP 安装阶段[系统前置条件]: TCP/UDP 安装阶段[Nginx 运行时]: TCP/UDP 独立服务的完整两代配置、专用身份、内核隔离或可用资源无法核对；未启动或重载服务"
			if err := s.finishRuntime(job, old, nil, true); err != nil {
				t.Fatal(err)
			}
			if err := (&Server{Store: s}).reconcileRegistryReceipts(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			before := streamInstallSnapshot(t, s)
			if _, err := s.LoadBalanceStreamInstallUpgradeJobs(ctx, nil); err == nil {
				t.Fatal("damaged original accepted")
			}
			if streamInstallSnapshot(t, s) != before {
				t.Fatal("failed census changed original evidence")
			}
		})
	}
}

func TestLoadBalanceStreamLegacyPreflightAllowsOnlyDistinctNewSignedRequest(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "incomplete"}[reject], func(t *testing.T) {
			s, user, oldID, _ := streamInstallFixture(t, "install", true)
			ctx := t.Context()
			const payload = `{"settings":{},"version":"1.9.0"}`
			const detail = "TCP/UDP 原安装没有可核对的完整原生完成回执；保留原任务，只允许观察，不重新派发；执行服务：TCP/UDP 安装阶段[系统前置条件]: TCP/UDP 安装阶段[Nginx 运行时]: TCP/UDP 独立服务的完整两代配置、专用身份、内核隔离或可用资源无法核对；未启动或重载服务"
			old := Job{ID: oldID, TargetID: "load-balance", Kind: "software_install", Payload: payload}
			if err := s.finishRuntime(old, detail, nil, true); err != nil {
				t.Fatal(err)
			}
			if err := (&Server{Store: s}).reconcileRegistryReceipts(ctx); err != nil {
				t.Fatal(err)
			}
			if reject {
				if _, err := s.DB.Exec("DELETE FROM audit_logs WHERE actor='executor'"); err != nil {
					t.Fatal(err)
				}
			}
			before := streamInstallSnapshot(t, s)
			id, key, now := ID(), ID(), Now()
			tx, err := s.DB.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err = tx.Exec(`INSERT INTO runtime_jobs(id,target_id,kind,state,payload,idempotency_key,created_at,updated_at)
				VALUES(?,'load-balance','software_install','queued',?,?,?,?)`, id, payload, key, now, now); err != nil {
				t.Fatal(err)
			}
			item := appcatalog.CatalogItem{ID: "load-balance", Target: "load-balance", Version: "1.9.0", SHA256: strings.Repeat("1", 64), Provider: "panel-module"}
			bind := s.bindRegistryInstall(item, item.Target, key, user.ID, registryInstallInput{Settings: map[string]any{}, ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256})
			err = s.bindLoadBalanceStreamRegistryRequest(user.ID, key, item.Target, item.Version, bind)(tx, id, false)
			if reject {
				if err == nil {
					t.Fatal("a distinct request accepted missing original history")
				}
				if err = tx.Rollback(); err != nil || streamInstallSnapshot(t, s) != before {
					t.Fatal("refused request persisted new records", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			if _, err = s.DB.Exec("UPDATE runtime_jobs SET state='running' WHERE id=?", id); err != nil {
				t.Fatal(err)
			}
			grant, err := s.LoadBalanceStreamInstallAuthority(ctx, id)
			if err != nil || grant.JobID != id {
				t.Fatal("new original did not reach normal execution admission", err)
			}
			jobs, err := s.LoadBalanceStreamInstallUpgradeJobs(ctx, &grant)
			if err != nil || len(jobs) != 2 {
				t.Fatal("new and historical authorities did not coexist", jobs, err)
			}
			for _, j := range jobs {
				if j.Authority.JobID == oldID && (j.State != "needs_attention" || j.RetainedRefusal != LoadBalanceStreamInstallNginx) {
					t.Fatal("historical refusal was relabeled or granted authority")
				}
			}
			kept, err := s.Job(oldID)
			if err != nil || kept.Error != detail || kept.State != "needs_attention" || !kept.RetryBlocked {
				t.Fatal("original request changed after distinct admission", kept, err)
			}
		})
	}
}
