package core

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"local/panel/internal/runtimecatalog"
)

func publicationStepsFixture(release, stamp string) []Step {
	messages := []string{"核对固定版本目录，等待源码构建锁", "本次安装总时限 240 分钟；超时即失败，不发布未校验程序", "已从官方站点下载源码，并通过目录中固定的 SHA-256 校验"}
	if release == "php-8.2.35" || release == "php-8.3.36" {
		messages = append(messages, "已逐字节核对 fileinfo 原始数据库；仅使用审核过的低内存构建表示，保留原文件、全部扩展及优化参数")
	}
	messages = append(messages, "以独立构建用户配置精确版本及固定模块")
	if release == "php-8.2.35" || release == "php-8.3.36" {
		messages = append(messages, "已启用固定 GCC 低内存编译策略；保留 -O2 和全部扩展，安装单元硬限 1 GiB、零交换，启动前保留 512 MiB 主机余量")
	}
	messages = append(messages, "开始源码编译（1 个并行任务）；完整构建日志保存在专用缓存目录", "编译完成，安装到暂存目录", RuntimePHPPublicationStep, "独立目录安装完成；精确版本与固定构建模块核对通过")
	var out []Step
	for _, message := range messages {
		out = append(out, Step{Time: stamp, Message: message})
	}
	return out
}

func TestRuntimePHPPublicationRequiresCompleteNewSourceBuild(t *testing.T) {
	for _, release := range []string{"php-8.2.35", "php-8.3.36", "php-8.4.27", "php-8.5.12"} {
		steps := publicationStepsFixture(release, Now())
		if !RuntimePHPPublicationSteps(release, steps) {
			t.Fatal("exact complete build refused", release)
		}
		for i := range steps {
			changed := append([]Step(nil), steps...)
			changed[i].Message += " "
			if RuntimePHPPublicationSteps(release, changed) || RuntimePHPPublicationSteps(release, append(steps[:i:i], steps[i+1:]...)) {
				t.Fatal("missing or changed phase accepted", release, i)
			}
		}
		if RuntimePHPPublicationSteps(release, []Step{{Now(), "该精确版本已安装，清单、程序文件与实际程序精确版本核对通过；未重新安装"}}) || RuntimePHPPublicationSteps(release, append(steps, Step{Now(), "unknown"})) {
			t.Fatal("no-op or extra authority accepted", release)
		}
	}
	for _, release := range []string{"php-8.2.33", "php-5.2.17", "nginx-1.30.6", "php-latest", "../php-8.2.35"} {
		if RuntimePHPPublicationSteps(release, publicationStepsFixture("php-8.2.35", Now())) {
			t.Fatal("unknown or non-PHP publisher accepted", release)
		}
	}
}

func runtimePublicationCoreSnapshot(t *testing.T, s *Store) map[string][][]any {
	t.Helper()
	out := map[string][][]any{}
	for _, table := range []string{"runtime_jobs", "runtime_installations", "runtime_versions", "runtime_instances", "runtime_native_retry_grants", "sites", "audit_logs"} {
		rows, err := s.DB.Query("SELECT * FROM " + table + " ORDER BY rowid")
		if err != nil {
			t.Fatal(err)
		}
		columns, _ := rows.Columns()
		for rows.Next() {
			values, pointers := make([]any, len(columns)), make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			if rows.Scan(pointers...) != nil {
				t.Fatal("snapshot scan")
			}
			out[table] = append(out[table], values)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
	}
	return out
}

func runtimeSupersededCoreFixture(t *testing.T, arch string) (*Store, RuntimeSupersededCompileOOMEvidence) {
	t.Helper()
	s := testStore(t)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := s.DB.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	base := time.Now().UTC().Truncate(time.Second)
	at := func(n int) string { return base.Add(time.Duration(n) * time.Second).Format(time.RFC3339) }
	r, _ := runtimecatalog.Find("php-8.2.35")
	old, err := s.QueueInstall(r.ID, ID(), "fixture-admin")
	if err != nil {
		t.Fatal(err)
	}
	exec("UPDATE runtime_jobs SET created_at=? WHERE id=?", at(-30), old)
	exec("UPDATE audit_logs SET created_at=? WHERE action='runtime.install'", at(-30))
	oldSteps := compileOOMStepsFixture()
	for i := range oldSteps {
		oldSteps[i].Time = at(-29)
	}
	if err := s.FinishRuntime(Job{ID: old, TargetID: r.ID, Kind: "install_runtime"}, RuntimeCompileOOMError, oldSteps); err != nil {
		t.Fatal(err)
	}
	exec("UPDATE runtime_jobs SET updated_at=? WHERE id=?", at(-25), old)
	exec("UPDATE audit_logs SET created_at=? WHERE result='failed' AND action='install_runtime'", at(-25))
	id, err := s.QueueInstall(r.ID, ID(), "fixture-admin")
	if err != nil {
		t.Fatal(err)
	}
	exec("UPDATE runtime_jobs SET created_at=? WHERE id=?", at(-20), id)
	exec("UPDATE audit_logs SET created_at=? WHERE action='runtime.install' AND created_at<>?", at(-20), at(-30))
	steps := publicationStepsFixture(r.ID, at(-10))
	steps[len(steps)-2].Time, steps[len(steps)-1].Time = at(-4), at(-3)
	if err := s.RecordInstallation(r, arch); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishRuntime(Job{ID: id, TargetID: r.ID, Kind: "install_runtime"}, "", steps); err != nil {
		t.Fatal(err)
	}
	exec("UPDATE runtime_jobs SET updated_at=? WHERE id=?", at(-2), id)
	exec("UPDATE audit_logs SET created_at=? WHERE result='succeeded' AND action='install_runtime'", at(-2))
	return s, RuntimeSupersededCompileOOMEvidence{Original: RuntimeCompileOOMInstallEvidence{JobID: old, ReleaseID: r.ID, Steps: oldSteps}, PublisherJobID: id, PublisherSteps: steps, Architecture: arch, InstalledAt: at(-5)}
}

func TestRuntimeSupersededCompileOOMCoreRequiresDistinctBoundPublisherAndNeverWrites(t *testing.T) {
	mutations := []string{"original", "legitimate-site-instance", "same-id", "publisher-id", "old-running", "old-succeeded", "old-error", "old-steps", "old-payload", "old-kind", "old-key", "publisher-running", "publisher-failed", "publisher-error", "publisher-target", "publisher-kind", "publisher-steps", "publisher-payload", "publisher-key", "publisher-before-failure", "publisher-future", "publisher-invalid-time", "publisher-no-op", "publication-before-staging", "publication-after-sealing", "publication-future", "publication-invalid-time", "publication-noncanonical-time", "old-retry", "publisher-retry", "other-active", "other-unknown", "missing-old-queue-audit", "duplicate-old-queue-audit", "missing-old-result", "duplicate-old-result", "missing-publisher-queue-audit", "duplicate-publisher-queue-audit", "missing-publisher-result", "duplicate-publisher-result", "missing-installation", "installation-path", "installation-version", "installation-arch", "installation-state", "installation-clock", "installation-future", "version-source", "version-hash", "version-family", "version-channel", "missing-version", "wrong-architecture", "old-id", "old-release", "cancelled"}
	for _, arch := range []string{"amd64", "arm64"} {
		for _, mutation := range mutations {
			t.Run(arch+"/"+mutation, func(t *testing.T) {
				s, in := runtimeSupersededCoreFixture(t, arch)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				exec := func(query string, args ...any) {
					t.Helper()
					if _, err := s.DB.Exec(query, args...); err != nil {
						t.Fatal(err)
					}
				}
				id := in.PublisherJobID
				switch mutation {
				case "same-id":
					in.PublisherJobID = in.Original.JobID
				case "publisher-id":
					in.PublisherJobID = ID()
				case "old-running", "old-succeeded":
					exec("UPDATE runtime_jobs SET state=? WHERE id=?", strings.TrimPrefix(mutation, "old-"), in.Original.JobID)
				case "old-error":
					exec("UPDATE runtime_jobs SET error='' WHERE id=?", in.Original.JobID)
				case "old-steps":
					exec("UPDATE runtime_jobs SET steps='[]' WHERE id=?", in.Original.JobID)
				case "old-payload":
					exec("UPDATE runtime_jobs SET payload='null' WHERE id=?", in.Original.JobID)
				case "old-kind":
					exec("UPDATE runtime_jobs SET kind='install_php_extension' WHERE id=?", in.Original.JobID)
				case "old-key":
					exec("UPDATE runtime_jobs SET idempotency_key='' WHERE id=?", in.Original.JobID)
				case "publisher-running", "publisher-failed":
					exec("UPDATE runtime_jobs SET state=? WHERE id=?", strings.TrimPrefix(mutation, "publisher-"), id)
				case "publisher-error":
					exec("UPDATE runtime_jobs SET error='retained failure' WHERE id=?", id)
				case "publisher-target":
					exec("UPDATE runtime_jobs SET target_id='php-8.3.36' WHERE id=?", id)
				case "publisher-kind":
					exec("UPDATE runtime_jobs SET kind='install_php_extension' WHERE id=?", id)
				case "publisher-steps":
					exec("UPDATE runtime_jobs SET steps='[]' WHERE id=?", id)
				case "publisher-payload":
					exec("UPDATE runtime_jobs SET payload='null' WHERE id=?", id)
				case "publisher-key":
					exec("UPDATE runtime_jobs SET idempotency_key='' WHERE id=?", id)
				case "publisher-before-failure":
					exec("UPDATE runtime_jobs SET created_at='2026-01-01T00:00:00Z' WHERE id=?", id)
				case "publisher-future":
					exec("UPDATE runtime_jobs SET updated_at=? WHERE id=?", time.Now().UTC().Add(time.Hour).Format(time.RFC3339), id)
				case "publisher-invalid-time":
					exec("UPDATE runtime_jobs SET updated_at='unknown' WHERE id=?", id)
				case "publisher-no-op":
					in.PublisherSteps = []Step{{Now(), "该精确版本已安装，清单、程序文件与实际程序精确版本核对通过；未重新安装"}}
					b, _ := json.Marshal(in.PublisherSteps)
					exec("UPDATE runtime_jobs SET steps=? WHERE id=?", string(b), id)
				case "publication-before-staging":
					in.InstalledAt = in.PublisherSteps[0].Time
					in.InstalledAt = time.Now().UTC().Add(-15 * time.Second).Format(time.RFC3339)
				case "publication-after-sealing":
					in.InstalledAt = time.Now().UTC().Add(-3 * time.Second).Format(time.RFC3339)
				case "publication-future":
					in.InstalledAt = time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
				case "publication-invalid-time":
					in.InstalledAt = "not-a-time"
				case "publication-noncanonical-time":
					in.InstalledAt = strings.TrimSuffix(in.InstalledAt, "Z") + "+00:00"
				case "old-retry", "publisher-retry":
					target := id
					if mutation == "old-retry" {
						target = in.Original.JobID
					}
					exec("INSERT INTO runtime_native_retry_grants(job_id,actor,granted_at,consumed_at) VALUES(?,?,?,NULL)", target, "fixture-admin", Now())
				case "other-active", "other-unknown":
					state := "running"
					if mutation == "other-unknown" {
						state = "unknown"
					}
					exec("INSERT INTO runtime_jobs(id,target_id,kind,state,idempotency_key,created_at,updated_at) VALUES(?,'redis','software_install',?,?,?,?)", ID(), state, ID(), Now(), Now())
				case "missing-old-queue-audit", "duplicate-old-queue-audit", "missing-old-result", "duplicate-old-result", "missing-publisher-queue-audit", "duplicate-publisher-queue-audit", "missing-publisher-result", "duplicate-publisher-result":
					which, action, result, field := id, "runtime.install", "queued", "created_at"
					if strings.Contains(mutation, "old-") {
						which = in.Original.JobID
					}
					if strings.HasSuffix(mutation, "result") {
						action, result, field = "install_runtime", "succeeded", "updated_at"
						if which == in.Original.JobID {
							result = "failed"
						}
					}
					var at string
					if err := s.DB.QueryRow("SELECT "+field+" FROM runtime_jobs WHERE id=?", which).Scan(&at); err != nil {
						t.Fatal(err)
					}
					if strings.HasPrefix(mutation, "missing-") {
						exec("DELETE FROM audit_logs WHERE action=? AND result=? AND created_at=?", action, result, at)
					} else {
						exec("INSERT INTO audit_logs(actor,action,target,result,created_at) SELECT actor,action,target,result,created_at FROM audit_logs WHERE action=? AND result=? AND created_at=?", action, result, at)
					}
				case "missing-installation":
					exec("DELETE FROM runtime_installations WHERE id=?", in.Original.ReleaseID)
				case "installation-path":
					exec("UPDATE runtime_installations SET binary_path='/foreign/php' WHERE id=?", in.Original.ReleaseID)
				case "installation-version":
					other, _ := runtimecatalog.Find("php-8.3.36")
					if err := s.RecordInstallation(other, arch); err != nil {
						t.Fatal(err)
					}
					exec("UPDATE runtime_installations SET version_id=? WHERE id=?", other.ID, in.Original.ReleaseID)
				case "installation-arch":
					other := "amd64"
					if arch == other {
						other = "arm64"
					}
					exec("UPDATE runtime_installations SET architecture=? WHERE id=?", other, in.Original.ReleaseID)
				case "installation-state":
					exec("UPDATE runtime_installations SET status='retired' WHERE id=?", in.Original.ReleaseID)
				case "installation-clock":
					exec("UPDATE runtime_installations SET detected_at='2026-01-01T00:00:00Z' WHERE id=?", in.Original.ReleaseID)
				case "installation-future":
					exec("UPDATE runtime_installations SET detected_at=? WHERE id=?", time.Now().UTC().Add(time.Hour).Format(time.RFC3339), in.Original.ReleaseID)
				case "version-source":
					exec("UPDATE runtime_versions SET source_url='https://foreign.invalid/php.tar.gz' WHERE id=?", in.Original.ReleaseID)
				case "version-hash":
					exec("UPDATE runtime_versions SET verification='sha256:unknown' WHERE id=?", in.Original.ReleaseID)
				case "version-family":
					exec("UPDATE runtime_versions SET family='node' WHERE id=?", in.Original.ReleaseID)
				case "version-channel":
					exec("UPDATE runtime_versions SET channel='foreign' WHERE id=?", in.Original.ReleaseID)
				case "missing-version":
					exec("DELETE FROM runtime_installations WHERE id=?", in.Original.ReleaseID)
					exec("DELETE FROM runtime_versions WHERE id=?", in.Original.ReleaseID)
				case "wrong-architecture":
					in.Architecture = "x86_64"
				case "old-id":
					in.Original.JobID = "../" + in.Original.JobID
				case "old-release":
					in.Original.ReleaseID = "php-8.2.33"
				case "cancelled":
					cancel()
				case "legitimate-site-instance":
					exec("INSERT INTO runtime_instances(id,installation_id,family,name,service_name) VALUES(?,?,'php','fixture-published','fixture-published.service')", ID(), in.Original.ReleaseID)
					exec("INSERT INTO sites(id,name,slug,domain,status,created_at,updated_at,php_version_id) VALUES(?,'fixture','fixture-published','fixture-published.invalid','running',?,?,?)", ID(), Now(), Now(), in.Original.ReleaseID)
				}
				before := runtimePublicationCoreSnapshot(t, s)
				digest, err := s.ValidateRuntimeSupersededCompileOOMInstall(ctx, in)
				if mutation == "original" || mutation == "legitimate-site-instance" {
					if err != nil || len(digest) != 64 {
						t.Fatal(digest, err)
					}
				} else if err == nil || digest != "" {
					t.Fatal("unbound original or publisher admitted", mutation, digest)
				}
				if !reflect.DeepEqual(before, runtimePublicationCoreSnapshot(t, s)) {
					t.Fatal("SELECT-only proof mutated original evidence")
				}
				if mutation == "original" || mutation == "legitimate-site-instance" {
					if digest, err := s.ValidateRuntimeCompileOOMInstall(t.Context(), in.Original); err == nil || digest != "" {
						t.Fatal("old unpublished protocol was weakened")
					}
				}
			})
		}
	}
}

func TestRuntimeSupersededCompileOOMInventoryClockIsValidatedButNotPublisherAuthority(t *testing.T) {
	s, in := runtimeSupersededCoreFixture(t, "amd64")
	set := func(raw string) {
		t.Helper()
		if _, err := s.DB.Exec("UPDATE runtime_installations SET detected_at=? WHERE id=?", raw, in.Original.ReleaseID); err != nil {
			t.Fatal(err)
		}
	}
	set(in.PublisherSteps[len(in.PublisherSteps)-1].Time)
	first, err := s.ValidateRuntimeSupersededCompileOOMInstall(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	set(Now())
	before := runtimePublicationCoreSnapshot(t, s)
	second, err := s.ValidateRuntimeSupersededCompileOOMInstall(t.Context(), in)
	if err != nil || first != second || !reflect.DeepEqual(before, runtimePublicationCoreSnapshot(t, s)) {
		t.Fatal("legitimate inventory watermark became mutable publisher authority", err)
	}
	for _, raw := range []string{"2026-01-01T00:00:00Z", time.Now().UTC().Add(time.Hour).Format(time.RFC3339), "unknown", strings.TrimSuffix(Now(), "Z") + "+00:00"} {
		set(raw)
		if digest, err := s.ValidateRuntimeSupersededCompileOOMInstall(t.Context(), in); err == nil || digest != "" {
			t.Fatal("invalid inventory clock accepted", raw)
		}
	}
}
