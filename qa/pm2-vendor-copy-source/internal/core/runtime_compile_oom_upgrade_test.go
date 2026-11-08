package core

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func compileOOMStepsFixture() []Step {
	messages := []string{
		"核对固定版本目录，等待源码构建锁",
		"本次安装总时限 240 分钟；超时即失败，不发布未校验程序",
		"已从官方站点下载源码，并通过目录中固定的 SHA-256 校验",
		"以独立构建用户配置精确版本及固定模块",
		"开始源码编译（1 个并行任务）；完整构建日志保存在专用缓存目录",
	}
	var out []Step
	for _, message := range messages {
		out = append(out, Step{Time: Now(), Message: message})
	}
	return out
}

func TestRuntimeCompileOOMPhaseMustPrecedeInstallationAndPublication(t *testing.T) {
	for _, release := range []string{"php-8.2.35", "php-8.3.36", "php-8.4.27", "php-8.5.12"} {
		for jobs := 1; jobs <= 4; jobs++ {
			steps := compileOOMStepsFixture()
			steps[4].Message = fmt.Sprintf("开始源码编译（%d 个并行任务）；完整构建日志保存在专用缓存目录", jobs)
			if !RuntimeCompileOOMSteps(release, steps) {
				t.Fatal("original fixed PHP compile phase refused", release, jobs)
			}
			steps = append(steps[:3], append([]Step{{Time: Now(), Message: "已逐字节核对 fileinfo 原始数据库；仅使用审核过的低内存构建表示，保留原文件、全部扩展及优化参数"}}, steps[3:]...)...)
			if RuntimeCompileOOMSteps(release, steps) != (release == "php-8.2.35" || release == "php-8.3.36") {
				t.Fatal("unreviewed source-transform phase", release)
			}
		}
	}
	for _, release := range []string{"nginx-1.30.6", "docker-29.0.2", "php-8.2.33", "php-5.2.17", "php-latest", "../php-8.2.35"} {
		if RuntimeCompileOOMSteps(release, compileOOMStepsFixture()) {
			t.Fatal("foreign/EOL/unreviewed build phase admitted", release)
		}
	}
	for _, mutation := range []string{"install", "publish", "empty", "extra", "missing", "reordered", "zero-jobs", "five-jobs", "changed-prefix"} {
		steps := compileOOMStepsFixture()
		switch mutation {
		case "install":
			steps[4].Message = "编译完成，安装到暂存目录"
		case "publish":
			steps[4].Message = "已发布运行时"
		case "empty":
			steps = nil
		case "extra":
			steps = append(steps, Step{Time: Now(), Message: "unknown"})
		case "missing":
			steps = steps[1:]
		case "reordered":
			steps[1], steps[2] = steps[2], steps[1]
		case "zero-jobs":
			steps[4].Message = "开始源码编译（0 个并行任务）；完整构建日志保存在专用缓存目录"
		case "five-jobs":
			steps[4].Message = "开始源码编译（5 个并行任务）；完整构建日志保存在专用缓存目录"
		case "changed-prefix":
			steps[0].Message += " "
		}
		if RuntimeCompileOOMSteps("php-8.2.35", steps) {
			t.Fatal("unknown/advanced phase admitted", mutation)
		}
	}
}

func TestRuntimeCompileOOMCoreRequiresOriginalObservedUnpublishedFailure(t *testing.T) {
	for _, mutation := range []string{"original", "running", "queued", "needs_attention", "succeeded", "wrong-kind", "wrong-target", "changed-error", "ordinary-error", "changed-steps", "changed-payload", "empty-key", "pending-retry", "other-active", "other-unknown", "installation", "instance", "site", "missing-audit", "duplicate-audit", "missing-result", "duplicate-result", "missing-job", "future", "reversed", "before-create", "after-finish", "invalid-time", "noncanonical-time", "cancelled", "invalid-id", "unreviewed-release"} {
		t.Run(mutation, func(t *testing.T) {
			s := testStore(t)
			id, err := s.QueueInstall("php-8.2.35", ID(), "fixture-admin")
			if err != nil {
				t.Fatal(err)
			}
			in := RuntimeCompileOOMInstallEvidence{JobID: id, ReleaseID: "php-8.2.35", Steps: compileOOMStepsFixture()}
			if err := s.FinishRuntime(Job{ID: id, TargetID: in.ReleaseID, Kind: "install_runtime"}, RuntimeCompileOOMError, in.Steps); err != nil {
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
			case "running", "queued", "needs_attention", "succeeded":
				exec("UPDATE runtime_jobs SET state=? WHERE id=?", mutation, id)
			case "wrong-kind":
				exec("UPDATE runtime_jobs SET kind='install_php_extension' WHERE id=?", id)
			case "wrong-target":
				exec("UPDATE runtime_jobs SET target_id='php-8.3.36' WHERE id=?", id)
			case "changed-error":
				exec("UPDATE runtime_jobs SET error='' WHERE id=?", id)
			case "ordinary-error":
				exec("UPDATE runtime_jobs SET error='compile failed' WHERE id=?", id)
			case "changed-steps":
				exec("UPDATE runtime_jobs SET steps='[]' WHERE id=?", id)
			case "changed-payload":
				exec(`UPDATE runtime_jobs SET payload='{"extension_id":"redis"}' WHERE id=?`, id)
			case "empty-key":
				exec("UPDATE runtime_jobs SET idempotency_key='' WHERE id=?", id)
			case "pending-retry":
				exec("INSERT INTO runtime_native_retry_grants(job_id,actor,granted_at,consumed_at) VALUES(?,?,?,NULL)", id, "fixture-admin", Now())
			case "other-active", "other-unknown":
				state := "running"
				if mutation == "other-unknown" {
					state = "unknown"
				}
				exec("INSERT INTO runtime_jobs(id,target_id,kind,state,idempotency_key,created_at,updated_at) VALUES(?,?,'software_install',?,?,?,?)", ID(), "redis", state, ID(), Now(), Now())
			case "installation", "instance", "site":
				exec("INSERT INTO runtime_versions(id,family,version,channel,source_url,verification) VALUES(?,'php','8.2.35','security','https://www.php.net/distributions/php-8.2.35.tar.gz','fixture')", in.ReleaseID)
				if mutation == "site" {
					exec("INSERT INTO sites(id,name,slug,domain,status,created_at,updated_at,php_version_id) VALUES(?,'fixture','fixture-oom','fixture-oom.invalid','running',?,?,?)", ID(), Now(), Now(), in.ReleaseID)
					break
				}
				exec("INSERT INTO runtime_installations(id,version_id,binary_path,architecture,detected_at) VALUES(?,?,'/fixture/php','arm64',?)", in.ReleaseID, in.ReleaseID, Now())
				if mutation == "instance" {
					exec("INSERT INTO runtime_instances(id,installation_id,family,name,service_name) VALUES(?,?,'php','fixture-php','fixture.service')", ID(), in.ReleaseID)
				}
			case "missing-audit":
				exec("DELETE FROM audit_logs WHERE action='runtime.install'")
			case "duplicate-audit":
				exec("INSERT INTO audit_logs(actor,action,target,result,created_at) SELECT actor,action,target,result,created_at FROM audit_logs WHERE action='runtime.install'")
			case "missing-result":
				exec("DELETE FROM audit_logs WHERE action='install_runtime'")
			case "duplicate-result":
				exec("INSERT INTO audit_logs(actor,action,target,result,created_at) SELECT actor,action,target,result,created_at FROM audit_logs WHERE action='install_runtime'")
			case "missing-job":
				exec("DELETE FROM runtime_jobs WHERE id=?", id)
			case "future":
				exec("UPDATE runtime_jobs SET updated_at=? WHERE id=?", time.Now().UTC().Add(time.Hour).Format(time.RFC3339), id)
			case "reversed":
				exec("UPDATE runtime_jobs SET updated_at='2026-01-01T00:00:00Z' WHERE id=?", id)
			case "before-create", "after-finish", "invalid-time", "noncanonical-time":
				switch mutation {
				case "before-create":
					in.Steps[0].Time = "2026-01-01T00:00:00Z"
				case "after-finish":
					in.Steps[4].Time = time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
				case "invalid-time":
					in.Steps[0].Time = "not-a-time"
				case "noncanonical-time":
					in.Steps[0].Time = "2026-10-23T00:00:00+00:00"
				}
				raw, _ := json.Marshal(in.Steps)
				exec("UPDATE runtime_jobs SET steps=? WHERE id=?", string(raw), id)
			case "cancelled":
				cancel()
			case "invalid-id":
				in.JobID = "../" + id
			case "unreviewed-release":
				in.ReleaseID = "php-8.2.33"
			}
			// A complete byte snapshot of the original row is retained across
			// this SELECT-only validator, including unknown/negative samples.
			rows := func() [][]any {
				t.Helper()
				r, err := s.DB.Query("SELECT * FROM runtime_jobs ORDER BY id")
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				cols, _ := r.Columns()
				var result [][]any
				for r.Next() {
					v, ptr := make([]any, len(cols)), make([]any, len(cols))
					for i := range v {
						ptr[i] = &v[i]
					}
					if err := r.Scan(ptr...); err != nil {
						t.Fatal(err)
					}
					result = append(result, v)
				}
				return result
			}
			before := rows()
			digest, err := s.ValidateRuntimeCompileOOMInstall(ctx, in)
			if mutation == "original" {
				if err != nil || len(digest) != 64 {
					t.Fatal(digest, err)
				}
			} else if err == nil || digest != "" {
				t.Fatal("active/unbound/published OOM state admitted", mutation, digest, err)
			}
			if !reflect.DeepEqual(before, rows()) {
				t.Fatal("read-only validation changed original job evidence")
			}
		})
	}
}
