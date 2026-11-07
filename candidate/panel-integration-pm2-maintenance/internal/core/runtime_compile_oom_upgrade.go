package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"local/panel/internal/runtimecatalog"
)

const RuntimeCompileOOMError = "原生构建服务已退出（oom-kill）；原构建记录与日志保留，请核对后显式重试"

// RuntimeCompileOOMSteps recognizes only the fixed PHP source-build phase,
// before make install or publication. It does not convert a running native
// ledger into a failed ledger, grant a retry, or prove an installed runtime.
// The original immutable ledger is independently fenced by the Root reader.
func RuntimeCompileOOMSteps(release string, steps []Step) bool {
	r, known := runtimecatalog.Find(release)
	if !known || r.Family != "php" || runtimecatalog.RuntimeInstallAdmission(r) != nil || len(steps) < 5 || len(steps) > 6 {
		return false
	}
	want := []string{
		"核对固定版本目录，等待源码构建锁",
		"本次安装总时限 240 分钟；超时即失败，不发布未校验程序",
		"已从官方站点下载源码，并通过目录中固定的 SHA-256 校验",
	}
	if len(steps) == 6 {
		if release != "php-8.2.35" && release != "php-8.3.36" {
			return false
		}
		want = append(want, "已逐字节核对 fileinfo 原始数据库；仅使用审核过的低内存构建表示，保留原文件、全部扩展及优化参数")
	}
	want = append(want, "以独立构建用户配置精确版本及固定模块")
	for i, message := range want {
		if steps[i].Message != message {
			return false
		}
	}
	for jobs := 1; jobs <= 4; jobs++ {
		if steps[len(steps)-1].Message == fmt.Sprintf("开始源码编译（%d 个并行任务）；完整构建日志保存在专用缓存目录", jobs) {
			return true
		}
	}
	return false
}

type RuntimeCompileOOMInstallEvidence struct {
	JobID, ReleaseID string
	Steps            []Step
}

// ValidateRuntimeCompileOOMInstall is SELECT-only and deliberately SEPARATE
// from the ordinary failed-exit protocol. Only Core's original observed OOM
// failure may match the still-running native ledger. No installation, instance,
// site binding, pending retry or other queued/running operation is admitted.
// Root additionally proves the stopped unit generation, original lock leases,
// canonical ledger identity and absence of either publication directory.
func (s *Store) ValidateRuntimeCompileOOMInstall(ctx context.Context, in RuntimeCompileOOMInstallEvidence) (string, error) {
	bad := errors.New("编译 OOM 缺少完整匹配且未发布的原始失败证据；阻止程序升级")
	if ctx.Err() != nil || !ValidID(in.JobID) || !RuntimeCompileOOMSteps(in.ReleaseID, in.Steps) {
		return "", bad
	}
	rawSteps, err := json.Marshal(in.Steps)
	if err != nil || len(rawSteps) > 192<<10 {
		return "", bad
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return "", bad
	}
	defer tx.Rollback()
	var target, kind, state, detail, steps, payload, key, created, updated string
	if tx.QueryRowContext(ctx, `SELECT target_id,kind,state,error,steps,payload,idempotency_key,created_at,updated_at FROM runtime_jobs WHERE id=?`, in.JobID).Scan(&target, &kind, &state, &detail, &steps, &payload, &key, &created, &updated) != nil || target != in.ReleaseID || kind != "install_runtime" || state != "failed" || detail != RuntimeCompileOOMError || steps != string(rawSteps) || payload != "{}" || key == "" || len(key) > 128 {
		return "", bad
	}
	start, e1 := time.Parse(time.RFC3339, created)
	end, e2 := time.Parse(time.RFC3339, updated)
	if e1 != nil || e2 != nil || start.UTC().Format(time.RFC3339) != created || end.UTC().Format(time.RFC3339) != updated || start.Year() < 2026 || end.Before(start) || end.After(time.Now().UTC().Add(time.Second)) {
		return "", bad
	}
	previous := start
	for _, step := range in.Steps {
		stamp, err := time.Parse(time.RFC3339, step.Time)
		if err != nil || stamp.UTC().Format(time.RFC3339) != step.Time || stamp.Before(previous) || stamp.After(end) {
			return "", bad
		}
		previous = stamp
	}
	var count int
	for _, query := range []struct {
		text string
		args []any
	}{
		{`SELECT count(*) FROM runtime_native_retry_grants WHERE job_id=? AND consumed_at IS NULL`, []any{in.JobID}},
		{`SELECT count(*) FROM runtime_jobs WHERE state NOT IN ('failed','succeeded')`, nil},
		{`SELECT count(*) FROM runtime_installations WHERE id=?`, []any{in.ReleaseID}},
		{`SELECT count(*) FROM runtime_instances WHERE installation_id=?`, []any{in.ReleaseID}},
		{`SELECT count(*) FROM sites WHERE php_version_id=?`, []any{in.ReleaseID}},
	} {
		if tx.QueryRowContext(ctx, query.text, query.args...).Scan(&count) != nil || count != 0 {
			return "", bad
		}
	}
	var actor string
	if tx.QueryRowContext(ctx, `SELECT count(*),coalesce(min(actor),'') FROM audit_logs WHERE action='runtime.install' AND target=? AND result='queued' AND created_at=?`, target, created).Scan(&count, &actor) != nil || count != 1 || actor == "" {
		return "", bad
	}
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE actor='executor' AND action='install_runtime' AND target=? AND result='failed' AND created_at=?`, target, updated).Scan(&count) != nil || count != 1 {
		return "", bad
	}
	bound, _ := json.Marshal([]string{in.JobID, target, kind, state, detail, steps, payload, key, created, updated, actor})
	if err := tx.Commit(); err != nil || ctx.Err() != nil {
		return "", bad
	}
	return Hash(string(bound)), nil
}
