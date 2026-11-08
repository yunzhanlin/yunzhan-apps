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

const RuntimePHPPublicationStep = "已核对 PHP CLI/FPM 精确版本并封存本次原生任务的源码与程序摘要"

// A completed no-op/existing-prefix check is not a publisher. Only this exact
// source-build path can create a publication seal. The original OOM/unpublished
// protocol is intentionally unchanged and remains independently strict.
func RuntimePHPPublicationSteps(release string, steps []Step) bool {
	r, found := runtimecatalog.Find(release)
	if !found || r.Family != "php" || runtimecatalog.RuntimeInstallAdmission(r) != nil {
		return false
	}
	messages := []string{"核对固定版本目录，等待源码构建锁", "本次安装总时限 240 分钟；超时即失败，不发布未校验程序", "已从官方站点下载源码，并通过目录中固定的 SHA-256 校验"}
	selected := release == "php-8.2.35" || release == "php-8.3.36"
	if selected {
		messages = append(messages, "已逐字节核对 fileinfo 原始数据库；仅使用审核过的低内存构建表示，保留原文件、全部扩展及优化参数")
	}
	messages = append(messages, "以独立构建用户配置精确版本及固定模块")
	if selected {
		messages = append(messages, "已启用固定 GCC 低内存编译策略；保留 -O2 和全部扩展，安装单元硬限 1 GiB、零交换，启动前保留 512 MiB 主机余量")
	}
	if len(steps) != len(messages)+4 {
		return false
	}
	for i, message := range messages {
		if steps[i].Message != message {
			return false
		}
	}
	compile := steps[len(messages)].Message
	valid := false
	for jobs := 1; jobs <= 4; jobs++ {
		valid = valid || compile == fmt.Sprintf("开始源码编译（%d 个并行任务）；完整构建日志保存在专用缓存目录", jobs)
	}
	return valid && steps[len(messages)+1].Message == "编译完成，安装到暂存目录" && steps[len(messages)+2].Message == RuntimePHPPublicationStep && steps[len(messages)+3].Message == "独立目录安装完成；精确版本与固定构建模块核对通过"
}

type RuntimeSupersededCompileOOMEvidence struct {
	Original                  RuntimeCompileOOMInstallEvidence
	PublisherJobID            string
	PublisherSteps            []Step
	Architecture, InstalledAt string
}

type runtimePublicationCoreJob struct {
	ID, Target, Kind, State, Error, Steps, Payload, Key, Created, Updated, Actor string
}

// SELECT-only. A later successful, distinct, fully built native publisher may
// coexist with the original failed OOM. This does not relabel the old job,
// grant a retry, adopt an existing prefix, start a service or authorize a site
// change. Root separately binds the seal, actual binaries, private ledgers and
// original stopped OOM generation under both existing read-only lock leases.
func (s *Store) ValidateRuntimeSupersededCompileOOMInstall(ctx context.Context, in RuntimeSupersededCompileOOMEvidence) (string, error) {
	bad := errors.New("编译 OOM 缺少独立成功发布任务与原始失败的完整关联；阻止程序升级")
	old := in.Original
	if ctx.Err() != nil || !ValidID(old.JobID) || !ValidID(in.PublisherJobID) || old.JobID == in.PublisherJobID || !RuntimeCompileOOMSteps(old.ReleaseID, old.Steps) || !RuntimePHPPublicationSteps(old.ReleaseID, in.PublisherSteps) || in.Architecture != "amd64" && in.Architecture != "arm64" {
		return "", bad
	}
	r, _ := runtimecatalog.Find(old.ReleaseID)
	stamp := func(raw string) (time.Time, bool) {
		t, e := time.Parse(time.RFC3339, raw)
		return t, e == nil && t.Year() >= 2026 && t.UTC().Format(time.RFC3339) == raw && !t.After(time.Now().UTC().Add(time.Second))
	}
	installed, valid := stamp(in.InstalledAt)
	if !valid {
		return "", bad
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return "", bad
	}
	defer tx.Rollback()
	read := func(id, state, detail string, input []Step) (runtimePublicationCoreJob, time.Time, time.Time, error) {
		j := runtimePublicationCoreJob{ID: id}
		raw, er := json.Marshal(input)
		if er != nil || len(raw) > 192<<10 || tx.QueryRowContext(ctx, `SELECT target_id,kind,state,error,steps,payload,idempotency_key,created_at,updated_at FROM runtime_jobs WHERE id=?`, id).Scan(&j.Target, &j.Kind, &j.State, &j.Error, &j.Steps, &j.Payload, &j.Key, &j.Created, &j.Updated) != nil || j.Target != r.ID || j.Kind != "install_runtime" || j.State != state || j.Error != detail || j.Steps != string(raw) || j.Payload != "{}" || j.Key == "" || len(j.Key) > 128 {
			return j, time.Time{}, time.Time{}, bad
		}
		start, a := stamp(j.Created)
		end, b := stamp(j.Updated)
		if !a || !b || end.Before(start) {
			return j, start, end, bad
		}
		previous := start
		for _, step := range input {
			t, ok := stamp(step.Time)
			if !ok || t.Before(previous) || t.After(end) {
				return j, start, end, bad
			}
			previous = t
		}
		var count int
		if tx.QueryRowContext(ctx, `SELECT count(*),coalesce(min(actor),'') FROM audit_logs WHERE action='runtime.install' AND target=? AND result='queued' AND created_at=?`, r.ID, j.Created).Scan(&count, &j.Actor) != nil || count != 1 || j.Actor == "" {
			return j, start, end, bad
		}
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE actor='executor' AND action='install_runtime' AND target=? AND result=? AND created_at=?`, r.ID, state, j.Updated).Scan(&count) != nil || count != 1 {
			return j, start, end, bad
		}
		return j, start, end, nil
	}
	original, _, oldEnd, err := read(old.JobID, "failed", RuntimeCompileOOMError, old.Steps)
	if err != nil {
		return "", bad
	}
	publisher, start, end, err := read(in.PublisherJobID, "succeeded", "", in.PublisherSteps)
	if err != nil || start.Before(oldEnd) || installed.Before(start) || installed.After(end) || original.Key == publisher.Key {
		return "", bad
	}
	staged, a := stamp(in.PublisherSteps[len(in.PublisherSteps)-3].Time)
	sealed, b := stamp(in.PublisherSteps[len(in.PublisherSteps)-2].Time)
	if !a || !b || installed.Before(staged) || installed.After(sealed) {
		return "", bad
	}
	var count int
	for _, query := range []struct {
		text string
		args []any
	}{
		{`SELECT count(*) FROM runtime_jobs WHERE state NOT IN ('failed','succeeded')`, nil},
		{`SELECT count(*) FROM runtime_native_retry_grants WHERE job_id IN (?,?) AND consumed_at IS NULL`, []any{old.JobID, in.PublisherJobID}},
	} {
		if tx.QueryRowContext(ctx, query.text, query.args...).Scan(&count) != nil || count != 0 {
			return "", bad
		}
	}
	var versionID, path, arch, detected, status string
	if tx.QueryRowContext(ctx, `SELECT version_id,binary_path,architecture,detected_at,status FROM runtime_installations WHERE id=?`, r.ID).Scan(&versionID, &path, &arch, &detected, &status) != nil || versionID != r.ID || path != r.CLI() || arch != in.Architecture || status != "installed" {
		return "", bad
	}
	detectedAt, valid := stamp(detected)
	if !valid || detectedAt.Before(installed) {
		return "", bad
	}
	var family, version, channel, url, verification string
	if tx.QueryRowContext(ctx, `SELECT family,version,channel,source_url,verification FROM runtime_versions WHERE id=?`, r.ID).Scan(&family, &version, &channel, &url, &verification) != nil || family != r.Family || version != r.Version || channel != r.Channel || url != r.URL || verification != "sha256:"+r.SHA256 {
		return "", bad
	}
	// detected_at is a validated observation watermark, not publisher authority:
	// normal inventory refresh may advance it between the two SELECT snapshots.
	// Validate its canonical range on every read; bind all installation identity,
	// status and source fields, and the actual publisher's immutable timestamps.
	bound, _ := json.Marshal([]any{"php-superseded-compile-oom-v1", original, publisher, in.Architecture, in.InstalledAt, versionID, path, arch, status, family, version, channel, url, verification})
	if tx.Commit() != nil || ctx.Err() != nil {
		return "", bad
	}
	return Hash(string(bound)), nil
}
