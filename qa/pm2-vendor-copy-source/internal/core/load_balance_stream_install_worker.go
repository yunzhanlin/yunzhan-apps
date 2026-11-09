package core

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"local/panel/internal/appcatalog"
	"local/panel/internal/loadbalancestream"
)

func loadBalanceStreamInstallJobSelected(j Job) bool {
	if len(j.Payload) == 0 || len(j.Payload) > 1024 || j.TargetID != "load-balance" || j.Kind != "software_install" && j.Kind != "software_update" {
		return false
	}
	var payload struct {
		Version string `json:"version"`
	}
	return json.Unmarshal([]byte(j.Payload), &payload) == nil && payload.Version == loadbalancestream.AppVersion
}

type loadBalanceStreamMetadataFetch func(context.Context, string, string) (appcatalog.LoadBalanceStreamReleaseEnvelope, error)

func loadBalanceStreamInstallFailureDetail(cause error) string {
	detail := "TCP/UDP 原安装没有可核对的完整原生完成回执；保留原任务，只允许观察，不重新派发"
	if cause == nil {
		return detail
	}
	// Preserve the actual one-shot error for diagnosis without accepting its
	// text as completion, recovery authority or a reason to repeat the POST.
	reason := strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, cause.Error())), " ")
	if len(reason) > 512 {
		reason = reason[:512]
		for !utf8.ValidString(reason) {
			reason = reason[:len(reason)-1]
		}
		reason += "…"
	}
	if reason != "" {
		detail += "；执行服务：" + reason
	}
	return detail
}

func runLoadBalanceStreamInstallJob(ctx context.Context, s *Store, e *ExecutorClient, j Job) {
	runLoadBalanceStreamInstallJobWithMetadata(ctx, s, e, j, appcatalog.Default().FetchLoadBalanceStreamReleaseEnvelope)
}

// The private metadata seam is for Core-only contract models. Production above
// always uses the current compiled availability and official signed catalogue;
// the Root recipient ALSO independently verifies the exact bytes and grant.
// There is exactly ONE POST, no generic software route and no retry loop.
func runLoadBalanceStreamInstallJobWithMetadata(ctx context.Context, s *Store, e *ExecutorClient, j Job, fetch loadBalanceStreamMetadataFetch) {
	fail := func(detail string, uncertain bool) {
		if ctx != nil && ctx.Err() == nil {
			_ = s.finishRuntime(j, detail, nil, uncertain)
		}
	}
	if ctx == nil || ctx.Err() != nil || s == nil || s.DB == nil || e == nil || fetch == nil || !loadBalanceStreamInstallJobSelected(j) {
		return
	}
	grant, err := s.LoadBalanceStreamInstallAuthority(ctx, j.ID)
	if err != nil || grant.PayloadSHA256 != Hash(j.Payload) || j.Kind != "software_"+grant.Action {
		fail("TCP/UDP 原始签名任务和当前完整授权不可核对；未调用本机安装", true)
		return
	}
	envelope, err := fetch(ctx, grant.AppVersion, grant.ManifestSHA256)
	if err != nil {
		fail(err.Error(), false)
		return
	}
	current, err := s.LoadBalanceStreamInstallAuthority(ctx, j.ID)
	if err != nil || current != grant || ctx.Err() != nil {
		fail("签名元数据读取期间原始授权或任务发生变化；未调用本机安装", true)
		return
	}
	in := LoadBalanceStreamInstallSubmission{1, j.ID, envelope}
	if _, err = LoadBalanceStreamInstallSubmissionBytes(in); err != nil {
		fail("TCP/UDP 签名元数据交接不完整；未调用本机安装", false)
		return
	}
	var raw json.RawMessage
	err = e.Call(ctx, http.MethodPost, "/v1/load-balance-stream/install-jobs", in, &raw)
	if ctx.Err() != nil {
		return
	}
	result, decodeErr := DecodeLoadBalanceStreamInstallResult(raw, j.ID)
	if err != nil || decodeErr != nil || result.State != "committed" {
		fail(loadBalanceStreamInstallFailureDetail(err), true)
		return
	}
	_ = s.finishRuntime(j, "", []Step{{Time: Now(), Message: "原签名任务、固定父子安装、完整旧记录备份、原子发布及实际退出回执已核对；没有自动启用 TCP/UDP 监听"}}, false)
}

// Capture interrupted RUNNING jobs synchronously, before any new worker may
// claim QUEUED work. An ongoing fresh dispatch must never be mistaken for a
// restarted job whose handoff is still absent. This snapshot never requeues,
// reissues grants or POSTs an original request.
func startLoadBalanceStreamInstallObserver(ctx context.Context, s *Store, e *ExecutorClient) {
	if ctx == nil || ctx.Err() != nil || s == nil || s.DB == nil || e == nil {
		return
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id,target_id,kind,substr(CAST(payload AS BLOB),1,1025),length(CAST(payload AS BLOB)) FROM runtime_jobs WHERE state='running'AND target_id='load-balance'AND kind IN('software_install','software_update')AND CASE WHEN length(CAST(payload AS BLOB)) BETWEEN 1 AND 1024 THEN CASE WHEN json_valid(payload)THEN json_extract(payload,'$.version') ELSE '' END ELSE '' END=? ORDER BY created_at,id LIMIT 129`, loadbalancestream.AppVersion)
	if err != nil {
		return
	}
	var original []Job
	for rows.Next() {
		var j Job
		var size int
		if rows.Scan(&j.ID, &j.TargetID, &j.Kind, &j.Payload, &size) != nil || size != len(j.Payload) || size < 1 || size > 1024 || !ValidID(j.ID) || len(original) >= 128 {
			rows.Close()
			return
		}
		original = append(original, j)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(original) == 0 {
		return
	}
	go func() {
		pending := original
		for len(pending) != 0 && ctx.Err() == nil {
			next := make([]Job, 0, len(pending))
			for _, j := range pending {
				keep, err := observeLoadBalanceStreamOriginalInstall(ctx, s, e, j)
				if ctx.Err() != nil {
					return
				}
				if keep || err != nil {
					next = append(next, j)
				}
			}
			pending = next
			if len(pending) == 0 {
				return
			}
			timer := time.NewTimer(2 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
}

func observeLoadBalanceStreamOriginalInstall(ctx context.Context, s *Store, e *ExecutorClient, j Job) (bool, error) {
	if ctx == nil || ctx.Err() != nil || !loadBalanceStreamInstallJobSelected(j) {
		return false, errLoadBalanceStreamInstallAuthority
	}
	var state, kind, target, payload string
	if s.DB.QueryRowContext(ctx, "SELECT state,kind,target_id,payload FROM runtime_jobs WHERE id=?", j.ID).Scan(&state, &kind, &target, &payload) != nil {
		return false, errLoadBalanceStreamInstallAuthority
	}
	if state != "running" {
		return false, nil
	}
	if kind != j.Kind || target != j.TargetID || payload != j.Payload {
		return false, errLoadBalanceStreamInstallAuthority
	}
	grant, grantErr := s.LoadBalanceStreamInstallAuthority(ctx, j.ID)
	if grantErr != nil || grant.PayloadSHA256 != Hash(j.Payload) || j.Kind != "software_"+grant.Action {
		return false, s.finishRuntime(j, "原 TCP/UDP 安装授权或原始历史不可核对；只保留记录，未读取为成功或重新派发", nil, true)
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var raw json.RawMessage
	err := e.Call(bounded, http.MethodGet, "/v1/load-balance-stream/install-jobs/"+j.ID, nil, &raw)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if _, known := decodeLoadBalanceStreamInstallError(raw, j.ID); known {
			return false, s.finishRuntime(j, "原 TCP/UDP 安装只读回执报告不确定；保留原编号和原生记录，未重新派发", nil, true)
		}
		return true, err
	}
	result, decodeErr := DecodeLoadBalanceStreamInstallResult(raw, j.ID)
	if decodeErr != nil {
		return true, errors.New("TCP/UDP 原始只读观察返回不可核对的回执")
	}
	if result.State == "running" {
		return true, nil
	}
	if result.State != "committed" {
		return false, s.finishRuntime(j, "服务重启后原 TCP/UDP 安装没有完整原生完成回执；保留原编号和原生记录，未重新派发", nil, true)
	}
	return false, s.finishRuntime(j, "", []Step{{Time: Now(), Message: "仅通过原任务只读接口核对已有完整原生退出回执；没有重新提交安装或创建账号"}}, false)
}
