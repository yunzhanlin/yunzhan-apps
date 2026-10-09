package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/appcatalog"
	"local/panel/internal/runtimecatalog"
	"net"
	"net/url"
	"runtime"
	"time"
)

func runNetworkIDSRuleFeedJob(parent context.Context, store *Store, executor *ExecutorClient, job Job, repository *appcatalog.Client) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	steps := []Step{}
	finish := func(detail string, uncertain bool) {
		if parent.Err() == nil {
			_ = store.finishRuntime(job, detail, steps, uncertain)
		}
	}
	selection, decodeErr := decodeNetworkIDSRuleFeedSelection([]byte(job.Payload))
	if job.TargetID != "network-threat-detection" || !ValidID(job.ID) || decodeErr != nil || repository == nil {
		finish("规则安装任务身份或选择无效", false)
		return
	}
	if err := ValidateSoftwareUpdate("network-threat-detection", selection.AppVersion); err != nil {
		finish(err.Error(), false)
		return
	}
	envelope, err := repository.FetchRuleFeedEnvelope(ctx, selection.AppVersion, selection.AppManifestSHA, selection.FeedID)
	if err != nil {
		finish("规则数据下载或验签失败："+err.Error(), false)
		return
	}
	var manifest appcatalog.Manifest
	if err := json.Unmarshal(envelope.AppManifest, &manifest); err != nil {
		finish("已签名规则清单不能解码", false)
		return
	}
	if err := ValidateNetworkIDSRuleFeedManifestOn(manifest, runtimecatalog.HostPlatform(), runtime.GOARCH); err != nil {
		finish(err.Error(), false)
		return
	}
	if Hash(string(envelope.Files["manifest.json"])) != selection.RuleManifestSHA {
		finish("规则数据版本摘要与任务选择不同", false)
		return
	}
	steps = append(steps, Step{Time: Now(), Message: "规则数据下载和签名绑定已核对；尚未声明安装、原生校验或启用采集"})
	query := url.Values{"app_version": {selection.AppVersion}, "app_manifest_sha256": {selection.AppManifestSHA}, "rule_manifest_sha256": {selection.RuleManifestSHA}}
	endpoint := "/v1/network-ids/rule-feeds/jobs/" + job.ID
	var result NetworkIDSRuleFeedStatus
	submitContext, submitCancel := context.WithTimeout(ctx, 20*time.Second)
	submitError := executor.Call(submitContext, "POST", endpoint+"?"+query.Encode(), envelope, &result)
	submitCancel()
	if submitError != nil {
		// POST may already have durably published the request. Never repeat it
		// or download the dataset again after a lost or malformed reply.
		result = NetworkIDSRuleFeedStatus{}
		steps = append(steps, Step{Time: Now(), Message: "安装提交回执未收到；只查询原任务标识，不重复提交或下载"})
	}
	baseSteps := append([]Step(nil), steps...)
	for {
		if result.JobID != "" {
			if result.JobID != job.ID || result.Selection != selection || !result.DataOnly || result.CaptureStarted || result.NativeSyntaxVerified || len(result.Steps) > 16 || len(result.Error) > 1024 {
				finish("规则安装响应身份或数据独立契约不符，未宣称完成", true)
				return
			}
			steps = append(append([]Step(nil), baseSteps...), result.Steps...)
			switch result.State {
			case "ready-data":
				if result.Error != "" {
					finish("规则安装完成记录仍含未解决错误", true)
				} else {
					finish("", false)
				}
				return
			case "failed":
				detail := result.Error
				if detail == "" {
					detail = "规则数据安装失败；原现场保留"
				}
				finish(detail, false)
				return
			case "needs-attention":
				finish(result.Error, true)
				return
			case "queued", "running":
			default:
				finish("规则数据安装状态无法核实", true)
				return
			}
		}
		select {
		case <-ctx.Done():
			finish("规则数据安装观察达到 3 分钟上限；未宣称成功，原记录保留", true)
			return
		case <-time.After(time.Second):
		}
		observeContext, observeCancel := context.WithTimeout(ctx, 15*time.Second)
		var observed NetworkIDSRuleFeedStatus
		err := executor.Call(observeContext, "GET", endpoint, nil, &observed)
		observeCancel()
		if err != nil {
			result = NetworkIDSRuleFeedStatus{}
			if temporaryRuleFeedObservation(err) {
				continue
			}
			finish("规则数据原任务结果不能核实："+err.Error(), true)
			return
		}
		// Empty/malformed success is not treated as a transient transport error.
		if observed.JobID == "" {
			finish("规则数据原任务响应缺少身份，未采用旧状态", true)
			return
		}
		result = observed
	}
}

func temporaryRuleFeedObservation(err error) bool {
	var network net.Error
	return errors.As(err, &network) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, context.DeadlineExceeded)
}
