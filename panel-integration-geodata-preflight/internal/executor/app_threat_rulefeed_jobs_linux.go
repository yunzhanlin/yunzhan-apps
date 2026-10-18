//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const threatIDSRuleFeedJobs = "/var/lib/panel-executor/network-rule-feed-jobs"

var networkIDSRootSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)

type threatIDSRuleFeedRequest struct {
	Format      int                              `json:"format"`
	JobID       string                           `json:"job_id"`
	Selection   core.NetworkIDSRuleFeedSelection `json:"selection"`
	EnvelopeSHA string                           `json:"envelope_sha256"`
}

func readThreatIDSRuleFeedRequest(id string) (threatIDSRuleFeedRequest, []byte, error) {
	var request threatIDSRuleFeedRequest
	if !core.ValidID(id) || threatIDSTrustedParents(threatIDSRuleFeedJobs, false) != nil || ruleFeedStoreOwned(threatIDSRuleFeedJobs, true, 0700) != nil || ruleFeedStoreOwned(filepath.Join(threatIDSRuleFeedJobs, id), true, 0700) != nil {
		return request, nil, errors.New("规则安装任务目录身份或权限无效")
	}
	root, err := os.OpenRoot(filepath.Join(threatIDSRuleFeedJobs, id))
	if err != nil {
		return request, nil, err
	}
	defer root.Close()
	if err := threatIDSRuleFeedJobContents(root, false); err != nil {
		return request, nil, err
	}
	data, err := ruleFeedStoreRead(root, "request.json", 8192, 0600)
	if err != nil || decodeThreatIDSPrivateJSON(data, &request) != nil || request.Format != 1 || request.JobID != id || core.ValidateNetworkIDSRuleFeedSelection(request.Selection) != nil || !networkIDSRootSHA.MatchString(request.EnvelopeSHA) {
		return request, nil, errors.New("规则安装请求记录损坏或绑定不完整")
	}
	envelope, err := ruleFeedStoreRead(root, "envelope.json", appcatalog.MaxRuleFeedEnvelopeBytes, 0600)
	if err != nil || core.Hash(string(envelope)) != request.EnvelopeSHA {
		return request, nil, errors.New("规则安装原始交付数据不能核对")
	}
	return request, envelope, nil
}

func (s *Service) createThreatIDSRuleFeedRequest(ctx context.Context, id string, selection core.NetworkIDSRuleFeedSelection, raw []byte) error {
	if s.Config.SystemRoot != "/" || os.Geteuid() != 0 || !core.ValidID(id) || core.ValidateNetworkIDSRuleFeedSelection(selection) != nil {
		return errors.New("规则安装任务身份无效")
	}
	if err := core.ValidateSoftwareUpdate("network-threat-detection", selection.AppVersion); err != nil {
		return err
	}
	in, err := appcatalog.DecodeRuleFeedEnvelope(raw)
	if err != nil {
		return err
	}
	store, err := s.threatIDSRuleFeedStore()
	if err != nil {
		return err
	}
	record, _, err := store.verify(ctx, in, selection.AppVersion, selection.AppManifestSHA)
	if err != nil || record.FeedID != selection.FeedID || record.RuleManifestSHA != selection.RuleManifestSHA {
		return errors.New("规则安装请求与本机独立验签结果不符")
	}
	if err := threatIDSRuleFeedManifestCompatible(in.AppManifest); err != nil {
		return err
	}
	request := threatIDSRuleFeedRequest{Format: 1, JobID: id, Selection: selection, EnvelopeSHA: core.Hash(string(raw))}
	if err := threatIDSTrustedParents(filepath.Dir(threatIDSRuleFeedJobs), false); err != nil {
		return err
	}
	if err := os.Mkdir(threatIDSRuleFeedJobs, 0700); err == nil {
		if err := os.Chmod(threatIDSRuleFeedJobs, 0700); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := ruleFeedStoreOwned(threatIDSRuleFeedJobs, true, 0700); err != nil {
		return err
	}
	root, err := os.OpenRoot(threatIDSRuleFeedJobs)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := threatIDSRuleFeedJobInventory(root); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(threatIDSRuleFeedJobs, id)); err == nil {
		prior, original, err := readThreatIDSRuleFeedRequest(id)
		if err != nil || prior.Selection != request.Selection {
			return errors.New("规则安装任务标识已用于不同或损坏的请求；未覆盖")
		}
		old, err := appcatalog.DecodeRuleFeedEnvelope(original)
		if err != nil {
			return err
		}
		bound, _, err := store.verify(ctx, old, prior.Selection.AppVersion, prior.Selection.AppManifestSHA)
		if err != nil || bound.FeedID != selection.FeedID || bound.RuleManifestSHA != selection.RuleManifestSHA {
			return errors.New("原规则交付不能独立验签；保留旧任务，未采用新输入修复")
		}
		if err := threatIDSRuleFeedManifestCompatible(old.AppManifest); err != nil {
			return err
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := dir.ReadDir(17)
	dir.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) >= 16 {
		return errors.New("规则交付任务达到 16 份；原请求和失败阶段保留")
	}
	stage := ".request-" + core.ID()
	if err := root.Mkdir(stage, 0700); err != nil {
		return err
	}
	if err := root.Chmod(stage, 0700); err != nil {
		return err
	}
	if err := ruleFeedStoreSync(root); err != nil {
		return err
	}
	staged, err := root.OpenRoot(stage)
	if err != nil {
		return err
	}
	defer staged.Close()
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if err := ruleFeedStoreWrite(staged, "envelope.json", raw, 0600); err != nil {
		return err
	}
	if err := ruleFeedStoreWrite(staged, "request.json", append(data, '\n'), 0600); err != nil {
		return err
	}
	if err := ruleFeedStoreSync(staged); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := renameNoReplace(root, stage, id); err != nil {
		return errors.New("规则请求独立发布失败；既有任务未覆盖，阶段保留")
	}
	return ruleFeedStoreSync(root)
}

// Call only after independent signature verification of these manifest bytes.
func threatIDSRuleFeedManifestCompatible(raw []byte) error {
	var manifest appcatalog.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return err
	}
	return core.ValidateNetworkIDSRuleFeedManifestOn(manifest, runtimecatalog.HostPlatform(), runtime.GOARCH)
}

// Unknown, writable, linked or oversized retained entries cannot be silently
// ignored to make the next installation look healthy. No automatic pruning.
func threatIDSRuleFeedJobInventory(root *os.Root) error {
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := dir.ReadDir(17)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 16 {
		return errors.New("规则任务目录超过 16 份，原现场保留")
	}
	for _, entry := range entries {
		name := entry.Name()
		stage := strings.HasPrefix(name, ".request-")
		id := name
		if stage {
			id = strings.TrimPrefix(name, ".request-")
		}
		if !core.ValidID(id) {
			return errors.New("规则任务目录包含未知身份，未修复或清理")
		}
		info, err := root.Lstat(name)
		if err != nil {
			return err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("规则任务目录所有者、类型或权限不同")
		}
		child, err := root.OpenRoot(name)
		if err != nil {
			return err
		}
		err = threatIDSRuleFeedJobContents(child, stage)
		child.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func threatIDSRuleFeedJobContents(root *os.Root, stage bool) error {
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := dir.ReadDir(5)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 4 {
		return errors.New("规则任务文件不是闭合集合")
	}
	limits := map[string]int64{"request.json": 8192, "envelope.json": appcatalog.MaxRuleFeedEnvelopeBytes, "result.json": 16 << 10, "install.lock": 0}
	seen := map[string]bool{}
	for _, entry := range entries {
		limit, known := limits[entry.Name()]
		if !known || stage && (entry.Name() == "result.json" || entry.Name() == "install.lock") {
			return errors.New("规则任务含未知或阶段不允许的文件")
		}
		info, err := root.Lstat(entry.Name())
		if err != nil {
			return err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > limit || entry.Name() != "install.lock" && info.Size() < 1 {
			return errors.New("规则任务文件身份、权限、链接数或容量不同")
		}
		seen[entry.Name()] = true
	}
	if !stage && (!seen["request.json"] || !seen["envelope.json"]) {
		return errors.New("已发布规则任务缺少原始请求或交付数据")
	}
	return nil
}

func (s *Service) threatIDSRuleFeedJobStatus(ctx context.Context, id string) (core.NetworkIDSRuleFeedStatus, error) {
	out := core.NetworkIDSRuleFeedStatus{JobID: id, State: "queued", DataOnly: true, Steps: []core.Step{}}
	request, _, err := readThreatIDSRuleFeedRequest(id)
	if err != nil {
		return out, err
	}
	out.Selection = request.Selection
	root, err := os.OpenRoot(filepath.Join(threatIDSRuleFeedJobs, id))
	if err != nil {
		return out, err
	}
	defer root.Close()
	data, err := ruleFeedStoreRead(root, "result.json", 16<<10, 0600)
	if err == nil {
		var result core.NetworkIDSRuleFeedStatus
		if decodeThreatIDSPrivateJSON(data, &result) != nil || result.JobID != id || result.Selection != request.Selection || !result.DataOnly || result.CaptureStarted || result.NativeSyntaxVerified || len(result.Steps) > 16 || len(result.Error) > 1024 {
			return out, errors.New("规则安装结果身份或独立数据契约不完整")
		}
		if result.State == "failed" {
			if result.Error == "" {
				return out, errors.New("规则安装失败记录缺少原因")
			}
			return result, nil
		}
		if result.State != "ready-data" || result.Error != "" {
			return out, errors.New("规则安装结果不是可核对的终态")
		}
		store, err := s.threatIDSRuleFeedStore()
		if err != nil {
			return out, err
		}
		if _, err := store.read(ctx, threatIDSRuleFeedName(request.Selection.FeedID, request.Selection.RuleManifestSHA), request.Selection.AppVersion, request.Selection.AppManifestSHA); err != nil {
			result.State = "needs-attention"
			result.Error = err.Error()
		}
		return result, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	// The first start has a real zero monotonic timestamp. systemctl omits
	// unset timestamps unless --all is requested; omission is not evidence of
	// zero and must never be repaired by inventing a default in the parser.
	state, err := s.moduleCommand(ctx, 5*time.Second, "/usr/bin/systemctl", "show", "--all", "panel-network-rulefeed-install@"+id+".service", "--property=LoadState,ActiveState,MainPID,ExecMainStartTimestampMonotonic")
	if err != nil {
		return out, err
	}
	out.State, out.Error, err = threatIDSRuleFeedUnitState(state)
	return out, err
}

// A missing or malformed property remains unknown, never a queued job that
// could execute again. A prior exit without a durable result needs attention.
func threatIDSRuleFeedUnitState(state string) (string, string, error) {
	// Capture-process observation deliberately requires fourteen different
	// properties; it is NOT a generic parser for this four-property job query.
	// Keep both contracts closed instead of weakening capture attestation.
	allowed := map[string]bool{"LoadState": true, "ActiveState": true, "MainPID": true, "ExecMainStartTimestampMonotonic": true}
	values := map[string]string{}
	if len(state) > 4096 {
		return "", "", errors.New("规则安装固定单元状态超过上限")
	}
	for _, line := range strings.Split(strings.TrimSuffix(state, "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || !allowed[key] || !threatEVEText(value, 32, false) {
			return "", "", errors.New("规则安装固定单元状态字段无效")
		}
		if _, exists := values[key]; exists {
			return "", "", errors.New("规则安装固定单元状态字段重复")
		}
		values[key] = value
	}
	if len(values) != len(allowed) || values["LoadState"] != "loaded" {
		return "", "", errors.New("规则安装固定单元状态不可核对")
	}
	pid, pidErr := strconv.ParseUint(values["MainPID"], 10, 32)
	started, startErr := strconv.ParseUint(values["ExecMainStartTimestampMonotonic"], 10, 64)
	if pidErr != nil || pid == 1 || strconv.FormatUint(pid, 10) != values["MainPID"] || startErr != nil || strconv.FormatUint(started, 10) != values["ExecMainStartTimestampMonotonic"] {
		return "", "", errors.New("规则安装固定单元进程或启动时钟不可核对")
	}
	switch values["ActiveState"] {
	case "active", "activating", "deactivating":
		return "running", "", nil
	case "inactive":
		if pid != 0 || started != 0 {
			return "needs-attention", "规则服务已退出但没有完整结果；原现场保留", nil
		}
		return "queued", "", nil
	case "failed":
		return "needs-attention", "规则服务失败但没有完整结果；原现场保留", nil
	default:
		return "", "", errors.New("规则安装固定单元状态异常")
	}
}

func (s *Service) networkIDSRuleFeedJobRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/network-ids/rule-feeds", func(w http.ResponseWriter, r *http.Request) {
		out := core.NetworkIDSRuleFeedInventory{Rows: []core.NetworkIDSRuleFeedStored{}}
		store, err := s.threatIDSRuleFeedStore()
		if err == nil {
			out = store.inventory(r.Context())
		} else {
			out.Error = err.Error()
		}
		respond(w, 200, out)
	})
	m.HandleFunc("GET /v1/network-ids/rule-feeds/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		out, err := s.threatIDSRuleFeedJobStatus(r.Context(), r.PathValue("id"))
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("POST /v1/network-ids/rule-feeds/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		query := r.URL.Query()
		if len(query) != 3 || len(query["app_version"]) != 1 || len(query["app_manifest_sha256"]) != 1 || len(query["rule_manifest_sha256"]) != 1 || !core.ValidID(id) {
			respond(w, 400, map[string]string{"error": "规则安装任务查询绑定无效"})
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, appcatalog.MaxRuleFeedEnvelopeBytes))
		if err != nil {
			respond(w, 400, map[string]string{"error": "规则交付数据超过容量或不可读取"})
			return
		}
		in, err := appcatalog.DecodeRuleFeedEnvelope(raw)
		if err != nil {
			respond(w, 400, map[string]string{"error": err.Error()})
			return
		}
		selection := core.NetworkIDSRuleFeedSelection{FeedID: in.FeedID, AppVersion: query.Get("app_version"), AppManifestSHA: query.Get("app_manifest_sha256"), RuleManifestSHA: query.Get("rule_manifest_sha256")}
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.moduleInstalled("network-threat-detection") {
			respond(w, 409, map[string]string{"error": "应用未安装；未存放或执行规则任务"})
			return
		}
		if err := s.createThreatIDSRuleFeedRequest(r.Context(), id, selection, raw); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		out, err := s.threatIDSRuleFeedJobStatus(r.Context(), id)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		if out.State == "queued" {
			if _, err := s.Config.Run(r.Context(), "/usr/bin/systemctl", "start", "--no-block", "panel-network-rulefeed-install@"+id+".service"); err != nil {
				respond(w, 409, map[string]string{"error": "规则安装派发失败；原请求保留"})
				return
			}
			out.State = "running"
		}
		respond(w, 202, out)
	})
}

// Fixed systemd entry: offline data verification and publication only. No
// dynamic path/key/URL, capture, native commands, account or unit modification.
func RunNetworkIDSRuleFeedInstall(id string) error {
	if !core.ValidID(id) || os.Geteuid() != 0 {
		return errors.New("规则安装固定入口身份无效")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	s := New(Config{})
	request, raw, err := readThreatIDSRuleFeedRequest(id)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Join(threatIDSRuleFeedJobs, id))
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := root.OpenFile("install.lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	lockInfo, err := lock.Stat()
	if err != nil {
		return err
	}
	lockOwner, ok := lockInfo.Sys().(*syscall.Stat_t)
	if !ok || lockOwner.Uid != 0 || lockOwner.Nlink != 1 || !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm() != 0600 {
		return errors.New("规则任务锁身份或权限不同；未修复既有锁")
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("同一规则安装任务仍在执行；未并行写入")
	}
	if _, err := root.Lstat("result.json"); err == nil {
		status, err := s.threatIDSRuleFeedJobStatus(ctx, id)
		if err != nil || status.State != "ready-data" {
			return errors.New("既有规则任务终态失败或不能核对；原证据不覆盖")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	status := core.NetworkIDSRuleFeedStatus{JobID: id, Selection: request.Selection, DataOnly: true, State: "failed", Steps: []core.Step{}}
	install := func() error {
		if !s.moduleInstalled("network-threat-detection") {
			return errors.New("规则应用已卸载；未安装数据或接管遗留应用")
		}
		if err := core.ValidateSoftwareUpdate("network-threat-detection", request.Selection.AppVersion); err != nil {
			return err
		}
		in, err := appcatalog.DecodeRuleFeedEnvelope(raw)
		if err != nil {
			return err
		}
		store, err := s.threatIDSRuleFeedStore()
		if err != nil {
			return err
		}
		bound, _, err := store.verify(ctx, in, request.Selection.AppVersion, request.Selection.AppManifestSHA)
		if err != nil || bound.FeedID != request.Selection.FeedID || bound.RuleManifestSHA != request.Selection.RuleManifestSHA {
			return errors.New("原始规则交付与任务选择不符；未写入规则数据")
		}
		if err := threatIDSRuleFeedManifestCompatible(in.AppManifest); err != nil {
			return err
		}
		record, err := store.install(ctx, in, request.Selection.AppVersion, request.Selection.AppManifestSHA)
		if err != nil {
			return err
		}
		if record.FeedID != request.Selection.FeedID || record.RuleManifestSHA != request.Selection.RuleManifestSHA {
			return errors.New("规则安装结果与任务版本绑定不同")
		}
		status.State = "ready-data"
		status.Steps = append(status.Steps, core.Step{Time: core.Now(), Message: "原始签名、闭合文件和来源已独立核对并持久存放；仅规则数据，未原生校验、选择规则或启用采集"})
		return nil
	}
	err = install()
	if err != nil {
		status.Error = err.Error()
		if len(status.Error) > 1024 {
			status.Error = status.Error[:1024]
		}
	}
	data, marshalErr := json.Marshal(status)
	if marshalErr != nil {
		return marshalErr
	}
	if writeErr := ruleFeedStoreWrite(root, "result.json", append(data, '\n'), 0600); writeErr != nil {
		return errors.New("规则业务可能已执行，但终态独立写入失败；保留现场")
	}
	if syncErr := ruleFeedStoreSync(root); syncErr != nil {
		return syncErr
	}
	return err
}
