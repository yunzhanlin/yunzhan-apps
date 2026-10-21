//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type adminScriptReceipt struct {
	JobID        string                 `json:"job_id"`
	ScriptSHA256 string                 `json:"script_sha256"`
	State        string                 `json:"state"`
	Result       core.AdminScriptResult `json:"result"`
}

type adminScriptRunner func(context.Context, string, int) (string, bool, error)

func validateAdminScriptRequest(in core.AdminScriptRequest) error {
	if !core.ValidID(in.JobID) || len(in.Script) < 1 || len(in.Script) > 16*1024 || strings.ContainsRune(in.Script, 0) || in.TimeoutSeconds < 1 || in.TimeoutSeconds > 60 {
		return errors.New("脚本任务参数无效")
	}
	if in.SiteID != "" && (!core.ValidID(in.SiteID) || !core.ValidSitePHPScriptPath(in.Script) || !strings.HasPrefix(in.PHPVersionID, "php-")) {
		return errors.New("网站 PHP 脚本参数无效")
	}
	if in.SiteID == "" && in.PHPVersionID != "" {
		return errors.New("PHP 版本必须绑定网站")
	}
	if in.ScriptSHA256 == "" || in.ScriptSHA256 != core.AdminScriptHash(in.Script, in.SiteID, in.PHPVersionID) {
		return errors.New("脚本内容摘要不匹配")
	}
	return nil
}

func readAdminScriptReceipt(path string) (adminScriptReceipt, error) {
	var receipt adminScriptReceipt
	info, e := os.Lstat(path)
	if e != nil {
		return receipt, e
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0002 != 0 || info.Size() > 70*1024 {
		return receipt, errors.New("脚本执行回执类型异常")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return receipt, e
	}
	e = json.Unmarshal(b, &receipt)
	return receipt, e
}

func writeAdminScriptReceipt(path string, receipt adminScriptReceipt) error {
	b, e := json.Marshal(receipt)
	if e != nil {
		return e
	}
	return atomicWrite(path, b, 0600)
}

func executeAdminScriptAt(ctx context.Context, in core.AdminScriptRequest, stateRoot, taskRoot string, uid, gid int, runner adminScriptRunner) (core.AdminScriptResult, error) {
	if e := validateAdminScriptRequest(in); e != nil {
		return core.AdminScriptResult{}, e
	}
	// Older installers omitted this root-owned receipt directory. Safely
	// create its leaf before the first Shell or PHP schedule is executed.
	if e := ordinary(filepath.Dir(stateRoot), true); e != nil {
		return core.AdminScriptResult{}, e
	}
	if e := os.Mkdir(stateRoot, 0700); e != nil && !errors.Is(e, os.ErrExist) {
		return core.AdminScriptResult{}, e
	}
	for _, dir := range []string{stateRoot, filepath.Join(taskRoot, "jobs"), filepath.Join(taskRoot, "work")} {
		if e := ordinary(dir, true); e != nil {
			return core.AdminScriptResult{}, e
		}
	}
	receiptPath := filepath.Join(stateRoot, in.JobID+".json")
	if receipt, e := readAdminScriptReceipt(receiptPath); e == nil {
		if receipt.JobID != in.JobID || receipt.ScriptSHA256 != in.ScriptSHA256 {
			return core.AdminScriptResult{}, errors.New("脚本执行回执身份不匹配")
		}
		switch receipt.State {
		case "completed":
			return receipt.Result, nil
		case "failed":
			return receipt.Result, errors.New("脚本执行失败: " + boundedText(receipt.Result.Output, 4000))
		case "started":
			return receipt.Result, errors.New("脚本执行曾经开始但结果未知，为避免重复副作用已拒绝再次执行")
		default:
			return receipt.Result, errors.New("脚本执行回执状态异常")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return core.AdminScriptResult{}, e
	}
	scriptPath := filepath.Join(taskRoot, "jobs", in.JobID+".sh")
	if e := atomicWrite(scriptPath, []byte(in.Script), 0640); e != nil {
		return core.AdminScriptResult{}, e
	}
	if e := os.Chown(scriptPath, uid, gid); e != nil {
		return core.AdminScriptResult{}, e
	}
	started := core.Now()
	result := core.AdminScriptResult{State: "started", StartedAt: started}
	receipt := adminScriptReceipt{JobID: in.JobID, ScriptSHA256: in.ScriptSHA256, State: "started", Result: result}
	if e := writeAdminScriptReceipt(receiptPath, receipt); e != nil {
		return core.AdminScriptResult{}, e
	}
	output, truncated, runErr := runner(ctx, scriptPath, in.TimeoutSeconds)
	if runErr != nil && output == "" {
		output = runErr.Error()
	}
	result.Output, result.Truncated, result.FinishedAt = output, truncated, core.Now()
	if runErr != nil {
		result.State = "failed"
		receipt.State, receipt.Result = "failed", result
		if e := writeAdminScriptReceipt(receiptPath, receipt); e != nil {
			return result, fmt.Errorf("脚本已经运行但最终回执写入失败，结果未知: %w", e)
		}
		return result, fmt.Errorf("脚本返回失败: %s", boundedText(output, 4000))
	}
	result.State = "completed"
	receipt.State, receipt.Result = "completed", result
	if e := writeAdminScriptReceipt(receiptPath, receipt); e != nil {
		return result, fmt.Errorf("脚本已经运行但最终回执写入失败，结果未知: %w", e)
	}
	return result, nil
}

func boundedText(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "\n[输出已截断]"
}

func runAdminScriptSystemd(ctx context.Context, scriptPath string, timeoutSeconds int) (string, bool, error) {
	job := strings.TrimSuffix(filepath.Base(scriptPath), ".sh")
	if !core.ValidID(job) {
		return "", false, errors.New("脚本任务标识无效")
	}
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds+10)*time.Second)
	defer cancel()
	unit := "panel-task-" + job + ".service"
	args := []string{
		"--quiet", "--wait", "--pipe", "--collect", "--service-type=exec", "--unit=" + unit,
		"--property=User=panel-task", "--property=Group=panel-task", "--property=WorkingDirectory=/var/lib/panel-tasks/work",
		"--property=PrivateTmp=yes", "--property=PrivateNetwork=yes", "--property=PrivateDevices=yes",
		"--property=ProtectSystem=strict", "--property=ProtectHome=yes", "--property=NoNewPrivileges=yes",
		"--property=ReadWritePaths=/var/lib/panel-tasks/work", "--property=RestrictAddressFamilies=AF_UNIX",
		"--property=RestrictSUIDSGID=yes", "--property=RestrictNamespaces=yes", "--property=LockPersonality=yes",
		"--property=ProtectKernelTunables=yes", "--property=ProtectKernelModules=yes", "--property=ProtectControlGroups=yes",
		"--property=CapabilityBoundingSet=", "--property=UMask=0077", "--property=RuntimeMaxSec=" + strconv.Itoa(timeoutSeconds) + "s",
		"--setenv=PATH=/usr/local/bin:/usr/bin:/bin", "/bin/bash", "--noprofile", "--norc", scriptPath,
	}
	cmd := exec.CommandContext(callCtx, "/usr/bin/systemd-run", args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	out := &boundedBuffer{max: 64 * 1024}
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = out, out, time.Second
	e := cmd.Run()
	if callCtx.Err() != nil {
		return out.String(), out.truncated, fmt.Errorf("脚本超过 %d 秒或执行连接中断: %w", timeoutSeconds, callCtx.Err())
	}
	return out.String(), out.truncated, e
}

func (s *Service) adminScriptRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/admin-scripts/run", func(w http.ResponseWriter, r *http.Request) {
		var in core.AdminScriptRequest
		if !readJSON(w, r, &in) {
			return
		}
		account, e := user.Lookup("panel-task")
		if e != nil {
			respond(w, 503, map[string]string{"error": "受限脚本用户尚未配置"})
			return
		}
		uid, uidErr := strconv.Atoi(account.Uid)
		gid, gidErr := strconv.Atoi(account.Gid)
		if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 {
			respond(w, 503, map[string]string{"error": "受限脚本用户身份无效"})
			return
		}
		lock := fileMutex("admin-script-" + in.JobID)
		lock.Lock()
		defer lock.Unlock()
		runner := runAdminScriptSystemd
		if in.SiteID != "" {
			runner = func(ctx context.Context, _ string, timeout int) (string, bool, error) {
				// Apply, archive and Nginx changes use this service guard. Keep
				// the root-owned binding stable during this bounded PHP run.
				s.mu.Lock()
				defer s.mu.Unlock()
				return runSitePHPScriptSystemd(ctx, in, timeout)
			}
		}
		result, e := executeAdminScriptAt(r.Context(), in, filepath.Join(s.Config.StateDir, "admin-scripts"), "/var/lib/panel-tasks", uid, gid, runner)
		if e != nil {
			respond(w, 409, map[string]any{"error": e.Error(), "result": result})
			return
		}
		respond(w, 200, result)
	})
}
