//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func sitePHPScriptPath(root, relative string) (string, error) {
	if !core.ValidSitePHPScriptPath(relative) {
		return "", errors.New("PHP 脚本必须是网站内的相对文件路径")
	}
	if e := ordinary(root, true); e != nil {
		return "", e
	}
	current := root
	parts := strings.Split(relative, "/")
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, e := os.Lstat(current)
		if e != nil {
			return "", e
		}
		if info.Mode()&os.ModeSymlink != 0 || (index < len(parts)-1 && !info.IsDir()) || (index == len(parts)-1 && !info.Mode().IsRegular()) {
			return "", errors.New("PHP 脚本路径不能包含符号链接或特殊文件")
		}
	}
	return current, nil
}

func sitePHPScriptArgs(in core.AdminScriptRequest, site core.Site, phpCLI, scriptPath string, ini []string, timeout int) ([]string, error) {
	if site.ID != in.SiteID || site.PHPVersionID != in.PHPVersionID {
		return nil, errors.New("网站 PHP 绑定已变更，本次运行已拒绝；请重新执行任务")
	}
	base := "/srv/panel/sites/" + in.SiteID
	args := []string{
		"--quiet", "--wait", "--pipe", "--collect", "--service-type=exec", "--unit=panel-task-" + in.JobID + ".service",
		"--property=User=" + siteUser(in.SiteID), "--property=Group=" + siteUser(in.SiteID), "--property=WorkingDirectory=" + base + "/public",
		"--property=PrivateTmp=yes", "--property=PrivateDevices=yes", "--property=ProtectSystem=strict", "--property=ProtectHome=yes",
		"--property=NoNewPrivileges=yes", "--property=ReadWritePaths=" + base,
		"--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", "--property=RestrictSUIDSGID=yes", "--property=RestrictNamespaces=yes",
		"--property=LockPersonality=yes", "--property=ProtectKernelTunables=yes", "--property=ProtectKernelModules=yes", "--property=ProtectControlGroups=yes",
		"--property=CapabilityBoundingSet=", "--property=UMask=0077", "--property=RuntimeMaxSec=" + strconv.Itoa(timeout) + "s",
		"--setenv=PATH=" + filepath.Dir(phpCLI) + ":/usr/bin:/bin", "--setenv=HOME=" + base + "/private", phpCLI,
	}
	args = append(args, ini...)
	return append(args, "-f", scriptPath), nil
}

func runSitePHPScriptSystemd(ctx context.Context, in core.AdminScriptRequest, timeout int) (string, bool, error) {
	if e := validateAdminScriptRequest(in); e != nil {
		return "", false, e
	}
	lock, e := runtimeUseLock()
	if e != nil {
		return "", false, e
	}
	defer lock.Close()
	// Site changes and file operations share this mutex. Keep the runtime and
	// binding stable until the bounded process and all its children have exited.
	siteLock := fileMutex(in.SiteID)
	siteLock.Lock()
	defer siteLock.Unlock()
	b, e := os.ReadFile(filepath.Join(phpConfigRoot, "bindings", in.SiteID+".json"))
	if e != nil {
		return "", false, e
	}
	var site core.Site
	if e = json.Unmarshal(b, &site); e != nil {
		return "", false, e
	}
	if site.ID != in.SiteID || site.PHPVersionID != in.PHPVersionID {
		return "", false, errors.New("网站 PHP 绑定已变更，本次运行已拒绝；请重新执行任务")
	}
	release, ok := runtimecatalog.Find(in.PHPVersionID)
	if !ok || release.Family != "php" {
		return "", false, errors.New("网站 PHP 版本无效")
	}
	if _, e = LoadRuntime(release.ID); e != nil {
		return "", false, e
	}
	account, e := user.Lookup(siteUser(in.SiteID))
	if e != nil || account.Uid == "0" || account.Gid == "0" {
		return "", false, errors.New("网站运行用户未就绪")
	}
	if e = core.ValidatePHPSettings(site.Settings.PHP); e != nil {
		return "", false, e
	}
	ini, e := phpExtensionArgs(ctx, release, site.Settings.PHP)
	if e != nil {
		return "", false, e
	}
	for _, pair := range core.PHPIniValues(site.Settings.PHP) {
		ini = append(ini, "-d", pair[0]+"="+pair[1])
	}
	scriptPath, e := sitePHPScriptPath("/srv/panel/sites/"+in.SiteID+"/public", in.Script)
	if e != nil {
		return "", false, e
	}
	args, e := sitePHPScriptArgs(in, site, release.CLI(), scriptPath, ini, timeout)
	if e != nil {
		return "", false, e
	}
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout+10)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(callCtx, "/usr/bin/systemd-run", args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	out := &boundedBuffer{max: 64 * 1024}
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = out, out, time.Second
	e = cmd.Run()
	if callCtx.Err() != nil {
		return out.String(), out.truncated, fmt.Errorf("PHP 脚本超过 %d 秒或执行连接中断: %w", timeout, callCtx.Err())
	}
	if e != nil && out.String() == "" {
		return e.Error(), false, e
	}
	return out.String(), out.truncated, e
}
