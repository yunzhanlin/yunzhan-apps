//go:build linux

package executor

import (
	"context"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func diagnosisVerdict(verdict, detail string) map[string]any {
	return map[string]any{"ok": verdict == "pass", "verdict": verdict, "detail": detail}
}

func (s *Service) diagnoseApache(ctx context.Context, siteID, domain string) (map[string]any, map[string]any) {
	// Keep the additional checks within one bounded budget, independently of DNS.
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	config := s.diagnoseApacheConfig(ctx, siteID, domain)
	return config, s.diagnoseApacheListener(ctx)
}

func (s *Service) diagnoseApacheConfig(ctx context.Context, siteID, domain string) map[string]any {
	release, err := apacheRelease()
	if err != nil {
		return diagnosisVerdict("fail", "未找到受管 Apache 运行程序。请检查软件商店中的 Apache 安装。")
	}
	info, err := os.Lstat(s.Config.ApacheSiteConfig)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
		return diagnosisVerdict("fail", "无法核对 Apache 受管配置的文件类型或所有权。")
	}
	_, bindings, err := s.apacheWAFSource()
	if err != nil {
		return diagnosisVerdict("fail", "无法读取 Apache 受管配置或识别其中的站点。")
	}
	if _, err := s.Config.RunWait(ctx, 3*time.Second, release.CLI(), "-t", "-f", s.Config.ApacheSiteConfig); err != nil {
		return diagnosisVerdict("fail", "Apache 配置语法检查失败或超时。请查看 Apache 服务日志。")
	}
	if len(bindings[siteID]) == 0 || !strings.EqualFold(bindings[siteID][0], domain) {
		return diagnosisVerdict("warn", "Apache 当前配置缺少该站点的主域名。请检查站点是否启用及配置是否同步。")
	}
	for otherID, hosts := range bindings {
		if otherID == siteID {
			continue
		}
		for _, host := range hosts {
			if strings.EqualFold(host, domain) {
				return diagnosisVerdict("fail", "同一域名出现在多个 Apache 虚拟主机中。请核对域名绑定。")
			}
		}
	}
	return diagnosisVerdict("pass", "Apache 配置语法通过，受管虚拟主机的站点和主域名一致。")
}

var apacheListenerOwner = regexp.MustCompile(`\("httpd",pid=([1-9][0-9]*),fd=([0-9]+)\)`)

func (s *Service) apacheOwnsDiagnosisListener(listeners, pid string) bool {
	for _, line := range strings.Split(listeners, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[0] != "LISTEN" || fields[3] != "127.0.0.1:19080" {
			continue
		}
		var inode string
		for _, field := range fields[5:] {
			if value, found := strings.CutPrefix(field, "ino:"); found {
				inode = value
				break
			}
		}
		number, err := strconv.ParseUint(inode, 10, 64)
		if err != nil || number == 0 {
			continue
		}
		for _, owner := range apacheListenerOwner.FindAllStringSubmatch(line, 512) {
			if owner[1] != pid {
				continue
			}
			target, err := os.Readlink(s.systemPath("/proc/" + pid + "/fd/" + owner[2]))
			if err == nil && target == "socket:["+inode+"]" {
				return true
			}
		}
	}
	return false
}

func (s *Service) diagnoseApacheListener(ctx context.Context) map[string]any {
	raw, err := s.Config.RunWait(ctx, 2*time.Second, "/usr/bin/systemctl", "show", "panel-apache.service", "--property=ActiveState,MainPID")
	if err != nil {
		return diagnosisVerdict("warn", "无法查询受管 Apache 服务状态。请查看 systemd 服务日志。")
	}
	state, pid := "", ""
	for _, line := range strings.Split(raw, "\n") {
		key, value, _ := strings.Cut(line, "=")
		switch key {
		case "ActiveState":
			state = value
		case "MainPID":
			pid = value
		}
	}
	number, err := strconv.Atoi(pid)
	if state != "active" || err != nil || number < 2 || strconv.Itoa(number) != pid {
		return diagnosisVerdict("fail", "受管 Apache 服务没有可核对的运行主进程。")
	}
	release, releaseErr := apacheRelease()
	if releaseErr != nil {
		return diagnosisVerdict("warn", "运行中的主进程无法与已安装的受管 Apache 程序核对。")
	}
	installed, installedErr := os.Stat(release.CLI())
	running, runningErr := os.Stat(s.systemPath("/proc/" + pid + "/exe"))
	if installedErr != nil || runningErr != nil || !os.SameFile(installed, running) {
		return diagnosisVerdict("warn", "运行中的主进程与已安装的受管 Apache 程序不一致。请检查服务配置。")
	}
	listeners, err := s.Config.RunWait(ctx, 2*time.Second, "/usr/bin/ss", "-H", "-ltnpe", "sport", "=", ":19080")
	if err != nil {
		return diagnosisVerdict("warn", "无法读取 Apache 后端端口的监听归属。")
	}
	if !s.apacheOwnsDiagnosisListener(listeners, pid) {
		return diagnosisVerdict("fail", "受管 Apache 主进程未持有 127.0.0.1:19080 监听。请核对端口冲突及服务日志。")
	}
	return diagnosisVerdict("pass", "受管 Apache 主进程正在监听 127.0.0.1:19080。")
}
