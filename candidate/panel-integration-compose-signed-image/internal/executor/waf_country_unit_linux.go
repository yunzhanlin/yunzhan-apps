//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"local/panel/internal/core"
)

// Exact compiled unit source. A source test keeps the release template equal;
// only the ordinary signed installer /opt/panel/current rewrite is accepted.
const countryTaskUnitBody = "[Unit]\nDescription=Panel original signed WAF country data operation %i\n\n[Service]\nType=oneshot\nUser=root\nGroup=root\nExecStart=/opt/panel/bin/panel-executor --waf-country-job=%i\nTimeoutStartSec=280s\nTimeoutStopSec=5s\nKillMode=control-group\nUMask=0077\nNoNewPrivileges=true\n# The supervisor reads panel-owned Core authorization, then changes the\n# network child's UID/GID and can cancel that same changed-UID child.\nCapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_KILL CAP_SETGID CAP_SETUID\nAmbientCapabilities=CAP_DAC_READ_SEARCH CAP_KILL CAP_SETGID CAP_SETUID\nProtectHome=true\nProtectSystem=strict\nPrivateTmp=true\nPrivateDevices=true\nProtectKernelTunables=true\nProtectKernelModules=true\nProtectControlGroups=true\nRestrictNamespaces=true\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nRestrictSUIDSGID=true\nReadWritePaths=/var/lib/panel-executor/waf-country-data /var/lib/panel-executor/waf-country-jobs\nReadOnlyPaths=/etc/panel /var/lib/panel\nInaccessiblePaths=-/run/panel-executor/control.sock -/etc/panel/credentials -/etc/nginx -/etc/systemd/system -/srv/panel/sites\nEnvironment=GOMEMLIMIT=160MiB\nEnvironment=GOMAXPROCS=2\nMemoryHigh=256M\nMemoryMax=384M\nMemorySwapMax=0\nTasksMax=32\nCPUQuota=70%\nLimitFSIZE=64M\nLimitCORE=0\n"

func countryTaskLoadedPolicy(raw, id string) bool {
	return countryFixedLoadedPolicy(raw, id, "/etc/systemd/system/panel-waf-country@.service")
}

func countryFixedLoadedPolicy(raw, id, fragment string) bool {
	if !core.ValidID(id) || len(raw) < 1 || len(raw) > 8192 {
		return false
	}
	wanted := map[string]string{"LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "FragmentPath": fragment, "DropInPaths": "", "Transient": "no", "NeedDaemonReload": "no"}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		want, known := wanted[key]
		if !ok || !known || seen[key] || value != want {
			return false
		}
		seen[key] = true
	}
	return len(seen) == len(wanted)
}

func (s *Service) countryTaskUnitTrusted(ctx context.Context, id string) error {
	return s.countryFixedUnitTrusted(ctx, id, "panel-waf-country", countryTaskUnitBody)
}

func (s *Service) countryFixedUnitTrusted(ctx context.Context, id, name, body string) error {
	if ctx == nil || ctx.Err() != nil || !core.ValidID(id) || os.Geteuid() != 0 || s.Config.SystemRoot != "/" {
		return errors.New("国家数据固定工作单元身份无效")
	}
	if name != "panel-waf-country" && name != "panel-waf-country-account" {
		return errors.New("国家数据工作单元不是固定编译目标")
	}
	path := "/etc/systemd/system/" + name + "@.service"
	if err := statisticsGeoParents(filepath.Dir(path)); err != nil {
		return err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return errors.New("国家数据专用单元尚未通过签名面板安装")
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || owner.Gid != 0 || owner.Nlink != 1 || !before.Mode().IsRegular() || before.Mode() != 0644 {
		return errors.New("国家数据工作单元不是Root受管的普通文件，未接管或重写")
	}
	raw, err := apacheWAFReadStableFile(path, 16<<10)
	production := strings.ReplaceAll(body, "/opt/panel/bin/", "/opt/panel/current/bin/")
	if err != nil || string(raw) != body && string(raw) != production {
		return errors.New("国家数据单元与当前固定签名处理器不同，未覆盖")
	}
	loaded, err := s.moduleCommand(ctx, 5*time.Second, "/usr/bin/systemctl", "show", "--all", name+"@"+id+".service", "--property=LoadState,ActiveState,SubState,MainPID,FragmentPath,DropInPaths,Transient,NeedDaemonReload")
	if err != nil || !countryFixedLoadedPolicy(loaded, id, path) {
		return errors.New("国家数据单元加载来源、附加覆盖、空闲状态或配置版本不能核对；未启动")
	}
	after, err := os.Lstat(path)
	if err != nil || !geoStoreStableInfo(before, after) {
		return errors.New("国家数据原始工作单元检查期间改变")
	}
	return nil
}
