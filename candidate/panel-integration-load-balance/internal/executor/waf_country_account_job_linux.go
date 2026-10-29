//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/upgradeguard"
)

const countryAccountUnitBody = `[Unit]
Description=Panel original WAF country network account preparation %i

[Service]
Type=oneshot
Slice=system.slice
User=root
Group=root
ExecStart=/opt/panel/bin/panel-executor --waf-country-account=%i
TimeoutStartSec=15s
TimeoutStopSec=3s
KillMode=control-group
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETGID CAP_SETUID CAP_AUDIT_WRITE
ProtectHome=true
ProtectSystem=strict
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_NETLINK
ReadWritePaths=/etc
ReadOnlyPaths=/var/lib/panel /var/lib/panel-executor/waf-country-jobs
InaccessiblePaths=-/run/panel-executor/control.sock -/etc/nginx -/etc/systemd/system -/etc/ssh -/srv/panel/sites
MemoryMax=96M
MemorySwapMax=0
TasksMax=16
CPUQuota=50%
LimitCORE=0
`

// Called inside the one durable original data dispatch, before the data worker.
// A missing reply never grants another preparation, request, or worker start.
func (s *Service) ensureWAFCountryNetworkAccount(ctx context.Context, request countryTaskRequest) error {
	if ctx == nil || ctx.Err() != nil || !countryTaskRequestValid(request) {
		return errors.New("国家数据原账户准备请求无效")
	}
	if err := verifyWAFCountryCoreOriginal(ctx, request.JobID, request.ActorID, request.PayloadSHA); err != nil {
		return err
	}
	if err := s.wafCountryInstanceGuard(request.Selection.InstallationSHA); err != nil {
		return err
	}
	if _, err := s.countryNetworkAccount(ctx); err == nil {
		return nil
	}
	if err := threatIDSTrustedParents(s.moduleDir("nginx-waf"), true); err != nil {
		return err
	}
	if err := s.countryFixedUnitTrusted(ctx, request.JobID, "panel-waf-country-account", countryAccountUnitBody); err != nil {
		return err
	}
	if _, err := s.moduleCommand(ctx, 17*time.Second, "/usr/bin/systemctl", "start", "panel-waf-country-account@"+request.JobID+".service"); err != nil {
		return errors.New("原国家数据账户准备结果未确认；保留原派发，不重建或重放")
	}
	if _, err := s.countryNetworkAccount(ctx); err != nil {
		return err
	}
	return verifyWAFCountryCoreOriginal(ctx, request.JobID, request.ActorID, request.PayloadSHA)
}

// No package install, body engine, arbitrary username/path, or network access.
// Partial NSS preparation remains visible and is never adopted as a new user.
func RunWAFCountryNetworkAccountJob(id string) error {
	if os.Geteuid() != 0 || !core.ValidID(id) {
		return errors.New("国家数据固定账户入口无效")
	}
	if err := upgradeguard.CheckStartup(); err != nil {
		return err
	}
	cgroup, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || !bytes.Equal(cgroup, []byte("0::/system.slice/panel-waf-country-account@"+id+".service\n")) {
		return errors.New("国家数据账户准备不属于原编号的固定工作单元")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	store := productionCountryTaskStore()
	base, err := store.open(false)
	if err != nil {
		return err
	}
	defer base.Close()
	request, envelope, dir, err := store.read(base, id)
	if err != nil {
		return err
	}
	defer dir.Close()
	dispatch, err := countryTaskReadDispatch(dir.Root, request)
	boot, bootErr := countryTaskBootID()
	if err != nil || bootErr != nil || dispatch.BootID != boot {
		return errors.New("国家数据账户原派发或主机启动身份改变，未执行")
	}
	for _, name := range []string{"started.json", "result.json"} {
		if _, err := dir.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return errors.New("原国家数据任务已有执行证据，账户准备不能重放")
		}
	}
	service := nativeWAFService()
	if _, _, err := service.authorizeWAFCountryData(ctx, id, request.ActorID, request.Selection, envelope); err != nil {
		return err
	}
	check, release, err := service.wafCountryPublicationLease(request.Selection.InstallationSHA)(ctx)
	if err != nil {
		return err
	}
	defer release()
	if err := check(); err != nil {
		return err
	}
	if err := service.prepareCountryNetworkAccount(ctx); err != nil {
		return err
	}
	if !base.current() || !dir.current() {
		return errors.New("国家数据账户准备期间原始目录改变")
	}
	if err := check(); err != nil {
		return err
	}
	return verifyWAFCountryCoreOriginal(ctx, id, request.ActorID, request.PayloadSHA)
}
