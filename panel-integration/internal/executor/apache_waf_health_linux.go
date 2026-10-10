//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Open first with no-follow/nonblocking flags, then validate the descriptor.
// A FIFO or a rename between lstat and open must not block or substitute bytes.
func apacheWAFReadStableFile(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() > limit {
		return nil, errors.New("Apache 受管文件类型或大小异常")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("Apache 受管文件读取失败或超过上限")
	}
	after, err := f.Stat()
	if err != nil || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("Apache 受管文件在核验期间发生变化")
	}
	current, err := os.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, current) {
		return nil, errors.New("Apache 受管文件路径在核验期间被替换")
	}
	return data, nil
}

func (s *Service) apacheWAFConfigurationMatches(version string, cfg core.WAFConfig) (string, error) {
	if version != core.ApacheWAFVersion {
		return "", errors.New("旧版 Apache WAF 需先签名升级，尚未按新版契约确认完整性")
	}
	source, bindings, err := s.apacheWAFSource()
	if err != nil || len(bindings) == 0 {
		return "", errors.New("Apache 受管配置或运行站点无法核实")
	}
	release, err := apacheRelease()
	if err != nil {
		return "", err
	}
	module := filepath.Join(release.Prefix(), "modules/mod_remoteip.so")
	return apacheWAFConfigurationFilesMatch(source, cfg, module, filepath.Join(s.moduleDir("apache-waf"), "rules.conf"))
}

func apacheWAFConfigurationFilesMatch(source string, cfg core.WAFConfig, module, rulesPath string) (string, error) {
	return apacheWAFConfigurationFilesMatchVersion(source, cfg, module, rulesPath, core.ApacheWAFVersion)
}

func apacheWAFConfigurationFilesMatchVersion(source string, cfg core.WAFConfig, module, rulesPath, version string) (string, error) {
	bindings, err := apacheWAFBindings(source)
	if err != nil || len(bindings) == 0 {
		return "", errors.New("Apache 受管站点无法核实")
	}
	if len(regexp.MustCompile(`(?m)^\s*IncludeOptional /etc/panel/security-apps/modules/apache-waf/rules\.conf\s*$`).FindAllString(source, -1)) != len(bindings) {
		return "", errors.New("Apache 防护挂载出现在受管虚拟主机之外或被重复加载")
	}
	// A correct rules file is insufficient if another virtual host dropped its
	// include or site identity. Check every owned host, not only the probe host.
	for _, block := range regexp.MustCompile(`(?ms)^<VirtualHost[^>]+>.*?</VirtualHost>`).FindAllString(source, -1) {
		id := regexp.MustCompile(`(?m)^\s*CustomLog /var/log/apache2/panel-([a-f0-9]{32})\.access\.log combined\s*$`).FindStringSubmatch(block)
		if len(id) != 2 || len(regexp.MustCompile(`(?m)^\s*IncludeOptional /etc/panel/security-apps/modules/apache-waf/rules\.conf\s*$`).FindAllString(block, -1)) != 1 || len(regexp.MustCompile(`(?m)^\s*SetEnvIfExpr "true" PANEL_AW_SITE=`+id[1]+`\s*$`).FindAllString(block, -1)) != 1 {
			return "", errors.New("Apache 站点缺少或重复防护挂载、站点身份")
		}
	}
	proxy := cfg.TrustedProxy
	if proxy == nil {
		proxy = &core.WAFTrustedProxyConfig{Header: "X-Forwarded-For", Recursive: true, TrustedCIDRs: []string{}}
	}
	prepared, err := prepareApacheWAFTrustedProxySource(source, proxy, module)
	if err != nil || prepared != source {
		return "", errors.New("Apache 可信代理模块或外部指令与已保存配置不一致")
	}
	if proxy.Enabled {
		if err := verifyApacheWAFRemoteIPModule(module); err != nil {
			return "", err
		}
	}
	expected, err := renderApacheWAFVersion(cfg, bindings, version)
	if err != nil {
		return "", err
	}
	actual, err := apacheWAFReadStableFile(rulesPath, 1<<20)
	if err != nil || string(actual) != expected {
		return "", errors.New("Apache 防护规则与已保存配置不一致，未宣称保护正常")
	}
	ids := make([]string, 0, len(bindings))
	for id := range bindings {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return bindings[ids[0]][0], nil
}

func apacheWAFProbeLoaded(ctx context.Context, cfg core.WAFConfig, domain string, client *http.Client) error {
	return apacheWAFProbeLoadedVersion(ctx, cfg, domain, client, core.ApacheWAFVersion)
}

func apacheWAFWaitLoadedVersion(ctx context.Context, cfg core.WAFConfig, domain, version string) error {
	client := &http.Client{Timeout: 1500 * time.Millisecond, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	var err error
	for i := 0; i < 8; i++ {
		err = apacheWAFProbeLoadedVersion(ctx, cfg, domain, client, version)
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return err
}

func apacheWAFProbeLoadedVersion(ctx context.Context, cfg core.WAFConfig, domain string, client *http.Client, version string) error {
	if version != core.ApacheWAFVersion && version != "2.2.0" && version != "2.1.0" && version != "2.0.0" && version != "1.0" {
		return errors.New("Apache 配置指纹版本不支持")
	}
	if !core.ValidDomain(domain) {
		return errors.New("Apache 配置指纹探针域名无效")
	}
	req, err := http.NewRequestWithContext(ctx, "HEAD", "http://127.0.0.1:19080/__yunzhan_waf_probe", nil)
	if err != nil {
		return err
	}
	req.Host = domain
	req.Header.Set("User-Agent", "Yunzhan Apache read-only integrity probe")
	res, err := client.Do(req)
	if err != nil {
		return errors.New("Apache 实际配置指纹探针不可达")
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode < 400 || res.StatusCode < 200 || res.StatusCode >= 500 || res.Header.Get("X-Panel-Apache-WAF") != apacheWAFProbeVersion(cfg, version) {
		return errors.New("Apache 实际加载指纹与配置不一致，未宣称保护正常")
	}
	if version == "1.0" {
		// Its old 'active' marker is not unique. Also verify the known fixed
		// scanner rule with a private HEAD request before allowing migration.
		probe := req.Clone(ctx)
		probe.Header.Set("User-Agent", "sqlmap")
		blocked, err := client.Do(probe)
		if err != nil {
			return errors.New("Apache 1.0 固定规则只读阻断探针不可达")
		}
		defer blocked.Body.Close()
		if blocked.StatusCode != http.StatusForbidden || blocked.Header.Get("X-Panel-Apache-WAF") != "active" {
			return errors.New("Apache 1.0 固定规则未确认实际加载，未迁移")
		}
	}
	return nil
}

func (s *Service) verifyApacheWAFLegacyUpgrade(ctx context.Context, status core.SoftwareAppStatus) error {
	if !status.Installed || status.Version != "2.2.0" && status.Version != "2.1.0" && status.Version != "2.0.0" && status.Version != "1.0" {
		return errors.New("仅允许已知完整旧版 Apache 1.0/2.0/2.1/2.2 防护经签名迁移")
	}
	if status.Version == "1.0" && len(status.Settings) != 0 {
		return errors.New("Apache 1.0 安装记录含非原始空设置，拒绝猜测迁移")
	}
	cfg, err := core.DecodeApacheWAFConfig(status.Settings)
	if err != nil || cfg.TrustedProxy != nil && status.Version != "2.1.0" && status.Version != "2.2.0" {
		return errors.New("旧版 Apache 防护记录含未知策略，未迁移")
	}
	source, _, err := s.apacheWAFSource()
	if err != nil {
		return err
	}
	release, err := apacheRelease()
	if err != nil {
		return err
	}
	domain, err := apacheWAFConfigurationFilesMatchVersion(source, cfg, filepath.Join(release.Prefix(), "modules/mod_remoteip.so"), filepath.Join(s.moduleDir("apache-waf"), "rules.conf"), status.Version)
	if err != nil {
		return err
	}
	state, err := s.Config.Run(ctx, "/usr/bin/systemctl", "is-active", "panel-apache")
	if err != nil || strings.TrimSpace(state) != "active" {
		return errors.New("旧版 Apache 实际服务未运行，未迁移")
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 1500 * time.Millisecond, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	return apacheWAFProbeLoadedVersion(bounded, cfg, domain, client, status.Version)
}

func (s *Service) verifyApacheWAFHealth(ctx context.Context, version string, settings map[string]any) error {
	if _, err := os.Lstat(s.apacheWAFTransactionService().wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
		return errors.New("Apache 防护仍有待恢复或待确认事务，未宣称保护正常")
	}
	cfg, err := core.DecodeApacheWAFConfig(settings)
	if err != nil {
		return err
	}
	domain, err := s.apacheWAFConfigurationMatches(version, cfg)
	if err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 1500 * time.Millisecond, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	return apacheWAFProbeLoaded(bounded, cfg, domain, client)
}
