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
	bindings, err := apacheWAFBindings(source)
	if err != nil || len(bindings) == 0 {
		return "", errors.New("Apache 受管站点无法核实")
	}
	// A correct rules file is insufficient if another virtual host dropped its
	// include or site identity. Check every owned host, not only the probe host.
	for _, block := range regexp.MustCompile(`(?ms)^<VirtualHost[^>]+>.*?</VirtualHost>`).FindAllString(source, -1) {
		id := regexp.MustCompile(`(?m)^\s*CustomLog /var/log/apache2/panel-([a-f0-9]{32})\.access\.log combined\s*$`).FindStringSubmatch(block)
		if len(id) != 2 || len(regexp.MustCompile(`(?m)^\s*IncludeOptional /etc/panel/security-apps/modules/apache-waf/rules\.conf\s*$`).FindAllString(block, -1)) != 1 || strings.Count(block, `SetEnvIfExpr "true" PANEL_AW_SITE=`+id[1]) != 1 {
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
	expected, err := renderApacheWAF(cfg, bindings)
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
	if !core.ValidDomain(domain) {
		return errors.New("Apache 配置指纹探针域名无效")
	}
	req, err := http.NewRequestWithContext(ctx, "HEAD", "http://127.0.0.1:19080/__yunzhan_waf_probe", nil)
	if err != nil {
		return err
	}
	req.Host = domain
	res, err := client.Do(req)
	if err != nil {
		return errors.New("Apache 实际配置指纹探针不可达")
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode < 400 || res.StatusCode < 200 || res.StatusCode >= 500 || res.Header.Get("X-Panel-Apache-WAF") != apacheWAFProbe(cfg) {
		return errors.New("Apache 实际加载指纹与配置不一致，未宣称保护正常")
	}
	return nil
}

func (s *Service) verifyApacheWAFHealth(ctx context.Context, version string, settings map[string]any) error {
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
