//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"time"
)

// Only this exact managed include is removed. No runtime, site, event log,
// backup, or independently configured Apache directive is uninstalled.
func apacheWAFSourceWithoutInclude(source string) (string, error) {
	if _, err := apacheWAFBindings(source); err != nil {
		return "", err
	}
	re := regexp.MustCompile(`(?m)^\s*IncludeOptional /etc/panel/security-apps/modules/apache-waf/rules\.conf\s*\n`)
	return re.ReplaceAllString(source, ""), nil
}

func apacheWAFProbeAbsent(ctx context.Context, domain string) error {
	if !core.ValidDomain(domain) {
		return errors.New("Apache 停用核验域名无效")
	}
	client := &http.Client{Timeout: 1500 * time.Millisecond, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	for i := 0; i < 8; i++ {
		req, err := http.NewRequestWithContext(ctx, "HEAD", "http://127.0.0.1:19080/__yunzhan_waf_probe", nil)
		if err != nil {
			return err
		}
		req.Host = domain
		req.Header.Set("User-Agent", "Yunzhan Apache removal integrity probe")
		res, err := client.Do(req)
		if err == nil {
			good := res.StatusCode >= 200 && res.StatusCode < 500 && (res.StatusCode < 300 || res.StatusCode >= 400) && res.Header.Get("X-Panel-Apache-WAF") == ""
			res.Body.Close()
			if good {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return errors.New("Apache 原生重载后仍有防护指纹或服务不可用，未确认卸载")
}

func (s *Service) removeApacheWAF(ctx context.Context, add func(string)) error {
	txs := s.apacheWAFTransactionService()
	lock, err := txs.lockWAFConfiguration()
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = txs.recoverApacheWAFBeforeMutation(ctx); err != nil {
		return err
	}
	paths := txs.apacheWAFConfigurationPaths()
	backups := []fileBackup{}
	for _, path := range paths {
		b, e := txs.apacheWAFStableBackup(path)
		if e != nil {
			return e
		}
		backups = append(backups, b)
	}
	if !backups[2].existed {
		return errors.New("Apache 防护模块未安装")
	}
	var current struct {
		ID       string         `json:"id"`
		Version  string         `json:"version"`
		Settings map[string]any `json:"settings"`
	}
	if err = json.Unmarshal(backups[2].data, &current); err != nil || current.ID != "apache-waf" {
		return errors.New("Apache 安装记录身份异常，未卸载")
	}
	if current.Version == core.ApacheWAFVersion {
		err = s.verifyApacheWAFHealth(ctx, current.Version, current.Settings)
	} else {
		err = s.verifyApacheWAFLegacyUpgrade(ctx, core.SoftwareAppStatus{Installed: true, Version: current.Version, Settings: current.Settings})
	}
	if err != nil {
		return err
	}
	release, err := apacheRelease()
	if err != nil {
		return err
	}
	source := string(backups[0].data)
	if _, err = prepareApacheWAFTrustedProxySource(source, nil, filepath.Join(release.Prefix(), "modules/mod_remoteip.so")); err != nil {
		return err
	}
	bindings, err := apacheWAFBindings(source)
	if err != nil || len(bindings) == 0 {
		return errors.New("Apache 卸载核验站点缺失")
	}
	source, err = apacheWAFSourceWithoutInclude(source)
	if err != nil {
		return err
	}
	plan, err := txs.planApacheWAFTransaction(backups, source, "", nil, true)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(bindings))
	for id := range bindings {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if err = txs.applyApacheWAFPlanned(ctx, plan, func(bounded context.Context) error { return apacheWAFProbeAbsent(bounded, bindings[ids[0]][0]) }, add); err != nil {
		return err
	}
	add("仅移除云栈防护挂载、规则和安装记录，原生程序、网站、日志、备份和恢复事务保留")
	return nil
}
