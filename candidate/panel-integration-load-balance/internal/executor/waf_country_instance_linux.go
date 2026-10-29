//go:build linux

package executor

import (
	"bytes"
	"errors"
	"path/filepath"
	"time"

	"local/panel/internal/core"
)

const wafCountryInstanceFile = "nginx-waf.instance.json"

type wafCountryInstance struct {
	Format    int    `json:"format"`
	App       string `json:"app"`
	ID        string `json:"instance_id"`
	CreatedAt string `json:"created_at"`
}

func decodeWAFCountryInstance(raw []byte) (wafCountryInstance, error) {
	var out wafCountryInstance
	if len(raw) < 1 || len(raw) > 1024 || countryCacheDecode(raw, &out) != nil || out.Format != 1 || out.App != "nginx-waf" || !core.ValidID(out.ID) || !hardeningCanonicalTime(out.CreatedAt) {
		return wafCountryInstance{}, errors.New("国家数据原应用实例记录不完整或不可核对")
	}
	return out, nil
}

// Pure plan bytes only, not filesystem authority. A new random identity is
// placed INSIDE the ordinary WAF transaction, never created by a status query,
// data download, repair or timestamp heuristic. Reinstall in the same second
// still gets a distinct identity. Historical2.5 policy bytes are unchanged.
func planWAFCountryInstanceBytes(previousVersion string, previous []byte, exists, uninstall bool, now time.Time) ([]byte, bool, error) {
	known := previousVersion == "" || previousVersion == "2.0.1" || previousVersion == "2.1.0" || previousVersion == "2.1.1" || previousVersion == "2.2.0" || previousVersion == "2.3.0" || previousVersion == "2.4.0" || previousVersion == "2.5.0" || previousVersion == "2.5.1" || previousVersion == "2.5.2" || previousVersion == core.WAFCountryDataVersion
	if !known || now.IsZero() {
		return nil, false, errors.New("国家数据实例迁移版本或时钟不能核对")
	}
	if previousVersion == core.WAFCountryDataVersion {
		if !exists {
			return nil, false, errors.New("已安装国家功能的原实例记录缺失，禁止自动补建")
		}
		if _, err := decodeWAFCountryInstance(previous); err != nil {
			return nil, false, err
		}
		if uninstall {
			return nil, false, nil
		}
		return bytes.Clone(previous), true, nil
	}
	if exists || len(previous) != 0 {
		return nil, false, errors.New("旧版本或未安装应用含外来实例记录，禁止接管或覆盖")
	}
	if uninstall {
		return nil, false, nil
	}
	raw, err := countryCacheJSON(wafCountryInstance{1, "nginx-waf", core.ID(), now.UTC().Format(time.RFC3339)})
	if err != nil {
		return nil, false, err
	}
	return raw, true, nil
}

func (s *Service) readWAFCountryInstance() (wafCountryInstance, string, error) {
	var empty wafCountryInstance
	if statisticsGeoParents(s.Config.SecurityDir) != nil {
		return empty, "", errors.New("国家数据实例祖先目录不受信，未创建或修复")
	}
	root, err := s.softwareManifestDirectory()
	if err != nil {
		return empty, "", err
	}
	defer root.Close()
	raw, _, err := geoStoreReadIdentity(root, wafCountryInstanceFile, 1024)
	if err != nil {
		return empty, "", err
	}
	record, err := decodeWAFCountryInstance(raw)
	if err != nil {
		return empty, "", err
	}
	if !s.softwareManifestAnchorCurrent(root) {
		return empty, "", errors.New("国家数据实例根目录已改变")
	}
	return record, core.Hash(string(raw)), nil
}

// The instance is read only AFTER the ordinary WAF2.6 transaction commits.
// Calling this cannot make current WAF2.5.2 support the unfinished capability.
func (s *Service) wafCountryInstanceGuard(expected string) error {
	if !wafLogDigestValid(expected) {
		return errors.New("国家数据原安装实例摘要无效")
	}
	manifest, err := s.readSoftwareManifest("nginx-waf")
	if err != nil || manifest.Version != core.WAFCountryDataVersion {
		return errors.New("国家数据需要明确安装或升级的对应防火墙版本")
	}
	if _, err := core.DecodeWAFConfig(manifest.Settings); err != nil {
		return err
	}
	if err := s.wafBackupArchiveNoPending(); err != nil {
		return err
	}
	_, digest, err := s.readWAFCountryInstance()
	if err != nil {
		return err
	}
	if digest != expected {
		return errors.New("原防火墙已卸载、重装或实例记录改变，未发布旧任务数据")
	}
	return nil
}

func (s *Service) wafCountryInstancePath() string {
	return filepath.Join(s.Config.SecurityDir, wafCountryInstanceFile)
}
