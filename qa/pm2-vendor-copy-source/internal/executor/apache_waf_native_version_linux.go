//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
)

func apacheNativeRecord(record map[string]any) bool {
	version, _ := record["version"].(string)
	return core.ApacheWAFNativeVersion(version)
}

func (s *Service) verifyApacheCurrentNativeConfigHealth(ctx context.Context, cfg core.WAFConfig) error {
	record, err := s.moduleInstalledRecord("apache-waf")
	if err != nil {
		return err
	}
	if !apacheNativeRecord(record) {
		return errors.New("当前 Apache 原签名原生版本无法核验")
	}
	settings, ok := record["settings"].(map[string]any)
	if !ok {
		return errors.New("Apache 原安装配置缺失，未采用默认值")
	}
	version := record["version"].(string)
	current, err := core.DecodeApacheWAFVersionConfig(settings, version)
	if err != nil {
		return err
	}
	a, _ := json.Marshal(current)
	b, _ := json.Marshal(cfg)
	if string(a) != string(b) {
		return errors.New("Apache 原安装策略已变化，刷新后再操作")
	}
	return s.verifyApacheWAFHealth(ctx, version, settings)
}
