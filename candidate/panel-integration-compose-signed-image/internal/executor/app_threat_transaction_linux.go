//go:build linux

package executor

import (
	"errors"
	"os"
	"path/filepath"
)

type threatIDSRecoveryState struct {
	WasActive        bool              `json:"was_active"`
	WasEnabled       bool              `json:"was_enabled"`
	UnitSHA          string            `json:"unit_sha256"`
	RuntimeRecordSHA string            `json:"runtime_record_sha256"`
	ApplyOwner       *moduleApplyOwner `json:"apply_owner"`
	RecoveryOwner    *moduleApplyOwner `json:"recovery_owner,omitempty"`
	StopRequested    bool              `json:"stop_requested,omitempty"`
}

// Distinct namespace and closed two-file recovery set; it cannot touch Nginx,
// WAF, website configs, application data, the installed unit or runtime tree.
func (s *Service) threatIDSTransactionService() *Service {
	return &Service{Config: s.Config, fileTransactionApplication: "network-ids"}
}
func (s *Service) threatIDSConfigurationPaths() []string {
	return []string{s.systemPath("/etc/panel/network-ids/suricata.yaml"), filepath.Join(s.moduleDir("network-threat-detection"), "ids-config.json")}
}

func validateThreatIDSJournal(tx wafTransaction) error {
	if len(tx.Changes) != 2 {
		return errors.New("IDS 恢复集合不是两文件")
	}
	yaml, record := tx.Changes[0], tx.Changes[1]
	if len(yaml.NextData) > 128<<10 || len(record.NextData) > 16<<10 || len(yaml.OldData) > 128<<10 || len(record.OldData) > 16<<10 || !yaml.NextExists || !record.NextExists || yaml.OldExists != record.OldExists || yaml.NextMode != 0644 || record.NextMode != 0600 {
		return errors.New("IDS 恢复集合大小、存在状态或私有模式不完整")
	}
	var next threatIDSConfig
	if decodeThreatIDSPrivateJSON(record.NextData, &next) != nil || next.Revision < 1 || validateThreatIDSConfig(next) != nil {
		return errors.New("IDS 下一修订的配置记录无效")
	}
	wanted, err := threatIDSYAML(next, "/opt/panel/app-modules/network-threat-detection/rules/cloudstack.rules", "/var/lib/panel-network-ids/logs")
	if err != nil || string(yaml.NextData) != wanted {
		return errors.New("IDS 下一修订原生配置与受限配置记录不同")
	}
	if record.OldExists {
		var old threatIDSConfig
		if yaml.OldMode != 0644 || record.OldMode != 0600 || decodeThreatIDSPrivateJSON(record.OldData, &old) != nil || old.Revision < 1 || validateThreatIDSConfig(old) != nil || next.Revision != old.Revision+1 {
			return errors.New("IDS 原始配置模式、修订或递增关系无效")
		}
		wanted, err = threatIDSYAML(old, "/opt/panel/app-modules/network-threat-detection/rules/cloudstack.rules", "/var/lib/panel-network-ids/logs")
		if err != nil || string(yaml.OldData) != wanted {
			return errors.New("IDS 原始原生配置与记录不同；不接管外部配置")
		}
	} else if next.Revision != 1 {
		return errors.New("IDS 首次配置必须为修订 1")
	}
	return nil
}
func (s *Service) threatIDSStableBackup(path string) (fileBackup, error) {
	b := fileBackup{path: path, mode: 0644}
	if !s.wafChangePathAllowed(path) {
		return b, errors.New("IDS 恢复路径不在固定两文件内")
	}
	if err := s.wafOwnedDirectory(filepath.Dir(path), false); err != nil {
		return b, err
	}
	before, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return b, nil
	}
	if err != nil {
		return b, err
	}
	if err := ownedRuntimePath(path, false); err != nil {
		return b, err
	}
	owner, err := fileOwnerForInfo(before)
	if err != nil {
		return b, err
	}
	data, err := apacheWAFReadStableFile(path, 128<<10)
	if err != nil {
		return b, err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return b, err
	}
	afterOwner, err := fileOwnerForInfo(after)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || *owner != *afterOwner || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return b, errors.New("IDS 配置备份期间被外部替换或改变")
	}
	b.data, b.existed, b.mode, b.owner = data, true, before.Mode().Perm(), owner
	return b, nil
}
