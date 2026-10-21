//go:build linux

package executor

import (
	"context"
	"errors"
	"path/filepath"
)

const intrusionPolicyName = "intrusion-policy.json"

// No persisted name can select a path. The Jail and the two private records
// are the complete fixed write domain; every observation remains no-create.
func (s *Service) intrusionJournalPaths() []string {
	return []string{s.systemPath("/etc/fail2ban/jail.d/panel-intrusion.local"), s.softwareManifestPath("intrusion-prevention"), filepath.Join(s.Config.SecurityDir, intrusionPolicyName)}
}

func (s *Service) intrusionJournalCurrentFiles() ([]fileBackup, error) {
	jail, err := s.intrusionConfigObservation()
	if err != nil {
		return nil, err
	}
	root, err := s.intrusionJournalRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	files := []fileBackup{jail}
	paths := s.intrusionJournalPaths()
	for i, name := range []string{"intrusion-prevention.json", intrusionPolicyName} {
		file, err := hardeningReadBackupLimit(root, name, paths[i+1], true, 16<<10)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	if !s.softwareManifestAnchorCurrent(root) {
		return nil, errors.New("入侵防护私有文件根目录在读取期间改变")
	}
	return files, nil
}

func (s *Service) intrusionJournalMatchFiles(plan intrusionJournalPlan, files []fileBackup, state string) error {
	if err := intrusionJournalValidate(plan); err != nil {
		return err
	}
	if len(files) != 3 || state != "committed" && state != "rolled_back" && state != "mixed" {
		return errors.New("入侵防护文件核对状态或固定范围无效")
	}
	paths := s.intrusionJournalPaths()
	for i, file := range files {
		before := hardeningBackupSame(file, plan.Files[i].Before.backup(paths[i]))
		after := hardeningBackupSame(file, plan.Files[i].After.backup(paths[i]))
		if state == "committed" && !after || state == "rolled_back" && !before || state == "mixed" && !before && !after {
			return errors.New("入侵防护文件不属于原事务完整前后状态；未创建、修复或覆盖外来对象")
		}
	}
	return nil
}

func (s *Service) intrusionJournalObserveFilesAndTree(ctx context.Context, plan intrusionJournalPlan, state string) ([]fileBackup, intrusionConfigurationTree, error) {
	var empty intrusionConfigurationTree
	if err := ctx.Err(); err != nil {
		return nil, empty, err
	}
	files, err := s.intrusionJournalCurrentFiles()
	if err != nil {
		return nil, empty, err
	}
	if err = s.intrusionJournalMatchFiles(plan, files, state); err != nil {
		return nil, empty, err
	}
	tree, err := s.readIntrusionConfigurationTree(ctx)
	if err != nil {
		return nil, empty, err
	}
	comparison, err := intrusionJournalTreeWithoutTemporary(plan, tree)
	if err != nil {
		return nil, empty, err
	}
	paths := s.intrusionJournalPaths()
	jail := plan.Files[0].After
	if hardeningBackupSame(files[0], plan.Files[0].Before.backup(paths[0])) {
		jail = plan.Files[0].Before
	}
	if err := intrusionConfigurationTreeAfterJail(plan.ConfigurationBefore, comparison, jail); err != nil {
		return nil, empty, err
	}
	return files, tree, nil
}
