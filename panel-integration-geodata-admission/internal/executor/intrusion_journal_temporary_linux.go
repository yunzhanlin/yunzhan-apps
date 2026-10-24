//go:build linux

package executor

import (
	"encoding/hex"
	"errors"
	"os"
	"path"
	"regexp"
	"strings"
)

var intrusionFileTemporaryName = regexp.MustCompile(`^\.intrusion-([a-f0-9]{32})-(jail|manifest|policy)-([a-f0-9]{32})\.tmp$`)

// These are retained write-attempt evidence, NEVER active configuration,
// replacement file contents, an executable or permission to delete anything.
// A partial write must not strand an otherwise recoverable original record.
// Only this exact original job's fixed-slot private bounded files qualify.
func intrusionJournalTemporaryValidate(plan intrusionJournalPlan, name string, slot int, entry intrusionConfigurationEntry) error {
	if slot < 0 || slot >= 3 {
		return errors.New("入侵防护临时证据固定位置无效")
	}
	parts := intrusionFileTemporaryName.FindStringSubmatch(name)
	if len(parts) != 4 || parts[1] != plan.ID || parts[2] != plan.Files[slot].Name {
		return errors.New("入侵防护临时证据没有匹配原任务和固定文件")
	}
	before, after := plan.Files[slot].Before, plan.Files[slot].After
	limit := max(len(before.Data), len(after.Data))
	mode := os.FileMode(entry.Mode)
	allowedMode := entry.Mode == 0600 || before.Exists && entry.Mode == before.Mode || after.Exists && entry.Mode == after.Mode
	allowedGroup := entry.GID == uint32(os.Getegid()) || before.Owner != nil && entry.GID == before.Owner.GID || after.Owner != nil && entry.GID == after.Owner.GID
	if entry.Kind != "file" || mode != mode.Perm() || !allowedMode || !allowedGroup || entry.UID != uint32(os.Geteuid()) || entry.Inode == 0 || entry.Size < 0 || entry.Size > int64(limit) || len(entry.SHA256) != 64 {
		return errors.New("入侵防护临时证据类型、身份、权限或容量未知；未忽略或修复")
	}
	if digest, err := hex.DecodeString(entry.SHA256); err != nil || len(digest) != 32 || strings.ToLower(entry.SHA256) != entry.SHA256 {
		return errors.New("入侵防护临时证据完整摘要无法核对")
	}
	return nil
}

func intrusionJournalTreeWithoutTemporary(plan intrusionJournalPlan, tree intrusionConfigurationTree) (intrusionConfigurationTree, error) {
	if err := intrusionJournalValidate(plan); err != nil {
		return intrusionConfigurationTree{}, err
	}
	out := intrusionConfigurationTree{Entries: map[string]intrusionConfigurationEntry{}, Bytes: tree.Bytes}
	for name, entry := range tree.Entries {
		out.Entries[name] = entry
	}
	count := 0
	for name, entry := range tree.Entries {
		if path.Dir(name) != "jail.d" || !strings.HasPrefix(path.Base(name), ".intrusion-"+plan.ID+"-") {
			continue
		}
		if err := intrusionJournalTemporaryValidate(plan, path.Base(name), 0, entry); err != nil {
			return intrusionConfigurationTree{}, err
		}
		count++
		if count > intrusionJournalRecords {
			return intrusionConfigurationTree{}, errors.New("入侵防护原任务临时证据超过固定容量；未删除证据")
		}
		delete(out.Entries, name)
		out.Bytes -= entry.Size
	}
	if out.Bytes < 0 {
		return intrusionConfigurationTree{}, errors.New("入侵防护原任务临时证据总容量无法核对")
	}
	return out, nil
}
