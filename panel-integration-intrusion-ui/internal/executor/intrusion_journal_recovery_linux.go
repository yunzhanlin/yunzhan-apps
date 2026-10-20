//go:build linux

package executor

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strings"

	"local/panel/internal/core"
)

// Explicit original-ID recovery from the versioned API. It does not infer
// authority from a new install/configure request, and
// it NEVER uses historical ban addresses, tickets, timestamps or nft scripts.
func (s *Service) recoverIntrusionOperation(ctx context.Context, settings map[string]any, add func(string)) error {
	recovery, err := intrusionOriginalJob(ctx)
	if err != nil {
		return err
	}
	id, idOK := settings["transaction_id"].(string)
	digest, digestOK := settings["plan_sha256"].(string)
	decoded, digestErr := hex.DecodeString(digest)
	if len(settings) != 2 || !idOK || !digestOK || !core.ValidID(id) || recovery == id || digestErr != nil || len(decoded) != 32 || strings.ToLower(digest) != digest {
		return errors.New("入侵防护恢复需要独立队列任务、原任务和完整小写摘要；未创建替代事务")
	}
	lock, err := s.intrusionMutationLock()
	if err != nil {
		return err
	}
	defer lock.Close()
	plan, raw, err := s.intrusionJournalPending()
	if errors.Is(err, os.ErrNotExist) {
		inventory, readErr := s.intrusionJournalInventoryRead()
		if readErr != nil {
			return readErr
		}
		previous, exists := inventory.Records[id]
		if !exists || previous.PlanSHA256 != digest {
			return errors.New("入侵防护没有匹配原任务和完整摘要的已闭合回执；未重放")
		}
		add("原入侵防护事务已有不可变终态且无待恢复记录；未执行任何系统变更，当前健康状态仍须独立检查")
		return nil
	}
	if err != nil {
		return err
	}
	if plan.ID != id || hardeningJournalDigest(raw) != digest {
		return errors.New("入侵防护恢复请求与当前原完整计划不符；未修改配置、限额或内核")
	}
	inventory, err := s.intrusionJournalInventoryRead()
	if err != nil {
		return err
	}
	if previous, exists := inventory.Records[id]; exists {
		if previous.PlanSHA256 != digest {
			return errors.New("入侵防护原终态与待恢复摘要冲突；未覆盖或回滚已提交事务")
		}
		if err = s.intrusionJournalCloseTerminal(ctx, lock, plan, raw, previous.State, previous.RecoveryJobID); err != nil {
			return err
		}
		add("已核对原不可变终态与当前文件、限额及内核，只关闭原待恢复记录；未重放事务")
		return nil
	}
	if err = s.intrusionJournalAdvance(ctx, lock, plan, raw, "rolled_back", recovery); err != nil {
		return err
	}
	add("已按原任务和完整摘要恢复原受管配置、运行限额及端口范围；保留当前真实封禁，不重建历史地址或计时")
	return nil
}
