//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"local/panel/internal/core"
)

func (s *Service) pm2ArchiveActiveDirectoryInfo() (*pm2JournalIdentity, error) {
	d, err := s.openPM2ConfigStore(false)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer d.Close()
	info, err := d.Stat(".")
	if err != nil || !d.current() {
		return nil, errors.New("PM2 active journal directory cannot be verified")
	}
	identity, err := pm2JournalIdentityOf(info)
	if err != nil {
		return nil, err
	}
	return &identity, nil
}

// Reverse recovery retains the entire original directory for review. It does
// not claim damaged original records are valid, start a service or modify an
// encrypted live manifest. Its direction is durably recorded before a rename.
func (s *Service) restorePM2ConfigurationArchive(ctx context.Context, in core.AppModuleInput) (out any, err error) {
	if err = pm2ArchiveActionInput(in, "RESTORE PM2 CONFIG ARCHIVE "+in.PM2OperationID); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	lease, err := s.lockPM2ConfigurationJournal()
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, lease.Close())
		if err != nil {
			out = nil
		}
	}()
	observed, err := s.readPM2ArchiveRequest(in.PM2OperationID)
	if err != nil {
		return nil, err
	}
	if observed.Intent == nil || observed.IntentSHA != in.ExpectedSHA {
		return nil, errors.New("所选原归档意图无法核对；全部原数据保留")
	}
	if observed.Outcome != nil {
		return map[string]any{"archive": publicPM2ArchiveRequest(observed), "already_terminal": true, "automatic_replay": false, "services_changed": false}, nil
	}
	request, err := s.openPM2ArchivePath("requests", in.PM2OperationID, false)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, request.Close())
		if err != nil {
			out = nil
		}
	}()
	module, err := s.moduleRecordDirectory("pm2-manager")
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, module.Close())
		if err != nil {
			out = nil
		}
	}()
	generations, err := s.openPM2ArchivePath("generations", "", false)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, generations.Close())
		if err != nil {
			out = nil
		}
	}()
	if observed.Restore == nil {
		original, observeErr := s.pm2ArchiveGenerationInfo(in.PM2OperationID)
		if observeErr != nil {
			return nil, observeErr
		}
		choice := pm2ConfigurationArchiveRestore{Format: 1, ID: in.PM2OperationID, IntentSHA: in.ExpectedSHA, Mode: "restore_for_review", RequestedAt: core.Now(), StartedAfterMove: original != nil}
		raw, err := json.Marshal(choice)
		if err != nil {
			return nil, err
		}
		raw = append(raw, '\n')
		if err = pm2ArchivePublish(request, "restore.json", raw); err != nil {
			return nil, err
		}
	}
	changed := false
	for step := 0; step < 4; step++ {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		if !lease.current() || !request.current() || !module.current() || !generations.current() {
			return nil, errors.New("原恢复目录已变化；所有目录保留，未采用其他数据")
		}
		row, err := s.readPM2ArchiveRequest(in.PM2OperationID)
		if err != nil {
			return nil, err
		}
		if row.Intent == nil || row.IntentSHA != in.ExpectedSHA || row.Restore == nil {
			return nil, errors.New("原显式恢复选择无法核对，未改变方向或覆盖数据")
		}
		if row.Outcome != nil {
			return map[string]any{"archive": publicPM2ArchiveRequest(row), "already_terminal": false, "automatic_replay": false, "services_changed": false}, nil
		}
		intent := *row.Intent
		active, err := s.pm2ArchiveActiveDirectoryInfo()
		if err != nil {
			return nil, err
		}
		original, err := s.pm2ArchiveGenerationInfo(in.PM2OperationID)
		if err != nil {
			return nil, err
		}
		state := ""
		switch {
		case original == nil && active != nil && pm2JournalSameDirectoryObject(intent.Inventory.Directory, *active) && row.Prepared != nil && row.PreparedEmpty && pm2JournalSameMovedDirectory(intent.PreparedDirectory, *row.Prepared):
			state = "not_moved"
		case original != nil && pm2JournalSameDirectoryObject(intent.Inventory.Directory, *original) && active != nil && pm2JournalSameDirectoryObject(intent.PreparedDirectory, *active) && row.Prepared == nil:
			current, err := s.openPM2ConfigStore(false)
			if err != nil {
				return nil, err
			}
			names, namesErr := pm2ArchiveNames(current.modulePrivateDirectory, 1)
			closeErr := current.Close()
			if namesErr != nil || closeErr != nil || len(names) != 0 {
				return nil, errors.Join(namesErr, closeErr, errors.New("新的活动目录含数据，全部保留；未隐藏或覆盖"))
			}
			if err = pm2ArchiveRenameNoReplace(module, "configuration-transactions", request, "prepared-new"); err != nil {
				return nil, err
			}
			changed = true
		case original != nil && pm2JournalSameDirectoryObject(intent.Inventory.Directory, *original) && active == nil && row.Prepared != nil && row.PreparedEmpty && pm2JournalSameMovedDirectory(intent.PreparedDirectory, *row.Prepared):
			if err = pm2ArchiveRenameNoReplace(generations, in.PM2OperationID, module, "configuration-transactions"); err != nil {
				return nil, err
			}
			changed = true
		default:
			return nil, errors.New("活动、原始或预备目录身份不一致，全部保留；未覆盖任何现有目录")
		}
		if state == "" {
			continue
		}
		// Whether a move occurred is a forensic observation, not a claim that every
		// old configuration is sound. A reverse choice deliberately does not read
		// or repair unknown original file contents before preserving the directory.
		if changed || row.Restore.StartedAfterMove {
			state = "restored_for_review"
		}
		outcome := pm2ConfigurationArchiveOutcome{Format: 1, ID: in.PM2OperationID, IntentSHA: in.ExpectedSHA, State: state, FinishedAt: core.Now(), OriginalDirectory: *active, ActiveDirectory: *active}
		if err = validatePM2ConfigurationArchiveOutcome(outcome, intent, in.ExpectedSHA); err != nil {
			return nil, err
		}
		raw, err := json.Marshal(outcome)
		if err != nil {
			return nil, err
		}
		raw = append(raw, '\n')
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		if err = pm2ArchivePublish(request, "outcome.json", raw); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("恢复原目录的请求已保留，请只读核对持久结果，未重复处理")
}
