//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"local/panel/internal/core"
)

func pm2ArchiveActionInput(in core.AppModuleInput, confirmation string) error {
	allowed := core.AppModuleInput{PM2InstallationID: in.PM2InstallationID, PM2OperationID: in.PM2OperationID, ExpectedSHA: in.ExpectedSHA, Confirm: in.Confirm}
	if !reflect.DeepEqual(in, allowed) || in.PM2InstallationID != "" && !core.ValidID(in.PM2InstallationID) || !core.ValidID(in.PM2OperationID) || !coreSHA.MatchString(in.ExpectedSHA) || in.Confirm != confirmation {
		return errors.New("请选择完整配置清单或原归档请求，并填写精确确认；未整理其他项目数据")
	}
	return nil
}
func publicPM2ArchiveRequest(row pm2ArchiveRequestObservation) map[string]any {
	state := "not_started"
	count := 0
	at := ""
	inventory := ""
	if row.Intent != nil {
		state = "needs_attention"
		count = row.Intent.Inventory.Records
		at = row.Intent.CreatedAt
		inventory = row.Intent.InventorySHA
	}
	if row.Outcome != nil {
		state = row.Outcome.State
	}
	return map[string]any{"pm2_operation_id": row.ID, "state": state, "created_at": at, "record_count": count, "expected_sha": row.IntentSHA, "inventory_sha256": inventory, "retained_fragments": len(row.Fragments), "restore_requested": row.Restore != nil, "automatic_replay": false, "services_changed": false}
}

func (s *Service) archivePM2Configurations(ctx context.Context, in core.AppModuleInput) (out any, err error) {
	if err = pm2ArchiveActionInput(in, "ARCHIVE PM2 CONFIGURATIONS "+in.ExpectedSHA); err != nil {
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
	rows, err := s.pm2ArchiveCatalogue()
	if err != nil {
		return nil, err
	}
	requestRaw, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	requestSHA := pm2ConfigHash(requestRaw)
	for _, row := range rows {
		if row.ID == in.PM2OperationID {
			if row.Intent != nil && row.Intent.RequestSHA != requestSHA {
				return nil, errors.New("原归档标识已用于其他请求，未重放")
			}
			return map[string]any{"archive": publicPM2ArchiveRequest(row), "original_request_retained": true, "duplicate_observation": true, "automatic_replay": false}, nil
		}
		if row.Intent != nil && row.Outcome == nil {
			return nil, errors.New("原配置归档尚未完成，请先读取原请求并显式恢复")
		}
	}
	if len(rows) >= pm2ConfigurationArchiveGenerations {
		return nil, errors.New("配置归档请求已达保留上限；原日志和历史均保留")
	}
	snapshot, err := s.snapshotPM2ConfigurationJournal()
	if err != nil {
		return nil, err
	}
	if err = validatePM2ArchiveSnapshot(snapshot); err != nil {
		return nil, err
	}
	inventorySHA, err := snapshot.sha256()
	if err != nil || inventorySHA != in.ExpectedSHA {
		return nil, errors.New("PM2 原配置清单已变化，请只读刷新后重新选择；未移动原目录")
	}
	// A previous consumed operation may not become a new generation member,
	// including when a legacy writer did not understand the archive namespace.
	for name := range snapshot.Files {
		operation := name[:32]
		for _, row := range rows {
			if row.Intent == nil || row.Outcome == nil || row.Outcome.State != "archived" {
				continue
			}
			_, intent := row.Intent.Inventory.Files[operation+".intent.json"]
			_, cancel := row.Intent.Inventory.Files[operation+".cancel.json"]
			if intent || cancel {
				return nil, errors.New("活动日志含已归档的旧操作标识，原数据保留；未重复归档")
			}
		}
	}
	requests, err := s.openPM2ArchivePath("requests", "", true)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, requests.Close())
		if err != nil {
			out = nil
		}
	}()
	generations, err := s.openPM2ArchivePath("generations", "", true)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, generations.Close())
		if err != nil {
			out = nil
		}
	}()
	if !lease.current() || ctx.Err() != nil {
		return nil, errors.New("归档准备已中断或父目录变化，未移动日志")
	}
	if err = requests.Mkdir(in.PM2OperationID, 0700); err != nil {
		return nil, err
	}
	if err = pm2ConfigSync(requests); err != nil {
		return nil, err
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
	if err = request.Mkdir("prepared-new", 0700); err != nil {
		return nil, err
	}
	if err = pm2ConfigSync(request); err != nil {
		return nil, err
	}
	prepared, err := s.openPM2ArchivePrepared(in.PM2OperationID)
	if err != nil {
		return nil, err
	}
	preparedInfo, statErr := prepared.Stat(".")
	identity, identityErr := pm2JournalIdentityOf(preparedInfo)
	names, namesErr := pm2ArchiveNames(prepared, 1)
	closeErr := prepared.Close()
	if statErr != nil || identityErr != nil || namesErr != nil || closeErr != nil || len(names) != 0 {
		return nil, errors.Join(statErr, identityErr, namesErr, closeErr, errors.New("新的私有配置目录无法核对，原日志未移动"))
	}
	owner, err := currentModuleApplyOwner()
	if err != nil {
		return nil, err
	}
	boot, err := currentPM2ConfigBoot()
	if err != nil {
		return nil, err
	}
	intent := pm2ConfigurationArchiveIntent{Format: 1, ID: in.PM2OperationID, CreatedAt: core.Now(), BootID: boot, Owner: owner, RequestSHA: requestSHA, Inventory: snapshot, InventorySHA: inventorySHA, PreparedDirectory: identity}
	if err = validatePM2ConfigurationArchiveIntent(intent); err != nil {
		return nil, err
	}
	intentRaw, err := json.Marshal(intent)
	if err != nil {
		return nil, err
	}
	intentRaw = append(intentRaw, '\n')
	if err = pm2ArchivePublish(request, "intent.json", intentRaw); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return s.finishPM2ConfigurationArchive(ctx, in.PM2OperationID, pm2ConfigHash(intentRaw), lease)
}

func (s *Service) recoverPM2ConfigurationArchive(ctx context.Context, in core.AppModuleInput) (out any, err error) {
	if err = pm2ArchiveActionInput(in, "RECOVER PM2 CONFIG ARCHIVE "+in.PM2OperationID); err != nil {
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
	return s.finishPM2ConfigurationArchive(ctx, in.PM2OperationID, in.ExpectedSHA, lease)
}

func (s *Service) pm2MovedJournalSnapshot(id string, before pm2JournalSnapshot) (snapshot pm2JournalSnapshot, err error) {
	d, err := s.openPM2ArchivePath("generations", id, false)
	if err != nil {
		return snapshot, err
	}
	defer func() { err = errors.Join(err, d.Close()) }()
	snapshot, err = (&pm2ConfigStore{modulePrivateDirectory: d}).snapshot()
	if err != nil {
		return snapshot, err
	}
	if !pm2JournalSameMovedDirectory(before.Directory, snapshot.Directory) || !reflect.DeepEqual(before.Files, snapshot.Files) || before.Records != snapshot.Records || len(snapshot.Pending) != 0 {
		return snapshot, errors.New("封存目录与原完整清单不一致，保留原数据；未自动采用或覆盖")
	}
	return snapshot, nil
}

// No service command or live manifest write belongs to this state machine.
// Re-entering it requires an explicit exact original request/digest. Reads
// never complete an interrupted rename and duplicate submissions never replay.
func (s *Service) finishPM2ConfigurationArchive(ctx context.Context, id, intentSHA string, lease *pm2ConfigurationJournalLease) (out any, err error) {
	if !core.ValidID(id) || !coreSHA.MatchString(intentSHA) || !lease.current() {
		return nil, errors.New("原归档请求或日志锁无法核对")
	}
	request, err := s.openPM2ArchivePath("requests", id, false)
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
	changed := false
	for step := 0; step < 4; step++ {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		if !lease.current() || !request.current() || !module.current() || !generations.current() {
			return nil, errors.New("归档父目录已变化，所有原目录保留")
		}
		observed, err := s.readPM2ArchiveRequest(id)
		if err != nil {
			return nil, err
		}
		if observed.Intent == nil || observed.IntentSHA != intentSHA {
			return nil, errors.New("原归档意图与所选完整摘要不一致；未移动数据")
		}
		if observed.Outcome != nil {
			return map[string]any{"archive": publicPM2ArchiveRequest(observed), "already_terminal": !changed, "automatic_replay": false, "services_changed": false}, nil
		}
		if observed.Restore != nil {
			return nil, errors.New("原归档请求已选择恢复原目录待核对，请继续该显式恢复；未重新归档")
		}
		intent := *observed.Intent
		active, err := s.snapshotPM2ConfigurationJournal()
		if err != nil {
			return nil, err
		}
		generation, err := s.pm2ArchiveGenerationInfo(id)
		if err != nil {
			return nil, err
		}
		switch {
		case active.Exists && generation == nil && reflect.DeepEqual(active, intent.Inventory) && observed.Prepared != nil && observed.PreparedEmpty && pm2JournalSameMovedDirectory(intent.PreparedDirectory, *observed.Prepared):
			if err = pm2ArchiveRenameNoReplace(module, "configuration-transactions", generations, id); err != nil {
				return nil, err
			}
			changed = true
		case !active.Exists && generation != nil && observed.Prepared != nil && observed.PreparedEmpty && pm2JournalSameMovedDirectory(intent.PreparedDirectory, *observed.Prepared):
			if _, err = s.pm2MovedJournalSnapshot(id, intent.Inventory); err != nil {
				return nil, err
			}
			if err = pm2ArchiveRenameNoReplace(request, "prepared-new", module, "configuration-transactions"); err != nil {
				return nil, err
			}
			changed = true
		case active.Exists && generation != nil && observed.Prepared == nil && active.Records == 0 && len(active.Files) == 0 && pm2JournalSameMovedDirectory(intent.PreparedDirectory, active.Directory):
			original, err := s.pm2MovedJournalSnapshot(id, intent.Inventory)
			if err != nil {
				return nil, err
			}
			receipt := pm2ConfigurationArchiveOutcome{Format: 1, ID: id, IntentSHA: intentSHA, State: "archived", FinishedAt: core.Now(), OriginalDirectory: original.Directory, ActiveDirectory: active.Directory}
			if err = validatePM2ConfigurationArchiveOutcome(receipt, intent, intentSHA); err != nil {
				return nil, err
			}
			raw, err := json.Marshal(receipt)
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
			changed = true
		default:
			return nil, errors.New("原目录、封存目录或新的空目录身份不一致；全部保留，未自动采用或覆盖，请显式核对原请求")
		}
	}
	return nil, errors.New("归档已保留原请求，请只读核对持久结果，未重复操作")
}

// Kept separate from the mutation path: an ordinary read never creates the
// archive namespace, reserves an ID, starts a service or writes history.
func (s *Service) pm2ConfigurationArchiveReport(in core.AppModuleInput) (any, error) {
	if in.Limit < 0 || in.Limit > 32 || in.Offset < 0 || in.Offset > pm2ConfigurationArchiveGenerations || in.PM2OperationID != "" && !core.ValidID(in.PM2OperationID) {
		return nil, errors.New("配置归档查询范围或标识无效")
	}
	rows, err := s.pm2ArchiveCatalogue()
	if err != nil {
		return nil, err
	}
	selected := []any{}
	for _, row := range rows {
		if in.PM2OperationID == "" || row.ID == in.PM2OperationID {
			selected = append(selected, publicPM2ArchiveRequest(row))
		}
	}
	limit := in.Limit
	if limit == 0 {
		limit = 16
	}
	start := in.Offset
	if start > len(selected) {
		start = len(selected)
	}
	end := start + limit
	if end > len(selected) {
		end = len(selected)
	}
	result := map[string]any{"configuration_archives": selected[start:end], "archive_inventory_complete": true, "total": len(selected), "limit": limit, "offset": start, "next_offset": end, "page_complete": end == len(selected), "max_retained_requests": pm2ConfigurationArchiveGenerations, "automatic_replay": false, "services_changed": false, "history_or_report_written": false}
	snapshot, snapshotErr := s.snapshotPM2ConfigurationJournal()
	if snapshotErr != nil {
		result["active_inventory_known"] = false
		result["active_error"] = snapshotErr.Error()
		return result, nil
	}
	hash, err := snapshot.sha256()
	if err != nil {
		return nil, err
	}
	pending := false
	for _, row := range rows {
		if row.Intent != nil && row.Outcome == nil {
			pending = true
		}
	}
	result["active_inventory_known"] = true
	result["active_record_count"] = snapshot.Records
	result["active_pending_count"] = len(snapshot.Pending)
	result["inventory_sha256"] = hash
	result["archive_eligible"] = snapshot.eligible() && !pending && len(rows) < pm2ConfigurationArchiveGenerations
	result["active_max_retained_records"] = pm2ConfigIntentLimit
	return result, nil
}
