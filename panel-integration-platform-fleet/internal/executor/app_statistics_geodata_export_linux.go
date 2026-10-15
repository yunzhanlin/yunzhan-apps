//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

// Only reads the selected fixed-path terminal job. No copy on the server,
// deletion, archive move, start-marker rewrite, service reset or dataset change.
func (store statisticsGeoJobArchiveStore) exportJob(ctx context.Context, in core.StatisticsGeoExportInput) (core.StatisticsGeoExportResult, error) {
	var out core.StatisticsGeoExportResult
	if err := core.ValidateStatisticsGeoExport(in); err != nil {
		return out, err
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	base, root, archived, err := store.openJob(in.JobID)
	if err != nil {
		return out, err
	}
	defer base.Close()
	defer root.Close()
	lock, err := root.OpenFile("install.lock", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return out, errors.New("原启动锁不可核对，未导出")
	}
	defer lock.Close()
	if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return out, errors.New("原任务执行中，未导出")
	}
	li, err := lock.Stat()
	visible, e := root.Lstat("install.lock")
	if err != nil || e != nil || !moduleRecordInfo(li, false, false) || li.Size() != 0 || !geoStoreStableInfo(li, visible) {
		return out, errors.New("原任务锁变化，未导出")
	}
	row, err := statisticsGeoJobRecord(root, in.JobID, archived)
	if err != nil || row.State == "pending" || row.SHA != in.SHA {
		return out, errors.New("原终态或完整摘要不同，未导出")
	}
	identities, err := statisticsGeoJobFileIdentities(root)
	if err != nil {
		return out, err
	}
	bundle := core.StatisticsGeoEvidenceBundle{Format: 1, Record: row, Files: map[string][]byte{}}
	// geoStoreRead intentionally rejects empty regular data records. The empty
	// lock was verified through its held descriptor above; keep that invariant.
	bundle.Files["install.lock"] = []byte{}
	for name, limit := range map[string]int64{"request.json": 4096, "envelope.json": 3 << 20, "started.json": 4096, "result.json": 32 << 10} {
		if err = ctx.Err(); err != nil {
			return out, err
		}
		raw, e := geoStoreRead(root, name, limit)
		if e != nil {
			return out, e
		}
		bundle.Files[name] = raw
	}
	raw, err := json.Marshal(bundle)
	if err != nil || core.ValidateStatisticsGeoEvidenceBundle(raw, row) != nil {
		return out, errors.New("原证据导出集合不能独立核对")
	}
	if err = store.checkpoint("before-export-final"); err != nil {
		return out, err
	}
	final, err := statisticsGeoJobRecord(root, in.JobID, archived)
	finalFiles, fe := statisticsGeoJobFileIdentities(root)
	info, e := base.Lstat(in.JobID)
	opened, oe := root.Stat(".")
	if err != nil || fe != nil || final != row || !statisticsGeoJobSameFiles(identities, finalFiles) || e != nil || oe != nil || !os.SameFile(info, opened) || !base.current() || ctx.Err() != nil {
		return out, errors.New("导出期间原证据字节或身份变化；未返回部分成功")
	}
	// Also reject a duplicate ID introduced in the other location mid-export.
	finalBase, finalRoot, finalArchived, err := store.openJob(in.JobID)
	if err != nil {
		return out, err
	}
	finalInfo, e := finalRoot.Stat(".")
	current := finalBase.current()
	finalRoot.Close()
	finalBase.Close()
	if e != nil || !current || finalArchived != archived || !os.SameFile(opened, finalInfo) {
		return out, errors.New("导出交接前原任务位置或目录身份变化")
	}
	out.Record = row
	out.Bundle = raw
	out.BundleSHA = core.Hash(string(raw))
	return out, nil
}
