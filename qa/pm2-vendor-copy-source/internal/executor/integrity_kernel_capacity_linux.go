//go:build linux

package executor

import (
	"errors"
	"io"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

const integrityKernelStoreBytes int64 = 512 << 20
const integrityKernelOperationReserve int64 = (2 * integrityKernelRecordBytes) + (64 << 10)

func (s *Service) integrityKernelCapacity(rows []core.IntegrityKernelOperation, action string) error {
	latest := map[string]core.IntegrityKernelOperation{}
	ids, err := s.integrityKernelOperationIDs()
	if err != nil {
		return err
	}
	var used int64
	for _, row := range rows {
		latest[row.Request.Input.SiteID] = row
	}
	for _, id := range ids {
		d, err := s.integrityKernelOperationDirectory(id)
		if err != nil {
			return err
		}
		if err = integrityKernelValidateNames(d); err != nil {
			d.Close()
			return err
		}
		f, err := d.Open(".")
		if err != nil {
			d.Close()
			return err
		}
		entries, readErr := f.ReadDir(7)
		f.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			d.Close()
			return readErr
		}
		for _, entry := range entries {
			info, e := entry.Info()
			if e != nil || !moduleRecordInfo(info, false, false) {
				d.Close()
				return errors.New("原内核保护容量见证无效")
			}
			used += info.Size()
			if used > integrityKernelStoreBytes {
				d.Close()
				return errors.New("内核保护历史超过 512 MiB 逻辑预算；没有自动清理或删除")
			}
		}
		current := d.current()
		d.Close()
		if !current {
			return errors.New("原内核保护容量目录变化")
		}
	}
	active := 0
	for _, row := range latest {
		if (row.State == "declined" || row.State == "cancelled") && row.Request.Action == "enable" || row.State == "succeeded" && row.Request.Action == "release" {
			continue
		}
		active++
	}
	reservedOperations := active
	if action == "enable" {
		reservedOperations += 2
	} // This enable and one later explicit release.
	if reservedOperations < 1 {
		reservedOperations = 1
	}
	if len(ids)+reservedOperations > integrityKernelRecords || used+int64(reservedOperations)*integrityKernelOperationReserve > integrityKernelStoreBytes {
		return errors.New("内核保护原记录容量不足；为已有保护保留解除余量，未删除记录或接收新启用")
	}
	// This is a logical reservation and a fresh free-space check, not a disk
	// quota against unrelated writers. External exhaustion remains unknown.
	d, err := s.moduleRecordDirectory(integrityKernelModule)
	if err != nil {
		return err
	}
	defer d.Close()
	f, err := d.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	var st unix.Statfs_t
	if unix.Fstatfs(int(f.Fd()), &st) != nil || st.Bsize < 1 {
		return errors.New("内核保护存储可用空间不能核对")
	}
	reserve := uint64(integrityKernelOperationReserve)
	if action == "enable" {
		reserve *= 2
	}
	if st.Bavail < reserve/uint64(st.Bsize)+1 {
		return errors.New("内核保护存储缺少完整任务与解除所需空间；原数据保留")
	}
	return nil
}
