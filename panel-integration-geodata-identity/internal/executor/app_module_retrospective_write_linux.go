//go:build linux

package executor

import (
	"encoding/json"
	"errors"
	"os"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

// Retrospective publication is confined to a verified private module tree.
// Refuse anomalous existing content before even creating our own temporary
// file; never chmod/chown/adopt old evidence. Callers serialize operations.
// This is not a claim of CAS against hostile concurrent root maintenance or
// atomicity between SQLite ledger commit and the downgrade-compatible ring.
func (s *Service) writeModuleRetrospectiveRecord(id, name string, value any) error {
	if name != "history.json" && name != "last-report.json" {
		return errors.New("模块报告写入名无效")
	}
	var previous any
	if err := s.moduleRetrospectiveRecord(id, name, &previous); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("原模块报告无法核对，未覆盖证据")
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if len(raw) > 4<<20 {
		return errors.New("模块报告超过容量，未覆盖旧记录")
	}
	if err := validateModuleRetrospectiveJSON(raw, name); err != nil {
		return err
	}
	dir, err := s.moduleRecordDirectory(id)
	if err != nil {
		return err
	}
	defer dir.Close()
	before, err := dir.Lstat(name)
	missing := errors.Is(err, os.ErrNotExist)
	if err != nil && !missing {
		return err
	}
	if !missing && !moduleRecordInfo(before, false, false) {
		return errors.New("原模块报告身份或权限变化")
	}
	temporary := ".panel-retrospective-" + core.ID()
	f, err := dir.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	defer dir.Remove(temporary)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	current, currentErr := dir.Lstat(name)
	if !dir.current() || missing && !errors.Is(currentErr, os.ErrNotExist) || !missing && (currentErr != nil || !os.SameFile(before, current) || !moduleRecordInfo(current, false, false) || before.Size() != current.Size() || before.ModTime() != current.ModTime()) {
		return errors.New("模块报告发布前原记录或目录变化，未覆盖")
	}
	if missing {
		// Exclusive creation must not replace a record appearing meanwhile.
		if err = dir.Link(temporary, name); err != nil {
			return err
		}
		if err = dir.Remove(temporary); err != nil {
			return errors.New("报告发布已创建，但私有临时链接清理失败，请核对原记录")
		}
	} else if err = dir.Rename(temporary, name); err != nil {
		return err
	}
	parent, err := dir.Open(".")
	if err != nil {
		return err
	}
	defer parent.Close()
	if err = parent.Sync(); err != nil {
		return err
	}
	if !dir.current() {
		return errors.New("报告可能已保存，但目录身份随后变化，请核对原记录")
	}
	return nil
}

func (s *Service) moduleRetrospectivePreflight(id string) error {
	for _, name := range []string{"history.json", "last-report.json"} {
		var value any
		if err := s.moduleRetrospectiveRecord(id, name, &value); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("原历史或报告无法核对，未执行业务或覆盖证据")
		}
	}
	// The read-only path also rejects hardlinked/corrupt databases and pending
	// sidecars. Known absence uses in-memory legacy summaries without creating
	// or migrating a database. An explicit recovery workflow is separate.
	_, err := s.moduleHistory(id, core.AppModuleInput{Limit: 1})
	return err
}
