//go:build linux

package executor

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// A configuration generation belongs to the complete journal, rather than one
// project. Keep the protected parent and the same ordinary lock inode open for
// the whole write/rotation. Do not repair an existing lock or follow links.
const pm2ConfigurationJournalLock = ".configuration-journal.lock"

type pm2ConfigurationJournalLease struct {
	directory *modulePrivateDirectory
	file      *os.File
	missing   bool // read-only absence witness; never creates a lock
}

func (s *Service) lockPM2ConfigurationJournal() (*pm2ConfigurationJournalLease, error) {
	d, err := s.moduleRecordDirectory("pm2-manager")
	if err != nil {
		return nil, err
	}
	f, err := d.OpenFile(pm2ConfigurationJournalLock, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		d.Close()
		return nil, err
	}
	lease := &pm2ConfigurationJournalLease{directory: d, file: f}
	if !lease.current() {
		lease.Close()
		return nil, errors.New("PM2 配置记录锁的身份或权限无法核对，原文件保留")
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lease.Close()
		return nil, fmt.Errorf("正在保存或整理 PM2 配置记录，请稍后刷新核对：%w", err)
	}
	if !lease.current() {
		lease.Close()
		return nil, errors.New("PM2 配置记录锁在取得时已变化，未修改配置")
	}
	if err = pm2ConfigSync(d); err != nil {
		lease.Close()
		return nil, err
	}
	return lease, nil
}

func (l *pm2ConfigurationJournalLease) current() bool {
	if l == nil || l.directory == nil || !l.directory.current() {
		return false
	}
	if l.missing {
		_, err := l.directory.Lstat(pm2ConfigurationJournalLock)
		return l.file == nil && errors.Is(err, os.ErrNotExist) && l.directory.current()
	}
	if l.file == nil {
		return false
	}
	held, err := l.file.Stat()
	visible, e := l.directory.Lstat(pm2ConfigurationJournalLock)
	return err == nil && e == nil && moduleRecordInfo(held, false, false) && moduleRecordInfo(visible, false, false) && held.Size() == 0 && visible.Size() == 0 && os.SameFile(held, visible)
}

func (l *pm2ConfigurationJournalLease) Close() error {
	if l == nil {
		return nil
	}
	var errs []error
	if l.file != nil {
		errs = append(errs, l.file.Close())
		l.file = nil
	}
	if l.directory != nil {
		errs = append(errs, l.directory.Close())
		l.directory = nil
	}
	return errors.Join(errs...)
}

// Existing journals may predate the global lock. A read keeps an explicit
// absence witness instead of creating a file; a concurrent first writer makes
// that witness stale. Existing locks are acquired shared and nonblocking.
func (s *Service) readPM2ConfigurationJournalLease() (*pm2ConfigurationJournalLease, error) {
	d, err := s.moduleRecordDirectory("pm2-manager")
	if err != nil {
		return nil, err
	}
	f, err := d.OpenFile(pm2ConfigurationJournalLock, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) && d.current() {
		l := &pm2ConfigurationJournalLease{directory: d, missing: true}
		if l.current() {
			return l, nil
		}
		l.Close()
		return nil, errors.New("PM2 original journal lock absence changed")
	}
	if err != nil {
		d.Close()
		return nil, err
	}
	l := &pm2ConfigurationJournalLease{directory: d, file: f}
	if !l.current() {
		l.Close()
		return nil, errors.New("PM2 original journal read lock cannot be verified")
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		l.Close()
		return nil, errors.New("PM2 原配置或归档正在持久保存，请稍后只读核对")
	}
	if !l.current() {
		l.Close()
		return nil, errors.New("PM2 original journal read lock changed")
	}
	return l, nil
}
