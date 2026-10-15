//go:build linux

package diskjob

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const JobsRoot = "/var/lib/panel-executor/disk-host-jobs"

var ErrJournal = errors.New("原全盘私有任务、文件身份或持久化不能核对；未修复、覆盖或重放")

type Journal struct {
	root     *os.Root
	base     *os.Root
	baseName string
	baseInfo os.FileInfo
	jobInfo  os.FileInfo
	id       string
}

// Tests may construct this unexported adapter on a fresh root-private trusted
// fixture. All exported production functions use only JobsRoot, never a path
// from a request, environment, package manifest or alternate-root CLI.
type jobTree struct{ name string }

func journalInfo(info os.FileInfo, dir bool) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != 0 || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	if dir {
		return info.IsDir() && info.Mode().Perm() == 0700
	}
	return info.Mode().IsRegular() && info.Mode().Perm() == 0600 && s.Nlink == 1
}

func journalParents(name string) bool {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name || name == "/" {
		return false
	}
	for p := filepath.Dir(name); ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return false
		}
		s, ok := info.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != 0 {
			return false
		}
		if p == "/" {
			return true
		}
	}
}

func (t jobTree) open(create bool) (*os.Root, os.FileInfo, error) {
	if os.Geteuid() != 0 || !journalParents(t.name) {
		return nil, nil, ErrJournal
	}
	if create {
		if err := os.Mkdir(t.name, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, nil, ErrJournal
		}
	}
	visible, err := os.Lstat(t.name)
	if err != nil {
		return nil, nil, err
	}
	if !journalInfo(visible, true) {
		return nil, nil, ErrJournal
	}
	r, err := os.OpenRoot(t.name)
	if err != nil {
		return nil, nil, ErrJournal
	}
	opened, err := r.Stat(".")
	if err != nil || !os.SameFile(opened, visible) || !journalInfo(opened, true) {
		r.Close()
		return nil, nil, ErrJournal
	}
	return r, opened, nil
}

func (j *Journal) current() bool {
	if !journalParents(j.baseName) {
		return false
	}
	a, e1 := j.base.Stat(".")
	b, e2 := os.Lstat(j.baseName)
	c, e3 := j.root.Stat(".")
	d, e4 := j.base.Lstat(j.id)
	return e1 == nil && e2 == nil && e3 == nil && e4 == nil && os.SameFile(a, j.baseInfo) && os.SameFile(a, b) && journalInfo(a, true) && journalInfo(b, true) && os.SameFile(c, j.jobInfo) && os.SameFile(c, d) && journalInfo(c, true) && journalInfo(d, true)
}

func (t jobTree) openJob(id string, create bool) (*Journal, error) {
	if !ValidID(id) {
		return nil, ErrJournal
	}
	base, info, err := t.open(create)
	if err != nil {
		return nil, err
	}
	if create {
		if err := base.Mkdir(id, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			base.Close()
			return nil, ErrJournal
		}
	}
	visible, err := base.Lstat(id)
	if err != nil {
		base.Close()
		return nil, err
	}
	if !journalInfo(visible, true) {
		base.Close()
		return nil, ErrJournal
	}
	r, err := base.OpenRoot(id)
	if err != nil {
		base.Close()
		return nil, ErrJournal
	}
	opened, err := r.Stat(".")
	if err != nil || !os.SameFile(opened, visible) || !journalInfo(opened, true) {
		r.Close()
		base.Close()
		return nil, ErrJournal
	}
	j := &Journal{root: r, base: base, baseName: t.name, baseInfo: info, jobInfo: opened, id: id}
	if !j.current() {
		j.Close()
		return nil, ErrJournal
	}
	return j, nil
}

func OpenRootJob(id string) (*Journal, error) { return (jobTree{JobsRoot}).openJob(id, false) }

// Observation must not create the worker's lock or repair an unsafe one.
func (j *Journal) RunLeaseFree() (bool, error) {
	return j.leaseFree("run.lock")
}

func (j *Journal) leaseFree(name string) (bool, error) {
	if name != "run.lock" && name != "launch.lock" {
		return false, ErrJournal
	}
	if !j.current() {
		return false, ErrJournal
	}
	before, err := j.root.Lstat(name)
	if err != nil {
		return false, err
	}
	if !journalInfo(before, false) || before.Size() != 0 {
		return false, ErrJournal
	}
	f, err := j.root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return false, ErrJournal
	}
	defer f.Close()
	opened, e1 := f.Stat()
	named, e2 := j.root.Lstat(name)
	if e1 != nil || e2 != nil || !sameJournalFile(before, opened) || !sameJournalFile(before, named) || !j.current() {
		return false, ErrJournal
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return false, nil
		}
		return false, ErrJournal
	}
	return true, nil
}

var journalLimits = map[string]int64{"request.json": 12288, "dispatch.json": 8192, "started.json": 8192, "progress.json": ReceiptBytesMax, "result.json": ReceiptBytesMax, "launcher.json": 8192, "closure.json": 32768, "cancel.json": 4096, "run.lock": 0, "launch.lock": 0, "inode-index.db": 512 << 20, "inode-index.db-journal": 8 << 20, "launcher.log": 65536}

// Presence, unsafe metadata or an unreadable closure all seal admission. Never
// treat a malformed tombstone as permission to start/replay the original job.
func (j *Journal) AdmissionBlocked() bool {
	if !j.current() {
		return true
	}
	_, err := j.root.Lstat("closure.json")
	return !errors.Is(err, os.ErrNotExist)
}

func (j *Journal) Read(name string) ([]byte, error) {
	return j.read(name, false)
}

func (j *Journal) recoveryRead(name string) ([]byte, error) {
	if name != "started.json" && name != "result.json" {
		return nil, ErrJournal
	}
	return j.read(name, true)
}

func (j *Journal) read(name string, allowEmpty bool) ([]byte, error) {
	limit, ok := journalLimits[name]
	if !ok || name == "inode-index.db" || name == "inode-index.db-journal" || !j.current() {
		return nil, ErrJournal
	}
	visible, err := j.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !journalInfo(visible, false) || visible.Size() > limit || !allowEmpty && name != "run.lock" && name != "launch.lock" && visible.Size() < 1 {
		return nil, ErrJournal
	}
	f, err := j.root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrJournal
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(opened, visible) || !journalInfo(opened, false) {
		return nil, ErrJournal
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	after, e1 := f.Stat()
	named, e2 := j.root.Lstat(name)
	if err != nil || e1 != nil || e2 != nil || int64(len(raw)) != visible.Size() || !sameJournalFile(visible, after) || !sameJournalFile(visible, named) || !j.current() {
		return nil, ErrJournal
	}
	return raw, nil
}

func sameJournalFile(a, b os.FileInfo) bool {
	x, ok1 := a.Sys().(*syscall.Stat_t)
	y, ok2 := b.Sys().(*syscall.Stat_t)
	return ok1 && ok2 && os.SameFile(a, b) && journalInfo(b, false) && a.Size() == b.Size() && x.Mtim == y.Mtim && x.Ctim == y.Ctim
}

func syncJournal(root *os.Root) error {
	f, err := root.Open(".")
	if err != nil {
		return ErrJournal
	}
	defer f.Close()
	if f.Sync() != nil {
		return ErrJournal
	}
	return nil
}

func (j *Journal) write(name string, raw []byte) error {
	if !j.current() {
		return ErrJournal
	}
	f, err := j.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrJournal
	}
	info, err := f.Stat()
	if err != nil || !journalInfo(info, false) || info.Size() != 0 {
		f.Close()
		return ErrJournal
	}
	n, err := f.Write(raw)
	if err == nil && n == len(raw) {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || n != len(raw) || !j.current() {
		return ErrJournal
	}
	return syncJournal(j.root)
}

// Original requests/dispatch/start/cancel/result receipts are immutable.
// A partial leaf after interrupted fsync stays evidence; never remove/replay it.
func (j *Journal) WriteImmutable(name string, raw []byte) error {
	limit, ok := journalLimits[name]
	if !ok || name == "progress.json" || name == "run.lock" || name == "launch.lock" || name == "launcher.log" || name == "inode-index.db" || name == "inode-index.db-journal" || len(raw) < 2 || int64(len(raw)) > limit || !json.Valid(raw) {
		return ErrJournal
	}
	if name == "request.json" {
		in, err := DecodeRequest(raw)
		if err != nil || in.JobID != j.id {
			return ErrJournal
		}
	}
	return j.write(name, raw)
}

func (j *Journal) Request() (Request, error) {
	raw, err := j.Read("request.json")
	if err != nil {
		return Request{}, err
	}
	in, err := DecodeRequest(raw)
	if err != nil || in.JobID != j.id {
		return Request{}, ErrJournal
	}
	return in, nil
}

func (j *Journal) WriteProgress(raw []byte) error {
	if len(raw) < 2 || len(raw) > ReceiptBytesMax || !json.Valid(raw) || !j.current() {
		return ErrJournal
	}
	if _, err := j.Read("result.json"); err == nil || !errors.Is(err, os.ErrNotExist) {
		return ErrJournal
	}
	if _, err := j.Read("progress.json"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrJournal
	}
	if err := j.write("progress.pending", raw); err != nil {
		return err
	}
	if err := j.root.Rename("progress.pending", "progress.json"); err != nil {
		return ErrJournal
	}
	return syncJournal(j.root)
}

// Request publication creates no process/service and provides no execution
// retry. A same-ID replay can only read the exact original request. Root status
// and Core dispatch ledgers decide whether a first launch may happen.
func publishRootRequest(t jobTree, in Request) (*Journal, bool, error) {
	if ValidateRequest(in) != nil {
		return nil, false, ErrJournal
	}
	base, _, err := t.open(true)
	if err != nil {
		return nil, false, err
	}
	d, err := base.Open(".")
	if err != nil {
		base.Close()
		return nil, false, ErrJournal
	}
	names, err := d.Readdirnames(ActiveJobsMax + 3)
	d.Close()
	defer base.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(names) > ActiveJobsMax+2 {
		return nil, false, ErrJournal
	}
	found := false
	count := 0
	for _, name := range names {
		if name == "instance.lock" || name == "slot.lock" {
			continue
		}
		if !ValidID(name) {
			return nil, false, ErrJournal
		}
		count++
		found = found || name == in.JobID
	}
	if count >= ActiveJobsMax && !found {
		return nil, false, ErrJournal
	}
	mkdirErr := base.Mkdir(in.JobID, 0700)
	fresh := mkdirErr == nil
	if mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
		return nil, false, ErrJournal
	}
	j, err := t.openJob(in.JobID, false)
	if err != nil {
		return nil, false, err
	}
	if prior, err := j.Request(); err == nil {
		if prior != in {
			j.Close()
			return nil, false, ErrJournal
		}
		return j, true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		j.Close()
		return nil, false, ErrJournal
	}
	// A pre-existing empty directory is an uncertain original preparation,
	// not a new request. Only this fresh creation may publish the first leaf.
	if !fresh {
		j.Close()
		return nil, false, ErrJournal
	}
	raw, _ := json.Marshal(in)
	if err := j.WriteImmutable("request.json", raw); err != nil {
		j.Close()
		return nil, false, err
	}
	if err := syncJournal(j.base); err != nil {
		j.Close()
		return nil, false, err
	}
	return j, false, nil
}

func PublishRootRequest(in Request) (*Journal, bool, error) {
	return publishRootRequest(jobTree{JobsRoot}, in)
}

func (j *Journal) Lease() (*os.File, error) {
	return j.lock("run.lock")
}

func (j *Journal) LaunchLease() (*os.File, error) { return j.lock("launch.lock") }

func (j *Journal) lock(name string) (*os.File, error) {
	if name != "run.lock" && name != "launch.lock" {
		return nil, ErrJournal
	}
	if !j.current() {
		return nil, ErrJournal
	}
	f, err := j.root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if errors.Is(err, os.ErrExist) {
		f, err = j.root.OpenFile(name, os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return nil, ErrJournal
	}
	info, err := f.Stat()
	visible, e := j.root.Lstat(name)
	if err != nil || e != nil || !journalInfo(info, false) || info.Size() != 0 || !sameJournalFile(info, visible) || unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil || !j.current() {
		f.Close()
		return nil, ErrJournal
	}
	return f, nil
}

// This root handle is for the worker's fixed SQLite spool only. It does not
// expose a public filesystem path or permit writes to original scanned files.
func (j *Journal) SpoolRoot() (*os.Root, error) {
	if !j.current() {
		return nil, ErrJournal
	}
	return j.root.OpenRoot(".")
}

func (j *Journal) Close() error {
	e1 := j.root.Close()
	e2 := j.base.Close()
	if e1 != nil || e2 != nil {
		return ErrJournal
	}
	return nil
}

func (j *Journal) HasOriginalResult() (bool, error) {
	raw, err := j.Read("result.json")
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !json.Valid(bytes.TrimSpace(raw)) {
		return false, ErrJournal
	}
	return true, nil
}

type LifecycleLease struct {
	*os.File
	root *os.Root
}

func (l *LifecycleLease) Close() error {
	e1 := l.File.Close()
	e2 := l.root.Close()
	if e1 != nil || e2 != nil {
		return ErrJournal
	}
	return nil
}

func treeLease(t jobTree, name string, exclusive bool) (*LifecycleLease, error) {
	if name != "instance.lock" && name != "slot.lock" {
		return nil, ErrJournal
	}
	r, before, err := t.open(true)
	if err != nil {
		return nil, err
	}
	f, err := r.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if errors.Is(err, os.ErrExist) {
		f, err = r.OpenFile(name, os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		r.Close()
		return nil, ErrJournal
	}
	opened, e1 := f.Stat()
	visible, e2 := r.Lstat(name)
	current, e3 := os.Lstat(t.name)
	mode := unix.LOCK_SH | unix.LOCK_NB
	if exclusive {
		mode = unix.LOCK_EX | unix.LOCK_NB
	}
	if e1 != nil || e2 != nil || e3 != nil || !journalInfo(opened, false) || opened.Size() != 0 || !sameJournalFile(opened, visible) || !os.SameFile(before, current) || !journalInfo(current, true) || unix.Flock(int(f.Fd()), mode) != nil {
		f.Close()
		r.Close()
		return nil, ErrJournal
	}
	return &LifecycleLease{File: f, root: r}, nil
}

// Worker shared instance lease and exclusive slot; lifecycle writers require
// exclusive instance lease and must additionally reject durable queued jobs.
func InstanceLease(exclusive bool) (*LifecycleLease, error) {
	return treeLease(jobTree{JobsRoot}, "instance.lock", exclusive)
}
func WorkerSlot() (*LifecycleLease, error) { return treeLease(jobTree{JobsRoot}, "slot.lock", true) }
