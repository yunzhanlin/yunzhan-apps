//go:build linux

package executor

import (
	"bytes"
	"errors"
	"io"
	"os"
	"regexp"
	"sort"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

var pm2ArchivePartName = regexp.MustCompile(`^(?:intent|outcome|restore)\.[a-f0-9]{32}\.part$`)
var pm2ArchiveSingleName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,95}$`)

// Only parents may be created here. A request ID is reserved separately with
// exclusive Mkdir, and a generation destination must remain absent until the
// original journal's atomic rename. Existing directories are never repaired.
func (s *Service) openPM2ArchivePath(kind, id string, createParents bool) (*modulePrivateDirectory, error) {
	if kind != "" && kind != "requests" && kind != "generations" || id != "" && (kind == "" || !core.ValidID(id)) {
		return nil, errors.New("PM2 archive namespace is invalid")
	}
	d, err := s.moduleRecordDirectory("pm2-manager")
	if err != nil {
		return nil, err
	}
	parts := []string{"configuration-archives"}
	if kind != "" {
		parts = append(parts, kind)
	}
	for _, name := range parts {
		if err = pm2ConfigChild(d, name, createParents); err != nil {
			d.Close()
			return nil, err
		}
	}
	if id != "" {
		if err = pm2ConfigChild(d, id, false); err != nil {
			d.Close()
			return nil, err
		}
	}
	return d, nil
}

func pm2ArchiveNames(d *modulePrivateDirectory, maximum int) ([]string, error) {
	if maximum < 1 || maximum > pm2ConfigurationArchiveGenerations {
		return nil, errors.New("PM2 archive inventory bound is invalid")
	}
	before, err := d.Stat(".")
	if err != nil || !d.current() {
		return nil, errors.New("PM2 archive inventory parent cannot be verified")
	}
	f, err := d.Open(".")
	if err != nil {
		return nil, err
	}
	entries, readErr := f.ReadDir(maximum + 1)
	if err = f.Close(); err != nil {
		return nil, errors.Join(readErr, err)
	}
	if readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) > maximum {
		return nil, errors.New("PM2 complete archive inventory exceeds its bound")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	if err = pm2ConfigSync(d); err != nil {
		return nil, err
	}
	after, err := d.Stat(".")
	if err != nil || !programQueueSame(before, after) || !d.current() {
		return nil, errors.New("PM2 archive namespace changed during inventory")
	}
	return names, nil
}

func pm2ArchiveRead(d *modulePrivateDirectory, name string) ([]byte, error) {
	fragment := pm2ArchivePartName.MatchString(name)
	if name != "intent.json" && name != "outcome.json" && name != "restore.json" && !fragment {
		return nil, errors.New("PM2 archive record name is invalid")
	}
	original, err := d.Lstat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !d.current() {
			return nil, errors.New("PM2 missing archive record belongs to a changed namespace")
		}
		return nil, err
	}
	minimum := int64(1)
	if fragment {
		minimum = 0
	}
	if !moduleRecordInfo(original, false, false) || original.Size() < minimum || original.Size() > pm2ConfigurationArchiveIntentLimit {
		return nil, errors.New("PM2 archive record identity or capacity cannot be verified")
	}
	f, err := d.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return pm2ConfigReadDurableSized(f, original, func() bool {
		current, err := d.Lstat(name)
		return err == nil && programQueueSame(original, current) && d.current()
	}, minimum, pm2ConfigurationArchiveIntentLimit)
}

// Callers pin the source object before using this primitive. Both parents
// remain current and are synced after a no-replace rename. A visible result
// after a sync error is retained for explicit durable observation/recovery.
func pm2ArchiveRenameNoReplace(from *modulePrivateDirectory, old string, to *modulePrivateDirectory, next string) (err error) {
	if !pm2ArchiveSingleName.MatchString(old) || !pm2ArchiveSingleName.MatchString(next) || old == "." || old == ".." || next == "." || next == ".." || !from.current() || !to.current() {
		return errors.New("PM2 archive rename parent or name is invalid")
	}
	a, err := from.Open(".")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, a.Close()) }()
	b, err := to.Open(".")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, b.Close()) }()
	if err = unix.Renameat2(int(a.Fd()), old, int(b.Fd()), next, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	if !from.current() || !to.current() {
		return errors.New("PM2 archive rename namespace changed; both original namespaces retained")
	}
	return errors.Join(pm2ConfigSync(from), pm2ConfigSync(to))
}

// Partial writes never create a partial final record. Unique ordinary private
// fragments are retained on every failure, and an existing final record is
// never replaced. Merely finding a fragment never acknowledges a request.
func pm2ArchivePublish(d *modulePrivateDirectory, name string, raw []byte) error {
	if name != "intent.json" && name != "outcome.json" && name != "restore.json" || len(raw) < 1 || len(raw) > pm2ConfigurationArchiveIntentLimit || !d.current() {
		return errors.New("PM2 archive publication identity or capacity is invalid")
	}
	prefix := name[:len(name)-len(".json")]
	part := prefix + "." + core.ID() + ".part"
	f, err := d.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	if err = pm2ConfigWriteDurable(f, raw); err != nil {
		return errors.Join(err, pm2ConfigSync(d))
	}
	observed, err := pm2ArchiveRead(d, part)
	if err != nil || !bytes.Equal(observed, raw) {
		return errors.Join(err, errors.New("PM2 archive complete fragment could not be independently verified"))
	}
	if err = pm2ArchiveRenameNoReplace(d, part, d, name); err != nil {
		return err
	}
	final, err := pm2ArchiveRead(d, name)
	if err != nil || !bytes.Equal(final, raw) {
		return errors.Join(err, errors.New("PM2 archive final record could not be durably observed"))
	}
	return pm2ConfigSync(d)
}
