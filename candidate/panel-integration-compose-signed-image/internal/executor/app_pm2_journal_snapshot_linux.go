//go:build linux

package executor

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"syscall"
)

// Capture original names, bytes and identities without changing a journal.
// The future generation rename is bound to this exact complete inventory.
// Access times are excluded: a read must not invalidate its own snapshot.
type pm2JournalIdentity struct {
	Device     uint64 `json:"device"`
	Inode      uint64 `json:"inode"`
	UID        uint32 `json:"uid"`
	GID        uint32 `json:"gid"`
	Mode       uint32 `json:"mode"`
	Links      uint64 `json:"links"`
	Size       int64  `json:"size"`
	ModifiedNS int64  `json:"modified_ns"`
	ChangedNS  int64  `json:"changed_ns"`
}
type pm2JournalFilePin struct {
	Identity pm2JournalIdentity `json:"identity"`
	SHA256   string             `json:"sha256"`
}
type pm2JournalSnapshot struct {
	Format    int                          `json:"format"`
	Exists    bool                         `json:"exists"`
	Directory pm2JournalIdentity           `json:"directory"`
	Files     map[string]pm2JournalFilePin `json:"files"`
	Records   int                          `json:"records"`
	Pending   []string                     `json:"pending"`
}

func pm2JournalIdentityOf(info os.FileInfo) (pm2JournalIdentity, error) {
	if info == nil {
		return pm2JournalIdentity{}, errors.New("PM2 original journal identity is missing")
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return pm2JournalIdentity{}, errors.New("PM2 original journal metadata cannot be verified")
	}
	return pm2JournalIdentity{Device: uint64(s.Dev), Inode: s.Ino, UID: s.Uid, GID: s.Gid, Mode: s.Mode, Links: uint64(s.Nlink), Size: s.Size, ModifiedNS: s.Mtim.Sec*1e9 + s.Mtim.Nsec, ChangedNS: s.Ctim.Sec*1e9 + s.Ctim.Nsec}, nil
}
func (v pm2JournalSnapshot) eligible() bool { return v.Exists && v.Records > 0 && len(v.Pending) == 0 }
func (v pm2JournalSnapshot) sha256() (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return pm2ConfigHash(raw), nil
}
func (s *Service) snapshotPM2ConfigurationJournal() (pm2JournalSnapshot, error) {
	empty := pm2JournalSnapshot{Format: 1, Files: map[string]pm2JournalFilePin{}, Pending: []string{}}
	d, err := s.openPM2ConfigStore(false)
	if errors.Is(err, os.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return pm2JournalSnapshot{}, err
	}
	defer d.Close()
	return d.snapshot()
}
func (d *pm2ConfigStore) snapshot() (pm2JournalSnapshot, error) {
	var result pm2JournalSnapshot
	before, err := d.Stat(".")
	if err != nil || !moduleRecordInfo(before, true, false) || !d.current() {
		return result, errors.New("PM2 original configuration directory cannot be verified")
	}
	identity, err := pm2JournalIdentityOf(before)
	if err != nil {
		return result, err
	}
	f, err := d.Open(".")
	if err != nil {
		return result, err
	}
	entries, readErr := f.ReadDir(2*pm2ConfigIntentLimit + 1)
	if err = f.Close(); err != nil {
		return result, errors.Join(readErr, err)
	}
	if readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) > 2*pm2ConfigIntentLimit {
		return result, errors.New("PM2 complete configuration inventory exceeds its original capacity")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	result = pm2JournalSnapshot{Format: 1, Exists: true, Directory: identity, Files: map[string]pm2JournalFilePin{}, Pending: []string{}}
	rawFiles := map[string][]byte{}
	total := 0
	for _, entry := range entries {
		name := entry.Name()
		original, err := d.Lstat(name)
		if err != nil {
			return pm2JournalSnapshot{}, err
		}
		raw, err := pm2ConfigRead(d.modulePrivateDirectory, name)
		if err != nil {
			return pm2JournalSnapshot{}, err
		}
		after, err := d.Lstat(name)
		if err != nil || !programQueueSame(original, after) {
			return pm2JournalSnapshot{}, errors.New("PM2 original configuration record changed while inventory was read")
		}
		pin, err := pm2JournalIdentityOf(after)
		if err != nil {
			return pm2JournalSnapshot{}, err
		}
		total += len(raw)
		if total > 64<<20 {
			return pm2JournalSnapshot{}, errors.New("PM2 original configuration inventory exceeds its byte budget")
		}
		rawFiles[name] = raw
		result.Files[name] = pm2JournalFilePin{Identity: pin, SHA256: pm2ConfigHash(raw)}
	}
	records, err := decodePM2ConfigurationRecords(rawFiles)
	if err != nil {
		return pm2JournalSnapshot{}, err
	}
	result.Records = len(records)
	for id, record := range records {
		if record.Receipt == nil && record.Cancellation == nil {
			result.Pending = append(result.Pending, id)
		}
	}
	sort.Strings(result.Pending)
	if err = pm2ConfigSync(d.modulePrivateDirectory); err != nil {
		return pm2JournalSnapshot{}, err
	}
	after, err := d.Stat(".")
	if err != nil || !programQueueSame(before, after) || !d.current() {
		return pm2JournalSnapshot{}, errors.New("PM2 original configuration namespace changed while inventory was read")
	}
	return result, nil
}
