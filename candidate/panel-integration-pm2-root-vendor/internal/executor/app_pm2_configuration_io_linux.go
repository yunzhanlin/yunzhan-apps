//go:build linux

package executor

import (
	"errors"
	"io"
	"os"
)

// These small interfaces keep error handling identical for actual os.File
// descriptors and fault fixtures. There are no runtime hooks or global fault
// switches. A failed storage operation leaves its original file untouched.
type pm2ConfigReadable interface {
	io.Reader
	Stat() (os.FileInfo, error)
	Sync() error
	Close() error
}

type pm2ConfigWritable interface {
	io.Writer
	Sync() error
	Close() error
}

type pm2ConfigSyncer interface {
	Sync() error
	Close() error
}

func pm2ConfigWriteDurable(f pm2ConfigWritable, raw []byte) (err error) {
	defer func() { err = errors.Join(err, f.Close()) }()
	n, err := f.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return err
	}
	return f.Sync()
}

func pm2ConfigSyncDurable(f pm2ConfigSyncer, current func() bool) (err error) {
	defer func() { err = errors.Join(err, f.Close()) }()
	if !current() {
		return errors.New("PM2 transaction namespace changed")
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if !current() {
		return errors.New("PM2 transaction namespace changed")
	}
	return nil
}

// A terminal record may be visible after a previous Write/Sync/Close returned
// an error. Merely decoding that file cannot establish a durable outcome.
// Observation revalidates the same opened inode and fsyncs it; the caller also
// syncs the containing directory before using the complete inventory. This
// never rewrites a record, manifest or service, and never replays the request.
func pm2ConfigReadDurable(f pm2ConfigReadable, original os.FileInfo, current func() bool) (raw []byte, err error) {
	defer func() {
		err = errors.Join(err, f.Close())
		if err != nil {
			raw = nil
		}
	}()
	if original == nil || original.Size() < 1 || original.Size() > pm2ConfigRecordLimit {
		return nil, errors.New("PM2 private record capacity is invalid")
	}
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !programQueueSame(original, opened) {
		return nil, errors.New("PM2 private record changed before read")
	}
	raw, err = io.ReadAll(io.LimitReader(f, pm2ConfigRecordLimit+1))
	if err != nil {
		return nil, err
	}
	if len(raw) != int(original.Size()) {
		return nil, errors.New("PM2 private record changed during read")
	}
	if err = f.Sync(); err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !programQueueSame(original, after) || !current() {
		return nil, errors.New("PM2 private record changed during durable observation")
	}
	return raw, nil
}
