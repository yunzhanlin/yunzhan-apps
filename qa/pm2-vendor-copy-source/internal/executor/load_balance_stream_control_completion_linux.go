//go:build linux

package executor

import (
	"bytes"
	"io"
	"os"

	"golang.org/x/sys/unix"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

// Independent new fixed-leaf budget. Do not increase any existing module,
// installation, programme-upgrade or generic native-read limit for this wire.
func readStreamControlCompletion(root *os.Root) ([]byte, error) {
	if root == nil {
		return nil, loadbalancestream.ErrJournal
	}
	f, err := root.OpenFile("controller-exit.json", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, loadbalancestream.ErrJournal
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !streamJournalFileInfo(before, core.LoadBalanceStreamNativeResultMaxBytes) || before.Size() == 0 {
		return nil, loadbalancestream.ErrJournal
	}
	raw, err := io.ReadAll(io.LimitReader(f, core.LoadBalanceStreamNativeResultMaxBytes+1))
	held, e1 := f.Stat()
	visible, e2 := root.Lstat("controller-exit.json")
	if err != nil || e1 != nil || e2 != nil || int64(len(raw)) != before.Size() ||
		!geoStoreStableInfo(before, held) || !geoStoreStableInfo(held, visible) {
		clear(raw)
		return nil, loadbalancestream.ErrJournal
	}
	return raw, nil
}

func streamControlCompletionMatches(root *os.Root, expected []byte) bool {
	if len(expected) == 0 || len(expected) > core.LoadBalanceStreamNativeResultMaxBytes {
		return false
	}
	actual, err := readStreamControlCompletion(root)
	defer clear(actual)
	return err == nil && bytes.Equal(actual, expected)
}

func writeStreamControlCompletion(root *os.Root, raw []byte) error {
	if root == nil || len(raw) == 0 || len(raw) > core.LoadBalanceStreamNativeResultMaxBytes {
		return loadbalancestream.ErrJournal
	}
	f, err := root.OpenFile("controller-exit.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return loadbalancestream.ErrJournal
	}
	defer f.Close()
	if f.Chown(0, 0) != nil || f.Chmod(0600) != nil {
		return loadbalancestream.ErrJournal
	}
	if n, err := f.Write(raw); err != nil || n != len(raw) || f.Sync() != nil || ruleFeedStoreSync(root) != nil ||
		!streamControlCompletionMatches(root, raw) {
		return loadbalancestream.ErrJournal
	}
	return nil
}

func decodeStreamControlCompletion(raw, seedRaw []byte) (core.LoadBalanceStreamNativeResult, error) {
	var empty core.LoadBalanceStreamNativeResult
	seed, err := loadbalancestream.DecodeControlSeed(seedRaw)
	if err != nil || len(raw) == 0 || !bytes.HasSuffix(raw, []byte("\n")) {
		return empty, loadbalancestream.ErrJournal
	}
	result, err := core.DecodeLoadBalanceStreamNativeResult(bytes.TrimSuffix(raw, []byte("\n")), seed.Operation)
	if err != nil || result.State != "committed" || result.Seed != string(seedRaw) {
		return empty, loadbalancestream.ErrJournal
	}
	return result, nil
}
