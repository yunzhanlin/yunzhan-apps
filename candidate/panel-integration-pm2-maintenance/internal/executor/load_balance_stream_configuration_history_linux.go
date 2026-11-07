//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

type loadBalanceStreamConfigurationHistory struct {
	Intent            loadBalanceStreamConfigurationIntent
	Staged            loadBalanceStreamConfigurationFileReceipt
	Promoted          loadBalanceStreamConfigurationFileReceipt
	Proposal          []byte
	ServiceReceipt    []byte
	CompletionReceipt []byte
}

func streamConfigurationIdentity(info os.FileInfo, digest string) (loadBalanceStreamModuleOriginalIdentity, bool) {
	if info == nil {
		return loadBalanceStreamModuleOriginalIdentity{}, false
	}
	v, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return loadBalanceStreamModuleOriginalIdentity{}, false
	}
	return loadBalanceStreamModuleOriginalIdentity{true, digest, uint64(v.Dev), v.Ino, v.Mode, v.Uid, v.Gid, uint64(v.Nlink), v.Size, v.Mtim.Sec, v.Mtim.Nsec, v.Ctim.Sec, v.Ctim.Nsec}, true
}

func streamConfigurationSameRenameIdentity(a, b loadBalanceStreamModuleOriginalIdentity) bool {
	// Only ctime changes in the reviewed rename. Data, inode, ownership,
	// permissions, link count, size and nanosecond mtime MUST remain exact.
	a.CTimeSecond, a.CTimeNano = b.CTimeSecond, b.CTimeNano
	return a == b
}

func readStreamConfigurationLeaf(root *os.Root, name string, gid uint32) ([]byte, os.FileInfo, error) {
	if root == nil {
		return nil, nil, loadbalancestream.ErrRuntime
	}
	if name != "nginx.conf" {
		id := strings.TrimSuffix(strings.TrimPrefix(name, ".candidate-"), ".conf")
		if !core.ValidID(id) || name != ".candidate-"+id+".conf" {
			return nil, nil, loadbalancestream.ErrRuntime
		}
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !streamConfigurationInfo(before, gid, false) {
		return nil, nil, loadbalancestream.ErrRuntime
	}
	raw, err := io.ReadAll(io.LimitReader(f, loadbalancestream.MaxRuntimeBytes+1))
	held, e1 := f.Stat()
	visible, e2 := root.Lstat(name)
	if err != nil || e1 != nil || e2 != nil || int64(len(raw)) != before.Size() || !geoStoreStableInfo(before, held) || !geoStoreStableInfo(held, visible) {
		clear(raw)
		return nil, nil, loadbalancestream.ErrRuntime
	}
	return raw, before, nil
}

// Historical filesystem evidence ONLY. The caller must separately bind the
// original full Root journal, Core completion, actual installed instance and
// predecessor chain. These receipts never authorize an effect or prove current
// service/traffic health. latest selects the fixed CURRENT leaf, not a path.
func checkStreamConfigurationPublication(publication, configuration *os.Root, seedRaw []byte, gid uint32, latest bool) (loadBalanceStreamConfigurationHistory, error) {
	var empty loadBalanceStreamConfigurationHistory
	if publication == nil || configuration == nil {
		return empty, loadbalancestream.ErrRuntime
	}
	pubInfo, e1 := publication.Stat(".")
	cfgInfo, e2 := configuration.Stat(".")
	if e1 != nil || e2 != nil || !memcachedUnixAdminDirectoryInfo(pubInfo) || !streamConfigurationInfo(cfgInfo, gid, true) {
		return empty, loadbalancestream.ErrRuntime
	}
	seed, err := loadbalancestream.DecodeControlSeed(seedRaw)
	if err != nil {
		return empty, loadbalancestream.ErrRuntime
	}
	raw, err := streamInstallationPrivateRead(publication, "intent.json", 8192)
	if err != nil {
		return empty, loadbalancestream.ErrRuntime
	}
	var intent loadBalanceStreamConfigurationIntent
	if decodeProgramQueueJSON(raw, &intent) != nil {
		return empty, loadbalancestream.ErrRuntime
	}
	canonical, _ := json.Marshal(intent)
	if !bytes.Equal(append(canonical, '\n'), raw) || intent.Format != 1 || intent.RequestID != seed.Operation.RequestID || intent.SeedSHA256 != core.Hash(string(seedRaw)) || intent.ConfigurationSHA256 != seed.AfterRuntimeSHA256 || intent.ServiceGID != gid || intent.Original.Exists != (len(seed.Before) != 0) {
		return empty, loadbalancestream.ErrRuntime
	}
	stagedRaw, e1 := streamInstallationPrivateRead(publication, "staged.json", 8192)
	promotedRaw, e2 := streamInstallationPrivateRead(publication, "promoted.json", 8192)
	if e1 != nil || e2 != nil {
		return empty, loadbalancestream.ErrRuntime
	}
	staged, e1 := decodeStreamConfigurationFileReceipt(stagedRaw)
	promoted, e2 := decodeStreamConfigurationFileReceipt(promotedRaw)
	if e1 != nil || e2 != nil || staged.Phase != "staged" || promoted.Phase != "promoted" || promoted.StagedReceiptSHA256 != core.Hash(string(stagedRaw)) || !streamConfigurationSameRenameIdentity(staged.File, promoted.File) {
		return empty, loadbalancestream.ErrRuntime
	}
	for _, r := range []loadBalanceStreamConfigurationFileReceipt{staged, promoted} {
		if r.RequestID != intent.RequestID || r.SeedSHA256 != intent.SeedSHA256 || r.IntentSHA256 != core.Hash(string(raw)) || r.ConfigurationSHA256 != intent.ConfigurationSHA256 || r.File.GID != gid {
			return empty, loadbalancestream.ErrRuntime
		}
	}
	facts := loadbalancestream.ValidationContext{PanelControlPorts: []int{19100, 19102, 19080}, MemoryBudgetBytes: loadbalancestream.MaxMemoryBudget}
	before, e1 := loadbalancestream.RenderRuntime(seed.Before, loadbalancestream.ServiceRuntimePrefix, facts)
	after, e2 := loadbalancestream.RenderRuntime(seed.After, loadbalancestream.ServiceRuntimePrefix, facts)
	if e1 != nil || e2 != nil || before.SHA256 != seed.BeforeRuntimeSHA256 || after.SHA256 != intent.ConfigurationSHA256 || !streamModulePublicationMatches(publication, "proposal.json", after.Main) {
		return empty, loadbalancestream.ErrRuntime
	}
	want := map[string]bool{"intent.json": true, "proposal.json": true, "staged.json": true, "promoted.json": true}
	var serviceReceipt []byte
	if _, err := publication.Lstat("service.json"); err == nil {
		serviceReceipt, err = streamInstallationPrivateRead(publication, "service.json", streamServiceReceiptMaxBytes)
		if err != nil {
			return empty, loadbalancestream.ErrRuntime
		}
		if _, err := decodeStreamServiceReceipt(serviceReceipt, seedRaw); err != nil {
			return empty, loadbalancestream.ErrRuntime
		}
		want["service.json"] = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, loadbalancestream.ErrRuntime
	}
	var completionReceipt []byte
	if _, err := publication.Lstat("controller-exit.json"); err == nil {
		completionReceipt, err = readStreamControlCompletion(publication)
		if err != nil {
			return empty, loadbalancestream.ErrRuntime
		}
		completed, err := decodeStreamControlCompletion(completionReceipt, seedRaw)
		if err != nil || len(serviceReceipt) == 0 || completed.ServiceReceiptSHA256 != core.Hash(string(serviceReceipt)) {
			return empty, loadbalancestream.ErrRuntime
		}
		want["controller-exit.json"] = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, loadbalancestream.ErrRuntime
	}
	name := ".candidate-" + intent.RequestID + ".conf"
	if intent.Original.Exists {
		want["original.json"] = true
		old, info, err := readStreamConfigurationLeaf(configuration, name, gid)
		if err != nil || !bytes.Equal(old, before.Main) || !streamModulePublicationMatches(publication, "original.json", old) || !streamModuleRetainedIdentityMatches(intent.Original, info, before.SHA256) {
			return empty, loadbalancestream.ErrRuntime
		}
	} else if intent.Original != (loadBalanceStreamModuleOriginalIdentity{}) {
		return empty, loadbalancestream.ErrRuntime
	} else if _, err := configuration.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return empty, loadbalancestream.ErrRuntime
	}
	dir, err := publication.Open(".")
	if err != nil {
		return empty, loadbalancestream.ErrRuntime
	}
	entries, err := dir.ReadDir(8)
	dir.Close()
	if err != nil && err != io.EOF || len(entries) != len(want) {
		return empty, loadbalancestream.ErrRuntime
	}
	for _, entry := range entries {
		if !want[entry.Name()] {
			return empty, loadbalancestream.ErrRuntime
		}
	}
	if latest {
		current, info, err := readStreamConfigurationLeaf(configuration, "nginx.conf", gid)
		identity, ok := streamConfigurationIdentity(info, core.Hash(string(current)))
		if err != nil || !ok || !bytes.Equal(current, after.Main) || identity != promoted.File {
			return empty, loadbalancestream.ErrRuntime
		}
	}
	return loadBalanceStreamConfigurationHistory{intent, staged, promoted, bytes.Clone(after.Main), serviceReceipt, completionReceipt}, nil
}
