//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

// Root-private original filesystem evidence, never a native service/traffic
// claim. The staged inode is recorded BEFORE syntax and promotion; the actual
// new inode/ctime is recorded AFTER the one-shot atomic rename. A later copied
// identical file is not a substitute for either original inode.
type loadBalanceStreamConfigurationFileReceipt struct {
	Format              int                                     `json:"format"`
	Phase               string                                  `json:"phase"`
	RequestID           string                                  `json:"request_id"`
	SeedSHA256          string                                  `json:"seed_sha256"`
	IntentSHA256        string                                  `json:"intent_sha256"`
	ConfigurationSHA256 string                                  `json:"configuration_sha256"`
	StagedReceiptSHA256 string                                  `json:"staged_receipt_sha256,omitempty"`
	File                loadBalanceStreamModuleOriginalIdentity `json:"file"`
}

func (p *loadBalanceStreamConfigurationPublication) fileReceipt(phase string, info os.FileInfo) ([]byte, error) {
	if p == nil || p.original == nil || !streamConfigurationInfo(info, p.original.gid, false) || phase != "staged" && phase != "promoted" {
		return nil, loadbalancestream.ErrRuntime
	}
	v, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, loadbalancestream.ErrRuntime
	}
	file := loadBalanceStreamModuleOriginalIdentity{true, core.Hash(string(p.proposal)), uint64(v.Dev), v.Ino, v.Mode, v.Uid, v.Gid, uint64(v.Nlink), v.Size, v.Mtim.Sec, v.Mtim.Nsec, v.Ctim.Sec, v.Ctim.Nsec}
	r := loadBalanceStreamConfigurationFileReceipt{Format: 1, Phase: phase, RequestID: p.request, SeedSHA256: core.Hash(string(p.seed)), IntentSHA256: core.Hash(string(p.intent)), ConfigurationSHA256: file.SHA256, File: file}
	if phase == "promoted" {
		if len(p.stagedReceipt) == 0 {
			return nil, loadbalancestream.ErrRuntime
		}
		r.StagedReceiptSHA256 = core.Hash(string(p.stagedReceipt))
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > 8191 {
		return nil, loadbalancestream.ErrRuntime
	}
	return append(raw, '\n'), nil
}

func streamConfigurationReceiptWrite(root *os.Root, name string, raw []byte) error {
	if root == nil || name != "staged.json" && name != "promoted.json" || len(raw) == 0 || len(raw) > 8192 {
		return loadbalancestream.ErrRuntime
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return loadbalancestream.ErrRuntime
	}
	defer f.Close()
	if f.Chown(0, 0) != nil || f.Chmod(0600) != nil {
		return loadbalancestream.ErrRuntime
	}
	if n, err := f.Write(raw); err != nil || n != len(raw) || f.Sync() != nil || ruleFeedStoreSync(root) != nil || !streamModulePublicationMatches(root, name, raw) {
		return loadbalancestream.ErrRuntime
	}
	return nil
}

func decodeStreamConfigurationFileReceipt(raw []byte) (loadBalanceStreamConfigurationFileReceipt, error) {
	var r loadBalanceStreamConfigurationFileReceipt
	if len(raw) == 0 || len(raw) > 8192 || decodeProgramQueueJSON(raw, &r) != nil || r.Format != 1 || r.Phase != "staged" && r.Phase != "promoted" || !core.ValidID(r.RequestID) {
		return r, loadbalancestream.ErrRuntime
	}
	for _, hash := range []string{r.SeedSHA256, r.IntentSHA256, r.ConfigurationSHA256, r.File.SHA256} {
		if !loadBalanceStreamAccountHash(hash) {
			return r, loadbalancestream.ErrRuntime
		}
	}
	if r.Phase == "staged" && r.StagedReceiptSHA256 != "" || r.Phase == "promoted" && !loadBalanceStreamAccountHash(r.StagedReceiptSHA256) {
		return r, loadbalancestream.ErrRuntime
	}
	f := r.File
	if !f.Exists || f.SHA256 != r.ConfigurationSHA256 || f.Device == 0 || f.Inode == 0 || f.Mode != unix.S_IFREG|0640 || f.UID != 0 || f.GID < 100 || f.GID >= 1000 || f.Links != 1 || f.Bytes < 1 || f.Bytes > loadbalancestream.MaxRuntimeBytes || f.MTimeNano < 0 || f.MTimeNano >= 1e9 || f.CTimeNano < 0 || f.CTimeNano >= 1e9 {
		return r, loadbalancestream.ErrRuntime
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(append(canonical, '\n'), raw) {
		return r, loadbalancestream.ErrRuntime
	}
	return r, nil
}
