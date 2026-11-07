//go:build linux

package executor

import (
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"os"
	"sort"
)

// This is an observation, never a writer permit. In particular it does not
// weaken CheckProgramUpgradeQueues or turn an old installation into 2.0.1.
type remoteUnpublishedOfflineReview struct {
	Format             int            `json:"format"`
	Kind               string         `json:"kind"`
	InstalledVersion   string         `json:"installed_version"`
	InstalledRecordSHA string         `json:"installed_record_sha256"`
	Target             string         `json:"remote_target_id"`
	Transaction        string         `json:"backup_transaction_id"`
	Revision           int64          `json:"revision"`
	ConfigSpecSHA      string         `json:"config_spec_sha256"`
	SnapshotSHA        string         `json:"snapshot_sha256"`
	CensusSHA          string         `json:"census_sha256"`
	GlobalCopies       int            `json:"global_copies"`
	ContentBytes       int64          `json:"content_bytes"`
	MetadataBytes      int64          `json:"unpublished_metadata_bytes"`
	UnpublishedRecord  map[string]any `json:"unpublished_record"`
	ReadOnly           bool           `json:"read_only"`
	NeedsWriterBarrier bool           `json:"requires_writer_barrier"`
	BackupComplete     bool           `json:"backup_complete"`
	SourceAuthority    bool           `json:"source_authority"`
	Downloadable       bool           `json:"downloadable"`
}

func remoteUnpublishedOfflineCensus(v remoteCopyInventory) string {
	type entry struct {
		Kind, Target, Transaction, StateSHA string
		Bytes                               int64
	}
	items := make([]entry, 0, v.count())
	for _, r := range v.Records {
		identity := r.Intent.Source.Snapshot
		items = append(items, entry{"copy", identity.TargetID, identity.TransactionID, remoteCopyStateSHA(r), r.Bytes})
	}
	for _, r := range v.Unpublished {
		state, _ := json.Marshal(struct {
			SHA      string
			Retained *remoteUnpublishedRetention
		}{r.SHA, r.Retained})
		items = append(items, entry{"unpublished", r.Snapshot.TargetID, r.Snapshot.TransactionID, core.Hash(string(state)), r.Bytes})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Target != items[j].Target {
			return items[i].Target < items[j].Target
		}
		return items[i].Transaction < items[j].Transaction
	})
	raw, _ := json.Marshal(struct {
		Entries                        []entry
		ContentBytes, UnpublishedBytes int64
	}{items, v.Bytes, v.UnpublishedBytes})
	return core.Hash(string(raw))
}

func (s *Service) reviewUnpublishedRemoteCopyOffline(in core.AppModuleInput) (remoteUnpublishedOfflineReview, error) {
	var out remoteUnpublishedOfflineReview
	// Reuse the strict fixed-ID read contract. No caller path, credentials,
	// pagination, mutation digest or confirmation is accepted by this reader.
	if remoteCopyInput("remote-copy-preview", in) != nil {
		return out, errors.New("离线核对仅接受固定连接、原事务和当前修订")
	}
	installed, err := s.moduleInstalledRecord("files-sync")
	if err != nil || installed["id"] != "files-sync" {
		return out, errors.New("原文件同步安装身份无法核对；未补写安装记录")
	}
	version, _ := installed["version"].(string)
	if !appcatalog.FilesSyncIndependentBackupSupported(version) {
		return out, errors.New("离线原片段核对要求已安装的精确2.0.0或2.0.1；未接管未知安装")
	}
	cfg, err := s.readRemoteConfig(in.RemoteTargetID)
	if err != nil || cfg.Revision != in.ExpectedRevision {
		return out, errors.New("当前本机连接身份或修订已变化；未沿用旧条件")
	}
	all, err := s.allRemoteCopyInventory()
	if err != nil {
		return out, err
	}
	for _, record := range all.Records {
		if record.Result == nil && record.Retained == nil {
			return out, errors.New("完整主意图的独立备份仍待核对；原片段恢复不能豁免该操作")
		}
	}
	for _, record := range all.Unpublished {
		if record.Snapshot.TargetID != cfg.ID || record.Snapshot.TransactionID != in.ResourceID {
			continue
		}
		installedRaw, err := json.Marshal(installed)
		if err != nil {
			return out, err
		}
		return remoteUnpublishedOfflineReview{
			Format: 1, Kind: "files-sync-offline-unpublished-review", InstalledVersion: version,
			InstalledRecordSHA: core.Hash(string(installedRaw)), Target: cfg.ID, Transaction: in.ResourceID,
			Revision: cfg.Revision, ConfigSpecSHA: cfg.SpecSHA, SnapshotSHA: record.SHA,
			CensusSHA: remoteUnpublishedOfflineCensus(all), GlobalCopies: all.count(), ContentBytes: all.Bytes,
			MetadataBytes: all.UnpublishedBytes, UnpublishedRecord: remoteUnpublishedPublic(record, cfg.Revision),
			ReadOnly: true, NeedsWriterBarrier: true,
		}, nil
	}
	return out, errors.New("所选原事务不是完整核对过的未发布主意图；未生成或修补目录")
}

// RunFilesSyncUnpublishedOfflineReview has only fixed production paths and
// constructs no Service workers. It reads no plaintext authentication secret,
// connects to no remote host and creates no files, receipts, locks or plans.
func RunFilesSyncUnpublishedOfflineReview(input io.Reader, output io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("原片段离线核对仅允许本机Root")
	}
	raw, err := io.ReadAll(io.LimitReader(input, 2049))
	if err != nil {
		return err
	}
	in, err := core.DecodeRemoteIndependentInput("remote-copy-preview", raw)
	if err != nil {
		return err
	}
	s := &Service{Config: Config{SecurityDir: "/etc/panel/security-apps"}}
	out, err := s.reviewUnpublishedRemoteCopyOffline(in)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(out)
}
