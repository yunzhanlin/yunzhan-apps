//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"os"
)

type remoteUnpublishedOfflineCondition struct {
	Format             int    `json:"format"`
	Target             string `json:"remote_target_id"`
	Transaction        string `json:"backup_transaction_id"`
	Revision           int64  `json:"revision"`
	InstalledRecordSHA string `json:"installed_record_sha256"`
	ConfigSpecSHA      string `json:"config_spec_sha256"`
	SnapshotSHA        string `json:"snapshot_sha256"`
	CensusSHA          string `json:"census_sha256"`
	Confirm            string `json:"confirm"`
}

func decodeUnpublishedOfflineCondition(raw []byte) (remoteUnpublishedOfflineCondition, error) {
	var out remoteUnpublishedOfflineCondition
	bad := errors.New("离线片段条件必须是固定有界、无别名、无重复字段的完整对象")
	if len(raw) == 0 || len(raw) > 2048 || bytes.ContainsRune(raw, '\\') {
		return out, bad
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return out, bad
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return out, bad
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return out, bad
		}
		var target any
		switch key {
		case "format":
			target = &out.Format
		case "remote_target_id":
			target = &out.Target
		case "backup_transaction_id":
			target = &out.Transaction
		case "revision":
			target = &out.Revision
		case "installed_record_sha256":
			target = &out.InstalledRecordSHA
		case "config_spec_sha256":
			target = &out.ConfigSpecSHA
		case "snapshot_sha256":
			target = &out.SnapshotSHA
		case "census_sha256":
			target = &out.CensusSHA
		case "confirm":
			target = &out.Confirm
		default:
			return out, bad
		}
		if json.Unmarshal(value, target) != nil {
			return out, bad
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') || d.Decode(&struct{}{}) != io.EOF || len(seen) != 9 {
		return out, bad
	}
	if out.Format != 1 || !syncPlanID.MatchString(out.Target) || !core.ValidID(out.Transaction) || out.Revision < 1 || out.Revision > 1e9 || out.Confirm != "RETAIN FRAGMENTS "+out.Transaction {
		return out, bad
	}
	for _, digest := range []string{out.InstalledRecordSHA, out.ConfigSpecSHA, out.SnapshotSHA, out.CensusSHA} {
		if !coreSHA.MatchString(digest) {
			return out, bad
		}
	}
	return out, nil
}

func (c remoteUnpublishedOfflineCondition) input() core.AppModuleInput {
	return core.AppModuleInput{RemoteTargetID: c.Target, ExpectedRevision: c.Revision, ResourceID: c.Transaction}
}

type remoteUnpublishedOfflineWitness struct {
	Format          int                            `json:"format"`
	State           string                         `json:"state"`
	OriginalCensus  string                         `json:"original_census_sha256"`
	ObservedCensus  string                         `json:"observed_census_sha256"`
	Review          remoteUnpublishedOfflineReview `json:"review"`
	ReadOnly        bool                           `json:"read_only"`
	WriterPermitted bool                           `json:"writer_permitted"`
}

func (s *Service) matchUnpublishedOfflineCondition(c remoteUnpublishedOfflineCondition) (remoteUnpublishedOfflineWitness, error) {
	var out remoteUnpublishedOfflineWitness
	raw, _ := json.Marshal(c)
	if _, err := decodeUnpublishedOfflineCondition(raw); err != nil {
		return out, err
	}
	view, err := s.reviewUnpublishedRemoteCopyOffline(c.input())
	if err != nil {
		return out, err
	}
	if view.InstalledRecordSHA != c.InstalledRecordSHA || view.ConfigSpecSHA != c.ConfigSpecSHA || view.SnapshotSHA != c.SnapshotSHA {
		return out, errors.New("原安装、连接或片段完整状态已变化；未授予恢复例外")
	}
	all, err := s.allRemoteCopyInventory()
	if err != nil || remoteUnpublishedOfflineCensus(all) != view.CensusSHA {
		return out, errors.New("完整私有库存核对期间变化；未沿用先前读数")
	}
	selected := -1
	for i, record := range all.Unpublished {
		if record.Snapshot.TargetID == c.Target && record.Snapshot.TransactionID == c.Transaction {
			selected = i
		} else if record.Retained == nil {
			// First protocol intentionally refuses a multi-orphan transaction.
			// A future batch needs an explicit complete set of confirmations;
			// one selected transaction cannot silently authorize the others.
			return out, errors.New("存在其他未发布且未保留的原事务；单事务恢复不接管其他目录")
		}
	}
	if selected < 0 || all.Unpublished[selected].SHA != c.SnapshotSHA {
		return out, errors.New("原未发布事务已不属于完整库存")
	}
	state, originalCensus := "original-unpublished", view.CensusSHA
	r := all.Unpublished[selected]
	if r.Retained != nil {
		if r.Retained.ReviewedSpecSHA != c.ConfigSpecSHA || r.Retained.ReviewedRevision != c.Revision || r.Retained.SnapshotSHA != c.SnapshotSHA {
			return out, errors.New("原保留回执不属于本次明确条件；未改写或重试")
		}
		// Reconstruct only the parent's HASH INPUT in memory. The on-disk
		// receipt, original parts and all other records remain untouched. This
		// recognizes a lost reply without issuing another retention request.
		var originalBytes int64
		for _, fragment := range r.Snapshot.Fragments {
			originalBytes += fragment.Bytes
		}
		receiptBytes := r.Bytes - originalBytes
		if receiptBytes <= 0 || receiptBytes > remoteCopyRecordLimit || all.UnpublishedBytes < receiptBytes {
			return out, errors.New("原回执容量无法完整核对；未重建旧库存条件")
		}
		parent := all
		parent.Unpublished = append([]remoteUnpublishedCopy(nil), all.Unpublished...)
		parent.Unpublished[selected].Retained, parent.Unpublished[selected].Bytes = nil, originalBytes
		parent.UnpublishedBytes -= receiptBytes
		originalCensus, state = remoteUnpublishedOfflineCensus(parent), "observed-original-retained-receipt"
	}
	if originalCensus != c.CensusSHA {
		return out, errors.New("原条件不能解释当前全量库存；其他变化未被豁免")
	}
	return remoteUnpublishedOfflineWitness{Format: 1, State: state, OriginalCensus: originalCensus, ObservedCensus: view.CensusSHA, Review: view, ReadOnly: true}, nil
}

// This additional Root-only observation runs EVERY existing complete queue
// fence. Its private reader recognizes only the exact original condition; it
// grants no write permission and never changes the ordinary nil-reader path.
func CheckFilesSyncUnpublishedUpgradeAdmission(input io.Reader, output io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("离线恢复准入核对仅允许本机Root")
	}
	raw, err := io.ReadAll(io.LimitReader(input, 2049))
	if err != nil {
		return err
	}
	condition, err := decodeUnpublishedOfflineCondition(raw)
	if err != nil {
		return err
	}
	var witness remoteUnpublishedOfflineWitness
	read := func(s *Service) error {
		var err error
		witness, err = s.matchUnpublishedOfflineCondition(condition)
		return err
	}
	if err := checkCompleteProgramUpgradeQueues(read); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(witness)
}
