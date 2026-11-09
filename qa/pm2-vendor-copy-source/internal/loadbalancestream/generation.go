package loadbalancestream

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
)

const MaxGenerationRecordBytes = 2 << 20

var ErrGeneration = errors.New("TCP/UDP 原实例、完整配置代次或原始控制回执无法核对；不据此启动、恢复或报告健康")

// GenerationRecord is bounded immutable Root metadata, not a health claim or
// a live grant. Its claimed hashes must still match the ACTUAL original full
// journal, current Core result, native configuration/unit/identity and kernel.
type GenerationRecord struct {
	Format                   int     `json:"format"`
	Version                  string  `json:"version"`
	InstallationID           string  `json:"installation_id"`
	Generation               int64   `json:"generation"`
	RequestID                string  `json:"request_id"`
	OperationSHA256          string  `json:"operation_sha256"`
	SeedSHA256               string  `json:"seed_sha256"`
	FinalEventSHA256         string  `json:"final_event_sha256"`
	ConfigurationSHA256      string  `json:"configuration_sha256"`
	ServiceUnitSHA256        string  `json:"service_unit_sha256"`
	ServiceObservationSHA256 string  `json:"service_observation_sha256"`
	Entries                  []Entry `json:"entries"`
}

func generationRecordBytes(v GenerationRecord) ([]byte, error) {
	if v.Format != 1 || v.Version != AppVersion || !operationID.MatchString(v.InstallationID) || !operationID.MatchString(v.RequestID) || v.Generation < 1 || v.Generation >= 1<<60 || v.Entries == nil || len(v.Entries) > MaxEntries {
		return nil, ErrGeneration
	}
	for _, value := range []string{v.OperationSHA256, v.SeedSHA256, v.FinalEventSHA256, v.ConfigurationSHA256, v.ServiceUnitSHA256, v.ServiceObservationSHA256} {
		if !operationHash(value) {
			return nil, ErrGeneration
		}
	}
	runtime, err := RenderRuntime(v.Entries, ServiceRuntimePrefix, ValidationContext{PanelControlPorts: []int{19100, 19102, 19080}, MemoryBudgetBytes: MaxMemoryBudget})
	if err != nil || runtime.SHA256 != v.ConfigurationSHA256 {
		return nil, ErrGeneration
	}
	raw, err := json.Marshal(v)
	if err != nil || len(raw) == 0 || len(raw) >= MaxGenerationRecordBytes {
		return nil, ErrGeneration
	}
	return append(raw, '\n'), nil
}

func DecodeGenerationRecord(raw []byte) (GenerationRecord, error) {
	var v GenerationRecord
	if len(raw) == 0 || len(raw) > MaxGenerationRecordBytes || json.Unmarshal(raw, &v) != nil {
		return v, ErrGeneration
	}
	canonical, err := generationRecordBytes(v)
	if err != nil || !bytes.Equal(raw, canonical) {
		return GenerationRecord{}, ErrGeneration
	}
	return v, nil
}

// ProposeGenerationRecord supplies bytes for the original Root writer AFTER
// its service-observed record, BEFORE its final commit. The returned final
// bytes are only a PROPOSAL; the reader below requires the ACTUAL persisted
// full chain. This function creates no file, unit, process or completion.
func ProposeGenerationRecord(installation string, generation int64, seedRaw []byte, records [][]byte) ([]byte, []byte, error) {
	if len(records) != len(controlPhases)-1 {
		return nil, nil, ErrGeneration
	}
	final, err := NextControlEvent(seedRaw, records, ControlAdvanceEvidence{})
	if err != nil {
		return nil, nil, ErrGeneration
	}
	prospective := make([][]byte, len(records)+1)
	copy(prospective, records)
	prospective[len(records)] = final
	v, err := generationFromOriginal(installation, generation, seedRaw, prospective)
	if err != nil {
		return nil, nil, ErrGeneration
	}
	raw, err := generationRecordBytes(v)
	if err != nil {
		return nil, nil, ErrGeneration
	}
	return raw, final, nil
}

func generationFromOriginal(installation string, generation int64, seedRaw []byte, records [][]byte) (GenerationRecord, error) {
	seed, err := DecodeControlSeed(seedRaw)
	if err != nil {
		return GenerationRecord{}, ErrGeneration
	}
	chain, err := DecodeControlChain(seedRaw, records)
	if err != nil || !chain.Complete || chain.OriginalUnknown || len(records) != len(controlPhases) {
		return GenerationRecord{}, ErrGeneration
	}
	entries := make([]Entry, len(seed.After))
	for i, v := range seed.After {
		entries[i] = copyEntry(v)
	}
	last := chain.Events[len(chain.Events)-1]
	v := GenerationRecord{1, AppVersion, installation, generation, seed.Operation.RequestID, OperationSHA256(seed.Operation), serviceDigest(seedRaw), serviceDigest(records[len(records)-1]), seed.AfterRuntimeSHA256, seed.ServiceUnitSHA256, last.ServiceObservationSHA, entries}
	if _, err := generationRecordBytes(v); err != nil {
		return GenerationRecord{}, ErrGeneration
	}
	return v, nil
}

// Pure recorded-binding check only. Caller MUST obtain records from the held
// actual Root journal; appending the expected final bytes in memory is NOT a
// persisted commit, native observation or permission to recover/start service.
func GenerationRecordBindsOriginal(raw []byte, installation string, generation int64, seedRaw []byte, actualRecords [][]byte) bool {
	v, err := DecodeGenerationRecord(raw)
	if err != nil || v.InstallationID != installation || v.Generation != generation {
		return false
	}
	wanted, err := generationFromOriginal(installation, generation, seedRaw, actualRecords)
	return err == nil && reflect.DeepEqual(v, wanted)
}
