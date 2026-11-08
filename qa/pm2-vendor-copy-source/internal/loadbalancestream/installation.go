package loadbalancestream

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"
)

const MaxInstallationSeedBytes = 8192
const InstallationPhaseCount = 6

var ErrInstallation = errors.New("TCP/UDP 独立安装的原始身份、阶段或持久回执无法核对；保留原始记录，不重放或接管")

// Private Root observations, not an RPC capability. Preparation needs no UID
// guess: account creation belongs to the original selected installation job,
// while later stream controls require its already verified locked identity.
type InstallationSeed struct {
	Format                 int    `json:"format"`
	Nonce                  string `json:"nonce"`
	JobID                  string `json:"job_id"`
	ActorID                string `json:"actor_id"`
	Action                 string `json:"action"`
	AppVersion             string `json:"app_version"`
	AccessRevision         int64  `json:"access_revision"`
	ActorObservationSHA256 string `json:"actor_observation_sha256"`
	ManifestSHA256         string `json:"manifest_sha256"`
	PayloadSHA256          string `json:"payload_sha256"`
	OriginalRequestSHA256  string `json:"original_request_sha256"`
	KeySHA256              string `json:"key_sha256"`
	JobCreatedAt           string `json:"job_created_at"`
	CatalogSHA256          string `json:"catalog_sha256"`
	SubmissionSHA256       string `json:"submission_sha256"`
	ProgrammeInputsSHA256  string `json:"programme_inputs_sha256"`
	OriginalModuleVersion  string `json:"original_module_version"`
	OriginalModuleSHA256   string `json:"original_module_sha256"`
	EmptyConfigurationSHA  string `json:"empty_configuration_sha256"`
}

func validateInstallationSeed(s InstallationSeed) bool {
	if s.Format != 1 || !operationID.MatchString(s.Nonce) || !operationID.MatchString(s.JobID) || !operationID.MatchString(s.ActorID) || s.AppVersion != AppVersion || s.AccessRevision < 1 {
		return false
	}
	for _, h := range []string{s.ActorObservationSHA256, s.ManifestSHA256, s.PayloadSHA256, s.OriginalRequestSHA256, s.KeySHA256, s.CatalogSHA256, s.SubmissionSHA256, s.ProgrammeInputsSHA256, s.EmptyConfigurationSHA} {
		if !operationHash(h) {
			return false
		}
	}
	stamp, err := time.Parse(time.RFC3339, s.JobCreatedAt)
	if err != nil || stamp.Year() < 2026 || stamp.UTC().Format(time.RFC3339) != s.JobCreatedAt || stamp.After(time.Now().Add(time.Second)) {
		return false
	}
	switch s.Action {
	case "install":
		if s.OriginalModuleVersion != "" || s.OriginalModuleSHA256 != "" {
			return false
		}
	case "update":
		if s.OriginalModuleVersion != "1.8.4" && s.OriginalModuleVersion != "1.8.5" && s.OriginalModuleVersion != AppVersion || !operationHash(s.OriginalModuleSHA256) {
			return false
		}
	default:
		return false
	}
	payload := `{"settings":{},"version":"` + AppVersion + `"}`
	if s.Action == "update" {
		payload = `{"settings":null,"version":"` + AppVersion + `"}`
	}
	if serviceDigest([]byte(payload)) != s.PayloadSHA256 {
		return false
	}
	// No existing HTTP entry is converted into an L4 listener by installing.
	// This only checks syntax/recorded bytes, never real absence or permissions.
	empty, err := RenderRuntime([]Entry{}, ServiceRuntimePrefix, ValidationContext{PanelControlPorts: []int{19100, 19102, 19080}, MemoryBudgetBytes: MaxMemoryBudget})
	return err == nil && empty.SHA256 == s.EmptyConfigurationSHA
}

func InstallationSeedBytes(s InstallationSeed) ([]byte, error) {
	if !validateInstallationSeed(s) {
		return nil, ErrInstallation
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) >= MaxInstallationSeedBytes {
		return nil, ErrInstallation
	}
	return append(raw, '\n'), nil
}

func DecodeInstallationSeed(raw []byte) (InstallationSeed, error) {
	var s InstallationSeed
	if len(raw) == 0 || len(raw) > MaxInstallationSeedBytes || json.Unmarshal(raw, &s) != nil {
		return InstallationSeed{}, ErrInstallation
	}
	canonical, err := InstallationSeedBytes(s)
	if err != nil || !bytes.Equal(raw, canonical) {
		return InstallationSeed{}, ErrInstallation
	}
	return s, nil
}

var installationPhases = [InstallationPhaseCount]string{"prepared", "account-intent", "account-observed", "module-intent", "module-published", "committed"}

type InstallationEvent struct {
	Format                int    `json:"format"`
	Sequence              int    `json:"sequence"`
	Phase                 string `json:"phase"`
	SeedSHA256            string `json:"seed_sha256"`
	PreviousEventSHA256   string `json:"previous_event_sha256"`
	AccountReceiptSHA256  string `json:"account_receipt_sha256"`
	PublishedModuleSHA256 string `json:"published_module_sha256"`
}

type InstallationEvidence struct{ AccountReceiptSHA256, PublishedModuleSHA256 string }
type InstallationChain struct {
	Events                    []InstallationEvent
	Complete, OriginalUnknown bool
}

func installationEventBytes(v InstallationEvent) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) >= 2048 {
		return nil, ErrInstallation
	}
	return append(raw, '\n'), nil
}

// A canonical incomplete prefix is ORIGINAL UNKNOWN, not resume permission.
// Only the newly exclusive Root creator may append; an old opener is read-only.
func DecodeInstallationChain(seedRaw []byte, records [][]byte) (InstallationChain, error) {
	if _, err := DecodeInstallationSeed(seedRaw); err != nil || len(records) == 0 || len(records) > InstallationPhaseCount {
		return InstallationChain{}, ErrInstallation
	}
	out := InstallationChain{Events: make([]InstallationEvent, 0, len(records)), OriginalUnknown: true}
	previous, account, module := "", "", ""
	for i, raw := range records {
		var v InstallationEvent
		if len(raw) == 0 || len(raw) > 2048 || json.Unmarshal(raw, &v) != nil {
			return InstallationChain{}, ErrInstallation
		}
		canonical, err := installationEventBytes(v)
		if err != nil || !bytes.Equal(raw, canonical) || v.Format != 1 || v.Sequence != i || v.Phase != installationPhases[i] || v.SeedSHA256 != serviceDigest(seedRaw) || v.PreviousEventSHA256 != previous {
			return InstallationChain{}, ErrInstallation
		}
		if i == 2 {
			if !operationHash(v.AccountReceiptSHA256) {
				return InstallationChain{}, ErrInstallation
			}
			account = v.AccountReceiptSHA256
		}
		if i == 4 {
			if !operationHash(v.PublishedModuleSHA256) {
				return InstallationChain{}, ErrInstallation
			}
			module = v.PublishedModuleSHA256
		}
		if v.AccountReceiptSHA256 != account || v.PublishedModuleSHA256 != module {
			return InstallationChain{}, ErrInstallation
		}
		out.Events = append(out.Events, v)
		previous = serviceDigest(raw)
	}
	out.Complete = len(records) == InstallationPhaseCount
	out.OriginalUnknown = !out.Complete
	return out, nil
}

// Serialization only: evidence hashes must come from fresh actual Root account
// ownership and published-module verification, not a client or this decoder.
func NextInstallationEvent(seedRaw []byte, records [][]byte, evidence InstallationEvidence) ([]byte, error) {
	if _, err := DecodeInstallationSeed(seedRaw); err != nil || len(records) >= InstallationPhaseCount {
		return nil, ErrInstallation
	}
	i := len(records)
	v := InstallationEvent{Format: 1, Sequence: i, Phase: installationPhases[i], SeedSHA256: serviceDigest(seedRaw)}
	if i > 0 {
		chain, err := DecodeInstallationChain(seedRaw, records)
		if err != nil || chain.Complete {
			return nil, ErrInstallation
		}
		prior := chain.Events[i-1]
		v.PreviousEventSHA256 = serviceDigest(records[i-1])
		v.AccountReceiptSHA256 = prior.AccountReceiptSHA256
		v.PublishedModuleSHA256 = prior.PublishedModuleSHA256
	}
	if i == 2 {
		if !operationHash(evidence.AccountReceiptSHA256) || evidence.PublishedModuleSHA256 != "" {
			return nil, ErrInstallation
		}
		v.AccountReceiptSHA256 = evidence.AccountReceiptSHA256
	} else if i == 4 {
		if !operationHash(evidence.PublishedModuleSHA256) || evidence.AccountReceiptSHA256 != "" {
			return nil, ErrInstallation
		}
		v.PublishedModuleSHA256 = evidence.PublishedModuleSHA256
	} else if evidence.AccountReceiptSHA256 != "" || evidence.PublishedModuleSHA256 != "" {
		return nil, ErrInstallation
	}
	raw, err := installationEventBytes(v)
	if err != nil {
		return nil, ErrInstallation
	}
	candidate := append(append([][]byte(nil), records...), raw)
	if _, err = DecodeInstallationChain(seedRaw, candidate); err != nil {
		return nil, ErrInstallation
	}
	return raw, nil
}
