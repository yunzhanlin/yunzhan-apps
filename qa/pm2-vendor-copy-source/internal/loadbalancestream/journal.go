package loadbalancestream

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
)

const MaxControlSeedBytes = 2 << 20

var ErrJournal = errors.New("TCP/UDP 原始事务、阶段或持久回执链无法核对；不重放或接管未确认结果")

// ControlSeed is immutable private Root metadata. OriginalKernelSHA256 must be
// independently observed before preparing the request. No digest or a decoded
// record grants live authority, listener ownership, service health or recovery.
type ControlSeed struct {
	Format               int              `json:"format"`
	Operation            Operation        `json:"operation"`
	Binding              OperationBinding `json:"binding"`
	FreshProbePort       int              `json:"fresh_probe_port"`
	Before               []Entry          `json:"before"`
	After                []Entry          `json:"after"`
	BeforeRuntimeSHA256  string           `json:"before_runtime_sha256"`
	AfterRuntimeSHA256   string           `json:"after_runtime_sha256"`
	ServiceUnitSHA256    string           `json:"service_unit_sha256"`
	OriginalKernelSHA256 string           `json:"original_kernel_sha256"`
	ColdBoot             *ColdBootRecord  `json:"cold_boot,omitempty"`
}

// PrepareControlSeed computes a plan, NEVER an effect or an authority decision.
// The Root controller must prove no unknown/third generation exists, supply
// fresh complete occupancy/resources and original actor/module authority, and
// hold its original lifetime and configuration leases before persisting it.
func PrepareControlSeed(operation Operation, binding OperationBinding, before []Entry, freshProbe int, kernelSHA string, facts ServiceFacts) (ControlSeed, ServicePlan, error) {
	return prepareControlSeed(operation, binding, before, freshProbe, kernelSHA, facts, nil)
}

func prepareControlSeed(operation Operation, binding OperationBinding, before []Entry, freshProbe int, kernelSHA string, facts ServiceFacts, cold *ColdBootRecord) (ControlSeed, ServicePlan, error) {
	bound, err := OperationBindingBytes(binding)
	if err != nil {
		return ControlSeed{}, ServicePlan{}, ErrJournal
	}
	if _, err := DecodeOperationBinding(bound, operation); err != nil || !operationHash(kernelSHA) {
		return ControlSeed{}, ServicePlan{}, ErrJournal
	}
	prior, err := RenderRuntime(before, ServiceRuntimePrefix, facts.Validation)
	if err != nil || prior.SHA256 != binding.OriginalConfigSHA256 {
		return ControlSeed{}, ServicePlan{}, ErrJournal
	}
	transition, err := PlanMutation(before, operation.Mutation, freshProbe, facts.Validation)
	if err != nil {
		return ControlSeed{}, ServicePlan{}, ErrJournal
	}
	retiring := before
	if cold != nil {
		if !coldBootTransitionValid(*cold, operation, before, transition.Entries) {
			return ControlSeed{}, ServicePlan{}, ErrJournal
		}
		retiring = nil
	}
	plan, err := PlanService(transition.Entries, retiring, facts)
	if err != nil {
		return ControlSeed{}, ServicePlan{}, ErrJournal
	}
	old := make([]Entry, len(before))
	for i, entry := range before {
		old[i] = copyEntry(entry)
	}
	next := make([]Entry, len(transition.Entries))
	for i, entry := range transition.Entries {
		next[i] = copyEntry(entry)
	}
	seed := ControlSeed{Format: 1, Operation: operation, Binding: binding, FreshProbePort: freshProbe, Before: old, After: next,
		BeforeRuntimeSHA256: prior.SHA256, AfterRuntimeSHA256: plan.Current.SHA256, ServiceUnitSHA256: plan.SHA256, OriginalKernelSHA256: kernelSHA}
	if cold != nil {
		copy := *cold
		seed.ColdBoot = &copy
	}
	// Deep-copy the caller's mutation policy/nodes too, not only its sets.
	opRaw, _ := OperationBytes(operation)
	seed.Operation, err = DecodeOperation(opRaw)
	if err != nil {
		return ControlSeed{}, ServicePlan{}, ErrJournal
	}
	raw, err := controlSeedBytes(seed)
	if err != nil {
		return ControlSeed{}, ServicePlan{}, ErrJournal
	}
	if _, err := DecodeControlSeed(raw); err != nil {
		return ControlSeed{}, ServicePlan{}, ErrJournal
	}
	return seed, plan, nil
}

func controlSeedBytes(seed ControlSeed) ([]byte, error) {
	raw, err := json.Marshal(seed)
	if err != nil || len(raw) == 0 || len(raw) >= MaxControlSeedBytes {
		return nil, ErrJournal
	}
	return append(raw, '\n'), nil
}

// ControlSeedBytes gives the separate Root filesystem adapter the exact closed
// serialization. It performs the same recorded-transition check as decoding,
// never filesystem admission or a live authority/resource/kernel decision.
func ControlSeedBytes(seed ControlSeed) ([]byte, error) {
	raw, err := controlSeedBytes(seed)
	if err != nil {
		return nil, ErrJournal
	}
	if _, err := DecodeControlSeed(raw); err != nil {
		return nil, ErrJournal
	}
	return raw, nil
}

// Decoding proves closed recorded syntax and the exact original transition,
// not current host resources or installed/module/actor/kernel authority. Those
// fresh checks remain mandatory before each external or filesystem effect.
func DecodeControlSeed(raw []byte) (ControlSeed, error) {
	var seed ControlSeed
	if len(raw) == 0 || len(raw) > MaxControlSeedBytes || json.Unmarshal(raw, &seed) != nil || seed.Format != 1 ||
		seed.Before == nil || seed.After == nil || len(seed.Before) > MaxEntries || len(seed.After) > MaxEntries {
		return ControlSeed{}, ErrJournal
	}
	canonical, err := controlSeedBytes(seed)
	if err != nil || !bytes.Equal(raw, canonical) {
		return ControlSeed{}, ErrJournal
	}
	binding, err := OperationBindingBytes(seed.Binding)
	if err != nil {
		return ControlSeed{}, ErrJournal
	}
	if _, err := DecodeOperationBinding(binding, seed.Operation); err != nil {
		return ControlSeed{}, ErrJournal
	}
	for _, hash := range []string{seed.BeforeRuntimeSHA256, seed.AfterRuntimeSHA256, seed.ServiceUnitSHA256, seed.OriginalKernelSHA256} {
		if !operationHash(hash) {
			return ControlSeed{}, ErrJournal
		}
	}
	// Static closed grammar only. This deliberately cannot replace actual
	// custom panel ports, external occupancy, host memory or kernel witnesses.
	syntax := ValidationContext{PanelControlPorts: []int{19100, 19102, 19080}, MemoryBudgetBytes: MaxMemoryBudget}
	before, err := RenderRuntime(seed.Before, ServiceRuntimePrefix, syntax)
	if err != nil || before.SHA256 != seed.BeforeRuntimeSHA256 || before.SHA256 != seed.Binding.OriginalConfigSHA256 {
		return ControlSeed{}, ErrJournal
	}
	change, err := PlanMutation(seed.Before, seed.Operation.Mutation, seed.FreshProbePort, syntax)
	if err != nil || !reflect.DeepEqual(change.Entries, seed.After) {
		return ControlSeed{}, ErrJournal
	}
	after, err := RenderRuntime(seed.After, ServiceRuntimePrefix, syntax)
	if err != nil || after.SHA256 != seed.AfterRuntimeSHA256 {
		return ControlSeed{}, ErrJournal
	}
	if seed.ColdBoot != nil && !coldBootTransitionValid(*seed.ColdBoot, seed.Operation, seed.Before, seed.After) {
		return ControlSeed{}, ErrJournal
	}
	return seed, nil
}

var controlPhases = [...]string{
	"prepared", "account-intent", "account-verified",
	"configuration-intent", "configuration-staged", "syntax-intent",
	"syntax-verified", "activation-intent", "configuration-promoted",
	"service-intent", "service-observed", "committed",
}

type ControlEvent struct {
	Format                int    `json:"format"`
	Sequence              int    `json:"sequence"`
	Phase                 string `json:"phase"`
	SeedSHA256            string `json:"seed_sha256"`
	PreviousEventSHA256   string `json:"previous_event_sha256"`
	AccountReceiptSHA256  string `json:"account_receipt_sha256"`
	ConfigurationSHA256   string `json:"configuration_sha256"`
	ServiceObservationSHA string `json:"service_observation_sha256"`
}

type ControlAdvanceEvidence struct {
	AccountReceiptSHA256  string
	ServiceObservationSHA string
}

type ControlChain struct {
	Events          []ControlEvent
	Complete        bool
	OriginalUnknown bool
}

func controlEventBytes(event ControlEvent) ([]byte, error) {
	raw, err := json.Marshal(event)
	if err != nil || len(raw) >= 2048 {
		return nil, ErrJournal
	}
	return append(raw, '\n'), nil
}

// An incomplete valid chain is an ORIGINAL UNKNOWN outcome, never a retry or
// resume permission. The filesystem adapter must hold all private original
// inodes and locks; only actual separately verified witnesses may advance it.
func DecodeControlChain(seedRaw []byte, records [][]byte) (ControlChain, error) {
	seed, err := DecodeControlSeed(seedRaw)
	if err != nil || len(records) == 0 || len(records) > len(controlPhases) {
		return ControlChain{}, ErrJournal
	}
	chain := ControlChain{Events: make([]ControlEvent, 0, len(records)), OriginalUnknown: true}
	seedSHA, previous := serviceDigest(seedRaw), ""
	account, config, observation := "", "", ""
	for sequence, raw := range records {
		var event ControlEvent
		if len(raw) == 0 || len(raw) > 2048 || json.Unmarshal(raw, &event) != nil {
			return ControlChain{}, ErrJournal
		}
		canonical, err := controlEventBytes(event)
		if err != nil || !bytes.Equal(raw, canonical) || event.Format != 1 || event.Sequence != sequence ||
			event.Phase != controlPhases[sequence] || event.SeedSHA256 != seedSHA || event.PreviousEventSHA256 != previous {
			return ControlChain{}, ErrJournal
		}
		if sequence == 2 {
			if !operationHash(event.AccountReceiptSHA256) {
				return ControlChain{}, ErrJournal
			}
			account = event.AccountReceiptSHA256
		}
		if sequence == 4 {
			config = seed.AfterRuntimeSHA256
		}
		if sequence == 10 {
			if !operationHash(event.ServiceObservationSHA) {
				return ControlChain{}, ErrJournal
			}
			observation = event.ServiceObservationSHA
		}
		if event.AccountReceiptSHA256 != account || event.ConfigurationSHA256 != config || event.ServiceObservationSHA != observation {
			return ControlChain{}, ErrJournal
		}
		chain.Events = append(chain.Events, event)
		previous = serviceDigest(raw)
	}
	chain.Complete = len(records) == len(controlPhases)
	chain.OriginalUnknown = !chain.Complete
	return chain, nil
}

// NextControlEvent only serializes the next sequential private record. It
// cannot persist, run an effect, retry an old intent or validate a real witness.
func NextControlEvent(seedRaw []byte, records [][]byte, evidence ControlAdvanceEvidence) ([]byte, error) {
	seed, err := DecodeControlSeed(seedRaw)
	if err != nil || len(records) >= len(controlPhases) {
		return nil, ErrJournal
	}
	sequence := len(records)
	event := ControlEvent{Format: 1, Sequence: sequence, Phase: controlPhases[sequence], SeedSHA256: serviceDigest(seedRaw)}
	if sequence > 0 {
		chain, err := DecodeControlChain(seedRaw, records)
		if err != nil || chain.Complete {
			return nil, ErrJournal
		}
		prior := chain.Events[len(chain.Events)-1]
		event.PreviousEventSHA256 = serviceDigest(records[len(records)-1])
		event.AccountReceiptSHA256, event.ConfigurationSHA256, event.ServiceObservationSHA = prior.AccountReceiptSHA256, prior.ConfigurationSHA256, prior.ServiceObservationSHA
	}
	if sequence == 2 {
		if !operationHash(evidence.AccountReceiptSHA256) || evidence.ServiceObservationSHA != "" {
			return nil, ErrJournal
		}
		event.AccountReceiptSHA256 = evidence.AccountReceiptSHA256
	} else if sequence == 10 {
		if !operationHash(evidence.ServiceObservationSHA) || evidence.AccountReceiptSHA256 != "" {
			return nil, ErrJournal
		}
		event.ServiceObservationSHA = evidence.ServiceObservationSHA
	} else if evidence.AccountReceiptSHA256 != "" || evidence.ServiceObservationSHA != "" {
		return nil, ErrJournal
	}
	if sequence == 4 {
		event.ConfigurationSHA256 = seed.AfterRuntimeSHA256
	}
	raw, err := controlEventBytes(event)
	if err != nil {
		return nil, ErrJournal
	}
	candidate := make([][]byte, len(records)+1)
	copy(candidate, records)
	candidate[len(records)] = raw
	if _, err := DecodeControlChain(seedRaw, candidate); err != nil {
		return nil, ErrJournal
	}
	return raw, nil
}
