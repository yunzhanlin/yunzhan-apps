package loadbalancestream

import (
	"reflect"
)

// ColdBootRecord is recorded evidence, never permission to restart a process.
// Only the live Root preparer may supply it, after checking the COMPLETE closed
// original generation and observing a different current boot, absent fixed unit,
// no service-UID process and absent owned nft table. The original Core request,
// actor/module grants, leases, resource admission and kernel checks still apply.
// In particular an old journal, saved PID or same-boot crash cannot supply it.
type ColdBootRecord struct {
	Format                   int    `json:"format"`
	PreviousBootID           string `json:"previous_boot_id"`
	BootID                   string `json:"boot_id"`
	OriginalGenerationSHA256 string `json:"original_generation_sha256"`
	OriginalSeedSHA256       string `json:"original_seed_sha256"`
	OriginalServiceSHA256    string `json:"original_service_sha256"`
}

func coldBootTransitionValid(cold ColdBootRecord, operation Operation, before, after []Entry) bool {
	if cold.Format != 1 || !accountPermitBoot.MatchString(cold.BootID) || !accountPermitBoot.MatchString(cold.PreviousBootID) ||
		cold.BootID == "00000000-0000-0000-0000-000000000000" || cold.PreviousBootID == "00000000-0000-0000-0000-000000000000" || cold.BootID == cold.PreviousBootID {
		return false
	}
	for _, hash := range []string{cold.OriginalGenerationSHA256, cold.OriginalSeedSHA256, cold.OriginalServiceSHA256} {
		if !operationHash(hash) {
			return false
		}
	}
	active := 0
	for _, entry := range before {
		if !entry.Removed {
			active++
		}
	}
	if active == 0 {
		// Previously stopped generations have no resident allocation to retire.
		// The ordinary exact mutation validator still checks all new policy.
		return true
	}
	// A cold recovery starts the ORIGINAL desired set. It cannot silently add,
	// delete, revive a tombstone or change a backend while recovering. A fresh
	// ordinary replace advances one existing active entry's original revision.
	if operation.Mutation.Action != "replace" || len(before) != len(after) {
		return false
	}
	wanted := make([]Entry, len(before))
	found := false
	for i, entry := range before {
		wanted[i] = copyEntry(entry)
		if entry.Name == operation.Mutation.Name && !entry.Removed {
			wanted[i].Revision++
			found = true
		}
	}
	return found && reflect.DeepEqual(wanted, after)
}

// PrepareColdBootControlSeed only computes a closed plan. It does not inspect
// the host or authorize recovery; the native adapter must retain and repeatedly
// verify the original live cold-boot witness until it issues its OWN new start.
func PrepareColdBootControlSeed(operation Operation, binding OperationBinding, before []Entry, freshProbe int, kernelSHA string, facts ServiceFacts, cold ColdBootRecord) (ControlSeed, ServicePlan, error) {
	return prepareControlSeed(operation, binding, before, freshProbe, kernelSHA, facts, &cold)
}

// ControlRetiringEntries separates immutable BEFORE configuration lineage from
// an actually resident old process generation. Never erase Before to represent
// a reboot: doing so would detach the new generation from its original files.
// This is a pure recorded-plan choice, NOT a native absence/authority check.
func ControlRetiringEntries(seed ControlSeed) []Entry {
	if seed.ColdBoot != nil {
		return nil
	}
	out := make([]Entry, len(seed.Before))
	for i, entry := range seed.Before {
		out[i] = copyEntry(entry)
	}
	return out
}

func RecordedControlServicePlan(seed ControlSeed, facts ServiceFacts) (ServicePlan, error) {
	if _, err := ControlSeedBytes(seed); err != nil {
		return ServicePlan{}, ErrService
	}
	plan, err := RecordedServicePlan(seed.After, ControlRetiringEntries(seed), facts)
	if err != nil || plan.Current.SHA256 != seed.AfterRuntimeSHA256 || plan.SHA256 != seed.ServiceUnitSHA256 {
		return ServicePlan{}, ErrService
	}
	return plan, nil
}

func PlanControlServiceLaunch(seed ControlSeed, facts ServiceFacts, request string) (ServiceLaunchPlan, error) {
	if request != seed.Operation.RequestID {
		return ServiceLaunchPlan{}, ErrService
	}
	if _, err := ControlSeedBytes(seed); err != nil {
		return ServiceLaunchPlan{}, ErrService
	}
	plan, err := PlanServiceLaunch(seed.After, ControlRetiringEntries(seed), facts, request)
	if err != nil || plan.Service.Current.SHA256 != seed.AfterRuntimeSHA256 || plan.Service.SHA256 != seed.ServiceUnitSHA256 {
		return ServiceLaunchPlan{}, ErrService
	}
	return plan, nil
}
