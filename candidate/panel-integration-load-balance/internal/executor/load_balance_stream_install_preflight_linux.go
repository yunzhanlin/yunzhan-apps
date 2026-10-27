//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
)

// Fresh dispatch admission BEFORE a handoff or native parent is created.
// The original parent/child repeat their independent checks under their own
// actual leases and capabilities. This is neither an account creator nor an
// assurance that resources/grants cannot change after this observation.
func preflightLoadBalanceStreamInstall(ctx context.Context, owner *loadBalanceStreamUpgradeOwner) error {
	if owner == nil || owner.parent != nil || owner.child != nil || owner.submission != nil || owner.current(ctx) != nil {
		return errLoadBalanceStreamInstallationGate
	}
	raw, err := streamAccountParentProc("/proc/meminfo", 65536)
	if err != nil {
		return err
	}
	if err = loadBalanceStreamInstallMemoryAdmission(raw); err != nil {
		return err
	}
	configuration, err := holdLoadBalanceStreamNSSConfiguration(ctx)
	if err != nil {
		return err
	}
	defer configuration.close()
	engine, err := holdLoadBalanceStreamEngine(ctx)
	if err != nil {
		return err
	}
	defer engine.close()
	// An unrelated identically named account is not adopted. An incomplete
	// old create intent remains a refusal, not permission to run useradd again.
	if _, err = os.Lstat(loadBalanceStreamAccountStorePath); errors.Is(err, os.ErrNotExist) {
		if err = loadBalanceStreamAccountAbsent(ctx); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		if _, _, err = loadBalanceStreamAccountReceiptHash(ctx); err != nil {
			return err
		}
	}
	if !configuration.current() || !engine.current() || owner.current(ctx) != nil {
		return errLoadBalanceStreamInstallationGate
	}
	return nil
}
