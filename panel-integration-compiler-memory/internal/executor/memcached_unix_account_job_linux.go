//go:build linux

package executor

import (
	"context"
	"os"
	"strings"
	"time"

	"local/panel/internal/core"
)

// Fixed dependency-unit entry, not an RPC/user-management command. Its only
// argument is the original journal ID. Never an account/UID/path/runner/key.
// The original Root executor must still own that exact job's run lease.
func RunMemcachedUnixAccountJob(job string) error {
	if os.Geteuid() != 0 || !core.ValidID(job) {
		return errMemcachedUnixNSS
	}
	cgroup, err := readModuleProcFile("/proc/self/cgroup", 4096)
	if err != nil || string(cgroup) != "0::/system.slice/panel-app-dependencies@memcached-unix-"+job+".service\n" {
		return errMemcachedUnixNSS
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	leaseContext, leaseCancel := context.WithTimeout(ctx, 3*time.Second)
	lifetime, err := acquireMemcachedUnixRuntime(leaseContext)
	leaseCancel()
	if err != nil {
		return err
	}
	defer lifetime.Close()
	j, err := (memcachedUnixJournalStore{base: memcachedUnixInstallJobsRoot}).open(job)
	if err != nil {
		return err
	}
	defer j.Close()
	chain, err := j.readChain()
	if err != nil || len(chain) != 2 || chain[0].Phase != "prepared" || chain[1].Phase != "account-intent" || chain[1].Operation.SiteID != "" {
		return errMemcachedUnixNSS
	}
	own, err := memcachedUnixFindOriginalRun(ctx, j)
	if err != nil {
		return err
	}
	reader, err := openMemcachedUpdateCoreAuthority(ctx)
	if err != nil {
		return err
	}
	defer reader.Close()
	head := chain[1]
	authority := func(check context.Context) error {
		current, err := j.read()
		if err != nil || current != head || own.current(check) != nil || reader.unixInstall(check, head.Operation, head.Binding) != nil {
			return errMemcachedUnixNSS
		}
		return nil
	}
	if authority(ctx) != nil {
		return errMemcachedUnixNSS
	}
	// Parent deliberately owns NO Compose lock while waiting for this fixed
	// child. Acquire original global runtime/engine ordering here; do not use
	// a general pending-work exemption or inherit another process's capability.
	bound, stop := context.WithTimeout(ctx, 3*time.Second)
	engine, err := productionDockerMutationStore().acquire(bound)
	stop()
	if err != nil {
		return err
	}
	defer engine.Close()
	return engine.use(ctx, func(active context.Context) error {
		if authority(active) != nil || own.otherTransactions(active) != nil {
			return errMemcachedUnixNSS
		}
		anchor, err := memcachedUnixBaseAt(memcachedUnixAdminStorePath, 0700)
		if err != nil {
			return err
		}
		anchor.Close()
		store, err := openMemcachedUnixAdminStore()
		if err != nil {
			return err
		}
		defer store.root.Close()
		ops := memcachedUnixAdminPrepareOps{
			absent: func(check context.Context) error {
				if authority(check) != nil {
					return errMemcachedUnixNSS
				}
				return memcachedUnixAdminAbsent(check)
			},
			create: func(check context.Context) error {
				if authority(check) != nil {
					return errMemcachedUnixNSS
				}
				return memcachedUnixAdminCreate(check)
			},
			// Persist a successfully observed account's ownership even if a
			// later revoke prevents its use. Never erase/retry an uncertain
			// account intent or adopt a same-name foreign account.
			resolve: func(check context.Context) (memcachedUnixAccount, error) {
				return memcachedUnixSystemAccount(check, "")
			},
		}
		if err := prepareMemcachedUnixAdminAt(active, store, ops); err != nil {
			return err
		}
		return authority(active)
	})
}

func memcachedUnixAccountInstance(job string) (string, error) {
	if !core.ValidID(job) || strings.TrimSpace(job) != job {
		return "", errMemcachedUnixNSS
	}
	return "panel-app-dependencies@memcached-unix-" + job + ".service", nil
}
