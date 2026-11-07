//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

func (r *loadBalanceStreamCoreAuthority) upgradeJobs(ctx context.Context, original *core.LoadBalanceStreamInstallAuthority) ([]core.LoadBalanceStreamUpgradeJob, error) {
	if r == nil || r.source == nil || ctx == nil || ctx.Err() != nil {
		return nil, errLoadBalanceStreamCoreAuthority
	}
	s := r.source
	s.mu.Lock()
	defer s.mu.Unlock()
	// The upgrader repeats this SELECT-only inventory with its own maintenance
	// marker present and Core stopped. This is not live installation authority:
	// owner.current/checkInstall still enforce the mutation fence independently.
	// Keep the held Core/WAL identity, complete schema and job/history checks.
	if s.db == nil || s.blocked == nil || !s.current() {
		return nil, errLoadBalanceStreamCoreAuthority
	}
	store := &core.Store{DB: s.db}
	if store.CheckLoadBalanceStreamControlUpgrade(ctx) != nil {
		return nil, errLoadBalanceStreamCoreAuthority
	}
	jobs, err := store.LoadBalanceStreamInstallUpgradeJobs(ctx, original)
	if err != nil || ctx.Err() != nil || !s.current() {
		return nil, errLoadBalanceStreamCoreAuthority
	}
	return jobs, nil
}

// Bounded fixed-directory inventory. It has no writer, alternate CLI root,
// chmod, stale-record cleanup or recursive arbitrary walk. The private root
// seam is used only by negative filesystem tests, never by the exported fence.
func streamUpgradeInventory(r *programQueueReader, path string, directories bool, limit int64) (map[string]map[string][]byte, error) {
	relative := strings.TrimPrefix(path, "/")
	root, err := r.directory(relative)
	if err != nil || root == nil {
		return map[string]map[string][]byte{}, err
	}
	defer root.Close()
	info, err := root.Stat(".")
	if err != nil || !memcachedUnixAdminDirectoryInfo(info) {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := dir.ReadDir(129)
	dir.Close()
	if err != nil && err != io.EOF || len(entries) > 128 {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	out := map[string]map[string][]byte{}
	for _, entry := range entries {
		name := entry.Name()
		id := name
		if !directories {
			id = strings.TrimSuffix(name, ".json")
			if name != id+".json" {
				return nil, errLoadBalanceStreamInstallationJournal
			}
		}
		if !core.ValidID(id) {
			return nil, errLoadBalanceStreamInstallationJournal
		}
		if !directories {
			raw, err := r.record(root, relative, name, limit)
			if err != nil {
				return nil, err
			}
			fileInfo, err := root.Lstat(name)
			if err != nil || !streamJournalFileInfo(fileInfo, limit) {
				return nil, errLoadBalanceStreamInstallationJournal
			}
			out[id] = map[string][]byte{name: raw}
			continue
		}
		child, err := r.directory(relative + "/" + id)
		if err != nil || child == nil {
			return nil, errLoadBalanceStreamInstallationJournal
		}
		files, err := func() (map[string][]byte, error) {
			defer child.Close()
			info, err := child.Stat(".")
			if err != nil || !memcachedUnixAdminDirectoryInfo(info) {
				return nil, errLoadBalanceStreamInstallationJournal
			}
			dir, err := child.Open(".")
			if err != nil {
				return nil, err
			}
			files, err := dir.ReadDir(10)
			dir.Close()
			if err != nil && err != io.EOF || len(files) > 9 {
				return nil, errLoadBalanceStreamInstallationJournal
			}
			raw := map[string][]byte{}
			for _, file := range files {
				name := file.Name()
				max := int64(2048)
				if path == loadBalanceStreamInstallationJobsRoot {
					switch name {
					case "seed.json":
						max = loadbalancestream.MaxInstallationSeedBytes
					case "submission.json":
						max = loadBalanceStreamInstallationSubmissionLimit
					case "run.lock":
						max = 0
					default:
						if !streamJournalEventName.MatchString(name) {
							return nil, errLoadBalanceStreamInstallationJournal
						}
					}
				} else if path == loadBalanceStreamModulePublicationsRoot {
					switch name {
					case "intent.json", "published.json":
						max = 8192
					case "original.json", "proposal.json":
						max = loadBalanceStreamModuleLimit
					default:
						return nil, errLoadBalanceStreamInstallationJournal
					}
				} else {
					return nil, errLoadBalanceStreamInstallationJournal
				}
				if name == "run.lock" {
					f, err := child.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
					if err != nil {
						return nil, err
					}
					before, e1 := f.Stat()
					visible, e2 := child.Lstat(name)
					f.Close()
					if e1 != nil || e2 != nil || !streamJournalFileInfo(before, 0) || !geoStoreStableInfo(before, visible) {
						return nil, errLoadBalanceStreamInstallationJournal
					}
					r.snapshots = append(r.snapshots, programQueueSnapshot{path: filepath.Join(r.root, relative, id, name), info: visible})
					raw[name] = []byte{}
					continue
				}
				body, err := r.record(child, relative+"/"+id, name, max)
				if err != nil {
					return nil, err
				}
				info, err := child.Lstat(name)
				if err != nil || !streamJournalFileInfo(info, max) {
					return nil, errLoadBalanceStreamInstallationJournal
				}
				raw[name] = body
			}
			return raw, nil
		}()
		if err != nil {
			return nil, err
		}
		out[id] = files
	}
	return out, nil
}

func streamUpgradeClearInventory(v map[string]map[string][]byte) {
	for _, files := range v {
		for _, raw := range files {
			clear(raw)
		}
	}
}

func checkLoadBalanceStreamRootUpgrade(ctx context.Context, jobs []core.LoadBalanceStreamUpgradeJob, owner *loadBalanceStreamUpgradeOwner) error {
	r := &programQueueReader{ctx: ctx, root: "/"}
	defer func() {
		for _, lease := range r.readLeases {
			lease.Close()
		}
	}()
	byID := map[string]core.LoadBalanceStreamUpgradeJob{}
	for _, job := range jobs {
		if _, ok := byID[job.Authority.JobID]; ok {
			return errLoadBalanceStreamInstallationJournal
		}
		byID[job.Authority.JobID] = job
	}
	own := ""
	if owner != nil {
		if owner.current(ctx) != nil {
			return errLoadBalanceStreamInstallationGate
		}
		own = owner.original.JobID
	}
	type namespace struct {
		path        string
		directories bool
		limit       int64
	}
	all := map[string]map[string]map[string][]byte{}
	defer func() {
		for _, v := range all {
			streamUpgradeClearInventory(v)
		}
	}()
	for _, ns := range []namespace{
		{loadBalanceStreamInstallationJobsRoot, true, 0}, {loadBalanceStreamModulePublicationsRoot, true, 0},
		{loadBalanceStreamSubmissionsRoot, false, core.LoadBalanceStreamInstallSubmissionMaxBytes},
		{loadBalanceStreamAccountPermitsRoot, false, loadbalancestream.MaxAccountChildPermitBytes},
		{loadBalanceStreamInstallationsRoot, false, 8192}, {loadBalanceStreamInstallObservationsRoot, false, 2048},
	} {
		v, err := streamUpgradeInventory(r, ns.path, ns.directories, ns.limit)
		if err != nil {
			return err
		}
		all[ns.path] = v
	}
	// Traffic controls are checked separately by the full read-only closed
	// generation fence. A successful installation inventory alone grants no
	// exemption for any native control, worker, publication or configuration.
	// Map nonce-keyed installation receipts back to the actual original job;
	// duplicate, orphan and failed-job artifacts are not a completed history.
	receipts := map[string]loadBalanceStreamInstallationReceipt{}
	for nonce, files := range all[loadBalanceStreamInstallationsRoot] {
		v, err := decodeStreamInstallationReceipt(files[nonce+".json"])
		if err != nil || v.InstallationID != nonce {
			return errLoadBalanceStreamInstallationJournal
		}
		if _, exists := receipts[v.JobID]; exists {
			return errLoadBalanceStreamInstallationJournal
		}
		receipts[v.JobID] = v
		if job, ok := byID[v.JobID]; !ok || v.JobID != own && job.State != "succeeded" {
			return errLoadBalanceStreamInstallationJournal
		}
	}
	for path, records := range all {
		if path == loadBalanceStreamInstallationsRoot {
			continue
		}
		for id, files := range records {
			job, ok := byID[id]
			if !ok || id != own && job.State != "succeeded" {
				return errLoadBalanceStreamInstallationJournal
			}
			switch path {
			case loadBalanceStreamSubmissionsRoot:
				v, err := core.DecodeLoadBalanceStreamInstallSubmission(files[id+".json"])
				if err != nil || v.JobID != id {
					return errLoadBalanceStreamInstallationJournal
				}
			case loadBalanceStreamAccountPermitsRoot:
				v, err := loadbalancestream.DecodeAccountChildPermit(files[id+".json"])
				if err != nil || v.JobID != id {
					return errLoadBalanceStreamInstallationJournal
				}
			case loadBalanceStreamInstallationJobsRoot:
				j, err := openLoadBalanceStreamInstallationJournalReadOnlyAt(loadBalanceStreamInstallationJobsRoot, id)
				if err != nil {
					return err
				}
				err = func() error {
					defer j.close()
					if id != own {
						lock, err := j.root.OpenFile("run.lock", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
						if err != nil {
							return err
						}
						info, err := lock.Stat()
						if err != nil || !streamJournalFileInfo(info, 0) || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
							lock.Close()
							return errLoadBalanceStreamInstallationJournal
						}
						r.readLeases = append(r.readLeases, lock)
					}
					seed, _, _, err := j.original(ctx)
					if err != nil || !loadBalanceStreamInstallationGrantMatches(seed, job.Authority) {
						return errLoadBalanceStreamInstallationJournal
					}
					_, err = j.officialAuthority(ctx)
					return err
				}()
				if err != nil {
					return err
				}
			}
		}
	}
	for id, job := range byID {
		if id == own {
			continue
		}
		if job.State == "succeeded" {
			for _, path := range []string{loadBalanceStreamInstallationJobsRoot, loadBalanceStreamModulePublicationsRoot, loadBalanceStreamSubmissionsRoot, loadBalanceStreamAccountPermitsRoot, loadBalanceStreamInstallObservationsRoot} {
				if _, ok := all[path][id]; !ok {
					return errLoadBalanceStreamInstallationJournal
				}
			}
			if _, ok := receipts[id]; !ok {
				return errLoadBalanceStreamInstallationJournal
			}
			actual, err := observeLoadBalanceStreamInstall(ctx, id)
			if err != nil || actual.State != "committed" {
				return errLoadBalanceStreamInstallationJournal
			}
		}
	}
	// The managed account's original creator remains part of the history even
	// when later operations reuse its owned receipt. Empty/partial identity is
	// allowed only inside the one original controller's still-live attempt.
	identity, err := r.directory(strings.TrimPrefix(loadBalanceStreamAccountStorePath, "/"))
	if err != nil {
		return err
	}
	if identity != nil {
		identity.Close()
		store, err := openLoadBalanceStreamAccountStoreAt(loadBalanceStreamAccountStorePath)
		if err != nil {
			return err
		}
		err = func() error {
			defer store.root.Close()
			relative := strings.TrimPrefix(loadBalanceStreamAccountStorePath, "/")
			intent, err := r.record(store.root, relative, "account-intent.json", 2048)
			if errors.Is(err, os.ErrNotExist) {
				_, receiptErr := store.root.Lstat("account.json")
				if own != "" && errors.Is(receiptErr, os.ErrNotExist) {
					return nil
				}
				return errLoadBalanceStreamAccount
			}
			if err != nil {
				return err
			}
			defer clear(intent)
			v, err := decodeLoadBalanceStreamAccountIntent(intent)
			if err != nil {
				return err
			}
			job, ok := byID[v.JobID]
			if !ok || job.State != "succeeded" && v.JobID != own || v.ActorID != job.Authority.ActorID || v.ManifestSHA != job.Authority.ManifestSHA256 {
				return errLoadBalanceStreamAccount
			}
			if v.JobID != own {
				_, _, err = loadBalanceStreamAccountReceiptHash(ctx)
				if err != nil {
					return err
				}
			}
			if raw, err := r.record(store.root, relative, "account.json", 2048); err == nil {
				defer clear(raw)
				receipt, err := decodeLoadBalanceStreamAccountReceipt(raw)
				if err != nil || receipt.IntentSHA != core.Hash(string(intent)) {
					return errLoadBalanceStreamAccount
				}
			} else if !errors.Is(err, os.ErrNotExist) || v.JobID != own {
				return errLoadBalanceStreamAccount
			}
			return nil
		}()
		if err != nil {
			return err
		}
	} else if len(receipts) != 0 {
		return errLoadBalanceStreamAccount
	}
	// A native module whose entire original Root history disappeared is NOT
	// an old unactivated host. This is a read-only fixed-path record reader;
	// it constructs no Service workers, directories or migration state.
	if err := checkLoadBalanceStreamNativeModuleHistory(r, receipts, own); err != nil {
		return err
	}
	if err = r.unchanged(); err != nil {
		return err
	}
	if owner != nil {
		return owner.current(ctx)
	}
	return ctx.Err()
}

// Absence under a shared Root-owned non-writable modules parent is distinct
// from an installed module's private record authority. Other applications
// legitimately create that shared parent with 0755. Pin the complete named
// chain and missing leaf; never chmod it or weaken an existing record reader.
func streamUpgradeModuleNamespaceMissing(r *programQueueReader) (bool, error) {
	if r == nil || r.ctx == nil || r.ctx.Err() != nil {
		return false, errLoadBalanceStreamModule
	}
	root, err := r.queueDirectory("etc/panel/security-apps/modules/load-balance", false)
	if root != nil {
		root.Close()
	}
	return err == nil && root == nil, err
}

func checkLoadBalanceStreamNativeModuleHistory(r *programQueueReader, receipts map[string]loadBalanceStreamInstallationReceipt, own string) error {
	if len(receipts) == 0 {
		missing, err := streamUpgradeModuleNamespaceMissing(r)
		if err != nil || missing {
			return err
		}
	}
	s := &Service{Config: Config{SystemRoot: "/", SecurityDir: "/etc/panel/security-apps"}}
	if threatIDSTrustedParents("/etc/panel/security-apps", false) != nil {
		return errLoadBalanceStreamModule
	}
	module, err := s.moduleRecordDirectory("load-balance")
	if errors.Is(err, os.ErrNotExist) && len(receipts) == 0 {
		return nil
	}
	if err != nil {
		return err
	}
	defer module.Close()
	// Legacy HTTP module files are Root:panel 0600 on older installations.
	// Group has no permissions; preserve it, never chown it to look new. The
	// separate new native journals/receipts retain strict Root:Root ownership.
	raw, err := streamUpgradeLegacyModuleRead(module)
	if errors.Is(err, os.ErrNotExist) {
		if len(receipts) == 0 {
			return nil
		}
		return errLoadBalanceStreamModule
	}
	if err != nil {
		return err
	}
	defer clear(raw)
	v, err := decodeLoadBalanceStreamModuleVersion(raw, true)
	if err != nil {
		return err
	}
	if v["version"] != loadbalancestream.AppVersion {
		if len(receipts) == 0 {
			return nil
		}
		return errLoadBalanceStreamModule
	}
	epoch, _ := v["installation_id"].(string)
	for job, receipt := range receipts {
		if receipt.InstallationID == epoch && receipt.PublishedModuleSHA256 == core.Hash(string(raw)) && (job == own || own == "") {
			return nil
		}
	}
	return errLoadBalanceStreamModule
}

func streamUpgradeLegacyModuleRead(module *modulePrivateDirectory) ([]byte, error) {
	if module == nil || !module.current() {
		return nil, errLoadBalanceStreamModule
	}
	f, err := module.Root.OpenFile("installed.json", os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !moduleRecordInfo(before, false, false) || before.Size() < 1 || before.Size() > loadBalanceStreamModuleLimit {
		return nil, errLoadBalanceStreamModule
	}
	raw, err := io.ReadAll(io.LimitReader(f, loadBalanceStreamModuleLimit+1))
	held, e1 := f.Stat()
	visible, e2 := module.Root.Lstat("installed.json")
	if err != nil || e1 != nil || e2 != nil || int64(len(raw)) != before.Size() || !geoStoreStableInfo(before, held) || !geoStoreStableInfo(held, visible) || !module.current() {
		clear(raw)
		return nil, errLoadBalanceStreamModule
	}
	return raw, nil
}

func checkLoadBalanceStreamUpgrade(ctx context.Context, owner *loadBalanceStreamUpgradeOwner) error {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 {
		return errLoadBalanceStreamInstallationGate
	}
	var original *core.LoadBalanceStreamInstallAuthority
	if owner != nil {
		if owner.current(ctx) != nil {
			return errLoadBalanceStreamInstallationGate
		}
		original = &owner.original
	}
	source, err := openLoadBalanceStreamCoreAuthority(ctx)
	if err != nil {
		return err
	}
	defer source.close()
	jobs, err := source.upgradeJobs(ctx, original)
	if err != nil {
		return err
	}
	if err = checkLoadBalanceStreamNativeQueues(ctx, owner); err != nil {
		return err
	}
	if err = checkLoadBalanceStreamRootUpgrade(ctx, jobs, owner); err != nil {
		return err
	}
	traffic, err := holdLoadBalanceStreamTrafficUpgrade(ctx, source)
	if err != nil {
		return err
	}
	defer traffic.close()
	if err = checkLoadBalanceStreamNativeQueues(ctx, owner); err != nil {
		return err
	}
	after, err := source.upgradeJobs(ctx, original)
	beforeRaw, _ := json.Marshal(jobs)
	afterRaw, _ := json.Marshal(after)
	if err != nil || !bytes.Equal(beforeRaw, afterRaw) {
		return errLoadBalanceStreamInstallationGate
	}
	if err = traffic.current(ctx); err != nil {
		return err
	}
	if owner != nil {
		return owner.current(ctx)
	}
	return ctx.Err()
}
