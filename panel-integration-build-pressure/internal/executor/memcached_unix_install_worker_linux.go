//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

type memcachedUnixInstallWorker struct {
	lifetime *memcachedUnixRuntimeLease
	run      *memcachedUnixJournalLease
	own      *memcachedUnixOriginalRun
	core     *memcachedUpdateCoreAuthority
	project  *composeUpdateDirectory
	account  memcachedUnixAccount
}

func (w *memcachedUnixInstallWorker) authority(ctx context.Context) error {
	if w == nil || w.lifetime == nil || !w.lifetime.current() || w.run == nil || !w.run.current() || w.own == nil || w.core == nil || ctx == nil || ctx.Err() != nil || w.own.current(ctx) != nil {
		return errMemcachedUnixJournal
	}
	head, err := w.run.j.read()
	if err != nil || w.core.unixInstall(ctx, head.Operation, head.Binding) != nil {
		return errMemcachedCoreAuthority
	}
	if head.UID != 0 && (head.UID != w.account.UID || head.GID != w.account.GID) {
		return errMemcachedUnixNSS
	}
	if w.project != nil {
		if _, err := readMemcachedUnixProject(w.project, head); err != nil {
			return err
		}
	}
	return nil
}

func (w *memcachedUnixInstallWorker) transition(ctx context.Context, phase string, change func(*core.MemcachedUnixInstallRecord)) error {
	if w.authority(ctx) != nil {
		return errMemcachedUnixJournal
	}
	head, err := w.run.j.read()
	if err != nil {
		return err
	}
	head.Sequence++
	head.Phase = phase
	if change != nil {
		change(&head)
	}
	return w.run.append(head)
}

// Uncertain side effects never become a retry/cleanup/rollback operation. The
// last observed UID/image/source/container identities remain in the new event.
func (w *memcachedUnixInstallWorker) interrupted(fault string) {
	if w == nil || w.run == nil || !w.run.current() {
		return
	}
	head, err := w.run.j.read()
	if err != nil || head.Phase == "committed" || head.Phase == "refused" || head.Phase == "needs-attention" {
		return
	}
	head.Sequence++
	head.Phase, head.Fault = "needs-attention", fault
	_ = w.run.append(head)
}

func (w *memcachedUnixInstallWorker) resolveAccount(ctx context.Context, site string) (memcachedUnixAccount, error) {
	if site != "" {
		return memcachedUnixOwnedSiteAccount(ctx, site)
	}
	store, err := openMemcachedUnixAdminStore()
	if err != nil {
		return memcachedUnixAccount{}, err
	}
	defer store.root.Close()
	return memcachedUnixAdminIdentityAt(ctx, store, func(c context.Context) (memcachedUnixAccount, error) { return memcachedUnixSystemAccount(c, "") })
}

func (w *memcachedUnixInstallWorker) dependencyAccount(ctx context.Context, job string) error {
	unit, err := memcachedUnixAccountInstance(job)
	if err != nil {
		return err
	}
	properties := func() (map[string]string, error) {
		raw, err := w.own.s.Config.Run(ctx, "/usr/bin/systemctl", "show", unit, "--property=LoadState,ActiveState,SubState,MainPID,ControlPID,ExecMainStatus,Result")
		if err != nil {
			return nil, err
		}
		out := map[string]string{}
		for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok || key == "" {
				return nil, errMemcachedUnixNSS
			}
			if _, found := out[key]; found {
				return nil, errMemcachedUnixNSS
			}
			out[key] = value
		}
		if len(out) != 7 {
			return nil, errMemcachedUnixNSS
		}
		return out, nil
	}
	prior, err := properties()
	if err != nil || (prior["LoadState"] != "loaded" && prior["LoadState"] != "not-found") || prior["MainPID"] != "0" || prior["ControlPID"] != "0" || prior["ActiveState"] != "inactive" || prior["SubState"] != "dead" || w.authority(ctx) != nil {
		return errMemcachedUnixNSS
	}
	// Once only: a lost reply or a failed original unit is retained, not start
	// retried/reset/stopped. The dedicated fixed child independently rechecks.
	if _, err := w.own.s.Config.Run(ctx, "/usr/bin/systemctl", "start", "--no-block", unit); err != nil {
		return err
	}
	deadline := time.NewTimer(40 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		current, err := properties()
		if err != nil {
			return err
		}
		if current["ActiveState"] == "failed" || current["Result"] != "success" {
			return errMemcachedUnixNSS
		}
		if current["ActiveState"] == "inactive" && current["SubState"] == "dead" && current["MainPID"] == "0" && current["ControlPID"] == "0" {
			if current["LoadState"] != "loaded" || current["ExecMainStatus"] != "0" {
				return errMemcachedUnixNSS
			}
			return w.authority(ctx)
		}
		select {
		case <-ctx.Done():
			return errMemcachedUnixNSS
		case <-deadline.C:
			return errMemcachedUnixNSS
		case <-tick.C:
		}
	}
}

func (w *memcachedUnixInstallWorker) observe(ctx context.Context) (string, error) {
	if w.authority(ctx) != nil || w.project == nil {
		return "", errMemcachedUnixJournal
	}
	head, err := w.run.j.read()
	if err != nil {
		return "", err
	}
	account, err := w.resolveAccount(ctx, head.Operation.SiteID)
	if err != nil || account != w.account || validateMemcachedUnixDirectory(head.Operation.ProjectID, head.Operation.SiteID, account) != nil {
		return "", errMemcachedUnixNSS
	}
	m, err := readMemcachedUnixProject(w.project, head)
	if err != nil {
		return "", err
	}
	filters, _ := json.Marshal(map[string][]string{"label": {"com.docker.compose.project=" + m.Engine}})
	var rows []struct {
		ID string `json:"Id"`
	}
	if memcachedUpdateDockerRead(ctx, "/containers/json?all=1&filters="+url.QueryEscape(string(filters)), &rows) != nil || len(rows) != 1 || len(rows[0].ID) != 64 || !dockerObjectPattern.MatchString(rows[0].ID) {
		return "", errMemcachedUnix
	}
	var raw json.RawMessage
	if memcachedUpdateDockerRead(ctx, "/containers/"+rows[0].ID+"/json", &raw) != nil {
		return "", errMemcachedUnix
	}
	read := func(c context.Context, path string) ([]byte, error) {
		var body json.RawMessage
		err := memcachedUpdateDockerRead(c, path, &body)
		return body, err
	}
	id, pid, _, err := memcachedUnixRuntime(ctx, raw, m, head.Operation.SiteID, account, read)
	var image struct{ Image string }
	if err != nil || json.Unmarshal(raw, &image) != nil || id != rows[0].ID || image.Image != head.ImageID || head.ContainerID != "" && head.ContainerID != id || memcachedUnixKernel(ctx, pid, id, account, memcachedUnixReadFile) != nil {
		return "", errMemcachedUnix
	}
	directory, err := core.MemcachedUnixDirectory(m.ID, head.Operation.SiteID)
	if err != nil || memcachedUnixReadyAt(ctx, filepath.Join(directory, "cache.sock"), pid, account) != nil || w.authority(ctx) != nil {
		return "", errMemcachedUnix
	}
	return id, nil
}

func (w *memcachedUnixInstallWorker) execute(ctx context.Context) error {
	if w.authority(ctx) != nil || memcachedUnixHostAvailable() != nil {
		return errMemcachedUnixJournal
	}
	head, err := w.run.j.read()
	if err != nil || head.Phase != "prepared" {
		return errMemcachedUnixJournal
	}
	if err = w.transition(ctx, "account-intent", nil); err != nil {
		return err
	}
	if head.Operation.SiteID == "" {
		if err = w.dependencyAccount(ctx, head.Operation.JobID); err != nil {
			return err
		}
	}
	account, err := w.resolveAccount(ctx, head.Operation.SiteID)
	if err != nil {
		return err
	}
	w.account = account
	if err = w.transition(ctx, "account-verified", func(r *core.MemcachedUnixInstallRecord) { r.UID, r.GID = account.UID, account.GID }); err != nil {
		return err
	}
	// Account child has completed and released its own lease. Only now may
	// the parent acquire the global engine capability; no cross-process deadlock.
	bound, cancel := context.WithTimeout(ctx, 3*time.Second)
	engine, err := productionDockerMutationStore().acquire(bound)
	cancel()
	if err != nil {
		return err
	}
	defer engine.Close()
	return engine.use(ctx, func(active context.Context) error {
		if w.authority(active) != nil || w.own.otherTransactions(active) != nil || memcachedUnixEmptyEngine(active, head.Operation.ProjectID, memcachedUpdateDockerRead) != nil {
			return errMemcachedUnixJournal
		}
		if err = w.transition(active, "pull-intent", nil); err != nil {
			return err
		}
		if w.authority(active) != nil {
			return errMemcachedUnixJournal
		}
		if err = dockerPullFromDaemon(active, appcatalog.MemcachedDigestImage, dockerClient(0), memcachedUpdateImageRead); err != nil {
			return err
		}
		_, digest, _ := strings.Cut(appcatalog.MemcachedDigestImage, "@")
		image, err := verifyDockerPulledImage(active, dockerPullReceipt{Image: appcatalog.MemcachedDigestImage, Digest: digest}, memcachedUpdateImageRead)
		if err != nil || w.authority(active) != nil {
			return errMemcachedUnix
		}
		if err = w.transition(active, "image-verified", func(r *core.MemcachedUnixInstallRecord) { r.ImageID = image }); err != nil {
			return err
		}
		resolved, err := w.resolveAccount(active, head.Operation.SiteID)
		if err != nil || resolved != account {
			return errMemcachedUnixNSS
		}
		compose, err := core.MemcachedUnixRuntimeCompose(head.Operation.ProjectID, head.Operation.SiteID, account.UID, account.GID)
		if err != nil {
			return err
		}
		if err = w.transition(active, "project-intent", func(r *core.MemcachedUnixInstallRecord) { r.ComposeSHA256 = core.Hash(compose) }); err != nil {
			return err
		}
		if w.authority(active) != nil || memcachedUnixEmptyEngine(active, head.Operation.ProjectID, memcachedUpdateDockerRead) != nil {
			return errMemcachedUnixJournal
		}
		if err = prepareMemcachedUnixDirectory(head.Operation.ProjectID, head.Operation.SiteID, account); err != nil {
			return err
		}
		current, err := w.run.j.read()
		if err != nil {
			return err
		}
		project, err := createMemcachedUnixProjectAt(dockerProjects, current)
		if err != nil {
			return err
		}
		defer project.Close()
		// Set project only after its corresponding immutable event exists.
		if err = w.transition(active, "project-written", nil); err != nil {
			return err
		}
		w.project = project
		projectHead, err := w.run.j.read()
		if err != nil {
			return err
		}
		metadata, err := readMemcachedUnixProject(project, projectHead)
		if err != nil {
			return err
		}
		if err = w.transition(active, "start-intent", nil); err != nil {
			return err
		}
		if w.authority(active) != nil || validateMemcachedUnixDirectory(head.Operation.ProjectID, head.Operation.SiteID, account) != nil || memcachedUnixEmptyEngine(active, head.Operation.ProjectID, memcachedUpdateDockerRead) != nil {
			return errMemcachedUnixJournal
		}
		if _, err = composeCommand(active, composeArgs(metadata, filepath.Join(dockerProjects, head.Operation.ProjectID), "up", "-d", "--pull", "never", "--no-build", "--no-recreate")...); err != nil {
			return err
		}
		deadline := time.NewTimer(90 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		var container string
		for {
			container, err = w.observe(active)
			if err == nil {
				break
			}
			if w.authority(active) != nil {
				return errMemcachedUnixJournal
			}
			select {
			case <-active.Done():
				return errMemcachedUnix
			case <-deadline.C:
				return errMemcachedUnix
			case <-tick.C:
			}
		}
		if err = w.transition(active, "runtime-verified", func(r *core.MemcachedUnixInstallRecord) { r.ContainerID = container }); err != nil {
			return err
		}
		actual, err := w.observe(active)
		if err != nil || actual != container {
			return errMemcachedUnix
		}
		return w.transition(active, "committed", nil)
	})
}

func runMemcachedUnixInstall(job string) {
	if os.Geteuid() != 0 || !core.ValidID(job) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	j, err := (memcachedUnixJournalStore{base: memcachedUnixInstallJobsRoot}).open(job)
	if err != nil {
		return
	}
	defer j.Close()
	run, err := j.lease()
	if err != nil {
		return
	}
	defer run.Close()
	w := &memcachedUnixInstallWorker{run: run}
	defer func() { w.interrupted("interrupted") }()
	leaseContext, leaseCancel := context.WithTimeout(ctx, 3*time.Second)
	lifetime, err := acquireMemcachedUnixRuntime(leaseContext)
	leaseCancel()
	if err != nil {
		return
	}
	defer lifetime.Close()
	w.lifetime = lifetime
	chain, err := j.readChain()
	if err != nil || len(chain) != 1 || chain[0].Phase != "prepared" {
		return
	}
	own, err := memcachedUnixFindOriginalRun(ctx, j)
	if err != nil {
		return
	}
	w.own = own
	reader, err := openMemcachedUpdateCoreAuthority(ctx)
	if err != nil {
		return
	}
	defer reader.Close()
	w.core = reader
	_ = w.execute(ctx)
}
