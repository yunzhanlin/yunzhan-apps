//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"net/url"
	"path/filepath"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

type memcachedUnixProjectOriginal struct {
	project *composeUpdateDirectory
	journal *memcachedUnixJournal
	head    core.MemcachedUnixInstallRecord
}

func (p *memcachedUnixProjectOriginal) Close() {
	if p != nil {
		if p.project != nil {
			p.project.Close()
		}
		if p.journal != nil {
			p.journal.Close()
		}
	}
}

// Historical ownership, not live health or actor mutation permission. Always
// authenticate the original signature and full Root chain, never labels alone.
func openMemcachedUnixProjectOriginal(ctx context.Context, id string) (*memcachedUnixProjectOriginal, error) {
	d, err := openComposeUpdateDirectory(dockerProjects, id)
	if err != nil {
		return nil, err
	}
	p := &memcachedUnixProjectOriginal{project: d}
	fail := func(e error) (*memcachedUnixProjectOriginal, error) { p.Close(); return nil, e }
	raw, err := readMemcachedUnixProjectMarker(d)
	if err != nil {
		return fail(err)
	}
	marker, err := core.DecodeMemcachedUnixInstallRecord(raw)
	if err != nil || marker.Phase != "project-written" || marker.Operation.ProjectID != id {
		return fail(errMemcachedUnixJournal)
	}
	j, err := (memcachedUnixJournalStore{base: memcachedUnixInstallJobsRoot}).open(marker.Operation.JobID)
	if err != nil {
		return fail(err)
	}
	p.journal = j
	head, err := j.read()
	if err != nil {
		return fail(err)
	}
	expected := head
	expected.Sequence, expected.Phase, expected.ContainerID, expected.Fault = 6, "project-written", "", ""
	if expected != marker {
		return fail(errMemcachedUnixJournal)
	}
	authority, err := j.officialAuthority(ctx)
	if err != nil || !authority.Matches(head.Binding.Version, head.Binding.ManifestSHA256) || authority.CatalogSHA256() != head.CatalogSHA256 {
		return fail(errMemcachedUnixJournal)
	}
	current, err := j.read()
	if err != nil || current != head || !d.current() || !j.current() || ctx == nil || ctx.Err() != nil {
		return fail(errMemcachedUnixJournal)
	}
	p.head = head
	return p, nil
}

func (p *memcachedUnixProjectOriginal) current(ctx context.Context) error {
	if p == nil || p.project == nil || p.journal == nil || !p.project.current() || !p.journal.current() || ctx == nil || ctx.Err() != nil {
		return errMemcachedUnixJournal
	}
	head, err := p.journal.read()
	if err != nil || head != p.head {
		return errMemcachedUnixJournal
	}
	authority, err := p.journal.officialAuthority(ctx)
	if err != nil || !authority.Matches(head.Binding.Version, head.Binding.ManifestSHA256) || authority.CatalogSHA256() != head.CatalogSHA256 {
		return errMemcachedUnixJournal
	}
	return nil
}

func memcachedUnixOriginalAccount(ctx context.Context, p *memcachedUnixProjectOriginal) (memcachedUnixAccount, error) {
	var empty memcachedUnixAccount
	if p == nil || p.current(ctx) != nil {
		return empty, errMemcachedUnixJournal
	}
	var account memcachedUnixAccount
	var err error
	if p.head.Operation.SiteID == "" {
		store, e := openMemcachedUnixAdminStore()
		if e != nil {
			return empty, e
		}
		defer store.root.Close()
		account, err = memcachedUnixAdminIdentityAt(ctx, store, func(c context.Context) (memcachedUnixAccount, error) { return memcachedUnixSystemAccount(c, "") })
	} else {
		// The original committed Root installation supplies account ownership
		// even after a website stops/archives. Fresh complete NSS still must
		// match the exact recorded non-root UID/GID. Start has a separate
		// fresh active-website/PHP binding requirement; this is not that gate.
		account, err = memcachedUnixSystemAccount(ctx, p.head.Operation.SiteID)
	}
	if err != nil || account.UID != p.head.UID || account.GID != p.head.GID || p.current(ctx) != nil {
		return empty, errMemcachedUnixNSS
	}
	return account, nil
}

func listMemcachedUnixProject(ctx context.Context, id string) (map[string]any, error) {
	p, err := openMemcachedUnixProjectOriginal(ctx, id)
	if err != nil {
		return nil, err
	}
	defer p.Close()
	out := map[string]any{"id": id, "name": p.head.Operation.Name, "engine_name": "panel_" + id[:12], "template_id": "memcached-cache", "template_profile": core.MemcachedUnixProfile, "site_id": p.head.Operation.SiteID, "host_port": 0, "services": 1, "containers": 0, "running": 0, "healthy": 0, "state": "needs_attention", "state_known": false, "created_at": "", "images": []string{appcatalog.MemcachedDigestImage}}
	if p.head.Phase != "committed" {
		return out, nil
	}
	metadata, err := readMemcachedUnixProject(p.project, p.head)
	if err != nil {
		return out, nil
	}
	out["created_at"] = metadata.CreatedAt
	account, err := memcachedUnixOriginalAccount(ctx, p)
	if err != nil {
		return out, nil
	}
	filters, _ := json.Marshal(map[string][]string{"label": {"com.docker.compose.project=" + metadata.Engine}})
	var rows []struct {
		ID string `json:"Id"`
	}
	if memcachedUpdateDockerRead(ctx, "/containers/json?all=1&filters="+url.QueryEscape(string(filters)), &rows) != nil || len(rows) != 1 || rows[0].ID != p.head.ContainerID {
		return out, nil
	}
	var raw json.RawMessage
	if memcachedUpdateDockerRead(ctx, "/containers/"+rows[0].ID+"/json", &raw) != nil {
		return out, nil
	}
	var state struct {
		Image string
		State struct {
			Running *bool
			Pid     int
		}
	}
	if memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &state) != nil || state.State.Running == nil || state.Image != p.head.ImageID {
		return out, nil
	}
	read := func(c context.Context, path string) ([]byte, error) {
		var body json.RawMessage
		err := memcachedUpdateDockerRead(c, path, &body)
		return body, err
	}
	if !*state.State.Running {
		actual, err := memcachedUnixStoppedRuntime(ctx, raw, metadata, p.head.Operation.SiteID, account, read)
		if err != nil || actual != p.head.ContainerID || p.current(ctx) != nil {
			return out, nil
		}
		out["containers"], out["state"], out["state_known"] = 1, "stopped", true
		return out, nil
	}
	actual, pid, _, err := memcachedUnixRuntime(ctx, raw, metadata, p.head.Operation.SiteID, account, read)
	if err != nil || actual != p.head.ContainerID || memcachedUnixKernel(ctx, pid, actual, account, memcachedUnixReadFile) != nil || validateMemcachedUnixDirectory(id, p.head.Operation.SiteID, account) != nil {
		return out, nil
	}
	directory, err := core.MemcachedUnixDirectory(id, p.head.Operation.SiteID)
	if err != nil || memcachedUnixReadyAt(ctx, filepath.Join(directory, "cache.sock"), pid, account) != nil || p.current(ctx) != nil {
		return out, nil
	}
	out["containers"], out["running"], out["healthy"], out["state"], out["state_known"] = 1, 1, 1, "running", true
	return out, nil
}
