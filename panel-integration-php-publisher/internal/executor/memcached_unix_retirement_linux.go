//go:build linux

package executor

import (
	"context"
	"io"
	"net/http"

	"local/panel/internal/core"
)

type memcachedUnixRetirementRemove func(context.Context, string) (int, []byte, error)

// Separate from the GET/POST retention helper: no caller can choose method,
// query, path or payload. force=false cannot kill a concurrently started
// container; v=false/link=false cannot remove volumes or unrelated links.
// The normal controller, not a raw HTTP field, supplies its verified full CID.
func memcachedUnixRetirementDaemon(ctx context.Context, cid string) (int, []byte, error) {
	if ctx == nil || ctx.Err() != nil || len(cid) != 64 || !dockerObjectPattern.MatchString(cid) {
		return 0, nil, core.ErrMemcachedUnixControl
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodDelete, "http://docker/containers/"+cid+"?force=false&v=false&link=false", nil)
	if e != nil {
		return 0, nil, e
	}
	client := dockerClient(0)
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	var status int
	var raw []byte
	e = withDockerMutation(ctx, func(active context.Context) error {
		response, e := client.Do(req.WithContext(active))
		if e != nil {
			return e
		}
		defer response.Body.Close()
		status = response.StatusCode
		raw, e = io.ReadAll(io.LimitReader(response.Body, 4097))
		if e != nil || len(raw) > 4096 || active.Err() != nil {
			return core.ErrMemcachedUnixControl
		}
		return nil
	})
	return status, raw, e
}

// One already-issued retirement ONLY. The caller retains the original signed
// stop-state/name proof, current Core/NSS authority and the original run/engine
// leases. A lost/refused reply remains unknown; this never repeats DELETE or
// tries another CID, stop, force, image removal, volume removal or FS cleanup.
func completeMemcachedUnixRetirement(ctx context.Context, seed memcachedUnixControlSeed, issued memcachedUnixControlIssued, check func(context.Context) error, read memcachedRetentionCall, remove memcachedUnixRetirementRemove) (core.MemcachedUnixControlResult, error) {
	var empty core.MemcachedUnixControlResult
	if ctx == nil || ctx.Err() != nil || check == nil || read == nil || remove == nil || validateMemcachedUnixRetirementIssued(seed, issued) != nil {
		return empty, core.ErrMemcachedUnixControl
	}
	if e := check(ctx); e != nil {
		return empty, e
	}
	status, body, e := remove(ctx, issued.ContainerID) // Exactly ONE original DELETE.
	if e != nil || status != http.StatusNoContent || len(body) != 0 {
		return empty, core.ErrMemcachedUnixControl
	}
	fingerprint := ""
	for observation := 0; observation < 2; observation++ {
		if e := check(ctx); e != nil {
			return empty, e
		}
		current, e := memcachedUnixRetirementAbsence(ctx, seed, issued, read)
		if e != nil || observation > 0 && current != fingerprint {
			return empty, core.ErrMemcachedUnixControl
		}
		fingerprint = current
	}
	if e := check(ctx); e != nil {
		return empty, e
	}
	out := memcachedUnixControlBaseResult(seed.Operation, "completed")
	out.FinalState = "retired"
	out.RuntimeSHA256 = fingerprint
	if core.ValidateMemcachedUnixControlResult(seed.Operation, out) != nil {
		return empty, core.ErrMemcachedUnixControl
	}
	return out, nil
}
