//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"local/panel/internal/core"
)

func memcachedUnixWorkspaceState(ctx context.Context, p *memcachedUnixProjectOriginal, account memcachedUnixAccount) (composeMetadata, json.RawMessage, int, string, error) {
	var empty composeMetadata
	if p == nil || p.head.Phase != "committed" || p.current(ctx) != nil {
		return empty, nil, 0, "", errMemcachedUnixJournal
	}
	m, err := readMemcachedUnixProject(p.project, p.head)
	if err != nil {
		return empty, nil, 0, "", err
	}
	filters, _ := json.Marshal(map[string][]string{"label": {"com.docker.compose.project=" + m.Engine}})
	var rows []struct {
		ID string `json:"Id"`
	}
	if memcachedUpdateDockerRead(ctx, "/containers/json?all=1&filters="+url.QueryEscape(string(filters)), &rows) != nil || len(rows) != 1 || rows[0].ID != p.head.ContainerID {
		return empty, nil, 0, "", errMemcachedUnix
	}
	var raw json.RawMessage
	if memcachedUpdateDockerRead(ctx, "/containers/"+p.head.ContainerID+"/json", &raw) != nil {
		return empty, nil, 0, "", errMemcachedUnix
	}
	var state struct {
		Image string
		State struct{ Running *bool }
	}
	if memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &state) != nil || state.State.Running == nil || state.Image != p.head.ImageID {
		return empty, nil, 0, "", errMemcachedUnix
	}
	read := func(c context.Context, path string) ([]byte, error) {
		var body json.RawMessage
		err := memcachedUpdateDockerRead(c, path, &body)
		return body, err
	}
	if !*state.State.Running {
		actual, err := memcachedUnixStoppedRuntime(ctx, raw, m, p.head.Operation.SiteID, account, read)
		if err != nil || actual != p.head.ContainerID || p.current(ctx) != nil {
			return empty, nil, 0, "", errMemcachedUnix
		}
		return m, raw, 0, "stopped", nil
	}
	actual, pid, _, err := memcachedUnixRuntime(ctx, raw, m, p.head.Operation.SiteID, account, read)
	if err != nil || actual != p.head.ContainerID || memcachedUnixKernel(ctx, pid, actual, account, memcachedUnixReadFile) != nil || validateMemcachedUnixDirectory(m.ID, p.head.Operation.SiteID, account) != nil || p.current(ctx) != nil {
		return empty, nil, 0, "", errMemcachedUnix
	}
	return m, raw, pid, "running", nil
}

func runMemcachedUnixWorkspace(ctx context.Context, in core.MemcachedUnixWorkspaceRequest) (core.MemcachedUnixWorkspace, error) {
	var out core.MemcachedUnixWorkspace
	if ctx == nil || ctx.Err() != nil || core.ValidateMemcachedUnixWorkspaceRequest(in) != nil {
		return out, core.ErrMemcachedUnixCacheInput
	}
	bound, cancel := context.WithTimeout(ctx, 3*time.Second)
	engine, err := productionDockerMutationStore().begin(bound)
	cancel()
	if err != nil {
		return out, err
	}
	defer engine.Close()
	err = engine.use(ctx, func(active context.Context) error {
		p, err := openMemcachedUnixProjectOriginal(active, in.ProjectID)
		if err != nil {
			return err
		}
		defer p.Close()
		if p.head.Phase != "committed" {
			return errMemcachedUnixJournal
		}
		reader, err := openMemcachedUpdateCoreAuthority(active)
		if err != nil {
			return err
		}
		defer reader.Close()
		permission := "stop"
		if in.Action == "cache" && in.Cache.Action != "get" && in.Cache.Action != "stats" {
			permission = "update"
		}
		check := func(check context.Context) error {
			if p.current(check) != nil || reader.unixOperation(check, in.ActorID, p.head.Operation, permission, p.head.Binding) != nil {
				return errMemcachedCoreAuthority
			}
			if _, err := readMemcachedUnixProject(p.project, p.head); err != nil {
				return err
			}
			return nil
		}
		if err := check(active); err != nil {
			return err
		}
		account, err := memcachedUnixOriginalAccount(active, p)
		if err != nil {
			return err
		}
		retired, retirementSHA, err := memcachedUnixRetiredState(active, p, account)
		if err != nil {
			return err
		}
		if retired != nil {
			if in.Action != "inspect" {
				return core.ErrMemcachedUnixControl
			}
			directory, pathErr := core.MemcachedUnixDirectory(in.ProjectID, p.head.Operation.SiteID)
			if pathErr != nil || check(active) != nil {
				return core.ErrMemcachedUnixControl
			}
			out = core.MemcachedUnixWorkspace{Format: 1, ProjectID: in.ProjectID, Name: p.head.Operation.Name, SiteID: p.head.Operation.SiteID, Version: p.head.Binding.Version, State: "retired", StateKnown: true, SocketPath: filepath.Join(directory, "cache.sock"), CacheMB: 128, MemoryLimitMB: 192, ItemLimitMB: 4, EditorLimitBytes: core.MemcachedUnixConsoleValueBytes, NetworkMode: "none", RuntimeSHA256: retirementSHA, RetirementRequestID: retired.Seed.Operation.RequestID}
			return nil
		}
		_, raw, pid, state, err := memcachedUnixWorkspaceState(active, p, account)
		if err != nil {
			return err
		}
		directory, err := core.MemcachedUnixDirectory(in.ProjectID, p.head.Operation.SiteID)
		if err != nil {
			return err
		}
		socketPath := filepath.Join(directory, "cache.sock")
		out = core.MemcachedUnixWorkspace{Format: 1, ProjectID: in.ProjectID, Name: p.head.Operation.Name, SiteID: p.head.Operation.SiteID, Version: p.head.Binding.Version, State: state, StateKnown: true, SocketPath: socketPath, CacheMB: 128, MemoryLimitMB: 192, ItemLimitMB: 4, EditorLimitBytes: core.MemcachedUnixConsoleValueBytes, NetworkMode: "none", RetirementSupported: true}
		out.RuntimeSHA256, err = memcachedUnixRuntimeFingerprint(raw)
		if err != nil {
			return err
		}
		if state == "stopped" {
			if in.Action == "cache" {
				return errMemcachedUnix
			}
			return check(active)
		}
		if in.Action == "inspect" {
			if memcachedUnixReadyAt(active, socketPath, pid, account) != nil || check(active) != nil {
				return errMemcachedUnix
			}
			out.Healthy = true
			return nil
		}
		// Gate is repeated on this exact verified connection before sending.
		// No raw cache key/value enters SQL, Root journals, audit or command argv.
		beforeWrite := func(c context.Context) error {
			if err := check(c); err != nil {
				return err
			}
			current, err := memcachedUnixOriginalAccount(c, p)
			if err != nil || current != account {
				return errMemcachedUnixNSS
			}
			if permission == "update" && p.head.Operation.SiteID != "" {
				owned, err := memcachedUnixOwnedSiteAccount(c, p.head.Operation.SiteID)
				if err != nil || owned != account {
					return errMemcachedUnixNSS
				}
			}
			return nil
		}
		result, err := exchangeMemcachedUnixCacheGatedAt(active, socketPath, pid, account, *in.Cache, beforeWrite)
		if err != nil {
			return err
		}
		if err := check(active); err != nil {
			if in.Cache.Action != "get" && in.Cache.Action != "stats" {
				return errMemcachedUnixCacheUnknown
			}
			return err
		}
		out.Healthy, out.Cache = true, &result
		return nil
	})
	if err != nil {
		return core.MemcachedUnixWorkspace{}, err
	}
	return out, nil
}

func (s *Service) memcachedUnixWorkspaceRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/memcached-unix/projects/{id}/workspace", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if !core.ValidID(r.PathValue("id")) || r.URL.RawQuery != "" {
			respond(w, 404, map[string]string{"error": "原缓存项目身份无效"})
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, core.MaxMemcachedUnixWorkspaceBytes+1))
		in, decodeErr := core.DecodeMemcachedUnixWorkspaceRequest(raw)
		if err != nil || decodeErr != nil || in.ProjectID != r.PathValue("id") {
			respond(w, 400, map[string]string{"error": "缓存工作区传输、容量或原身份无效"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		out, err := runMemcachedUnixWorkspace(ctx, in)
		if err != nil {
			status := 409
			if errors.Is(err, core.ErrMemcachedUnixCacheInput) {
				status = 400
			}
			respond(w, status, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
}
