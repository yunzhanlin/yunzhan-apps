package core

import (
	"bytes"
	"encoding/json"
	"io"
)

const MaxMemcachedUnixWorkspaceBytes = MemcachedUnixCacheInputBytes + 2048

type memcachedUnixWorkspaceInput struct {
	Action string                   `json:"action"`
	Cache  *MemcachedUnixCacheInput `json:"cache,omitempty"`
}

// Browser JSON may use whitespace or a different field order, but cannot
// supply duplicate/aliased fields, nulls, an actor or a native address.
func memcachedUnixWorkspaceObject(raw []byte, allowed map[string]bool) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return nil, ErrMemcachedUnixCacheInput
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] || out[key] != nil {
			return nil, ErrMemcachedUnixCacheInput
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, ErrMemcachedUnixCacheInput
		}
		out[key] = value
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		return nil, ErrMemcachedUnixCacheInput
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrMemcachedUnixCacheInput
	}
	return out, nil
}

func decodeMemcachedUnixWorkspaceInput(raw []byte) (memcachedUnixWorkspaceInput, error) {
	var in memcachedUnixWorkspaceInput
	if len(raw) == 0 || len(raw) > MaxMemcachedUnixWorkspaceBytes {
		return in, ErrMemcachedUnixCacheInput
	}
	fields, err := memcachedUnixWorkspaceObject(raw, map[string]bool{"action": true, "cache": true})
	if err != nil || fields["action"] == nil || json.Unmarshal(raw, &in) != nil {
		return in, ErrMemcachedUnixCacheInput
	}
	if cache := fields["cache"]; cache != nil {
		values, err := memcachedUnixWorkspaceObject(cache, map[string]bool{"action": true, "key_base64": true, "value_base64": true, "cas": true, "ttl_seconds": true, "flags": true, "stats": true})
		if err != nil || values["action"] == nil {
			return memcachedUnixWorkspaceInput{}, ErrMemcachedUnixCacheInput
		}
	}
	return in, nil
}

// Native RPC only: Core supplies actor/project from authenticated routing.
// No executable, credential, path, PID, UID or claimed verification flags.
type MemcachedUnixWorkspaceRequest struct {
	Format    int                      `json:"format"`
	ProjectID string                   `json:"project_id"`
	ActorID   string                   `json:"actor_id"`
	Action    string                   `json:"action"`
	Cache     *MemcachedUnixCacheInput `json:"cache,omitempty"`
}

type MemcachedUnixWorkspace struct {
	Format           int                       `json:"format"`
	ProjectID        string                    `json:"project_id"`
	Name             string                    `json:"name"`
	SiteID           string                    `json:"site_id"`
	Version          string                    `json:"version"`
	State            string                    `json:"state"`
	StateKnown       bool                      `json:"state_known"`
	Healthy          bool                      `json:"healthy"`
	SocketPath       string                    `json:"socket_path"`
	CacheMB          int                       `json:"cache_mb"`
	MemoryLimitMB    int                       `json:"memory_limit_mb"`
	ItemLimitMB      int                       `json:"item_limit_mb"`
	EditorLimitBytes int                       `json:"editor_limit_bytes"`
	NetworkMode      string                    `json:"network_mode"`
	RuntimeSHA256    string                    `json:"runtime_sha256"`
	Cache            *MemcachedUnixCacheResult `json:"cache,omitempty"`
}

func ValidateMemcachedUnixWorkspaceRequest(in MemcachedUnixWorkspaceRequest) error {
	if in.Format != 1 || !ValidID(in.ProjectID) || !ValidID(in.ActorID) {
		return ErrMemcachedUnixCacheInput
	}
	switch in.Action {
	case "inspect":
		if in.Cache != nil {
			return ErrMemcachedUnixCacheInput
		}
	case "cache":
		if in.Cache == nil || ValidateMemcachedUnixCacheInput(*in.Cache) != nil {
			return ErrMemcachedUnixCacheInput
		}
	default:
		return ErrMemcachedUnixCacheInput
	}
	return nil
}

func DecodeMemcachedUnixWorkspaceRequest(raw []byte) (MemcachedUnixWorkspaceRequest, error) {
	var in MemcachedUnixWorkspaceRequest
	if len(raw) == 0 || len(raw) > MaxMemcachedUnixWorkspaceBytes || json.Unmarshal(raw, &in) != nil {
		return in, ErrMemcachedUnixCacheInput
	}
	canonical, err := json.Marshal(in)
	if err != nil || !bytes.Equal(raw, canonical) || ValidateMemcachedUnixWorkspaceRequest(in) != nil {
		return MemcachedUnixWorkspaceRequest{}, ErrMemcachedUnixCacheInput
	}
	return in, nil
}
