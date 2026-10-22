//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"unicode/utf8"

	"local/panel/internal/core"
)

var errMemcachedRetention = errors.New("Memcached 原镜像保留身份或创建结果不能核对；不重建、启动或删除原容器")

const memcachedRetentionOwner = "yunzhan.memcached-image-retention.v1"

type memcachedRetentionIntent struct {
	Format         int    `json:"format"`
	JobID          string `json:"job_id"`
	ProjectID      string `json:"project_id"`
	DispatchSHA256 string `json:"dispatch_sha256"`
	ImageID        string `json:"image_id"`
	Name           string `json:"name"`
}
type memcachedRetentionReceipt struct {
	Format       int    `json:"format"`
	IntentSHA256 string `json:"intent_sha256"`
	ContainerID  string `json:"container_id"`
}

func memcachedRetentionOriginal(seed core.MemcachedUpdateRecord) (memcachedRetentionIntent, []byte, error) {
	if core.ValidateMemcachedUpdateRecord(seed) != nil {
		return memcachedRetentionIntent{}, nil, errMemcachedRetention
	}
	in := memcachedRetentionIntent{1, seed.Dispatch.JobID, seed.Dispatch.ProjectID, seed.DispatchSHA256, seed.Plan.RuntimeImageID, "yunzhan-retain-memcached-" + seed.Dispatch.JobID}
	raw, err := json.Marshal(in)
	return in, raw, err
}
func memcachedRetentionLabels(in memcachedRetentionIntent, raw []byte) map[string]string {
	return map[string]string{"io.yunzhan.owner": memcachedRetentionOwner, "io.yunzhan.job": in.JobID, "io.yunzhan.project": in.ProjectID, "io.yunzhan.dispatch-sha256": in.DispatchSHA256, "io.yunzhan.retention-sha256": core.Hash(string(raw))}
}
func memcachedRetentionPayload(in memcachedRetentionIntent, raw []byte) map[string]any {
	// This is NEVER started. It keeps the exact local image referenced even
	// after Compose recreates the original service; no mutable rollback tag.
	return map[string]any{"Image": in.ImageID, "User": "memcache", "Entrypoint": []string{"memcached"}, "Cmd": []string{"-h"}, "NetworkDisabled": true, "Healthcheck": map[string]any{"Test": []string{"NONE"}}, "Labels": memcachedRetentionLabels(in, raw), "HostConfig": map[string]any{"NetworkMode": "none", "IpcMode": "none", "ReadonlyRootfs": true, "Privileged": false, "AutoRemove": false, "CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges:true"}, "PidsLimit": 16, "Memory": 16 << 20, "MemorySwap": 16 << 20, "RestartPolicy": map[string]any{"Name": "no", "MaximumRetryCount": 0}}}
}

// Internal protocol seam, never an HTTP/config-supplied client or callback.
// The worker owns independently verified signature/current Core/project/run
// authority and a Docker mutation lease across this entire operation.
type memcachedRetentionCall func(context.Context, string, string, any) (int, []byte, error)

func memcachedRetentionDaemon(ctx context.Context, method, path string, input any) (int, []byte, error) {
	if ctx == nil || ctx.Err() != nil || (method != http.MethodGet && method != http.MethodPost) {
		return 0, nil, errMemcachedRetention
	}
	var body io.Reader
	if input != nil {
		raw, err := json.Marshal(input)
		if err != nil {
			return 0, nil, errMemcachedRetention
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, body)
	if err != nil {
		return 0, nil, errMemcachedRetention
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := dockerClient(0)
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	var status int
	var raw []byte
	call := func(bound context.Context) error {
		response, err := client.Do(req.WithContext(bound))
		if err != nil {
			return errMemcachedRetention
		}
		defer response.Body.Close()
		status = response.StatusCode
		raw, err = io.ReadAll(io.LimitReader(response.Body, (256<<10)+1))
		if err != nil || len(raw) > 256<<10 || bound.Err() != nil {
			return errMemcachedRetention
		}
		return nil
	}
	if method == http.MethodGet {
		err = call(ctx)
	} else {
		err = withDockerMutation(ctx, call)
	}
	return status, raw, err
}

// Reject duplicate/case-alias keys recursively before permissive Go struct
// decoding. Unknown Docker metadata remains forward compatible, not authority.
func memcachedDaemonJSON(raw []byte) error {
	if len(raw) == 0 || len(raw) > 256<<10 || !utf8.Valid(raw) {
		return errMemcachedRetention
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 20 {
			return errMemcachedRetention
		}
		token, err := d.Token()
		if err != nil {
			return errMemcachedRetention
		}
		delim, nested := token.(json.Delim)
		if !nested {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				fold := strings.ToLower(name)
				if err != nil || !ok || seen[fold] {
					return errMemcachedRetention
				}
				seen[fold] = true
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errMemcachedRetention
		}
		end, err := d.Token()
		if err != nil || delim == '{' && end != json.Delim('}') || delim == '[' && end != json.Delim(']') {
			return errMemcachedRetention
		}
		return nil
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errMemcachedRetention
	}
	return nil
}

func memcachedRetentionInspect(raw []byte, in memcachedRetentionIntent, intentRaw []byte, expected string) (string, error) {
	if memcachedDaemonJSON(raw) != nil {
		return "", errMemcachedRetention
	}
	// Critical fields must use Docker's exact spelling, not Go's permissive
	// case-folded struct aliases. Unknown metadata is not interpreted as a grant.
	fields, err := dockerPullJSONObject(raw)
	if err != nil || memcachedDaemonFields(fields, "Id", "Name", "Image", "RestartCount", "Config", "State", "HostConfig", "Mounts") != nil {
		return "", errMemcachedRetention
	}
	for key, names := range map[string][]string{
		"Config":     {"Image", "User", "Entrypoint", "Cmd", "NetworkDisabled", "Labels", "Healthcheck"},
		"State":      {"Status", "Running", "Paused", "Restarting", "OOMKilled", "Dead", "Pid", "ExitCode", "StartedAt"},
		"HostConfig": {"Privileged", "ReadonlyRootfs", "AutoRemove", "NetworkMode", "IpcMode", "PidsLimit", "Memory", "MemorySwap", "CapDrop", "SecurityOpt", "RestartPolicy"},
	} {
		object, e := dockerPullJSONObject(fields[key])
		if e != nil || memcachedDaemonFields(object, names...) != nil {
			return "", errMemcachedRetention
		}
		if key == "Config" {
			health, e := dockerPullJSONObject(object["Healthcheck"])
			if e != nil || memcachedDaemonFields(health, "Test") != nil {
				return "", errMemcachedRetention
			}
		}
		if key == "HostConfig" {
			restart, e := dockerPullJSONObject(object["RestartPolicy"])
			if e != nil || memcachedDaemonFields(restart, "Name", "MaximumRetryCount") != nil {
				return "", errMemcachedRetention
			}
		}
	}
	var v struct {
		ID           string `json:"Id"`
		Name         string `json:"Name"`
		Image        string `json:"Image"`
		RestartCount *int   `json:"RestartCount"`
		Config       *struct {
			Image           string `json:"Image"`
			User            string `json:"User"`
			Entrypoint, Cmd []string
			NetworkDisabled *bool
			Labels          map[string]string
			Healthcheck     *struct{ Test []string }
		}
		State *struct {
			Status                                       string
			Running, Paused, Restarting, OOMKilled, Dead *bool
			Pid, ExitCode                                *int
			StartedAt                                    string
		}
		HostConfig *struct {
			Privileged, ReadonlyRootfs, AutoRemove                              *bool
			NetworkMode, IpcMode, PidMode, UTSMode, UsernsMode                  string
			CapAdd, CapDrop, SecurityOpt, Binds, VolumesFrom, DeviceCgroupRules []string
			Devices, Mounts                                                     []json.RawMessage
			Tmpfs, Sysctls                                                      map[string]string
			PortBindings                                                        map[string]json.RawMessage
			PidsLimit, Memory, MemorySwap                                       *int64
			RestartPolicy                                                       struct {
				Name              string
				MaximumRetryCount int
			}
		}
		Mounts []json.RawMessage
	}
	if json.Unmarshal(raw, &v) != nil || !dockerPullDigestPattern.MatchString("sha256:"+v.ID) || expected != "" && v.ID != expected || v.Name != "/"+in.Name || v.Image != in.ImageID || v.RestartCount == nil || *v.RestartCount != 0 || v.Config == nil || v.State == nil || v.HostConfig == nil {
		return "", errMemcachedRetention
	}
	c, s, h := v.Config, v.State, v.HostConfig
	if c.Image != in.ImageID || c.User != "memcache" || !slices.Equal(c.Entrypoint, []string{"memcached"}) || !slices.Equal(c.Cmd, []string{"-h"}) || c.NetworkDisabled == nil || !*c.NetworkDisabled || c.Healthcheck == nil || !slices.Equal(c.Healthcheck.Test, []string{"NONE"}) || len(c.Labels) != 5 {
		return "", errMemcachedRetention
	}
	for key, value := range memcachedRetentionLabels(in, intentRaw) {
		if c.Labels[key] != value {
			return "", errMemcachedRetention
		}
	}
	if s.Status != "created" || s.StartedAt != "0001-01-01T00:00:00Z" || s.Pid == nil || *s.Pid != 0 || s.ExitCode == nil || *s.ExitCode != 0 {
		return "", errMemcachedRetention
	}
	for _, value := range []*bool{s.Running, s.Paused, s.Restarting, s.OOMKilled, s.Dead, h.Privileged, h.AutoRemove} {
		if value == nil || *value {
			return "", errMemcachedRetention
		}
	}
	if h.ReadonlyRootfs == nil || !*h.ReadonlyRootfs || h.NetworkMode != "none" || h.IpcMode != "none" || h.PidMode != "" || h.UTSMode != "" || h.UsernsMode != "" || !slices.Equal(h.CapDrop, []string{"ALL"}) || !slices.Equal(h.SecurityOpt, []string{"no-new-privileges:true"}) || h.RestartPolicy.Name != "no" || h.RestartPolicy.MaximumRetryCount != 0 {
		return "", errMemcachedRetention
	}
	if len(h.CapAdd)+len(h.Binds)+len(h.VolumesFrom)+len(h.DeviceCgroupRules)+len(h.Devices)+len(h.Mounts)+len(h.Tmpfs)+len(h.Sysctls)+len(h.PortBindings)+len(v.Mounts) != 0 {
		return "", errMemcachedRetention
	}
	for _, pair := range []struct {
		actual   *int64
		expected int64
	}{{h.PidsLimit, 16}, {h.Memory, 16 << 20}, {h.MemorySwap, 16 << 20}} {
		if pair.actual == nil || *pair.actual != pair.expected {
			return "", errMemcachedRetention
		}
	}
	return v.ID, nil
}

func memcachedDaemonFields(fields map[string]json.RawMessage, required ...string) error {
	for _, name := range required {
		value, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errMemcachedRetention
		}
	}
	// Reject even a single case alias of a field that Go would interpret.
	// Optional absent fields keep the daemon's normal zero-value defaults.
	for name := range fields {
		for _, canonical := range required {
			if name != canonical && strings.EqualFold(name, canonical) {
				return errMemcachedRetention
			}
		}
	}
	return nil
}

func (j *memcachedUpdateJournal) retentionEvidence(seed core.MemcachedUpdateRecord) (*memcachedRetentionReceipt, error) {
	_, expected, err := memcachedRetentionOriginal(seed)
	if err != nil {
		return nil, err
	}
	intent, err := geoStoreRead(j.d.root, "image-retention.intent.json", 4096)
	if errors.Is(err, os.ErrNotExist) {
		if _, e := j.d.root.Lstat("image-retention.receipt.json"); !errors.Is(e, os.ErrNotExist) {
			return nil, errMemcachedRetention
		}
		return nil, nil
	}
	if err != nil || !bytes.Equal(expected, intent) {
		return nil, errMemcachedRetention
	}
	raw, err := geoStoreRead(j.d.root, "image-retention.receipt.json", 4096)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errMemcachedRetention
	}
	var receipt memcachedRetentionReceipt
	if json.Unmarshal(raw, &receipt) != nil || receipt.Format != 1 || receipt.IntentSHA256 != core.Hash(string(intent)) || !dockerPullDigestPattern.MatchString("sha256:"+receipt.ContainerID) {
		return nil, errMemcachedRetention
	}
	canonical, _ := json.Marshal(receipt)
	if !bytes.Equal(canonical, raw) {
		return nil, errMemcachedRetention
	}
	return &receipt, nil
}

// A fresh write-ahead intent permits ONE create. Reopening an intent permits
// only inspection of its deterministic name. A lost reply never gets another
// POST, another name, a start, a force delete or a tag-based rollback.
func (l *memcachedUpdateJournalLease) retainOriginalImage(ctx context.Context, call memcachedRetentionCall, beforeEffect func(context.Context) error) (string, error) {
	if ctx == nil || ctx.Err() != nil || call == nil || beforeEffect == nil || !l.current() {
		return "", errMemcachedRetention
	}
	head, err := l.j.read()
	if err != nil || head.Phase != "prepared" {
		return "", errMemcachedRetention
	}
	in, intentRaw, err := memcachedRetentionOriginal(head)
	if err != nil {
		return "", err
	}
	receipt, err := l.j.retentionEvidence(head)
	if err != nil {
		return "", err
	}
	_, intentErr := l.j.d.root.Lstat("image-retention.intent.json")
	fresh := errors.Is(intentErr, os.ErrNotExist)
	if intentErr != nil && !fresh {
		return "", errMemcachedRetention
	}
	path := "/containers/" + url.PathEscape(in.Name) + "/json"
	status, raw, err := call(ctx, http.MethodGet, path, nil)
	if err != nil {
		return "", errMemcachedRetention
	}
	if fresh {
		if status != 404 || receipt != nil || beforeEffect(ctx) != nil || !l.current() {
			return "", errMemcachedRetention
		}
		if ruleFeedStoreWrite(l.j.d.root, "image-retention.intent.json", intentRaw, 0600) != nil || ruleFeedStoreSync(l.j.d.root) != nil {
			return "", errMemcachedRetention
		}
		if beforeEffect(ctx) != nil || !l.current() {
			return "", errMemcachedRetention
		}
		// Deliberately do not infer non-creation from any POST error/status.
		// The same original name is inspected exactly once, never resubmitted.
		_, _, _ = call(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(in.Name), memcachedRetentionPayload(in, intentRaw))
		status, raw, err = call(ctx, http.MethodGet, path, nil)
	}
	if err != nil || status != 200 || ctx.Err() != nil || !l.current() {
		return "", errMemcachedRetention
	}
	expected := ""
	if receipt != nil {
		expected = receipt.ContainerID
	}
	id, err := memcachedRetentionInspect(raw, in, intentRaw, expected)
	if err != nil {
		return "", err
	}
	if receipt == nil {
		value := memcachedRetentionReceipt{1, core.Hash(string(intentRaw)), id}
		body, _ := json.Marshal(value)
		if ruleFeedStoreWrite(l.j.d.root, "image-retention.receipt.json", body, 0600) != nil || ruleFeedStoreSync(l.j.d.root) != nil {
			return "", errMemcachedRetention
		}
	}
	actual, err := l.j.retentionEvidence(head)
	if err != nil || actual == nil || actual.ContainerID != id || !l.current() {
		return "", errMemcachedRetention
	}
	return id, nil
}
