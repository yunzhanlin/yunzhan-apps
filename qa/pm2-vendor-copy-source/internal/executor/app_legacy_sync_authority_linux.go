//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"local/panel/internal/core"
)

var errLegacySyncAuthority = errors.New("隔离 PHP 项目、固定镜像、数据卷、网络或运行配置身份无法核对；未执行文件同步，请先核对原项目")

type legacySyncAuthority struct {
	directory                *composeUpdateDirectory
	metadata                 composeMetadata
	metadataRaw, source      []byte
	metadataInfo, sourceInfo os.FileInfo
	container, runtimeSHA    string
}

func decodeLegacySyncMetadata(raw []byte, id string) (composeMetadata, error) {
	var m composeMetadata
	f, e := dockerPullJSONObject(raw)
	if e != nil || memcachedDaemonJSON(raw) != nil || len(f) != 7 || memcachedDaemonFields(f, "id", "name", "engine_name", "template_id", "host_port", "services", "created_at") != nil || json.Unmarshal(raw, &m) != nil ||
		!core.ValidID(id) || m.ID != id || m.Engine != "panel_"+id[:12] || !dockerResourceNamePattern.MatchString(m.Name) || m.Services != 2 || m.HostPort < 1024 || m.HostPort > 65535 {
		return m, errLegacySyncAuthority
	}
	if _, ok := core.LegacyPHPImages[m.TemplateID]; !ok {
		return m, errLegacySyncAuthority
	}
	if _, e := time.Parse(time.RFC3339, m.CreatedAt); e != nil {
		return m, errLegacySyncAuthority
	}
	return m, nil
}

// Production passes only dockerProjects. The separate base is a private
// trusted-root fixture seam, never an HTTP path or environment override.
func openLegacySyncAuthority(base, id string) (*legacySyncAuthority, error) {
	if runtime.GOARCH != "amd64" {
		return nil, errLegacySyncAuthority
	}
	d, err := openComposeUpdateDirectory(base, id)
	if err != nil {
		return nil, errLegacySyncAuthority
	}
	a := &legacySyncAuthority{directory: d}
	fail := func() (*legacySyncAuthority, error) { d.Close(); return nil, errLegacySyncAuthority }
	if a.metadataRaw, a.metadataInfo, err = d.read("metadata.json", 16<<10); err != nil {
		return fail()
	}
	if a.source, a.sourceInfo, err = d.read("compose.yaml", 48<<10); err != nil {
		return fail()
	}
	if a.metadata, err = decodeLegacySyncMetadata(a.metadataRaw, id); err != nil {
		return fail()
	}
	expected, err := core.LegacyPHPTemplate(a.metadata.TemplateID, a.metadata.HostPort)
	if err != nil || expected == "" || !bytes.Equal(a.source, []byte(expected)) || !a.current() {
		return fail()
	}
	return a, nil
}

func (a *legacySyncAuthority) current() bool {
	if a == nil || a.directory == nil || !a.directory.current() {
		return false
	}
	m, mi, me := a.directory.read("metadata.json", 16<<10)
	s, si, se := a.directory.read("compose.yaml", 48<<10)
	return me == nil && se == nil && sameComposeUpdateFile(a.metadataInfo, mi) && sameComposeUpdateFile(a.sourceInfo, si) && bytes.Equal(m, a.metadataRaw) && bytes.Equal(s, a.source)
}

func legacySyncDockerRead(ctx context.Context, path string, out any) error {
	raw, err := dockerRequest(ctx, http.MethodGet, path, nil, nil, 256<<10)
	if err != nil || memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, out) != nil {
		return errLegacySyncAuthority
	}
	return nil
}

// Actual daemon identity, not just matching user-controllable Compose labels.
// All reads are bounded, no image pull/repair/start/stop or exec occurs here.
func legacySyncRuntime(ctx context.Context, m composeMetadata, read composeUpdateDockerRead) (string, string, error) {
	fail := func() (string, string, error) { return "", "", errLegacySyncAuthority }
	if ctx == nil || ctx.Err() != nil || read == nil {
		return fail()
	}
	filter, _ := json.Marshal(map[string][]string{"label": {"com.docker.compose.project=" + m.Engine}})
	var rows []struct {
		ID     string            `json:"Id"`
		Labels map[string]string `json:"Labels"`
	}
	if read(ctx, "/containers/json?all=1&filters="+url.QueryEscape(string(filter)), &rows) != nil || len(rows) != 2 {
		return fail()
	}
	cid := ""
	seen := map[string]bool{}
	for _, row := range rows {
		service := row.Labels["com.docker.compose.service"]
		if len(row.ID) != 64 || !dockerObjectPattern.MatchString(row.ID) || seen[service] || row.Labels["com.docker.compose.project"] != m.Engine || row.Labels["com.docker.compose.oneoff"] != "False" || service != "php" && service != "web" {
			return fail()
		}
		seen[service] = true
		if service == "php" {
			cid = row.ID
		}
	}
	var raw json.RawMessage
	var v memcachedUpdateInspection
	if read(ctx, "/containers/"+cid+"/json", &raw) != nil || memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &v) != nil || v.ID != cid || v.Config == nil || v.HostConfig == nil || v.State == nil || v.State.Running == nil || !*v.State.Running || v.State.Health == nil || v.State.Health.Status != "healthy" || v.NetworkSettings == nil {
		return fail()
	}
	fields, err := dockerPullJSONObject(raw)
	if err != nil || memcachedDaemonFields(fields, "Id", "Image", "Config", "HostConfig", "State", "NetworkSettings", "Mounts") != nil {
		return fail()
	}
	configFields, ce := dockerPullJSONObject(fields["Config"])
	if ce != nil || memcachedDaemonFields(configFields, "Image", "User", "WorkingDir", "Cmd", "Entrypoint", "Env", "Labels", "Healthcheck") != nil {
		return fail()
	}
	hostFields, err := dockerPullJSONObject(fields["HostConfig"])
	if err != nil || memcachedDaemonFields(hostFields, "Privileged", "ReadonlyRootfs", "PidMode", "IpcMode", "UTSMode", "UsernsMode", "NetworkMode", "Memory", "PidsLimit") != nil {
		return fail()
	}
	var limits struct {
		Memory    int64
		PidsLimit *int64
	}
	if json.Unmarshal(fields["HostConfig"], &limits) != nil || limits.Memory != 256<<20 || limits.PidsLimit == nil || *limits.PidsLimit != 96 {
		return fail()
	}
	c, h, n := v.Config, v.HostConfig, v.NetworkSettings
	if c.Image != core.LegacyPHPImages[m.TemplateID] || !slices.Equal(c.Entrypoint, []string{"/bin/sh", "-c"}) || !slices.Equal(c.Cmd, []string{core.LegacyPHPBootstrap}) || c.Labels["com.docker.compose.project"] != m.Engine || c.Labels["com.docker.compose.service"] != "php" || c.Labels["com.docker.compose.oneoff"] != "False" ||
		h.Privileged == nil || *h.Privileged || h.ReadonlyRootfs == nil || !*h.ReadonlyRootfs || h.PidMode != "" || h.IpcMode != "private" || h.UTSMode != "" || h.UsernsMode != "" || h.NetworkMode != m.Engine+"_default" || len(h.CapAdd)+len(h.CapDrop)+len(h.VolumesFrom)+len(h.DeviceCgroupRules)+len(h.Devices)+len(h.Sysctls)+len(h.PortBindings) != 0 ||
		!slices.Equal(h.SecurityOpt, []string{"no-new-privileges:true"}) || len(h.Tmpfs) != 2 || len(n.Networks) != 1 || h.RestartPolicy.Name != "unless-stopped" || h.RestartPolicy.MaximumRetryCount != 0 {
		return fail()
	}
	if _, ok := h.Tmpfs["/tmp"]; !ok {
		return fail()
	}
	if _, ok := h.Tmpfs["/var/run"]; !ok {
		return fail()
	}
	for _, options := range h.Tmpfs {
		if options != "" {
			return fail()
		}
	}
	for _, ports := range n.Ports {
		if len(ports) != 0 {
			return fail()
		}
	}
	if len(v.Image) != 71 || !strings.HasPrefix(v.Image, "sha256:") || !dockerObjectPattern.MatchString(v.Image[7:]) {
		return fail()
	}
	var image struct {
		ID           string `json:"Id"`
		OS           string `json:"Os"`
		Architecture string `json:"Architecture"`
		Config       *struct {
			User       string   `json:"User"`
			WorkingDir string   `json:"WorkingDir"`
			Env        []string `json:"Env"`
		} `json:"Config"`
	}
	if read(ctx, "/images/"+url.PathEscape(c.Image)+"/json", &image) != nil || image.ID != v.Image || image.OS != "linux" || image.Architecture != "amd64" || image.Config == nil || c.User != image.Config.User || c.WorkingDir != image.Config.WorkingDir {
		return fail()
	}
	env := map[string]string{}
	for _, e := range image.Config.Env {
		k, val, ok := strings.Cut(e, "=")
		if !ok || k == "" {
			return fail()
		}
		if _, dup := env[k]; dup {
			return fail()
		}
		env[k] = val
	}
	env["PHP_INI_SCAN_DIR"] = "/tmp/cloudstack-ini"
	if len(c.Env) != len(env) {
		return fail()
	}
	for _, e := range c.Env {
		k, val, ok := strings.Cut(e, "=")
		expected, present := env[k]
		if !ok || !present || expected != val {
			return fail()
		}
		delete(env, k)
	}
	if len(env) != 0 {
		return fail()
	}
	var mounts []struct {
		Type, Name, Source, Destination, Driver, Mode, Propagation string
		RW                                                         *bool
	}
	if json.Unmarshal(fields["Mounts"], &mounts) != nil || len(mounts) != 1 {
		return fail()
	}
	mount := mounts[0]
	volumeName := m.Engine + "_site-data"
	if mount.Type != "volume" || mount.Name != volumeName || mount.Destination != "/var/www/html" || mount.Driver != "local" || mount.RW == nil || !*mount.RW || !filepath.IsAbs(mount.Source) || filepath.Clean(mount.Source) != mount.Source || mount.Propagation != "" {
		return fail()
	}
	if len(h.Binds)+len(h.Mounts) != 1 {
		return fail()
	}
	if len(h.Binds) == 1 && h.Binds[0] != volumeName+":/var/www/html:rw" {
		return fail()
	}
	if len(h.Mounts) == 1 {
		var hm struct {
			Type, Source, Target                     string
			ReadOnly                                 bool
			BindOptions, VolumeOptions, TmpfsOptions json.RawMessage
		}
		if json.Unmarshal(h.Mounts[0], &hm) != nil || hm.Type != "volume" || hm.Source != volumeName || hm.Target != "/var/www/html" || hm.ReadOnly || len(hm.BindOptions) > 0 && string(hm.BindOptions) != "null" || len(hm.TmpfsOptions) > 0 && string(hm.TmpfsOptions) != "null" {
			return fail()
		}
		if len(hm.VolumeOptions) > 0 && string(hm.VolumeOptions) != "null" {
			var options struct {
				NoCopy bool `json:"NoCopy"`
			}
			d := json.NewDecoder(bytes.NewReader(hm.VolumeOptions))
			d.DisallowUnknownFields()
			if d.Decode(&options) != nil {
				return fail()
			}
		}
	}
	var volume struct {
		Name, Driver, Mountpoint, Scope string
		Options                         map[string]string
		Labels                          map[string]string
	}
	if read(ctx, "/volumes/"+url.PathEscape(volumeName), &volume) != nil || volume.Name != volumeName || volume.Driver != "local" || volume.Scope != "local" || volume.Mountpoint != mount.Source || len(volume.Options) != 0 || volume.Labels["com.docker.compose.project"] != m.Engine || volume.Labels["com.docker.compose.volume"] != "site-data" {
		return fail()
	}
	networkRaw, ok := n.Networks[m.Engine+"_default"]
	if !ok {
		return fail()
	}
	var attachment struct{ NetworkID string }
	if json.Unmarshal(networkRaw, &attachment) != nil || len(attachment.NetworkID) != 64 || !dockerObjectPattern.MatchString(attachment.NetworkID) {
		return fail()
	}
	var network struct {
		ID                  string `json:"Id"`
		Name, Driver, Scope string
		Internal            *bool
		Labels              map[string]string
	}
	if read(ctx, "/networks/"+attachment.NetworkID, &network) != nil || network.ID != attachment.NetworkID || network.Name != m.Engine+"_default" || network.Driver != "bridge" || network.Scope != "local" || network.Internal == nil || !*network.Internal || network.Labels["com.docker.compose.project"] != m.Engine || network.Labels["com.docker.compose.network"] != "default" {
		return fail()
	}
	if ctx.Err() != nil {
		return fail()
	}
	// Complete static configuration, not volatile health counters, timestamps or
	// IP assignments. Recomputed before each file, never a cached label verdict.
	fingerprint, err := json.Marshal([]any{fields["Config"], fields["HostConfig"], fields["Mounts"], v.Image, volume, attachment.NetworkID})
	if err != nil {
		return fail()
	}
	return cid, core.Hash(string(fingerprint)), nil
}

func (a *legacySyncAuthority) check(ctx context.Context, read composeUpdateDockerRead) error {
	if !a.current() {
		return errLegacySyncAuthority
	}
	id, digest, err := legacySyncRuntime(ctx, a.metadata, read)
	if err != nil || !a.current() || a.container != "" && (a.container != id || a.runtimeSHA != digest) {
		return errLegacySyncAuthority
	}
	a.container, a.runtimeSHA = id, digest
	return nil
}
