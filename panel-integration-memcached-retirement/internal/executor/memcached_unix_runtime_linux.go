//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

type memcachedUnixDockerRead func(context.Context, string) ([]byte, error)

// This verifies the daemon's actual closed contract, not just YAML or a
// 'healthy' label. The kernel cgroup/process/socket gates remain independent.
// There is no internal bridge or published loopback port to fall back to.
func memcachedUnixRuntime(ctx context.Context, raw []byte, m composeMetadata, site string, account memcachedUnixAccount, read memcachedUnixDockerRead) (string, int, string, error) {
	directory, e := core.MemcachedUnixDirectory(m.ID, site)
	if e != nil {
		return "", 0, "", errMemcachedUnix
	}
	return memcachedUnixRuntimeAt(ctx, raw, m, site, directory, account, read)
}

// The explicit directory seam is for an independently sealed private native
// fixture. No production HTTP/CLI/config chooses it: the wrapper derives the
// sole production directory from the original project and website identity.
func memcachedUnixRuntimeAt(ctx context.Context, raw []byte, m composeMetadata, site, directory string, account memcachedUnixAccount, read memcachedUnixDockerRead) (string, int, string, error) {
	return memcachedUnixRuntimeStateAt(ctx, raw, m, site, directory, account, read, true)
}

// A stopped service is not a ready service. Its CURRENT raw daemon state must
// say Running=false AND Pid=0 while retaining the same closed security/image
// contract. Never synthesize a live PID/state or perform a protocol exchange.
func memcachedUnixStoppedRuntime(ctx context.Context, raw []byte, m composeMetadata, site string, account memcachedUnixAccount, read memcachedUnixDockerRead) (string, error) {
	directory, err := core.MemcachedUnixDirectory(m.ID, site)
	if err != nil {
		return "", err
	}
	id, pid, _, err := memcachedUnixRuntimeStateAt(ctx, raw, m, site, directory, account, read, false)
	if err != nil || pid != 0 {
		return "", errMemcachedUnix
	}
	return id, nil
}

func memcachedUnixRuntimeStateAt(ctx context.Context, raw []byte, m composeMetadata, site, directory string, account memcachedUnixAccount, read memcachedUnixDockerRead, running bool) (string, int, string, error) {
	refuse := func() (string, int, string, error) { return "", 0, "", errMemcachedUnix }
	var v memcachedUpdateInspection
	var limits struct {
		State      struct{ Pid int }
		HostConfig struct {
			Memory, MemorySwap, NanoCpus, PidsLimit *int64
			CpuPeriod, CpuQuota                     int64
			CpusetCpus                              string
			Ulimits                                 []struct {
				Name       string
				Soft, Hard int64
			}
			LogConfig struct {
				Type   string
				Config map[string]string
			}
		}
	}
	if ctx == nil || ctx.Err() != nil || read == nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "/" || account.UID == 0 || account.GID == 0 || !core.ValidID(m.ID) || m.Engine != "panel_"+m.ID[:12] || m.TemplateID != "memcached-cache" || m.HostPort != 0 || m.Services != 1 || site != "" && !core.ValidID(site) || memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &v) != nil || json.Unmarshal(raw, &limits) != nil || len(v.ID) != 64 || !dockerObjectPattern.MatchString(v.ID) || v.Config == nil || v.State == nil || v.State.Running == nil || *v.State.Running != running || v.State.Health == nil || v.HostConfig == nil || v.NetworkSettings == nil || running && limits.State.Pid < 2 || !running && limits.State.Pid != 0 {
		return refuse()
	}
	c, h, n, l := v.Config, v.HostConfig, v.NetworkSettings, limits.HostConfig
	if _, present := c.Labels["io.yunzhan.memcached.site-id"]; !present {
		return refuse()
	}
	command := []string{"-s", "/run/memcached/cache.sock", "-a", "666", "-m", "128", "-I", "4m", "-U", "0", "-c", "256", "-t", "2"}
	if c.Image != appcatalog.MemcachedDigestImage || c.User != fmt.Sprintf("%d:%d", account.UID, account.GID) || !slices.Equal(c.Entrypoint, []string{"memcached"}) || !slices.Equal(c.Cmd, command) || c.Labels["com.docker.compose.project"] != m.Engine || c.Labels["com.docker.compose.service"] != "memcached" || c.Labels["com.docker.compose.oneoff"] != "False" || c.Labels["io.yunzhan.memcached.site-id"] != site || h.Privileged == nil || *h.Privileged || h.ReadonlyRootfs == nil || !*h.ReadonlyRootfs || h.PidMode != "" || h.IpcMode != "private" || h.UTSMode != "" || h.UsernsMode != "" || h.NetworkMode != "none" || !slices.Equal(h.CapDrop, []string{"ALL"}) || !slices.Equal(h.SecurityOpt, []string{"no-new-privileges:true"}) || len(h.CapAdd)+len(h.Binds)+len(h.VolumesFrom)+len(h.DeviceCgroupRules)+len(h.Devices)+len(h.Tmpfs)+len(h.Sysctls)+len(h.PortBindings) != 0 || len(h.Mounts) != 1 || len(v.Mounts) != 1 || h.RestartPolicy.Name != "unless-stopped" || h.RestartPolicy.MaximumRetryCount != 0 {
		return refuse()
	}
	if l.Memory == nil || *l.Memory != 192<<20 || l.MemorySwap == nil || *l.MemorySwap != 192<<20 || l.NanoCpus == nil || *l.NanoCpus != 1_000_000_000 || l.PidsLimit == nil || *l.PidsLimit != 32 || l.CpuPeriod != 0 || l.CpuQuota != 0 || l.CpusetCpus != "" || len(l.Ulimits) != 1 || l.Ulimits[0].Name != "nofile" || l.Ulimits[0].Soft != 1024 || l.Ulimits[0].Hard != 1024 || l.LogConfig.Type != "json-file" || len(l.LogConfig.Config) != 2 || l.LogConfig.Config["max-size"] != "10m" || l.LogConfig.Config["max-file"] != "3" {
		return refuse()
	}
	var desired struct {
		Type, Source, Target string
		ReadOnly             bool
		BindOptions          *struct {
			Propagation                    string
			NonRecursive, CreateMountpoint bool
		}
	}
	var mounted struct {
		Type, Source, Destination, Propagation string
		RW                                     *bool
	}
	if json.Unmarshal(h.Mounts[0], &desired) != nil || json.Unmarshal(v.Mounts[0], &mounted) != nil || desired.Type != "bind" || desired.Source != directory || desired.Target != "/run/memcached" || desired.ReadOnly || desired.BindOptions == nil || desired.BindOptions.NonRecursive || desired.BindOptions.CreateMountpoint || desired.BindOptions.Propagation != "" && desired.BindOptions.Propagation != "rprivate" || mounted.Type != "bind" || mounted.Source != directory || mounted.Destination != "/run/memcached" || mounted.Propagation != "rprivate" || mounted.RW == nil || !*mounted.RW {
		return refuse()
	}
	// Some daemon versions retain the image's EXPOSE key with a null value.
	// That is not a binding. Any actual TCP/UDP publication is a refusal.
	for key, ports := range n.Ports {
		if key != "11211/tcp" || len(ports) != 0 {
			return refuse()
		}
	}
	var network struct{ IPAddress, GlobalIPv6Address, Gateway, IPv6Gateway string }
	if len(n.Networks) != 1 || n.Networks["none"] == nil || json.Unmarshal(n.Networks["none"], &network) != nil || network.IPAddress != "" || network.GlobalIPv6Address != "" || network.Gateway != "" || network.IPv6Gateway != "" {
		return refuse()
	}
	health := c.Healthcheck
	if health == nil || !slices.Equal(health.Test, []string{"CMD-SHELL", core.MemcachedUnixLiveness}) || health.Interval != int64(10*time.Second) || health.Timeout != int64(3*time.Second) || health.StartPeriod != 0 || health.Retries != 12 || running && v.State.Health.Status != "starting" && v.State.Health.Status != "healthy" || !running && v.State.Health.Status != "starting" && v.State.Health.Status != "healthy" && v.State.Health.Status != "unhealthy" {
		return refuse()
	}
	if len(v.Image) != 71 || !strings.HasPrefix(v.Image, "sha256:") || !dockerObjectPattern.MatchString(v.Image[7:]) {
		return refuse()
	}
	imageRaw, e := read(ctx, "/images/"+url.PathEscape(v.Image)+"/json")
	var image struct {
		ID, OS, Architecture string
		RepoDigests          []string
		Config               *struct {
			User, WorkingDir string
			Env              []string
		}
	}
	_, digest, _ := strings.Cut(appcatalog.MemcachedDigestImage, "@")
	if e != nil || memcachedDaemonJSON(imageRaw) != nil || json.Unmarshal(imageRaw, &image) != nil || image.ID != v.Image || image.OS != "linux" || image.Architecture != runtime.GOARCH || image.Config == nil || image.Config.User != "memcache" || image.Config.WorkingDir != c.WorkingDir || !slices.Equal(image.Config.Env, c.Env) || !slices.Contains(image.RepoDigests, "memcached@"+digest) && !slices.Contains(image.RepoDigests, "docker.io/library/memcached@"+digest) || ctx.Err() != nil {
		return refuse()
	}
	return v.ID, limits.State.Pid, v.State.Health.Status, nil
}
