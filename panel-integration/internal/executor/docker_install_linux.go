//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func dockerInstallCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive"}
	out := &boundedBuffer{max: 128 * 1024}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.WaitDelay = 3 * time.Second
	if e := cmd.Run(); e != nil {
		return out.String(), fmt.Errorf("%s: %w: %s", filepath.Base(name), e, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

const dockerBookwormKeyFingerprint = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"

func setupDockerBookwormRepository(ctx context.Context) error {
	const keyPath = "/etc/apt/keyrings/panel-docker.asc"
	const sourcePath = "/etc/apt/sources.list.d/panel-docker.sources"
	const source = "Types: deb\nURIs: https://download.docker.com/linux/debian\nSuites: bookworm\nComponents: stable\nArchitectures: amd64\nSigned-By: " + keyPath + "\n"
	if runtime.GOARCH != "amd64" {
		return errors.New("Debian 12 Docker 固定清单目前仅验收 amd64")
	}
	if e := os.MkdirAll(filepath.Dir(keyPath), 0755); e != nil {
		return e
	}
	key, e := os.CreateTemp(filepath.Dir(keyPath), ".panel-docker-key-*")
	if e != nil {
		return e
	}
	defer os.Remove(key.Name())
	key.Close()
	gpgHome, e := os.MkdirTemp("", "panel-docker-gpg-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(gpgHome)
	if _, e = dockerInstallCommand(ctx, "/usr/bin/curl", "--fail", "--silent", "--show-error", "--location", "--max-time", "30", "--output", key.Name(), "https://download.docker.com/linux/debian/gpg"); e != nil {
		return e
	}
	info, e := dockerInstallCommand(ctx, "/usr/bin/gpg", "--homedir", gpgHome, "--batch", "--with-colons", "--show-keys", key.Name())
	if e != nil {
		return e
	}
	primary := ""
	publicKeys := 0
	for _, line := range strings.Split(info, "\n") {
		fields := strings.Split(line, ":")
		if fields[0] == "pub" {
			publicKeys++
		}
		if len(fields) > 9 && fields[0] == "fpr" && primary == "" {
			primary = fields[9]
		}
	}
	if primary != dockerBookwormKeyFingerprint || publicKeys != 1 {
		return errors.New("Docker 官方仓库签名密钥指纹与审核值不符")
	}
	contents, e := os.ReadFile(key.Name())
	if e != nil {
		return e
	}
	if len(contents) == 0 || len(contents) > 16*1024 {
		return errors.New("Docker 官方仓库签名密钥大小无效")
	}
	if existing, readErr := os.ReadFile(keyPath); readErr == nil && string(existing) != string(contents) {
		return errors.New("现有 Docker 仓库密钥与审核值不同，拒绝覆盖")
	} else if readErr != nil && !os.IsNotExist(readErr) {
		return readErr
	}
	if existing, readErr := os.ReadFile(sourcePath); readErr == nil && string(existing) != source {
		return errors.New("现有 Docker 软件源配置不同，拒绝覆盖")
	} else if readErr != nil && !os.IsNotExist(readErr) {
		return readErr
	}
	if e = atomicWrite(keyPath, contents, 0644); e != nil {
		return e
	}
	return atomicWrite(sourcePath, []byte(source), 0644)
}

func installedDebianPackageVersion(ctx context.Context, name string) (string, error) {
	cmd := exec.CommandContext(ctx, "/usr/bin/dpkg-query", "-W", "-f=${Status} ${Version}", name)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	out, e := cmd.CombinedOutput()
	if e != nil {
		var exit *exec.ExitError
		if errors.As(e, &exit) && exit.ExitCode() == 1 && strings.Contains(string(out), "no packages found matching") {
			return "", nil
		}
		return "", fmt.Errorf("查询已安装的 %s 失败: %w", name, e)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 4 && strings.Join(fields[:3], " ") == "install ok installed" {
		return fields[3], nil
	}
	return "", nil
}

func checkDockerBookwormPackages(ctx context.Context, spec runtimecatalog.DockerInstallSpec) error {
	for _, name := range []string{"docker.io", "docker-compose", "docker-doc", "docker-buildx", "podman-docker", "containerd", "runc"} {
		installed, e := installedDebianPackageVersion(ctx, name)
		if e != nil {
			return e
		}
		if installed != "" {
			return fmt.Errorf("已存在 %s；请先检查现有容器与数据，再决定迁移", name)
		}
	}
	for _, item := range spec.Packages {
		name, version, _ := strings.Cut(item, "=")
		installed, e := installedDebianPackageVersion(ctx, name)
		if e != nil {
			return e
		}
		if installed != "" && installed != version {
			return fmt.Errorf("已存在不同版本的 %s；拒绝自动升级或降级", name)
		}
	}
	return nil
}

func installDocker(ctx context.Context, r runtimecatalog.Release, id string, add func(string) error) error {
	spec, available := runtimecatalog.DockerSpecOn(runtimecatalog.HostDebianMajor())
	if !available || r.ID != spec.ReleaseID {
		return errors.New("Docker 固定软件包清单无效")
	}
	if spec.ExternalRepo {
		if e := checkDockerBookwormPackages(ctx, spec); e != nil {
			return e
		}
		if e := add("校验 Docker 官方签名密钥并配置 Debian 12 软件源"); e != nil {
			return e
		}
		if e := setupDockerBookwormRepository(ctx); e != nil {
			return e
		}
	}
	if e := add("更新 Debian 签名软件包索引"); e != nil {
		return e
	}
	if _, e := dockerInstallCommand(ctx, "/usr/bin/apt-get", "update"); e != nil {
		return e
	}
	if e := add("安装固定版本 Docker Engine 与 Compose 插件"); e != nil {
		return e
	}
	args := append([]string{"install", "-y", "--no-install-recommends"}, spec.Packages...)
	if _, e := dockerInstallCommand(ctx, "/usr/bin/apt-get", args...); e != nil {
		return e
	}
	for _, item := range spec.Packages {
		name, expected, _ := strings.Cut(item, "=")
		actual, err := installedDebianPackageVersion(ctx, name)
		if err != nil || actual != expected {
			return fmt.Errorf("Docker 软件包 %s 精确版本核对失败: %s: %v", name, actual, err)
		}
	}
	if _, e := RunCommand(ctx, "/usr/bin/systemctl", "enable", "--now", "docker.service"); e != nil {
		return e
	}
	engine, e := RunCommand(ctx, "/usr/bin/docker", "version", "--format", "{{.Server.Version}}")
	if e != nil || strings.TrimSpace(engine) != spec.EngineVersion {
		return fmt.Errorf("Docker Engine 版本核对失败: %s: %v", strings.TrimSpace(engine), e)
	}
	compose, e := RunCommand(ctx, "/usr/bin/docker", "compose", "version", "--short")
	if e != nil || strings.TrimSpace(compose) != spec.ComposeVersion {
		return fmt.Errorf("Docker Compose 版本核对失败: %s: %v", strings.TrimSpace(compose), e)
	}
	prefix := r.Prefix()
	if e = os.MkdirAll(prefix, 0755); e != nil {
		return e
	}
	manifest := RuntimeManifest{Release: r, Architecture: runtime.GOARCH, InstalledAt: core.Now(), Extensions: []string{"compose-" + strings.TrimSpace(compose)}, Configure: append([]string(nil), spec.Packages...)}
	b, _ := json.MarshalIndent(manifest, "", "  ")
	if e = atomicWrite(filepath.Join(prefix, ".panel-runtime.json"), b, 0644); e != nil {
		return e
	}
	return add("Docker Engine、Compose、daemon 与精确软件包版本核对通过")
}
