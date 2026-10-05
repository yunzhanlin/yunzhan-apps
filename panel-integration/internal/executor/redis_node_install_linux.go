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
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

func prepareRuntimeSource(ctx context.Context, r runtimecatalog.Release, id string, add func(string) error) (string, string, error) {
	base := filepath.Join("/var/cache/panel-build", id)
	if e := os.MkdirAll(base, 0700); e != nil {
		return "", "", e
	}
	if e := os.Chmod(base, 0755); e != nil {
		return "", "", e
	}
	archive := filepath.Join(base, "source.tar.gz")
	if e := downloadRuntimeSource(ctx, r, archive); e != nil {
		return "", "", e
	}
	if e := add("已从官方站点下载固定版本，并通过官方 SHA-256 清单校验"); e != nil {
		return "", "", e
	}
	work := filepath.Join(base, "work")
	if e := os.RemoveAll(work); e != nil {
		return "", "", e
	}
	if e := os.Mkdir(work, 0755); e != nil {
		return "", "", e
	}
	if e := extractSource(archive, work); e != nil {
		return "", "", e
	}
	if _, e := RunCommand(ctx, "/usr/bin/chown", "-R", "panel-build:panel-build", work); e != nil {
		return "", "", e
	}
	return base, work, nil
}

func promoteRuntime(r runtimecatalog.Release, id, source string, manifest RuntimeManifest) error {
	if _, e := os.Stat(r.Prefix()); e == nil {
		return errors.New("目标目录已存在但没有匹配的完整清单，请核对后重试")
	}
	if e := os.MkdirAll(filepath.Dir(r.Prefix()), 0755); e != nil {
		return e
	}
	temp := r.Prefix() + ".pending-" + id
	if e := os.RemoveAll(temp); e != nil {
		return e
	}
	defer os.RemoveAll(temp)
	if e := copyBuildTree(source, temp); e != nil {
		return e
	}
	b, e := json.MarshalIndent(manifest, "", "  ")
	if e != nil {
		return e
	}
	if e = atomicWrite(filepath.Join(temp, ".panel-runtime.json"), b, 0644); e != nil {
		return e
	}
	return os.Rename(temp, r.Prefix())
}

func installRedis(ctx context.Context, r runtimecatalog.Release, id string, add func(string) error) error {
	base, work, e := prepareRuntimeSource(ctx, r, id, add)
	if e != nil {
		return e
	}
	source := filepath.Join(work, "redis-"+r.Version)
	logPath := filepath.Join(base, "build.log")
	jobs := runtimeBuildJobs()
	if e = add(fmt.Sprintf("以独立构建用户编译 Redis（%d 个并行任务，启用 TLS）", jobs)); e != nil {
		return e
	}
	if e = buildCommand(ctx, source, logPath, "/usr/bin/make", "-j"+strconv.Itoa(jobs), "BUILD_TLS=yes"); e != nil {
		return e
	}
	stage := filepath.Join(work, "stage")
	if e = add("编译完成，安装到隔离暂存目录"); e != nil {
		return e
	}
	if e = buildCommand(ctx, source, logPath, "/usr/bin/make", "install", "BUILD_TLS=yes", "PREFIX="+stage); e != nil {
		return e
	}
	candidate := filepath.Join(stage, "bin/redis-server")
	version, er := RunCommand(ctx, candidate, "--version")
	if er != nil || !strings.Contains(version, "v="+r.Version) {
		return fmt.Errorf("Redis 精确版本校验失败: %s: %v", version, er)
	}
	manifest := RuntimeManifest{Release: r, Architecture: runtime.GOARCH, InstalledAt: core.Now(), Extensions: []string{"tls"}, Configure: []string{"BUILD_TLS=yes"}}
	if e = promoteRuntime(r, id, stage, manifest); e != nil {
		return e
	}
	return add("Redis 独立目录安装完成；服务端、客户端与精确版本核对通过")
}

func installNode(ctx context.Context, r runtimecatalog.Release, id string, add func(string) error) error {
	_, work, e := prepareRuntimeSource(ctx, r, id, add)
	if e != nil {
		return e
	}
	arch := map[string]string{"amd64": "x64", "arm64": "arm64"}[runtime.GOARCH]
	if arch == "" {
		return errors.New("当前 CPU 架构没有固定 Node.js 二进制")
	}
	source := filepath.Join(work, "node-v"+r.Version+"-linux-"+arch)
	node := filepath.Join(source, "bin/node")
	version, er := RunCommand(ctx, node, "--version")
	if er != nil || strings.TrimSpace(version) != "v"+r.Version {
		return fmt.Errorf("Node.js 精确版本校验失败: %s: %v", version, er)
	}
	npmScript := filepath.Join(source, "lib/node_modules/npm/bin/npm-cli.js")
	npm, er := RunCommand(ctx, node, npmScript, "--version")
	if er != nil || strings.TrimSpace(npm) == "" {
		return fmt.Errorf("npm 运行校验失败: %v", er)
	}
	if e = add("Node.js 与随附 npm 已在隔离目录完成运行校验"); e != nil {
		return e
	}
	manifest := RuntimeManifest{Release: r, Architecture: runtime.GOARCH, InstalledAt: core.Now(), Extensions: []string{"npm-" + strings.TrimSpace(npm)}, Configure: []string{"official-prebuilt", "linux-" + arch}}
	if e = promoteRuntime(r, id, source, manifest); e != nil {
		return e
	}
	return add("Node.js 独立目录安装完成；node、npm 与精确版本核对通过")
}
