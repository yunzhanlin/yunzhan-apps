//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
)

//go:embed assets/nfs-rpc-isolation.c
var nfsRPCIsolation []byte

type nfsAPTPackage struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	Depends      string `json:"depends"`
}
type nfsRuntimeSelection struct {
	Format             int               `json:"format"`
	Prefix             string            `json:"prefix"`
	Platform           string            `json:"platform"`
	Architecture       string            `json:"architecture"`
	MainLibrary        string            `json:"main_library"`
	IsolationSourceSHA string            `json:"isolation_source_sha256"`
	Packages           []nfsAPTPackage   `json:"packages"`
	Files              map[string]string `json:"files"`
	Binary             string            `json:"-"`
	LibraryDir         string            `json:"-"`
	Shim               string            `json:"-"`
}

var nfsAPTVersion = regexp.MustCompile(`^[0-9][A-Za-z0-9.+:~_-]{0,127}$`)
var nfsLibraryName = regexp.MustCompile(`^libganesha_nfsd\.so(\.[0-9]+)*$`)
var nfsNativePrefix = regexp.MustCompile(`^apt-[a-f0-9]{16}$`)
var nfsDependencyName = regexp.MustCompile(`^(libntirpc[0-9.]+(t64)?|liburcu[0-9]+(t64)?)$`)

func nfsAllowedDependencies(raw string) ([]string, error) {
	known := map[string]bool{"libacl1": true, "libblkid1": true, "libc6": true, "libcap2": true, "libcom-err2": true, "libdbus-1-3": true, "libgssapi-krb5-2": true, "libkrb5-3": true, "libnfsidmap1": true, "libuuid1": true, "libwbclient0": true, "libgcc-s1": true, "libstdc++6": true, "librados2": true, "libjemalloc2": true}
	seen := map[string]bool{}
	for _, entry := range strings.Split(raw, ",") {
		parts := strings.Fields(strings.TrimSpace(entry))
		if len(parts) == 0 || strings.Contains(entry, "|") {
			return nil, errors.New("NFS APT 依赖结构未经审核")
		}
		name := parts[0]
		if name == "nfs-common" || name == "rpcbind" || name == "dbus" {
			continue
		}
		if name == "nfs-ganesha" {
			continue
		} // The VFS package's parent is privately extracted.
		if !known[name] && !nfsDependencyName.MatchString(name) {
			return nil, fmt.Errorf("未审核的 NFS 系统库依赖：%s", name)
		}
		seen[name] = true
	}
	out := []string{}
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}
func parseNFSAPTMetadata(name, version, arch, data string) (nfsAPTPackage, error) {
	var result nfsAPTPackage
	if (name != "nfs-ganesha" && name != "nfs-ganesha-vfs") || !nfsAPTVersion.MatchString(version) || (arch != "amd64" && arch != "arm64") {
		return result, errors.New("NFS APT 包身份无效")
	}
	for _, paragraph := range strings.Split(strings.TrimSpace(data), "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(paragraph, "\n") {
			if line == "" || line[0] == ' ' || line[0] == '\t' {
				continue
			}
			if key, value, ok := strings.Cut(line, ":"); ok {
				fields[key] = strings.TrimSpace(value)
			}
		}
		if fields["Package"] != name || fields["Version"] != version || fields["Architecture"] != arch {
			continue
		}
		size, e := strconv.ParseInt(fields["Size"], 10, 64)
		if e != nil || size < 1024 || size > 64<<20 || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(fields["SHA256"]) || fields["Depends"] == "" {
			return result, errors.New("APT 缺少有效完整摘要、大小或依赖记录")
		}
		next := nfsAPTPackage{name, version, arch, fields["SHA256"], size, fields["Depends"]}
		if result.Name != "" && result != next {
			return result, errors.New("同版本 NFS APT 元数据不一致")
		}
		result = next
	}
	if result.Name == "" {
		return result, errors.New("未找到当前候选版本的已认证 NFS APT 元数据")
	}
	_, e := nfsAllowedDependencies(result.Depends)
	return result, e
}
func nfsFileDigest(path string, limit int64) (string, error) {
	if e := ownedRuntimePath(path, false); e != nil {
		return "", e
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return "", e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > limit || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return "", errors.New("NFS 程序或许可文件身份/大小无效")
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, limit+1))
	if e != nil || n != info.Size() {
		return "", errors.New("NFS 文件摘要读取不完整")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func validateNFSELF(path, arch string) error {
	f, e := elf.Open(path)
	if e != nil {
		return errors.New("NFS 原生文件不是有效 ELF")
	}
	defer f.Close()
	want := elf.EM_AARCH64
	if arch == "amd64" {
		want = elf.EM_X86_64
	}
	if f.Class != elf.ELFCLASS64 || f.Machine != want || f.Data != elf.ELFDATA2LSB {
		return errors.New("NFS 原生程序架构不符")
	}
	return nil
}
func (s *Service) nfsRuntime() (nfsRuntimeSelection, error) {
	var v nfsRuntimeSelection
	b, e := ftpPrivateRead(filepath.Join(s.moduleDir("nfs-manager"), "native-runtime.json"), 32<<10)
	if e != nil {
		return v, e
	}
	if decodeFTPPrivateJSON(b, &v) != nil {
		return v, errors.New("NFS 私有运行时记录损坏")
	}
	return s.validateNFSRuntime(v)
}
func (s *Service) validateNFSRuntime(v nfsRuntimeSelection) (nfsRuntimeSelection, error) {
	if v.Format != 1 || !nfsNativePrefix.MatchString(v.Prefix) || !nfsLibraryName.MatchString(v.MainLibrary) || v.Architecture != runtime.GOARCH || v.Platform != runtimecatalog.HostPlatform() || v.IsolationSourceSHA != core.Hash(string(nfsRPCIsolation)) || len(v.Packages) != 2 || len(v.Files) != 7 {
		return v, errors.New("NFS 私有运行时来源、平台或隔离记录无效")
	}
	for i, name := range []string{"nfs-ganesha", "nfs-ganesha-vfs"} {
		p := v.Packages[i]
		if p.Name != name || p.Architecture != v.Architecture || !nfsAPTVersion.MatchString(p.Version) || len(p.SHA256) != 64 || p.Size < 1024 || p.Size > 64<<20 || p.Version != v.Packages[0].Version {
			return v, errors.New("NFS 原生包来源不一致")
		}
		if _, e := nfsAllowedDependencies(p.Depends); e != nil {
			return v, e
		}
	}
	base := s.systemPath(filepath.Join(appNativeRoot, "nfs-manager", v.Prefix))
	encoded, _ := json.Marshal(v.Packages)
	if v.Prefix != "apt-"+core.Hash(string(encoded) + v.IsolationSourceSHA)[:16] {
		return v, errors.New("NFS 私有目录与包来源不符")
	}
	for _, dir := range []string{s.systemPath(appNativeRoot), s.systemPath(filepath.Join(appNativeRoot, "nfs-manager")), base, filepath.Join(base, "bin"), filepath.Join(base, "lib"), filepath.Join(base, "licenses")} {
		if e := ownedRuntimePath(dir, true); e != nil {
			return v, e
		}
	}
	for _, name := range []string{"bin/ganesha.nfsd", "lib/" + v.MainLibrary, "lib/libfsalvfs.so", "lib/libpanel-nfs-rpc-isolation.so", "licenses/nfs-ganesha.txt", "licenses/nfs-ganesha-vfs.txt", "licenses/cloudstack-nfs-rpc-isolation.c"} {
		path := filepath.Join(base, name)
		digest, e := nfsFileDigest(path, 32<<20)
		if e != nil || v.Files[name] != digest {
			return v, errors.New("NFS 独立原生文件或完整许可通知摘要不符")
		}
		if !strings.HasPrefix(name, "licenses/") {
			if e = validateNFSELF(path, v.Architecture); e != nil {
				return v, e
			}
		}
	}
	v.Binary = filepath.Join(base, "bin/ganesha.nfsd")
	v.LibraryDir = filepath.Join(base, "lib")
	v.Shim = filepath.Join(v.LibraryDir, "libpanel-nfs-rpc-isolation.so")
	return v, nil
}
func nfsCommandIn(ctx context.Context, dir, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "DEBIAN_FRONTEND=noninteractive"}
	out := &boundedBuffer{max: 128 << 10}
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.WaitDelay = time.Second
	if e := cmd.Run(); e != nil {
		return "", fmt.Errorf("NFS 固定命令 %s 失败：%w：%s", filepath.Base(name), e, out.String())
	}
	return out.String(), nil
}
func copyNFSNative(source, target string, mode os.FileMode) error {
	if e := ownedRuntimePath(source, false); e != nil {
		return e
	}
	f, e := os.OpenFile(source, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = os.MkdirAll(filepath.Dir(target), 0755); e != nil {
		return e
	}
	out, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, mode)
	if e != nil {
		return e
	}
	n, e := io.Copy(out, io.LimitReader(f, (32<<20)+1))
	if e == nil && (n == 0 || n > 32<<20) {
		e = errors.New("NFS 原生文件大小无效")
	}
	if e == nil {
		e = out.Sync()
	}
	closeErr := out.Close()
	if e == nil {
		e = closeErr
	}
	return e
}
func installPrivateNFSRuntime(ctx context.Context) error {
	s := New(Config{})
	if _, e := s.nfsRuntime(); e == nil {
		return nil
	}
	if exists(filepath.Join(s.moduleDir("nfs-manager"), "native-runtime.json")) {
		return errors.New("现有 NFS 原生来源校验失败，拒绝静默覆盖")
	}
	if _, e := s.moduleCommand(ctx, 2*time.Minute, "/usr/bin/apt-get", "update"); e != nil {
		return e
	}
	packages := []nfsAPTPackage{}
	for _, name := range []string{"nfs-ganesha", "nfs-ganesha-vfs"} {
		policy, e := s.moduleCommand(ctx, 20*time.Second, "/usr/bin/apt-cache", "policy", name)
		if e != nil {
			return e
		}
		version := ""
		for _, line := range strings.Split(policy, "\n") {
			if parts := strings.Fields(line); len(parts) == 2 && parts[0] == "Candidate:" {
				version = parts[1]
			}
		}
		if !nfsAPTVersion.MatchString(version) {
			return errors.New("当前平台没有经过 APT 认证的 NFS-Ganesha 候选包")
		}
		control, e := s.moduleCommand(ctx, 20*time.Second, "/usr/bin/apt-cache", "show", name+"="+version)
		if e != nil {
			return e
		}
		p, e := parseNFSAPTMetadata(name, version, runtime.GOARCH, control)
		if e != nil {
			return e
		}
		packages = append(packages, p)
	}
	if packages[0].Version != packages[1].Version {
		return errors.New("NFS 主程序与 VFS 候选版本不一致")
	}
	dependencies := map[string]bool{"nfs-common": true, "build-essential": true}
	for _, p := range packages {
		names, e := nfsAllowedDependencies(p.Depends)
		if e != nil {
			return e
		}
		for _, name := range names {
			dependencies[name] = true
		}
	}
	install := []string{}
	for name := range dependencies {
		install = append(install, name)
	}
	sort.Strings(install)
	// No nfs-ganesha package is installed: its maintainer scripts and system
	// service must never execute or replace an existing host NFS server.
	if _, e := s.moduleCommand(ctx, 5*time.Minute, "/usr/bin/apt-get", append([]string{"install", "-y", "--no-install-recommends"}, install...)...); e != nil {
		return e
	}
	base := filepath.Join(appNativeRoot, "nfs-manager")
	if e := os.MkdirAll(base, 0755); e != nil {
		return e
	}
	if e := ownedRuntimePath(base, true); e != nil {
		return e
	}
	work, e := os.MkdirTemp(base, ".install-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work) // Only this uniquely created, validated private stage.
	extracted := filepath.Join(work, "extract")
	if e = os.Mkdir(extracted, 0700); e != nil {
		return e
	}
	for _, p := range packages {
		if _, e = nfsCommandIn(ctx, work, "/usr/bin/apt-get", "download", p.Name+"="+p.Version); e != nil {
			return e
		}
		matches, e := filepath.Glob(filepath.Join(work, p.Name+"_*.deb"))
		if e != nil || len(matches) != 1 {
			return errors.New("NFS APT 下载文件不唯一")
		}
		info, e := os.Stat(matches[0])
		if e != nil || info.Size() != p.Size {
			return errors.New("NFS APT 原始包大小不符")
		}
		digest, e := nfsFileDigest(matches[0], 64<<20)
		if e != nil || digest != p.SHA256 {
			return errors.New("NFS APT 完整包摘要与已认证元数据不符")
		}
		if _, e = nfsCommandIn(ctx, work, "/usr/bin/dpkg-deb", "--extract", matches[0], extracted); e != nil {
			return e
		}
	}
	binary := filepath.Join(extracted, "usr/bin/ganesha.nfsd")
	if e = validateNFSELF(binary, runtime.GOARCH); e != nil {
		return e
	}
	f, e := elf.Open(binary)
	if e != nil {
		return e
	}
	needed, e := f.ImportedLibraries()
	f.Close()
	if e != nil {
		return e
	}
	mainLibrary := ""
	for _, name := range needed {
		if nfsLibraryName.MatchString(name) {
			if mainLibrary != "" {
				return errors.New("NFS 原生主库身份不唯一")
			}
			mainLibrary = name
		}
	}
	if mainLibrary == "" {
		return errors.New("NFS 程序缺少已审核的主库依赖")
	}
	fsal, e := filepath.Glob(filepath.Join(extracted, "usr/lib/*-linux-gnu/ganesha/libfsalvfs.so"))
	if e != nil || len(fsal) != 1 {
		return errors.New("NFS VFS 库不唯一")
	}
	encoded, _ := json.Marshal(packages)
	prefix := "apt-" + core.Hash(string(encoded) + core.Hash(string(nfsRPCIsolation)))[:16]
	target := filepath.Join(base, prefix)
	if exists(target) {
		var saved nfsRuntimeSelection
		b, e := ftpPrivateRead(filepath.Join(target, "runtime-manifest.json"), 32<<10)
		if e != nil || decodeFTPPrivateJSON(b, &saved) != nil {
			return errors.New("NFS 候选已存在但恢复来源缺失；保留，不覆盖")
		}
		if _, e = s.validateNFSRuntime(saved); e != nil {
			return e
		}
		if e = moduleWrite(filepath.Join(s.moduleDir("nfs-manager"), "native-runtime.json"), saved); e != nil {
			return e
		}
		return nil
	}
	stage := filepath.Join(work, "candidate")
	if e = os.Mkdir(stage, 0755); e != nil {
		return e
	}
	files := map[string]string{}
	for _, item := range []struct {
		source, name string
		mode         os.FileMode
	}{{binary, "bin/ganesha.nfsd", 0755}, {filepath.Join(extracted, "usr/lib/ganesha", mainLibrary), "lib/" + mainLibrary, 0644}, {fsal[0], "lib/libfsalvfs.so", 0644}, {filepath.Join(extracted, "usr/share/doc/nfs-ganesha/copyright"), "licenses/nfs-ganesha.txt", 0644}, {filepath.Join(extracted, "usr/share/doc/nfs-ganesha-vfs/copyright"), "licenses/nfs-ganesha-vfs.txt", 0644}} {
		if e = copyNFSNative(item.source, filepath.Join(stage, item.name), item.mode); e != nil {
			return e
		}
		digest, e := nfsFileDigest(filepath.Join(stage, item.name), 32<<20)
		if e != nil {
			return e
		}
		files[item.name] = digest
	}
	source := filepath.Join(work, "nfs-rpc-isolation.c")
	if e = atomicWrite(source, nfsRPCIsolation, 0600); e != nil {
		return e
	}
	shim := filepath.Join(stage, "lib/libpanel-nfs-rpc-isolation.so")
	if _, e = nfsCommandIn(ctx, work, "/usr/bin/cc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror", "-Wl,-z,relro,-z,now", "-o", shim, source); e != nil {
		return e
	}
	if e = os.Chmod(shim, 0644); e != nil {
		return e
	}
	if e = validateNFSELF(shim, runtime.GOARCH); e != nil {
		return e
	}
	files["lib/libpanel-nfs-rpc-isolation.so"], e = nfsFileDigest(shim, 32<<20)
	if e != nil {
		return e
	}
	licensePath := filepath.Join(stage, "licenses/cloudstack-nfs-rpc-isolation.c")
	if e = atomicWrite(licensePath, nfsRPCIsolation, 0644); e != nil {
		return e
	}
	files["licenses/cloudstack-nfs-rpc-isolation.c"], e = nfsFileDigest(licensePath, 32<<20)
	if e != nil {
		return e
	}
	selection := nfsRuntimeSelection{Format: 1, Prefix: prefix, Platform: runtimecatalog.HostPlatform(), Architecture: runtime.GOARCH, MainLibrary: mainLibrary, IsolationSourceSHA: core.Hash(string(nfsRPCIsolation)), Packages: packages, Files: files}
	if e = moduleWrite(filepath.Join(stage, "runtime-manifest.json"), selection); e != nil {
		return e
	}
	if e = os.Rename(stage, target); e != nil {
		return e
	}
	if e = moduleWrite(filepath.Join(s.moduleDir("nfs-manager"), "native-runtime.json"), selection); e != nil {
		return e
	}
	_, e = s.nfsRuntime()
	return e
}
