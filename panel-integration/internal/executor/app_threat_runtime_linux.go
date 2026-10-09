//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

type threatIDSRuntime struct {
	Format    int                     `json:"format"`
	Prefix    string                  `json:"prefix"`
	Platform  string                  `json:"platform"`
	Package   threatIDSPackage        `json:"package"`
	Files     map[string]string       `json:"files"`
	Source    *threatIDSPackageSource `json:"source,omitempty"`
	Libraries *threatIDSLibraryBundle `json:"private_libraries,omitempty"`
	Binary    string                  `json:"-"`
}

type threatIDSPackageSource struct {
	URL         string `json:"repository_url"`
	Suite       string `json:"suite"`
	KeySHA      string `json:"key_sha256"`
	CatalogSHA  string `json:"signed_catalog_sha256"`
	MetadataSHA string `json:"package_metadata_sha256"`
}

var threatIDSPrefix = regexp.MustCompile(`^apt-[a-f0-9]{16}$`)

func threatIDSPackagePrefix(p threatIDSPackage) string {
	return threatIDSPackagePrefixPortable(p)
}
func (s *Service) threatIDSRuntime() (threatIDSRuntime, error) {
	var v threatIDSRuntime
	b, err := ftpPrivateRead(filepath.Join(s.moduleDir("network-threat-detection"), "native-runtime.json"), 32<<10)
	if err != nil {
		return v, err
	}
	if decodeThreatIDSPrivateJSON(b, &v) != nil {
		return v, errors.New("IDS 私有来源记录损坏；不覆盖现有运行时")
	}
	return s.validateThreatIDSRuntime(v)
}
func (s *Service) validateThreatIDSRuntime(v threatIDSRuntime) (threatIDSRuntime, error) {
	p := v.Package
	if p.Architecture != runtime.GOARCH || v.Platform != runtimecatalog.HostPlatform() {
		return v, errors.New("IDS 运行时来源、版本、架构或文件集合不符")
	}
	if err := validateThreatIDSRuntimeHeader(v); err != nil {
		return v, err
	}
	base := s.systemPath(filepath.Join(appNativeRoot, "network-threat-detection", v.Prefix))
	if threatIDSTrustedParents(base, false) != nil || threatIDSTrustedParents(s.moduleDir("network-threat-detection"), false) != nil {
		return v, errors.New("IDS 来源或程序树父目录不可信")
	}
	dirs := []string{s.systemPath(appNativeRoot), s.systemPath(filepath.Join(appNativeRoot, "network-threat-detection")), base, filepath.Join(base, "bin"), filepath.Join(base, "licenses")}
	if v.Format == 3 {
		dirs = append(dirs, filepath.Join(base, "libraries"))
	}
	for _, dir := range dirs {
		if ownedRuntimePath(dir, true) != nil {
			return v, errors.New("IDS 程序父目录身份或权限无效")
		}
	}
	for name := range v.Files {
		path := filepath.Join(base, name)
		digest, err := nfsFileDigest(path, 32<<20)
		info, statErr := os.Lstat(path)
		wanted := os.FileMode(0644)
		if name == "bin/suricata" {
			wanted = 0755
		}
		if err != nil || statErr != nil || info.Mode().Perm() != wanted || !threatPackageSHA.MatchString(v.Files[name]) || v.Files[name] != digest {
			return v, errors.New("IDS 原生程序或完整许可文件身份、模式或摘要不符")
		}
	}
	// An unexpected file, plugin or linked entry is not silently adopted.
	allowed := map[string]bool{"bin": true, "licenses": true, "bin/suricata": true, "licenses/suricata-copyright.txt": true, "licenses/GPL-2.txt": true, "runtime-manifest.json": true}
	if v.Format == 3 {
		allowed["libraries"] = true
		for name, spec := range threatIDSEventLibraries {
			file := "libraries/" + spec.SONAME
			data, err := apacheWAFReadStableFile(filepath.Join(base, file), 8<<20)
			if err != nil || validateThreatIDSEventELF(data, name, p.Architecture) != nil {
				return v, errors.New("IDS 私有库 ELF 装载身份发生变化")
			}
			allowed[file] = true
			allowed["licenses/"+name+"-copyright.txt"] = true
		}
	}
	err := filepath.WalkDir(base, func(path string, entry os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if path == base {
			return nil
		}
		rel, e := filepath.Rel(base, path)
		if e != nil || !allowed[rel] || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("IDS 程序树包含未知或链接文件")
		}
		return nil
	})
	if err != nil || validateNFSELF(filepath.Join(base, "bin/suricata"), p.Architecture) != nil {
		return v, errors.New("IDS 原生程序树或 ELF 架构核验失败")
	}
	var manifest threatIDSRuntime
	b, err := ftpPrivateRead(filepath.Join(base, "runtime-manifest.json"), 32<<10)
	if err != nil || decodeThreatIDSPrivateJSON(b, &manifest) != nil {
		return v, errors.New("IDS 原生发布来源记录不可读取")
	}
	encoded, _ := json.Marshal(v)
	recorded, _ := json.Marshal(manifest)
	if string(encoded) != string(recorded) {
		return v, errors.New("IDS 安装记录和原生发布记录不同")
	}
	v.Binary = filepath.Join(base, "bin/suricata")
	return v, nil
}

func validateThreatIDSRuntimeHeader(v threatIDSRuntime) error {
	p := v.Package
	switch v.Platform {
	case "debian-12", "debian-13", "ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04":
	default:
		return errors.New("IDS 运行时平台身份未审核")
	}
	if (v.Format != 1 && v.Format != 2 && v.Format != 3) || !threatIDSPrefix.MatchString(v.Prefix) || v.Prefix != threatIDSRuntimePrefix(p, v.Libraries) || p.Name != "suricata" || (p.Architecture != "amd64" && p.Architecture != "arm64") || !threatAPTVersion.MatchString(p.Version) || !threatPackageSHA.MatchString(p.SHA256) || p.Size < 1024 || p.Size > 32<<20 || !threatPackageFile.MatchString(p.Filename) || strings.Contains(p.Filename, "..") || strings.Contains(p.Filename, "//") || !strings.HasSuffix(p.Filename, "_"+p.Architecture+".deb") {
		return errors.New("IDS 原生来源记录结构无效")
	}
	if v.Format < 3 && (v.Libraries != nil || len(v.Files) != 3) {
		return errors.New("IDS 旧运行时不得声明未记录的私有库")
	}
	if v.Format == 3 {
		if err := validateThreatIDSLibraryBundle(v.Platform, p.Architecture, v.Libraries, v.Files); err != nil {
			return err
		}
	}
	for _, name := range []string{"bin/suricata", "licenses/suricata-copyright.txt", "licenses/GPL-2.txt"} {
		if !threatPackageSHA.MatchString(v.Files[name]) {
			return errors.New("IDS 原生程序或许可摘要缺失")
		}
	}
	if v.Format == 1 && v.Source != nil {
		return errors.New("IDS 旧运行时不能声明未记录的独立目录来源")
	}
	if v.Format >= 2 {
		profile, err := threatIDSRepositoryFor(v.Platform, p.Architecture)
		if err != nil || v.Source == nil || v.Source.URL != profile.URL || v.Source.Suite != profile.Suite || !threatPackageSHA.MatchString(v.Source.KeySHA) || !threatPackageSHA.MatchString(v.Source.CatalogSHA) || !threatPackageSHA.MatchString(v.Source.MetadataSHA) {
			return errors.New("IDS 独立官方包来源记录无效")
		}
		if profile.Key != "" && v.Source.KeySHA != core.Hash(profile.Key) {
			return errors.New("IDS 运行时的 OISF 固定签名密钥摘要不符")
		}
	}
	if _, err := threatIDSDependencies(p.Depends); err != nil {
		return err
	}
	return nil
}

// Called only by the fixed root dependency unit. This prepares a private
// binary, never starts packet capture and never installs the suricata service.
func installPrivateThreatIDSRuntime(ctx context.Context) error {
	s := New(Config{})
	base := filepath.Join(appNativeRoot, "network-threat-detection")
	if err := threatIDSTrustedParents(base, true); err != nil {
		return err
	}
	lock, err := threatIDSPrepareLock(s.moduleDir("network-threat-detection"))
	if err != nil {
		return err
	}
	defer lock.Close()
	if previous, err := s.threatIDSRuntime(); err == nil {
		return threatIDSRequireSupported(previous.Package.Version)
	}
	record := filepath.Join(s.moduleDir("network-threat-detection"), "native-runtime.json")
	if _, err := os.Lstat(record); !errors.Is(err, os.ErrNotExist) {
		return errors.New("现有 IDS 来源校验失败或状态未知；未修复、替换或清理")
	}
	var candidate threatIDSRuntime
	if err := s.stagePrivateThreatIDSRuntime(ctx, &candidate); err != nil {
		return err
	}
	return moduleWrite(record, candidate)
}

// Publish an immutable, fully verified candidate only. Activation belongs to
// the separately recoverable configuration/unit transaction; preparing a
// candidate must not rebind an existing capture or rewrite its source record.
// Caller holds native-prepare.lock.
func (s *Service) stagePrivateThreatIDSRuntime(ctx context.Context, out *threatIDSRuntime) error {
	base := filepath.Join(appNativeRoot, "network-threat-detection")
	if out == nil {
		return errors.New("IDS 候选输出缺失")
	}
	if err := threatIDSPrepareBudget(base); err != nil {
		return err
	}
	// A previous interruption or an unrelated unfinished package transaction
	// is not permission to let APT configure everything on this server.
	audit, auditErr := s.moduleCommand(ctx, 20*time.Second, "/usr/bin/dpkg", "--audit")
	if auditErr != nil || strings.TrimSpace(audit) != "" {
		return errors.New("系统存在未完成或无法核对的 dpkg 状态；IDS 未运行 APT，也不会自动修复无关包")
	}
	work, err := os.MkdirTemp(base, ".prepare-")
	if err != nil {
		return err
	}
	// Retain private catalog and original .deb on failure, never broadly prune.
	if err = os.Chmod(work, 0700); err != nil {
		return err
	}
	var provenance threatIDSPackageSource
	p, catalogArgs, err := s.threatIDSPrivateCatalog(ctx, work, &provenance)
	if err != nil {
		return err
	}
	strictAPT := []string{"-o", "APT::Get::AllowUnauthenticated=false", "-o", "Acquire::AllowInsecureRepositories=false", "-o", "Acquire::AllowDowngradeToInsecureRepositories=false"}
	if _, err := s.moduleCommand(ctx, 2*time.Minute, "/usr/bin/apt-get", append(strictAPT, "update")...); err != nil {
		return errors.New("IDS 已认证 APT 目录刷新失败；请核对固定依赖服务日志")
	}
	deps, err := threatIDSDependencies(p.Depends)
	if err != nil {
		return err
	}
	var libraries *threatIDSLibraryBundle
	var libraryFiles map[string][]byte
	if runtimecatalog.HostPlatform() == "ubuntu-24.04" {
		seen := map[string]bool{}
		for _, name := range deps {
			seen[name] = true
		}
		if !seen["libevent-2.1-7t64"] || !seen["libevent-pthreads-2.1-7t64"] {
			return errors.New("IDS 当前候选不属于已审核私有事件库 ABI")
		}
		libraries, libraryFiles, err = s.stageThreatIDSEventLibraries(ctx, work)
		if err != nil {
			return err
		}
		deps, err = threatIDSDependencies(threatIDSHostLibraryDependencies(p.Depends, true))
		if err != nil {
			return err
		}
		for _, lib := range libraries.Packages {
			if err := s.threatIDSCheckInstalledDependencies(ctx, threatIDSHostLibraryDependencies(lib.Package.Depends, true)); err != nil {
				return err
			}
		}
		if err := s.threatIDSCheckPrivateLibraryConstraints(ctx, p.Depends, libraries); err != nil {
			return err
		}
	}
	// The service package is deliberately absent. Existing host libraries are
	// not upgraded and unrelated native services must not be restarted.
	args := append(append([]string{}, strictAPT...), "install", "-y", "--no-upgrade", "--no-install-recommends")
	plan, err := s.moduleCommand(ctx, 30*time.Second, "/usr/bin/apt-get", append(append([]string{"--simulate"}, args...), deps...)...)
	if err != nil {
		return errors.New("IDS 实际依赖计划不可核对；未运行库安装")
	}
	if err = validateThreatAPTPlan(plan); err != nil {
		return err
	}
	if _, err = s.moduleCommand(ctx, 12*time.Minute, "/usr/bin/apt-get", append(args, deps...)...); err != nil {
		return errors.New("IDS 固定库准备失败；未安装系统 Suricata 服务，请核对固定依赖日志")
	}
	if err := s.threatIDSCheckInstalledDependencies(ctx, threatIDSHostLibraryDependencies(p.Depends, libraries != nil)); err != nil {
		return err
	}
	if ownedRuntimePath(base, true) != nil {
		return errors.New("IDS 程序目录不属于可信 root")
	}
	prefix := threatIDSRuntimePrefix(p, libraries)
	target := filepath.Join(base, prefix)
	if _, err = os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		var previous threatIDSRuntime
		b, e := ftpPrivateRead(filepath.Join(target, "runtime-manifest.json"), 32<<10)
		if e != nil || decodeThreatIDSPrivateJSON(b, &previous) != nil {
			return errors.New("IDS 原生候选已存在但不可核验；保留、不覆盖")
		}
		if previous.Prefix != prefix {
			return errors.New("IDS 候选来源与当前 APT 完整摘要不同")
		}
		if previous, e = s.validateThreatIDSRuntime(previous); e != nil {
			return e
		}
		if e := s.probeThreatIDSRuntime(ctx, previous); e != nil {
			return e
		}
		*out = previous
		return nil
	}
	if _, err = nfsCommandIn(ctx, work, "/usr/bin/apt-get", append(append([]string{}, catalogArgs...), "download", "suricata="+p.Version)...); err != nil {
		return errors.New("IDS 固定包下载失败，未运行维护脚本")
	}
	matches, err := filepath.Glob(filepath.Join(work, "suricata_*.deb"))
	if err != nil || len(matches) != 1 {
		return errors.New("IDS 下载包身份不唯一")
	}
	info, err := os.Lstat(matches[0])
	if err != nil || !info.Mode().IsRegular() || info.Size() != p.Size {
		return errors.New("IDS 下载包大小或类型与已认证目录不同")
	}
	digest, err := nfsFileDigest(matches[0], 32<<20)
	if err != nil || digest != p.SHA256 {
		return errors.New("IDS 原始下载包完整摘要不符")
	}
	selected, err := threatIDSDebFiles(ctx, matches[0])
	if err != nil {
		return err
	}
	candidate := filepath.Join(work, "candidate")
	if err = os.Mkdir(candidate, 0755); err != nil {
		return err
	}
	if err = os.Chmod(candidate, 0755); err != nil {
		return err
	}
	dirs := []string{"bin", "licenses"}
	if libraries != nil {
		dirs = append(dirs, "libraries")
	}
	for _, name := range dirs {
		dir := filepath.Join(candidate, name)
		if err = os.Mkdir(dir, 0755); err != nil {
			return err
		}
		if err = os.Chmod(dir, 0755); err != nil {
			return err
		}
	}
	v := threatIDSRuntime{Format: 2, Prefix: prefix, Platform: runtimecatalog.HostPlatform(), Package: p, Files: map[string]string{}, Source: &provenance}
	if libraries != nil {
		v.Format = 3
		v.Libraries = libraries
	}
	for _, item := range []struct {
		Source, Name string
		Mode         os.FileMode
	}{{"usr/bin/suricata", "bin/suricata", 0755}, {"usr/share/doc/suricata/copyright", "licenses/suricata-copyright.txt", 0644}, {"/usr/share/common-licenses/GPL-2", "licenses/GPL-2.txt", 0644}} {
		dest := filepath.Join(candidate, item.Name)
		if data, ok := selected[item.Source]; ok {
			err = atomicWrite(dest, data, item.Mode)
		} else {
			err = copyNFSNative(item.Source, dest, item.Mode)
		}
		if err != nil {
			return errors.New("IDS 原生程序或完整许可复制失败")
		}
		// The dependency unit's restrictive umask must not change the
		// immutable file modes. This is our newly created private candidate,
		// never an existing host file or a previously published runtime.
		if err = os.Chmod(dest, item.Mode); err != nil {
			return err
		}
		v.Files[item.Name], err = nfsFileDigest(dest, 32<<20)
		if err != nil {
			return err
		}
	}
	for name, data := range libraryFiles {
		dest := filepath.Join(candidate, name)
		if err := atomicWrite(dest, data, 0644); err != nil {
			return err
		}
		if err := os.Chmod(dest, 0644); err != nil {
			return err
		}
		v.Files[name], err = nfsFileDigest(dest, 8<<20)
		if err != nil {
			return err
		}
	}
	if validateNFSELF(filepath.Join(candidate, "bin/suricata"), runtime.GOARCH) != nil {
		return errors.New("IDS 原生程序不是当前架构的受支持 ELF")
	}
	if err = moduleWrite(filepath.Join(candidate, "runtime-manifest.json"), v); err != nil {
		return err
	}
	// Rename without replacement: concurrent or unknown publications survive.
	if err = unix.Renameat2(unix.AT_FDCWD, candidate, unix.AT_FDCWD, target, unix.RENAME_NOREPLACE); err != nil {
		return errors.New("IDS 独立发布失败；既有程序与准备记录保留")
	}
	parent, err := os.Open(base)
	if err != nil {
		return err
	}
	err = parent.Sync()
	parent.Close()
	if err != nil {
		return err
	}
	if v, err = s.validateThreatIDSRuntime(v); err != nil {
		return err
	}
	if err := s.probeThreatIDSRuntime(ctx, v); err != nil {
		return err
	}
	*out = v
	return nil
}

func (s *Service) probeThreatIDSRuntime(ctx context.Context, v threatIDSRuntime) error {
	environment := []string{}
	if v.Format == 3 {
		if validateThreatIDSRuntimeHeader(v) != nil || v.Binary != s.systemPath(filepath.Join(appNativeRoot, "network-threat-detection", v.Prefix, "bin/suricata")) {
			return errors.New("IDS 私有库探测程序来源不完整")
		}
		environment = []string{"LD_LIBRARY_PATH=" + s.systemPath(filepath.Join(appNativeRoot, "network-threat-detection", v.Prefix, "libraries")), "LD_PRELOAD=", "LD_AUDIT=", "LD_DEBUG="}
	}
	output, err := s.moduleCommandEnvironment(ctx, 15*time.Second, v.Binary, environment, "--build-info")
	if err != nil {
		return errors.New("IDS 实际候选程序无法运行或库绑定失败；未激活")
	}
	return validateThreatIDSBuildInfo(v.Package.Version, output)
}
