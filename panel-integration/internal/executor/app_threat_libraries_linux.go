//go:build linux

package executor

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Download-only, independent Ubuntu archive catalog. No host source, trust,
// policy, APT hook or installed package is changed by preparing this cohort.
func (s *Service) stageThreatIDSEventLibraries(ctx context.Context, work string) (*threatIDSLibraryBundle, map[string][]byte, error) {
	url, err := threatIDSLibraryURL(runtime.GOARCH)
	if err != nil {
		return nil, nil, err
	}
	catalog := filepath.Join(work, "library-catalog")
	for _, path := range []string{catalog, filepath.Join(catalog, "lists"), filepath.Join(catalog, "lists/partial"), filepath.Join(catalog, "cache"), filepath.Join(catalog, "cache/archives"), filepath.Join(catalog, "cache/archives/partial")} {
		if err := os.Mkdir(path, 0700); err != nil {
			return nil, nil, err
		}
	}
	canonical := s.systemPath("/usr/share/keyrings/ubuntu-archive-keyring.gpg")
	if threatIDSTrustedParents(filepath.Dir(canonical), false) != nil || ownedRuntimePath(canonical, false) != nil {
		return nil, nil, errors.New("IDS Ubuntu 规范公钥文件身份不能核对；不下载替代密钥")
	}
	key, err := apacheWAFReadStableFile(canonical, 256<<10)
	if err != nil || len(key) < 1024 {
		return nil, nil, errors.New("IDS Ubuntu 公钥读取不完整")
	}
	keyring := filepath.Join(catalog, "ubuntu-archive.gpg")
	if err := atomicWrite(keyring, key, 0600); err != nil {
		return nil, nil, err
	}
	source := ""
	for _, suite := range []string{"noble", "noble-updates", "noble-security"} {
		source += fmt.Sprintf("deb [arch=%s signed-by=%s] %s %s main\n", runtime.GOARCH, keyring, url, suite)
	}
	if err := atomicWrite(filepath.Join(catalog, "sources.list"), []byte(source), 0600); err != nil {
		return nil, nil, err
	}
	args, err := threatIDSPrivateAPTArgs(catalog)
	if err != nil {
		return nil, nil, err
	}
	if _, err := s.moduleCommand(ctx, 3*time.Minute, "/usr/bin/apt-get", append(append([]string{}, args...), "update")...); err != nil {
		return nil, nil, errors.New("IDS 私有库独立 Ubuntu 签名目录刷新失败")
	}
	bundle := &threatIDSLibraryBundle{URL: url, KeySHA: core.Hash(string(key)), Catalogs: map[string]string{}, Packages: map[string]threatIDSLibrary{}}
	entries, err := os.ReadDir(filepath.Join(catalog, "lists"))
	if err != nil || len(entries) > 32 {
		return nil, nil, errors.New("IDS 私有库目录文件集合不能核对")
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), "_InRelease") {
			continue
		}
		found := false
		for _, suite := range []string{"noble", "noble-updates", "noble-security"} {
			if !strings.HasSuffix(entry.Name(), "_dists_"+suite+"_InRelease") {
				continue
			}
			if bundle.Catalogs[suite] != "" {
				return nil, nil, errors.New("IDS 私有库签名目录身份重复")
			}
			bundle.Catalogs[suite], err = nfsFileDigest(filepath.Join(catalog, "lists", entry.Name()), 1<<20)
			if err != nil {
				return nil, nil, err
			}
			found = true
		}
		if !found {
			return nil, nil, errors.New("IDS 私有库目录包含未知发行版签名")
		}
	}
	if len(bundle.Catalogs) != 3 {
		return nil, nil, errors.New("IDS 私有库完整发行版签名目录缺失")
	}
	files := map[string][]byte{}
	names := []string{}
	for name := range threatIDSEventLibraries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		policy, err := s.moduleCommand(ctx, 15*time.Second, "/usr/bin/apt-cache", append(append([]string{}, args...), "policy", name)...)
		if err != nil {
			return nil, nil, err
		}
		version := ""
		for _, line := range strings.Split(policy, "\n") {
			if f := strings.Fields(line); len(f) == 2 && f[0] == "Candidate:" {
				if version != "" {
					return nil, nil, errors.New("IDS 私有库候选版本重复")
				}
				version = f[1]
			}
		}
		metadata, err := s.moduleCommand(ctx, 15*time.Second, "/usr/bin/apt-cache", append(append([]string{}, args...), "show", name+"="+version)...)
		if err != nil {
			return nil, nil, err
		}
		p, err := parseThreatIDSLibraryMetadata(name, version, runtime.GOARCH, metadata)
		if err != nil {
			return nil, nil, err
		}
		download := filepath.Join(work, "library-"+name)
		if err := os.Mkdir(download, 0700); err != nil {
			return nil, nil, err
		}
		if _, err := nfsCommandIn(ctx, download, "/usr/bin/apt-get", append(append([]string{}, args...), "download", name+"="+version)...); err != nil {
			return nil, nil, errors.New("IDS 私有库固定包下载失败；未执行维护脚本")
		}
		entries, err := os.ReadDir(download)
		if err != nil || len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".deb") {
			return nil, nil, errors.New("IDS 私有库原始包文件集合不唯一")
		}
		archive := filepath.Join(download, entries[0].Name())
		info, err := os.Lstat(archive)
		digest, digestErr := nfsFileDigest(archive, 8<<20)
		if err != nil || digestErr != nil || !info.Mode().IsRegular() || info.Size() != p.Size || digest != p.SHA256 {
			return nil, nil, errors.New("IDS 私有库原始包大小和完整摘要不符")
		}
		selected, err := threatIDSDebSelected(ctx, archive, func(ctx context.Context, input io.Reader) (map[string][]byte, error) {
			return readThreatIDSLibraryFiles(ctx, input, name, runtime.GOARCH)
		})
		if err != nil {
			return nil, nil, err
		}
		spec := threatIDSEventLibraries[name]
		lib := threatIDSLibrary{Package: p, MetadataSHA: core.Hash(metadata)}
		for file, data := range selected {
			if file == "copyright" {
				files["licenses/"+name+"-copyright.txt"] = data
				continue
			}
			if len(data) > 8<<20 {
				return nil, nil, errors.New("IDS 私有库 ELF 超过审核预算")
			}
			if err := validateThreatIDSEventELF(data, name, runtime.GOARCH); err != nil {
				return nil, nil, fmt.Errorf("IDS 私有库 %s ELF 核验失败：%w", name, err)
			}
			lib.File = file
			files["libraries/"+spec.SONAME] = data
		}
		bundle.Packages[name] = lib
	}
	// Bind every selected byte before any global dependency install is allowed.
	digests := map[string]string{"bin/suricata": strings.Repeat("0", 64), "licenses/suricata-copyright.txt": strings.Repeat("0", 64), "licenses/GPL-2.txt": strings.Repeat("0", 64)}
	for name, data := range files {
		digests[name] = core.Hash(string(data))
	}
	if err := validateThreatIDSLibraryBundle("ubuntu-24.04", runtime.GOARCH, bundle, digests); err != nil {
		return nil, nil, err
	}
	return bundle, files, nil
}

func validateThreatIDSEventELF(data []byte, name, arch string) error {
	spec, ok := threatIDSEventLibraries[name]
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer f.Close()
	machine := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}[arch]
	if !ok || machine == 0 || f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Type != elf.ET_DYN || f.Machine != machine {
		return errors.New("IDS 私有库 ELF 结构无效")
	}
	sonames, err := f.DynString(elf.DT_SONAME)
	if err != nil || len(sonames) != 1 || sonames[0] != spec.SONAME {
		return errors.New("IDS 私有库 SONAME 不符")
	}
	for _, tag := range []elf.DynTag{elf.DT_RPATH, elf.DT_RUNPATH, elf.DT_AUDIT, elf.DT_DEPAUDIT, elf.DT_FILTER, elf.DT_AUXILIARY} {
		values, err := f.DynValue(tag)
		if err != nil || len(values) != 0 {
			return errors.New("IDS 私有库含未审核装载器路径或插件")
		}
	}
	needed, err := f.DynString(elf.DT_NEEDED)
	if err != nil || len(needed) < 1 || len(needed) > 3 {
		return errors.New("IDS 私有库动态依赖不完整")
	}
	seen := map[string]bool{}
	// ARM Ubuntu's authenticated libevent explicitly names its native glibc
	// loader; it belongs to the already checked host libc6, not this private
	// cohort. Never copy a loader or accept a cross-ABI/name-pattern fallback.
	loader := map[string]string{"amd64": "ld-linux-x86-64.so.2", "arm64": "ld-linux-aarch64.so.1"}[arch]
	for _, dependency := range needed {
		if seen[dependency] || dependency != "libc.so.6" && dependency != loader && !(name == "libevent-pthreads-2.1-7t64" && dependency == "libevent_core-2.1.so.7") {
			return errors.New("IDS 私有库包含未审核动态依赖")
		}
		seen[dependency] = true
	}
	if !seen["libc.so.6"] || name == "libevent-pthreads-2.1-7t64" && !seen["libevent_core-2.1.so.7"] {
		return errors.New("IDS 私有库动态依赖闭包缺失")
	}
	return nil
}

// Source bytes and service policy alone do not prove which ABI was actually
// loaded. Bind all three mapped regular files to their recorded private paths
// and kernel device/inode identities before reporting capture as verified.
func (s *Service) threatIDSProcessPrivateLibraries(procRoot string, pid int, v threatIDSRuntime) error {
	base := s.systemPath(filepath.Join(appNativeRoot, "network-threat-detection", v.Prefix, "libraries"))
	environment, err := readModuleProcFile(filepath.Join(procRoot, strconv.Itoa(pid), "environ"), 64<<10)
	if err != nil {
		return errors.New("IDS 私有库实际环境不能核对")
	}
	seen := map[string]bool{}
	for _, entry := range strings.Split(strings.TrimSuffix(string(environment), "\x00"), "\x00") {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || seen[key] {
			return errors.New("IDS 实际环境结构重复或无效")
		}
		seen[key] = true
		if key == "LD_LIBRARY_PATH" && value != base || (key == "LD_PRELOAD" || key == "LD_AUDIT" || key == "LD_DEBUG") && value != "" {
			return errors.New("IDS 私有库实际装载器环境不符")
		}
	}
	if !seen["LD_LIBRARY_PATH"] {
		return errors.New("IDS 私有库实际固定路径缺失")
	}
	maps, err := readModuleProcFile(filepath.Join(procRoot, strconv.Itoa(pid), "maps"), 128<<10)
	if err != nil {
		return errors.New("IDS 实际私有库内存映射不能核对")
	}
	loaded := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(maps)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return errors.New("IDS 实际内存映射结构不完整")
		}
		if len(fields) == 5 {
			continue
		}
		for _, spec := range threatIDSEventLibraries {
			basename := filepath.Base(fields[5])
			if basename != spec.SONAME && !strings.HasPrefix(basename, spec.SONAME+".") {
				continue
			}
			path := filepath.Join(base, spec.SONAME)
			if len(fields) != 6 || fields[5] != path {
				return errors.New("IDS 实际事件库来自系统目录、已删除文件或未审核路径")
			}
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() {
				return errors.New("IDS 实际库映射普通文件身份异常")
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			inode, inodeErr := strconv.ParseUint(fields[4], 10, 64)
			major, minor, deviceOK := strings.Cut(fields[3], ":")
			devMajor, majorErr := strconv.ParseUint(major, 16, 32)
			devMinor, minorErr := strconv.ParseUint(minor, 16, 32)
			if !ok || inodeErr != nil || inode != st.Ino || !deviceOK || majorErr != nil || minorErr != nil || devMajor != uint64(unix.Major(uint64(st.Dev))) || devMinor != uint64(unix.Minor(uint64(st.Dev))) {
				return errors.New("IDS 实际库映射 inode 或设备与来源文件不符")
			}
			loaded[spec.SONAME] = true
		}
	}
	if len(loaded) != 3 {
		return errors.New("IDS 实际进程没有加载完整私有事件库闭包")
	}
	return nil
}

func (s *Service) threatIDSCheckPrivateLibraryConstraints(ctx context.Context, raw string, bundle *threatIDSLibraryBundle) error {
	if bundle == nil {
		return errors.New("IDS 私有库版本记录缺失")
	}
	if _, err := threatIDSDependencies(raw); err != nil {
		return err
	}
	for _, entry := range strings.Split(raw, ",") {
		fields := strings.Fields(entry)
		lib, ok := bundle.Packages[fields[0]]
		if !ok || len(fields) == 1 {
			continue
		}
		if len(fields) != 3 {
			return errors.New("IDS 私有库版本约束不完整")
		}
		op := map[string]string{"(>=": "ge", "(=": "eq", "(>>": "gt", "(<=": "le", "(<<": "lt"}[fields[1]]
		wanted := strings.TrimSuffix(fields[2], ")")
		if op == "" || wanted == "" {
			return errors.New("IDS 私有库版本约束未审核")
		}
		if _, err := s.moduleCommand(ctx, 5*time.Second, "/usr/bin/dpkg", "--compare-versions", lib.Package.Version, op, wanted); err != nil {
			return errors.New("IDS 私有库低于候选要求；未激活")
		}
	}
	return nil
}
