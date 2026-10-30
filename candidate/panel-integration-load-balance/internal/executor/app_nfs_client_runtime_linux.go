//go:build linux

package executor

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const nfsRuntimeInstallLock = "runtime-install.lock"

// Only mount.nfs is copied from nfs-common. Installing that entire package
// runs its maintainer scripts and pulls rpcbind; neither is necessary for our
// explicit NFS4.2/AUTH_SYS client. Dependencies of its other utilities are
// recognized but are not installed on behalf of this private client.
func nfsClientDependencies(raw string) ([]string, error) {
	helper := map[string]bool{"libc6": true, "libmount1": true, "libtirpc3": true, "libtirpc3t64": true}
	other := map[string]bool{
		"libcap2": true, "libcom-err2": true, "libdevmapper1.02.1": true,
		"libevent-core-2.1-7": true, "libevent-core-2.1-7t64": true,
		"libgssapi-krb5-2": true, "libkeyutils1": true, "libkrb5-3": true,
		"libnfsidmap1": true, "libwrap0": true, "libk5crypto3": true,
		"rpcbind": true, "adduser": true, "ucf": true, "keyutils": true,
		"python3": true, "python3:any": true, "lsb-base": true, "init-system-helpers": true,
	}
	seen := map[string]bool{}
	for _, entry := range strings.Split(raw, ",") {
		parts := strings.Fields(strings.TrimSpace(entry))
		if len(parts) == 0 || strings.Contains(entry, "|") {
			return nil, errors.New("NFS 客户端 APT 依赖结构未经审核")
		}
		name := parts[0]
		if helper[name] {
			seen[name] = true
		} else if !other[name] {
			return nil, fmt.Errorf("未审核的 NFS 客户端依赖：%s", name)
		}
	}
	if !seen["libc6"] || !seen["libmount1"] || seen["libtirpc3"] == seen["libtirpc3t64"] {
		return nil, errors.New("NFS 客户端缺少明确的 libc、mount 或单一 TIRPC 依赖")
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

func nfsPackageDependencies(p nfsAPTPackage) ([]string, error) {
	if p.Name == "nfs-common" {
		return nfsClientDependencies(p.Depends)
	}
	return nfsAllowedDependencies(p.Depends)
}

func nfsGlobalDependencies(packages []nfsAPTPackage, reuseServer bool) ([]string, error) {
	if len(packages) != 3 || packages[0].Name != "nfs-ganesha" || packages[1].Name != "nfs-ganesha-vfs" || packages[2].Name != "nfs-common" {
		return nil, errors.New("NFS 依赖计划与已认证包集合不符")
	}
	seen := map[string]bool{}
	start := 0
	if reuseServer {
		// The original server and isolation shim remain byte-for-byte intact.
		// Neither a compiler nor newer server libraries belong to this update.
		start = 2
	} else {
		seen["build-essential"] = true
	}
	for _, p := range packages[start:] {
		names, err := nfsPackageDependencies(p)
		if err != nil {
			return nil, err
		}
		for _, name := range names {
			seen[name] = true
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

func nfsServerRuntimeFiles(mainLibrary string) []string {
	return []string{"bin/ganesha.nfsd", "lib/" + mainLibrary, "lib/libfsalvfs.so", "lib/libpanel-nfs-rpc-isolation.so", "licenses/nfs-ganesha.txt", "licenses/nfs-ganesha-vfs.txt", "licenses/cloudstack-nfs-rpc-isolation.c"}
}

func copyNFSVerifiedNative(source, target string, mode os.FileMode, expectedSHA string) (string, error) {
	if err := copyNFSNative(source, target, mode); err != nil {
		return "", err
	}
	digest, err := nfsFileDigest(target, 32<<20)
	if err != nil {
		return "", err
	}
	if expectedSHA != "" && expectedSHA != digest {
		return "", errors.New("NFS 原服务端文件在复制期间变化；拒绝切换运行时")
	}
	return digest, nil
}

func nfsExtractedClient(extracted string) (string, error) {
	var selected string
	// Jammy and merged-/usr distributions put the ordinary executable in
	// different archive locations. Do not follow a link or choose arbitrarily.
	for _, relative := range []string{"sbin/mount.nfs", "usr/sbin/mount.nfs"} {
		name := filepath.Join(extracted, relative)
		info, err := os.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || selected != "" {
			return "", errors.New("NFS 客户端原生工具缺失、链接或位置不唯一")
		}
		if err := ownedRuntimePath(name, false); err != nil {
			return "", err
		}
		for parent := filepath.Dir(name); ; parent = filepath.Dir(parent) {
			if err := ownedRuntimePath(parent, true); err != nil {
				return "", err
			}
			if parent == extracted {
				break
			}
			if parent == filepath.Dir(parent) {
				return "", errors.New("NFS 客户端解包根目录身份无效")
			}
		}
		selected = name
	}
	if selected == "" {
		return "", errors.New("认证 nfs-common 包中没有可核对的挂载工具")
	}
	return selected, nil
}

func validateNFSClientELF(path, arch string) error {
	if err := validateNFSELF(path, arch); err != nil {
		return err
	}
	f, err := elf.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	libraries, err := f.ImportedLibraries()
	if err != nil || len(libraries) < 3 || len(libraries) > 4 {
		return errors.New("NFS 挂载工具动态库集合未经审核")
	}
	loader := "ld-linux-aarch64.so.1"
	if arch == "amd64" {
		loader = "ld-linux-x86-64.so.2"
	}
	allowed := map[string]bool{"libc.so.6": true, "libmount.so.1": true, "libtirpc.so.3": true, loader: true}
	seen := map[string]bool{}
	for _, name := range libraries {
		if !allowed[name] || seen[name] {
			return errors.New("NFS 挂载工具含未审核或重复动态库")
		}
		seen[name] = true
	}
	if !seen["libc.so.6"] || !seen["libmount.so.1"] || !seen["libtirpc.so.3"] {
		return errors.New("NFS 挂载工具缺少经过审核的动态库")
	}
	return nil
}

func (s *Service) nfsPrivateClientReady() bool {
	v, err := s.nfsRuntime()
	return err == nil && v.Format == 2 && v.ClientBinary != ""
}

func nfsClientMountCommand(v nfsRuntimeSelection, m nfsMount) (string, []string, error) {
	if !moduleResourceID.MatchString(m.ID) || !validNFSSource(m.Source) || m.Port < 0 || m.Port > 65535 {
		return "", nil, errors.New("NFS 挂载清单身份或来源无效")
	}
	if m.Port == 0 {
		m.Port = 2049
	}
	permission := "rw"
	if m.ReadOnly {
		permission = "ro"
	}
	options := permission + ",nosuid,nodev,noexec,vers=4.2,proto=" + nfsClientTransport(m.Source) + ",port=" + strconv.Itoa(m.Port) + ",timeo=50,retrans=2"
	target := filepath.Join("/srv/panel/nfs", m.ID)
	if v.Format == 1 {
		// Keep an already-installed, verified legacy runtime usable until the
		// signed application update prepares the private helper. No package or
		// service installation is performed by this compatibility path.
		return "/usr/bin/mount", []string{"-t", "nfs", "-o", options, m.Source, target}, nil
	}
	if v.Format != 2 || !nfsNativePrefix.MatchString(v.Prefix) || v.ClientBinary != filepath.Join(appNativeRoot, "nfs-manager", v.Prefix, "bin/mount.nfs") {
		return "", nil, errors.New("NFS 独立挂载工具身份无法核对")
	}
	// -n keeps the helper from writing /etc/mtab; actual mount identity is
	// verified independently in /proc/self/mountinfo. Never use fake/sloppy or
	// fallback-to-v3 options, nor a caller-selected command or arbitrary flags.
	return v.ClientBinary, []string{m.Source, target, "-n", "-o", options + ",sec=sys"}, nil
}
