//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func (s *Service) threatIDSPrivateCatalog(ctx context.Context, work string, provenance *threatIDSPackageSource) (threatIDSPackage, []string, error) {
	var p threatIDSPackage
	if provenance == nil {
		return p, nil, errors.New("IDS 下载来源输出缺失")
	}
	profile, err := threatIDSRepositoryFor(runtimecatalog.HostPlatform(), runtime.GOARCH)
	if err != nil {
		return p, nil, err
	}
	if err := threatIDSTrustedParents(work, false); err != nil {
		return p, nil, err
	}
	catalog := filepath.Join(work, "catalog")
	for _, path := range []string{catalog, filepath.Join(catalog, "lists"), filepath.Join(catalog, "lists/partial"), filepath.Join(catalog, "cache"), filepath.Join(catalog, "cache/archives"), filepath.Join(catalog, "cache/archives/partial")} {
		if err := os.Mkdir(path, 0700); err != nil {
			return p, nil, err
		}
	}
	keyring := profile.Keyring
	if profile.Key != "" {
		keyring = filepath.Join(catalog, "oisf-stable.asc")
		if err := atomicWrite(keyring, []byte(profile.Key), 0600); err != nil {
			return p, nil, err
		}
	} else {
		canonical, err := s.threatIDSDebianKeyringPath()
		if err != nil {
			return p, nil, err
		}
		data, err := apacheWAFReadStableFile(canonical, 256<<10)
		if err != nil || len(data) < 1024 {
			return p, nil, errors.New("IDS 发行版原生信任密钥不可核对；未下载替代密钥")
		}
		// Snapshot only the known canonical distro keyring. Authentication
		// cannot race a subsequent system keyring rotation or follow a link.
		keyring = filepath.Join(catalog, "debian-archive.gpg")
		if err := atomicWrite(keyring, data, 0600); err != nil {
			return p, nil, err
		}
	}
	source := fmt.Sprintf("deb [arch=%s signed-by=%s] %s %s main\n", runtime.GOARCH, keyring, profile.URL, profile.Suite)
	if err := atomicWrite(filepath.Join(catalog, "sources.list"), []byte(source), 0600); err != nil {
		return p, nil, err
	}
	args, err := threatIDSPrivateAPTArgs(catalog)
	if err != nil {
		return p, nil, err
	}
	if _, err := s.moduleCommand(ctx, 3*time.Minute, "/usr/bin/apt-get", append(append([]string{}, args...), "update")...); err != nil {
		return p, nil, errors.New("IDS 独立官方签名目录刷新失败；未改系统软件源或退回不安全下载")
	}
	policy, err := s.moduleCommand(ctx, 20*time.Second, "/usr/bin/apt-cache", append(append([]string{}, args...), "policy", "suricata")...)
	if err != nil {
		return p, nil, err
	}
	version := ""
	for _, line := range strings.Split(policy, "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "Candidate:" {
			if version != "" {
				return p, nil, errors.New("IDS 独立目录候选重复")
			}
			version = f[1]
		}
	}
	if err := threatIDSRequireSupported(version); err != nil {
		return p, nil, err
	}
	metadata, err := s.moduleCommand(ctx, 20*time.Second, "/usr/bin/apt-cache", append(append([]string{}, args...), "show", "suricata="+version)...)
	if err != nil {
		return p, nil, err
	}
	p, err = parseThreatAPTMetadata(version, runtime.GOARCH, metadata)
	if err != nil {
		return p, nil, err
	}
	keySHA, err := nfsFileDigest(keyring, 256<<10)
	if err != nil {
		return p, nil, err
	}
	files, err := os.ReadDir(filepath.Join(catalog, "lists"))
	if err != nil || len(files) > 32 {
		return p, nil, errors.New("IDS 独立目录文件集合无法核对")
	}
	var catalogSHA string
	for _, f := range files {
		if strings.HasSuffix(f.Name(), "_InRelease") {
			if catalogSHA != "" {
				return p, nil, errors.New("IDS 独立签名目录身份不唯一")
			}
			catalogSHA, err = nfsFileDigest(filepath.Join(catalog, "lists", f.Name()), 1<<20)
			if err != nil {
				return p, nil, err
			}
		}
	}
	if catalogSHA == "" {
		return p, nil, errors.New("IDS 缺少已经验证的独立 InRelease 证据")
	}
	*provenance = threatIDSPackageSource{URL: profile.URL, Suite: profile.Suite, KeySHA: keySHA, CatalogSHA: catalogSHA, MetadataSHA: core.Hash(metadata)}
	return p, args, nil
}

func (s *Service) threatIDSDebianKeyringPath() (string, error) {
	legacy := s.systemPath("/usr/share/keyrings/debian-archive-keyring.gpg")
	if err := s.wafOwnedDirectory(filepath.Dir(legacy), false); err != nil {
		return "", err
	}
	info, err := os.Lstat(legacy)
	if err != nil {
		return "", err
	}
	if info.Mode().IsRegular() {
		if ownedRuntimePath(legacy, false) != nil {
			return "", errors.New("IDS Debian 公钥身份异常")
		}
		return legacy, nil
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return "", errors.New("IDS Debian 公钥不是发行版普通文件或固定兼容链接")
	}
	owner, err := fileOwnerForInfo(info)
	target, linkErr := os.Readlink(legacy)
	if err != nil || owner.UID != 0 || owner.GID != 0 || linkErr != nil || target != "debian-archive-keyring.pgp" {
		return "", errors.New("IDS Debian 公钥链接不是已审核的发行版固定映射")
	}
	canonical := filepath.Join(filepath.Dir(legacy), target)
	if ownedRuntimePath(canonical, false) != nil {
		return "", errors.New("IDS Debian 规范公钥文件身份异常")
	}
	return canonical, nil
}
