package executor

import (
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"regexp"
	"strconv"
	"strings"
)

// Only this reviewed ABI cohort is private. This is not a general package or
// loader-path API. The libc/loader remain the host's maintained native ABI.
var threatIDSEventLibraries = map[string]struct{ SONAME, FilePattern string }{
	"libevent-2.1-7t64":          {"libevent-2.1.so.7", `^libevent-2\.1\.so\.7\.[0-9.]+$`},
	"libevent-core-2.1-7t64":     {"libevent_core-2.1.so.7", `^libevent_core-2\.1\.so\.7\.[0-9.]+$`},
	"libevent-pthreads-2.1-7t64": {"libevent_pthreads-2.1.so.7", `^libevent_pthreads-2\.1\.so\.7\.[0-9.]+$`},
}

type threatIDSLibraryBundle struct {
	URL      string                      `json:"repository_url"`
	KeySHA   string                      `json:"key_sha256"`
	Catalogs map[string]string           `json:"signed_catalogs"`
	Packages map[string]threatIDSLibrary `json:"packages"`
}

type threatIDSLibrary struct {
	Package     threatIDSPackage `json:"package"`
	MetadataSHA string           `json:"metadata_sha256"`
	File        string           `json:"selected_regular_file"`
}

var threatIDSLibraryVersion = regexp.MustCompile(`^2\.1\.12-stable-[0-9]+ubuntu[0-9]+(\.[0-9]+)?$`)

func threatIDSLibraryURL(arch string) (string, error) {
	switch arch {
	case "arm64":
		return "https://ports.ubuntu.com/ubuntu-ports", nil
	case "amd64":
		return "https://archive.ubuntu.com/ubuntu", nil
	}
	return "", errors.New("IDS 私有库架构未审核")
}

func parseThreatIDSLibraryMetadata(name, version, arch, data string) (threatIDSPackage, error) {
	var result threatIDSPackage
	if _, ok := threatIDSEventLibraries[name]; !ok || !threatIDSLibraryVersion.MatchString(version) || arch != "amd64" && arch != "arm64" || len(data) > 128<<10 {
		return result, errors.New("IDS 私有库元数据不属于已审核 ABI")
	}
	for _, paragraph := range strings.Split(strings.TrimSpace(data), "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(paragraph, "\n") {
			if line == "" || line[0] == ' ' || line[0] == '\t' {
				continue
			}
			key, value, ok := strings.Cut(line, ":")
			_, duplicate := fields[key]
			if !ok || duplicate {
				return result, errors.New("IDS 私有库元数据结构重复或无效")
			}
			fields[key] = strings.TrimSpace(value)
		}
		if fields["Package"] != name || fields["Version"] != version || fields["Architecture"] != arch {
			continue
		}
		size, err := strconv.ParseInt(fields["Size"], 10, 64)
		filename := "pool/main/libe/libevent/" + name + "_" + version + "_" + arch + ".deb"
		if err != nil || size < 1024 || size > 8<<20 || !threatPackageSHA.MatchString(fields["SHA256"]) || fields["Filename"] != filename {
			return result, errors.New("IDS 私有库包摘要、大小或固定路径不符")
		}
		p := threatIDSPackage{name, version, arch, fields["SHA256"], size, fields["Depends"], filename}
		if result.Name != "" && result != p {
			return result, errors.New("IDS 同版本私有库目录元数据冲突")
		}
		result = p
	}
	if result.Name == "" {
		return result, errors.New("IDS 缺少匹配私有库目录元数据")
	}
	return result, nil
}

func threatIDSRuntimePrefix(p threatIDSPackage, libraries *threatIDSLibraryBundle) string {
	if libraries == nil {
		return threatIDSPackagePrefixPortable(p)
	}
	encoded, _ := json.Marshal(struct {
		Package   threatIDSPackage
		Libraries *threatIDSLibraryBundle
	}{p, libraries})
	return "apt-" + core.Hash(string(encoded))[:16]
}

func threatIDSPackagePrefixPortable(p threatIDSPackage) string {
	encoded, _ := json.Marshal(p)
	return "apt-" + core.Hash(string(encoded))[:16]
}

func validateThreatIDSLibraryBundle(platform, arch string, bundle *threatIDSLibraryBundle, files map[string]string) error {
	url, err := threatIDSLibraryURL(arch)
	if err != nil || platform != "ubuntu-24.04" || bundle == nil || bundle.URL != url || !threatPackageSHA.MatchString(bundle.KeySHA) || len(bundle.Catalogs) != 3 || len(bundle.Packages) != 3 || len(files) != 9 {
		return errors.New("IDS 私有库来源集合不是已审核的 Ubuntu 24.04 ABI")
	}
	for _, suite := range []string{"noble", "noble-updates", "noble-security"} {
		if !threatPackageSHA.MatchString(bundle.Catalogs[suite]) {
			return errors.New("IDS 私有库缺少完整官方签名目录身份")
		}
	}
	version := ""
	for name, spec := range threatIDSEventLibraries {
		lib, ok := bundle.Packages[name]
		p := lib.Package
		if !ok || p.Name != name || p.Architecture != arch || !threatIDSLibraryVersion.MatchString(p.Version) || !threatPackageSHA.MatchString(p.SHA256) || !threatPackageSHA.MatchString(lib.MetadataSHA) || p.Size < 1024 || p.Size > 8<<20 || p.Filename != "pool/main/libe/libevent/"+name+"_"+p.Version+"_"+arch+".deb" || !regexp.MustCompile(spec.FilePattern).MatchString(lib.File) || version != "" && version != p.Version {
			return errors.New("IDS 私有库版本、包身份或普通文件选择不一致")
		}
		version = p.Version
		if name == "libevent-pthreads-2.1-7t64" {
			if p.Depends != "libc6 (>= 2.34), libevent-core-2.1-7t64 (= "+p.Version+")" {
				return errors.New("IDS 私有线程库依赖不属于已审核闭包")
			}
		} else if p.Depends != "libc6 (>= 2.38)" {
			return errors.New("IDS 私有事件库依赖不属于已审核闭包")
		}
		for _, file := range []string{"libraries/" + spec.SONAME, "licenses/" + name + "-copyright.txt"} {
			if !threatPackageSHA.MatchString(files[file]) {
				return errors.New("IDS 私有库或完整许可文件缺少摘要")
			}
		}
	}
	return nil
}

func threatIDSHostLibraryDependencies(raw string, isolated bool) string {
	if !isolated {
		return raw
	}
	entries := []string{}
	for _, entry := range strings.Split(raw, ",") {
		fields := strings.Fields(entry)
		if len(fields) > 0 {
			if _, private := threatIDSEventLibraries[fields[0]]; private {
				continue
			}
		}
		entries = append(entries, strings.TrimSpace(entry))
	}
	return strings.Join(entries, ", ")
}
