package executor

import (
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Package extraction does not run Suricata's maintainer scripts or touch the
// host's existing /etc/suricata configuration/service. Libraries are closed-list
// dependencies; this type is not a request-controlled package installer.
type threatIDSPackage struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	Depends      string `json:"depends"`
	Filename     string `json:"filename"`
}

var threatAPTVersion = regexp.MustCompile(`^(1:)?[78]\.[0-9]+\.[0-9]+[A-Za-z0-9.+~_-]{0,100}$`)
var threatPackageSHA = regexp.MustCompile(`^[a-f0-9]{64}$`)
var threatPackageFile = regexp.MustCompile(`^pool/[a-z0-9/.-]+/suricata_[A-Za-z0-9.+~_-]+_(amd64|arm64)\.deb$`)
var threatDPDKDependency = regexp.MustCompile(`^librte-(eal|ethdev|kvargs|log|mbuf|mempool|net-bond)(23|24|25|26)$`)

var threatAPTTransitiveDPDK = regexp.MustCompile(`^librte-(bus-pci|bus-vdev|eal|ethdev|hash|ip-frag|kvargs|log|mbuf|mempool|meter|net-bond|net|pci|rcu|ring|sched|telemetry)(23|24|25|26)$`)
var threatAPTPlanSummary = regexp.MustCompile(`^([0-9]+) upgraded, ([0-9]+) newly installed, ([0-9]+) to remove and [0-9]+ not upgraded\.$`)

func threatAPTInstallName(name string) bool {
	// Debian's Hyperscan ISA prerequisite checks are fixed CPU-test packages,
	// not a service or API-selected command. Never broaden to arbitrary tools.
	return threatIDSAllowedLibraries[name] || threatIDSAdditionalLibraries[name] || threatAPTTransitiveDPDK.MatchString(name) || name == "ibverbs-providers" || name == "isa-support" || name == "sse3-support" || name == "sse4.2-support"
}

// An arbitrary lib* package can still contain daemon maintainer scripts. Keep
// the reviewed direct and transitive closure explicit; unknown plans fail.
var threatIDSAdditionalLibraries = map[string]bool{
	"libevent-core-2.1-7": true, "libevent-core-2.1-7t64": true,
	"libluajit-5.1-common": true, "libluajit2-5.1-common": true,
	"libfdt1": true, "libibverbs1": true, "libnl-3-200": true, "libnl-route-3-200": true,
	"libhwloc-plugins": true, "libpciaccess0": true, "libxnvctrl0": true,
	"libx11-6": true, "libx11-data": true, "libx11-xcb1": true, "libxcb1": true, "libxau6": true, "libxdmcp6": true,
	"libatomic1": true, "libstdc++6": true, "libcap2": true, "libdbus-1-3": true,
	"libelf1": true, "libelf1t64": true, "libssl3": true, "libssl3t64": true,
	"libudev1": true, "libgcrypt20": true, "libgpg-error0": true,
}

// Inspect the real APT plan before any library installation. --no-upgrade on
// requested names alone cannot authorize transitive upgrades or removals.
func validateThreatAPTPlan(output string) error {
	if len(output) > 128<<10 {
		return errors.New("IDS 依赖计划超过读取上限")
	}
	installs := map[string]bool{}
	summaries := 0
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Remv ") || strings.HasPrefix(line, "Purg ") || strings.HasPrefix(line, "E:") {
			return errors.New("IDS 依赖计划包含移除或错误；未运行安装")
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "Inst" {
			if len(fields) < 3 || strings.HasPrefix(fields[2], "[") || fields[2][0] != '(' || !threatAPTInstallName(fields[1]) || installs[fields[1]] {
				return errors.New("IDS 依赖计划含既有软件升级、重复或非库程序；未运行安装")
			}
			installs[fields[1]] = true
		}
		if summary := threatAPTPlanSummary.FindStringSubmatch(line); len(summary) == 4 {
			added, err := strconv.Atoi(summary[2])
			if err != nil || summary[1] != "0" || summary[3] != "0" {
				return errors.New("IDS 依赖计划将升级或移除既有包；未运行安装")
			}
			if added > 200 {
				return errors.New("IDS 新增库计划超过 200 包上限")
			}
			summaries++
			if summaries > 1 {
				return errors.New("IDS 依赖计划摘要重复")
			}
			// Actual Inst lines occur after this summary; bind their count below.
		}
	}
	if summaries != 1 {
		return errors.New("IDS 依赖计划缺少完整摘要；未运行安装")
	}
	for _, line := range strings.Split(output, "\n") {
		if summary := threatAPTPlanSummary.FindStringSubmatch(strings.TrimSpace(line)); len(summary) == 4 {
			added, _ := strconv.Atoi(summary[2])
			if added != len(installs) {
				return errors.New("IDS 依赖计划摘要与实际包集合不符")
			}
		}
	}
	return nil
}

var threatIDSAllowedLibraries = map[string]bool{
	"libbpf1": true, "libbsd0": true, "libc6": true, "libcap-ng0": true, "libevent-2.1-7": true, "libevent-2.1-7t64": true,
	"libevent-pthreads-2.1-7": true, "libevent-pthreads-2.1-7t64": true, "libgcc-s1": true,
	"libhiredis0.14": true, "libhiredis1.1.0": true, "libhtp2": true, "libhwloc15": true, "libhyperscan5": true,
	"libjansson4": true, "liblua5.1-0": true, "libluajit-5.1-2": true, "libluajit2-5.1-2": true, "liblz4-1": true,
	"libmagic1": true, "libmagic1t64": true, "libmaxminddb0": true, "libnet1": true, "libnet9": true,
	"libnetfilter-log1": true, "libnetfilter-queue1": true, "libnfnetlink0": true, "libnuma1": true,
	"libpcap0.8": true, "libpcap0.8t64": true, "libpcre2-8-0": true, "libsystemd0": true, "libunwind8": true, "libxdp1": true, "libyaml-0-2": true, "zlib1g": true,
}

// The fixed native ELF is extracted without running distro maintainer scripts,
// init scripts, suricatactl or suricata-update. These explicitly reviewed helper
// dependencies are not installed or executed. Unknown tools still fail closed.
// Keep this same classification in the post-install ABI constraint check.
func threatIDSNonEngineDependency(name string) bool {
	return name == "python3:any" || name == "python3" || name == "python3-yaml" || name == "procps" || name == "lsb-base"
}

func threatIDSDependencies(raw string) ([]string, error) {
	if raw == "" || len(raw) > 8192 || strings.ContainsAny(raw, "\r\n\x00") {
		return nil, errors.New("IDS 原生包依赖记录无效")
	}
	seen := map[string]bool{}
	for _, entry := range strings.Split(raw, ",") {
		alternatives := strings.Split(entry, "|")
		if len(alternatives) > 2 {
			return nil, errors.New("IDS 依赖备选结构未审核")
		}
		first := ""
		for i, alternative := range alternatives {
			fields := strings.Fields(strings.TrimSpace(alternative))
			if len(fields) == 0 {
				return nil, errors.New("IDS 依赖为空")
			}
			name := fields[0]
			ignored := len(alternatives) == 1 && threatIDSNonEngineDependency(name)
			if !ignored && !threatIDSAllowedLibraries[name] && !threatDPDKDependency.MatchString(name) {
				return nil, errors.New("IDS 原生库依赖不在已审核清单中")
			}
			if len(alternatives) == 2 && name != "libluajit-5.1-2" && name != "libluajit2-5.1-2" {
				return nil, errors.New("IDS 依赖备选未审核")
			}
			// Only a package name and a parenthesized Debian version comparison may
			// follow it; no architecture profiles, options, shells or API text.
			suffix := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(alternative), name))
			if suffix != "" && !regexp.MustCompile(`^\((>=|=|>>|<=|<<) [0-9A-Za-z.+:~_-]+\)$`).MatchString(suffix) {
				return nil, errors.New("IDS 依赖约束结构无效")
			}
			if ignored {
				continue
			}
			if i == 0 {
				first = name
			}
		}
		if first != "" {
			seen[first] = true
		}
	}
	result := []string{}
	for name := range seen {
		result = append(result, name)
	}
	sort.Strings(result)
	if len(result) == 0 || len(result) > 48 {
		return nil, errors.New("IDS 原生库数量无效")
	}
	return result, nil
}
func parseThreatAPTMetadata(version, arch, data string) (threatIDSPackage, error) {
	var result threatIDSPackage
	if !threatAPTVersion.MatchString(version) || arch != "amd64" && arch != "arm64" || len(data) > 128<<10 {
		return result, errors.New("IDS 包版本或架构不在当前审核范围")
	}
	for _, paragraph := range strings.Split(strings.TrimSpace(data), "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(paragraph, "\n") {
			if line == "" || line[0] == ' ' || line[0] == '\t' {
				continue
			}
			key, value, ok := strings.Cut(line, ":")
			if !ok {
				return result, errors.New("IDS APT 元数据格式无效")
			}
			if _, duplicate := fields[key]; duplicate {
				return result, errors.New("IDS APT 元数据重复字段")
			}
			fields[key] = strings.TrimSpace(value)
		}
		if fields["Package"] != "suricata" || fields["Version"] != version || fields["Architecture"] != arch {
			continue
		}
		size, err := strconv.ParseInt(fields["Size"], 10, 64)
		if err != nil || size < 1024 || size > 32<<20 || !threatPackageSHA.MatchString(fields["SHA256"]) || !threatPackageFile.MatchString(fields["Filename"]) || strings.Contains(fields["Filename"], "..") || strings.Contains(fields["Filename"], "//") || !strings.HasSuffix(fields["Filename"], "_"+arch+".deb") {
			return result, errors.New("IDS APT 包完整摘要、大小或路径无效")
		}
		if _, err = threatIDSDependencies(fields["Depends"]); err != nil {
			return result, err
		}
		next := threatIDSPackage{"suricata", version, arch, fields["SHA256"], size, fields["Depends"], fields["Filename"]}
		if result.Name != "" && result != next {
			return result, errors.New("同版本 IDS APT 来源元数据不一致")
		}
		result = next
	}
	if result.Name == "" {
		return result, errors.New("没有匹配当前候选版本的完整 IDS APT 元数据")
	}
	return result, nil
}
