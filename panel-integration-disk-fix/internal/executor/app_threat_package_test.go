package executor

import (
	"reflect"
	"strings"
	"testing"
)

const threatAPTFixture = "Package: suricata\nVersion: 1:7.0.10-1+deb13u4\nArchitecture: amd64\nDepends: python3:any, libbpf1 (>= 1:0.7.0), libc6 (>= 2.39), libluajit-5.1-2 (>= 2.0.4) | libluajit2-5.1-2 (>= 2.1~), librte-eal25 (>= 23.11), libyaml-0-2, zlib1g (>= 1:1.1.4)\nFilename: pool/main/s/suricata/suricata_7.0.10-1+deb13u4_amd64.deb\nSize: 2987312\nSHA256: 25917d6784aa5c4150361c96b108b2b71ecf714bd14a908d98df45554e8acad6\nDescription: IDS engine\n continuation text ignored\n"

func TestThreatAPTPackageExactIdentityAndDependencies(t *testing.T) {
	result, err := parseThreatAPTMetadata("1:7.0.10-1+deb13u4", "amd64", threatAPTFixture)
	if err != nil || result.Name != "suricata" || result.Size != 2987312 || result.Architecture != "amd64" {
		t.Fatal(result, err)
	}
	dependencies, err := threatIDSDependencies(result.Depends)
	if err != nil || !reflect.DeepEqual(dependencies, []string{"libbpf1", "libc6", "libluajit-5.1-2", "librte-eal25", "libyaml-0-2", "zlib1g"}) {
		t.Fatal(dependencies, err)
	}
	if repeated, err := parseThreatAPTMetadata(result.Version, "amd64", threatAPTFixture+"\n"+threatAPTFixture); err != nil || repeated != result {
		t.Fatal("identical authenticated metadata rejected", repeated, err)
	}
	for _, version := range []string{"1:8.0.7-1~bpo13+1", "8.0.3-1", "1:7.0.3-1build3"} {
		if !threatAPTVersion.MatchString(version) {
			t.Fatal("expected audited major rejected", version)
		}
	}
	for _, version := range []string{"1:6.0.4-3", "9.0.0-1", "1:7x0x10-1", "1:7.0.10;id", "1:7.0.10/../x", "-y", "1:7.0.10\n"} {
		if threatAPTVersion.MatchString(version) {
			t.Fatal("unaudited version accepted", version)
		}
	}
}
func TestThreatAPTPackageRefusesMissingChangedDuplicateOrTraversal(t *testing.T) {
	for _, input := range []string{
		strings.Replace(threatAPTFixture, "Package: suricata", "Package: other-service", 1),
		strings.Replace(threatAPTFixture, "Architecture: amd64", "Architecture: arm64", 1),
		strings.Replace(threatAPTFixture, "Size: 2987312", "Size: 33554433", 1),
		strings.Replace(threatAPTFixture, "Size: 2987312", "Size: 1", 1),
		strings.Replace(threatAPTFixture, "SHA256: 2591", "SHA256: xxxx", 1),
		strings.Replace(threatAPTFixture, "pool/main/s/suricata/", "pool/../suricata/", 1),
		strings.Replace(threatAPTFixture, "pool/main/s/suricata/", "pool//main/s/suricata/", 1),
		strings.Replace(threatAPTFixture, "_amd64.deb", "_arm64.deb", 1),
		threatAPTFixture + "Size: 2987312\n",
		threatAPTFixture + "\n" + strings.Replace(threatAPTFixture, "Size: 2987312", "Size: 2987313", 1),
		strings.Replace(threatAPTFixture, "libbpf1", "openssh-server", 1),
	} {
		if _, err := parseThreatAPTMetadata("1:7.0.10-1+deb13u4", "amd64", input); err == nil {
			t.Fatal("invalid authenticated candidate accepted", input)
		}
	}
}
func TestThreatAPTDependenciesClosedListNoShellProfilesOrUnexpectedAlternatives(t *testing.T) {
	for _, input := range []string{"", "python3:any", "libc6,", "libc6, openssh-server", "libc6; id", "libc6 && id", "libc6 (>= 2.39); id", "libc6:any", "libc6 [amd64]", "libc6 | libbpf1", "libluajit-5.1-2 | openssh-server", "libluajit-5.1-2 | libluajit2-5.1-2 | libc6", "libc6\nlibbpf1", "libc6, python3:any && touch /tmp/unsafe", "librte-eal99, libc6"} {
		if _, err := threatIDSDependencies(input); err == nil {
			t.Fatal("invalid package expression accepted", input)
		}
	}
}

func TestThreatAPTUbuntu8NativeClosureExcludesUnexecutedHelperPackages(t *testing.T) {
	// Exact Depends of authenticated OISF 1:8.0.7-0ubuntu0 ARM64 package,
	// SHA256 c67e43c958c4f9e0b19438c0b0b5ce7f9384d249553a419599f4507437ae4f2d.
	raw := "libc6 (>= 2.38), libcap-ng0 (>= 0.7.9), libevent-2.1-7t64 (>= 2.1.8-stable), libevent-pthreads-2.1-7t64 (>= 2.1.8-stable), libgcc-s1 (>= 4.2), libhiredis1.1.0 (>= 1.2.0), libjansson4 (>= 2.14), liblz4-1 (>= 0.0~r127), libmagic1t64 (>= 5.12), libmaxminddb0 (>= 1.0.2), libnet1 (>= 1.1.5), libnetfilter-queue1 (>= 1.0.2), libnfnetlink0 (>= 1.0.2), libpcap0.8t64 (>= 1.0.0), libpcre2-8-0 (>= 10.22), libunwind8, libyaml-0-2, zlib1g (>= 1:1.2.3.4), lsb-base (>= 3.0-6), python3, python3-yaml, liblua5.1-0"
	libraries, err := threatIDSDependencies(raw)
	if err != nil || len(libraries) != 19 {
		t.Fatal(libraries, err)
	}
	for _, name := range libraries {
		if threatIDSNonEngineDependency(name) || !threatAPTInstallName(name) {
			t.Fatal("helper package installed or unreviewed library accepted", name)
		}
	}
	for _, name := range []string{"python3", "python3:any", "python3-yaml", "procps", "lsb-base"} {
		if !threatIDSNonEngineDependency(name) || threatAPTInstallName(name) {
			t.Fatal("helper classification widened installation", name)
		}
	}
	for _, raw := range []string{"libc6, python3-yaml | python3", "libc6, lsb-base | libc6", "libc6, python3-yaml:any", "libc6, python3-yaml (>= 6.0); id", "libc6, lsb-release", "libc6, liblua5.4-0"} {
		if _, err := threatIDSDependencies(raw); err == nil {
			t.Fatal("unreviewed helper or library accepted", raw)
		}
	}
	plan := "0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.\nInst liblua5.1-0 (5.1.5-9build2 Ubuntu:24.04 [arm64])\n"
	if err := validateThreatAPTPlan(plan); err != nil {
		t.Fatal(err)
	}
	for _, helper := range []string{"lsb-base", "python3-yaml", "suricata", "suricata-update"} {
		if err := validateThreatAPTPlan(strings.Replace(plan, "Inst liblua5.1-0", "Inst "+helper, 1)); err == nil {
			t.Fatal("helper/service installation plan accepted", helper)
		}
	}
}

func TestThreatAPTPlanRefusesTransitiveUpgradeRemovalServicesAndIncompleteSummary(t *testing.T) {
	valid := "0 upgraded, 2 newly installed, 0 to remove and 0 not upgraded.\nInst libbpf1 (1:1.3.0 Ubuntu:24.04 [arm64])\nInst ibverbs-providers (1:50.0 Ubuntu:24.04 [arm64])\nConf libbpf1 (1:1.3.0 Ubuntu:24.04 [arm64])\n"
	isa := "0 upgraded, 3 newly installed, 0 to remove and 21 not upgraded.\nInst isa-support (27 Debian:13.7/stable [amd64])\nInst sse3-support (27 Debian:13.7/stable [amd64])\nInst sse4.2-support (27 Debian:13.7/stable [amd64])\n"
	if err := validateThreatAPTPlan(isa); err != nil {
		t.Fatal("fixed Hyperscan ISA checks rejected", err)
	}
	for _, bad := range []string{strings.Replace(isa, "Inst isa-support (", "Inst isa-support [26] (", 1), strings.Replace(isa, "sse3-support", "avx2-support", 1), strings.Replace(isa, "sse4.2-support", "rdma-core", 1)} {
		if err := validateThreatAPTPlan(bad); err == nil {
			t.Fatal("unaudited or upgrade ISA plan accepted")
		}
	}
	for _, name := range []string{"libvirt-daemon-system", "libnss-systemd", "libpam-systemd", "libunreviewed-agent1", "librte-net-bond99"} {
		if err := validateThreatAPTPlan(strings.Replace(valid, "Inst libbpf1", "Inst "+name, 1)); err == nil {
			t.Fatal("unreviewed lib-prefixed daemon/transitive package accepted", name)
		}
	}
	for _, name := range []string{"libevent-core-2.1-7t64", "libluajit-5.1-common", "librte-bus-pci25", "librte-ip-frag25", "libnl-route-3-200"} {
		if err := validateThreatAPTPlan(strings.Replace(valid, "Inst libbpf1", "Inst "+name, 1)); err != nil {
			t.Fatal("reviewed fixed native closure refused", name, err)
		}
	}
	if err := validateThreatAPTPlan(valid); err != nil {
		t.Fatal(err)
	}
	if err := validateThreatAPTPlan("0 upgraded, 0 newly installed, 0 to remove and 4 not upgraded.\n"); err != nil {
		t.Fatal("already installed dependencies rejected", err)
	}
	for _, plan := range []string{
		strings.Replace(valid, "Inst libbpf1 (", "Inst libbpf1 [1:0.9.0] (", 1),
		strings.Replace(valid, "0 upgraded", "1 upgraded", 1),
		strings.Replace(valid, "0 to remove", "1 to remove", 1),
		strings.Replace(valid, "Inst libbpf1", "Inst openssh-server", 1),
		strings.Replace(valid, "Inst libbpf1", "Inst suricata", 1),
		strings.Replace(valid, "2 newly installed", "3 newly installed", 1),
		valid + "Remv libc6 [2.39]\n", valid + "Purg libhtp2\n", valid + "E: unauthenticated\n",
		"Inst libbpf1 (1:1.3.0 Ubuntu [arm64])\n", valid + valid,
	} {
		if err := validateThreatAPTPlan(plan); err == nil {
			t.Fatal("unsafe APT plan accepted", plan)
		}
	}
}
