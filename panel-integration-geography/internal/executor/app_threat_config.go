package executor

import (
	"errors"
	"fmt"
	"local/panel/internal/core"
	"net/netip"
	"regexp"
	"strings"
)

type threatIDSConfig struct {
	Revision     int64                             `json:"revision"`
	Interface    string                            `json:"interface"`
	HomeNetworks []string                          `json:"home_networks"`
	RuleFeed     *core.NetworkIDSRuleFeedSelection `json:"rule_feed,omitempty"`
}

var threatIDSInterface = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$`)

func validateThreatIDSConfig(in threatIDSConfig) error {
	if in.Revision < 0 || in.Revision >= 1<<60 || !threatIDSInterface.MatchString(in.Interface) || in.Interface == "any" || len(in.HomeNetworks) == 0 || len(in.HomeNetworks) > 16 {
		return errors.New("IDS 修订、真实接口名称或本机网段范围无效")
	}
	if in.RuleFeed != nil {
		if err := core.ValidateNetworkIDSRuleProfile(core.NetworkIDSRuleProfileSelection{Source: "verified-feed", Selection: in.RuleFeed}); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, raw := range in.HomeNetworks {
		network, err := netip.ParsePrefix(raw)
		if err != nil || network.Bits() == 0 || network != network.Masked() || network.Addr().Is4In6() || network.Addr().IsMulticast() || network.Addr().Zone() != "" || raw != network.String() || seen[raw] {
			return errors.New("IDS 本机范围必须为明确、规范且不重复的 IPv4/IPv6 CIDR；不接受 /0")
		}
		seen[raw] = true
	}
	return nil
}

// Only passive AF_PACKET capture is generated. No NFQUEUE, copy-mode, BPF,
// rule files, includes, Lua, filenames, external commands or inline IPS options
// can be supplied by a client. Encrypted application bodies remain encrypted.
func threatIDSYAML(in threatIDSConfig, rulesPath, logPath string) (string, error) {
	if err := validateThreatIDSConfig(in); err != nil {
		return "", err
	}
	if rulesPath != "/opt/panel/app-modules/network-threat-detection/rules/cloudstack.rules" || logPath != "/var/lib/panel-network-ids/logs" {
		return "", errors.New("IDS 只能使用固定的受管规则和日志目录")
	}
	if in.RuleFeed != nil {
		return threatIDSRuleDataYAML(in, *in.RuleFeed)
	}
	home := strings.Join(in.HomeNetworks, ",")
	return fmt.Sprintf(`%%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: %q
    EXTERNAL_NET: "any"
  port-groups:
    HTTP_PORTS: "any"
    SHELLCODE_PORTS: "!80"
    SSH_PORTS: "22"
default-log-dir: %q
default-rule-path: "/opt/panel/app-modules/network-threat-detection/rules"
classification-file: "/opt/panel/app-modules/network-threat-detection/rules/classification.config"
reference-config-file: "/opt/panel/app-modules/network-threat-detection/rules/reference.config"
threshold-file: "/opt/panel/app-modules/network-threat-detection/rules/threshold.config"
rule-files:
  - "cloudstack.rules"
runmode: workers
max-pending-packets: 256
af-packet:
  - interface: %q
    threads: 1
    cluster-id: 97
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
    block-size: 1048576
    block-timeout: 10
    ring-size: 256
    buffer-size: 65536
    disable-promisc: yes
    checksum-checks: kernel
capture:
  disable-offloading: false
stream:
  memcap: 32mb
  checksum-validation: yes
  midstream: false
  reassembly:
    memcap: 64mb
    depth: 1mb
flow:
  memcap: 32mb
  hash-size: 4096
  prealloc: 1000
defrag:
  memcap: 16mb
  hash-size: 4096
  trackers: 1024
  max-frags: 8192
  prealloc: yes
detect:
  profile: low
  sgh-mpm-context: auto
  inspection-recursion-limit: 1000
stats:
  enabled: yes
  interval: 5
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      buffer-size: 0
      types:
        - alert:
            payload: no
            packet: no
            http-body: no
            http-body-printable: no
            metadata: no
            tagged-packets: no
        - stats:
            totals: yes
            threads: no
            deltas: no
            null-values: true
logging:
  default-log-level: warning
  outputs:
    - console:
        enabled: yes
unix-command:
  enabled: no
pcap-log:
  enabled: no
`, "["+home+"]", logPath, in.Interface), nil
}
