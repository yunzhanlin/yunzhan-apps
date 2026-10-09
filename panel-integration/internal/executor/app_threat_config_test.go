package executor

import (
	"strings"
	"testing"
)

func TestThreatIDSConfigClosedPassiveAndPrivateLogGeneration(t *testing.T) {
	in := threatIDSConfig{Revision: 1, Interface: "eth0", HomeNetworks: []string{"192.0.2.0/24", "2001:db8::/32"}}
	config, err := threatIDSYAML(in, "/opt/panel/app-modules/network-threat-detection/rules/cloudstack.rules", "/var/lib/panel-network-ids/logs")
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{`HOME_NET: "[192.0.2.0/24,2001:db8::/32]"`, `interface: "eth0"`, "disable-promisc: yes", "tpacket-v3: yes", "block-size: 1048576", "disable-offloading: false", "threads: 1", "payload: no", "http-body: no", "metadata: no", "packet: no", "interval: 5", "memcap: 64mb"} {
		if !strings.Contains(config, marker) {
			t.Fatal("closed configuration missing:", marker)
		}
	}
	for _, unsafe := range []string{"copy-mode", "nfqueue", "include:", "lua:", "redis", "request_headers"} {
		if strings.Contains(config, unsafe) {
			t.Fatal("passive capture widened", unsafe)
		}
	}
	if _, err := threatIDSYAML(in, "/tmp/other.rules", "/var/lib/panel-network-ids/logs"); err == nil {
		t.Fatal("arbitrary rule path accepted")
	}
	if _, err := threatIDSYAML(in, "/opt/panel/app-modules/network-threat-detection/rules/cloudstack.rules", "/tmp/output"); err == nil {
		t.Fatal("arbitrary output path accepted")
	}
}
func TestThreatIDSConfigRejectsInterfaceInjectionAndAmbiguousNetworks(t *testing.T) {
	valid := threatIDSConfig{Interface: "lo", HomeNetworks: []string{"127.0.0.1/32", "::1/128"}}
	if err := validateThreatIDSConfig(valid); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "any", "../etc", "eth0\noutputs:", "eth0;id", "eth0\"", "-i", strings.Repeat("e", 16)} {
		in := valid
		in.Interface = name
		if validateThreatIDSConfig(in) == nil {
			t.Fatal("bad interface accepted", name)
		}
	}
	for _, cidrs := range [][]string{nil, {"0.0.0.0/0"}, {"::/0"}, {"192.0.2.1/24"}, {"::ffff:192.0.2.1/128"}, {"ff00::/8"}, {"fe80::1%eth0/128"}, {"127.0.0.1/32", "127.0.0.1/32"}, {"192.0.2.0/24\ninclude: unsafe"}} {
		in := valid
		in.HomeNetworks = cidrs
		if validateThreatIDSConfig(in) == nil {
			t.Fatal("unsafe home range accepted", cidrs)
		}
	}
	in := valid
	in.Revision = -1
	if validateThreatIDSConfig(in) == nil {
		t.Fatal("negative revision accepted")
	}
	in.Revision = 1 << 60
	if validateThreatIDSConfig(in) == nil {
		t.Fatal("revision exhaustion accepted")
	}
}
