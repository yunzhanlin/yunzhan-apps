package executor

import (
	"net/netip"
	"testing"

	"local/panel/internal/loadbalancestream"
)

func streamListenerEvidenceFixture() ([]loadbalancestream.Entry, []loadBalanceStreamHostSocket, map[string]bool, []map[string]bool) {
	entries := []loadbalancestream.Entry{{Format: 1, Revision: 1, Name: "tcp.lb.invalid", Protocol: "tcp", Port: 42000, ProbePort: 43000, Nodes: []loadbalancestream.Node{{Address: "192.0.2.1:41000", Weight: 1}, {Address: "192.0.2.2:41001", Weight: 2}}, Method: "round-robin", ConnectMilliseconds: 1000, SessionSeconds: 30, MaxSessions: 16}}
	udp := entries[0]
	udp.Name = "udp.lb.invalid"
	udp.Protocol = "udp"
	udp.Port = 42001
	udp.ProbePort = 43001
	udp.UDPRequests = 1
	udp.UDPResponses = 1
	entries = append(entries, udp)
	rows := []loadBalanceStreamHostSocket{
		{"tcp", netip.MustParseAddrPort("127.0.0.1:42000"), netip.MustParseAddrPort("0.0.0.0:0"), 10, 991, 1},
		{"tcp", netip.MustParseAddrPort("127.0.0.1:43000"), netip.MustParseAddrPort("0.0.0.0:0"), 10, 991, 2},
		{"udp", netip.MustParseAddrPort("127.0.0.1:42001"), netip.MustParseAddrPort("0.0.0.0:0"), 7, 991, 3},
		{"tcp", netip.MustParseAddrPort("127.0.0.1:43001"), netip.MustParseAddrPort("0.0.0.0:0"), 10, 991, 4},
	}
	return entries, rows, map[string]bool{"1": true, "2": true, "3": true, "4": true}, []map[string]bool{{"1": true, "2": true, "3": true, "4": true}}
}

func TestLoadBalanceStreamListenerEvidenceJoinsEveryActualEndpointMasterAndWorker(t *testing.T) {
	entries, rows, master, workers := streamListenerEvidenceFixture()
	owned, err := matchStreamOwnedListeners(rows, master, workers, entries, 991)
	if err != nil || len(owned) != 4 || owned["tcp|127.0.0.1:42000"] != "1" || owned["udp|127.0.0.1:42001"] != "3" {
		t.Fatal("complete owned endpoint evidence refused", err)
	}
	// Ordinary old TCP clients and connected UDP peers do not become extra
	// listeners or a barrier that waits for every existing client to finish.
	rows = append(rows, loadBalanceStreamHostSocket{"tcp", netip.MustParseAddrPort("127.0.0.1:42000"), netip.MustParseAddrPort("127.0.0.1:52000"), 1, 991, 5}, loadBalanceStreamHostSocket{"udp", netip.MustParseAddrPort("127.0.0.1:52001"), netip.MustParseAddrPort("127.0.0.1:41000"), 1, 991, 6})
	workers = append(workers, map[string]bool{"5": true, "6": true})
	if got, err := matchStreamOwnedListeners(rows, master, workers, entries, 991); err != nil || len(got) != 4 {
		t.Fatal("retiring existing clients invented listeners", err)
	}
}

func TestLoadBalanceStreamListenerEvidenceUIDFingerprintAndPartialDescriptorsCannotClaimOwnership(t *testing.T) {
	for _, fault := range []string{"UID-only", "master-only", "worker-only", "missing-probe", "wrong-inode", "wrong-uid", "wildcard", "ipv6-alias", "extra-owned-listener", "foreign-same-port", "duplicate", "third-worker", "root-uid"} {
		t.Run(fault, func(t *testing.T) {
			entries, rows, master, workers := streamListenerEvidenceFixture()
			uid := uint32(991)
			switch fault {
			case "UID-only":
				master = map[string]bool{}
				workers = []map[string]bool{{}}
			case "master-only":
				workers = []map[string]bool{{}}
			case "worker-only":
				master = map[string]bool{"unused": true}
			case "missing-probe":
				rows = rows[:3]
			case "wrong-inode":
				rows[0].Inode = 99
			case "wrong-uid":
				rows[0].UID = 992
			case "wildcard":
				rows[0].Local = netip.MustParseAddrPort("0.0.0.0:42000")
			case "ipv6-alias":
				rows[0].Protocol = "tcp6"
				rows[0].Local = netip.MustParseAddrPort("[::1]:42000")
			case "extra-owned-listener":
				extra := rows[0]
				extra.Local = netip.MustParseAddrPort("127.0.0.1:42002")
				rows = append(rows, extra)
			case "foreign-same-port":
				extra := rows[0]
				extra.Inode = 99
				extra.UID = 992
				extra.Local = netip.MustParseAddrPort("0.0.0.0:42000")
				rows = append(rows, extra)
			case "duplicate":
				rows = append(rows, rows[0])
			case "third-worker":
				workers = append(workers, map[string]bool{}, map[string]bool{})
			case "root-uid":
				uid = 0
			}
			if got, err := matchStreamOwnedListeners(rows, master, workers, entries, uid); err == nil || got != nil {
				t.Fatal("unowned/partial listener evidence accepted", fault)
			}
		})
	}
}
