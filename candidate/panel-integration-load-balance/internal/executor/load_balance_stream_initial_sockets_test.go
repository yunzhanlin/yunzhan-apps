package executor

import (
	"local/panel/internal/loadbalancestream"
	"net/netip"
	"testing"
)

func TestLoadBalanceStreamInitialPortConflictDistinguishesClosedTimeWaitFromLiveSockets(t *testing.T) {
	entries := []loadbalancestream.Entry{{Protocol: "tcp", Port: 41080, ProbePort: 60000}, {Protocol: "udp", Port: 41081, ProbePort: 59999}}
	for _, protocol := range []string{"tcp", "tcp6"} {
		local, remote := "127.0.0.1:60000", "127.0.0.1:43210"
		if protocol == "tcp6" {
			local, remote = "[::1]:60000", "[::1]:43210"
		}
		closed := loadBalanceStreamHostSocket{Protocol: protocol, Local: netip.MustParseAddrPort(local), Remote: netip.MustParseAddrPort(remote), State: 6}
		if streamInitialSocketConflicts(closed, entries) {
			t.Fatal("ownerless closed kernel TIME_WAIT mistaken for a live listener")
		}
		for _, fault := range []string{"UID", "inode", "established", "listen", "bound", "unspecified-remote", "zero-remote-port"} {
			row := closed
			switch fault {
			case "UID":
				row.UID = 988
			case "inode":
				row.Inode = 123
			case "established":
				row.State = 1
			case "listen":
				row.State = 10
			case "bound":
				row.State = 7
			case "unspecified-remote":
				row.Remote = netip.MustParseAddrPort("0.0.0.0:43210")
			case "zero-remote-port":
				row.Remote = netip.MustParseAddrPort("127.0.0.1:0")
			}
			if !streamInitialSocketConflicts(row, entries) {
				t.Fatal("live or noncanonical socket stopped blocking", protocol, fault)
			}
		}
	}
	for _, protocol := range []string{"udp", "udp6"} {
		row := loadBalanceStreamHostSocket{Protocol: protocol, Local: netip.MustParseAddrPort("127.0.0.1:41081"), Remote: netip.MustParseAddrPort("127.0.0.1:43210"), State: 6}
		if !streamInitialSocketConflicts(row, entries) {
			t.Fatal("UDP borrowed TCP TIME_WAIT semantics")
		}
	}
}
