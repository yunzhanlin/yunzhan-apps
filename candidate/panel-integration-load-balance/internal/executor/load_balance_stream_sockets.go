package executor

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"

	"local/panel/internal/loadbalancestream"
)

const streamSocketTableBytes = 16 << 20
const streamSocketTableRows = 65536

type loadBalanceStreamHostSocket struct {
	Protocol string
	Local    netip.AddrPort
	Remote   netip.AddrPort
	State    uint8
	UID      uint32
	Inode    uint64
}

// TIME_WAIT is a closed kernel TCP endpoint, not a userspace descriptor or a
// listener. Only its canonical ownerless shape may be omitted from the known
// conflict set. This is never a claim that a port is free: the original single
// native bind and complete owned listener/process/cgroup checks still decide
// activation. Every live/unknown TCP state and every UDP socket remain blocking.
func streamInitialSocketConflicts(socket loadBalanceStreamHostSocket, entries []loadbalancestream.Entry) bool {
	if (socket.Protocol == "tcp" || socket.Protocol == "tcp6") && socket.State == 6 && socket.Inode == 0 && socket.UID == 0 &&
		socket.Remote.IsValid() && !socket.Remote.Addr().IsUnspecified() && socket.Remote.Port() != 0 {
		return false
	}
	for _, entry := range entries {
		if entry.Removed {
			continue
		}
		port := int(socket.Local.Port())
		if (socket.Protocol == "tcp" || socket.Protocol == "tcp6") && (port == entry.ProbePort || entry.Protocol == "tcp" && port == entry.Port) ||
			(socket.Protocol == "udp" || socket.Protocol == "udp6") && entry.Protocol == "udp" && port == entry.Port {
			return true
		}
	}
	return false
}

func streamSocketAddress(value string, ipv6 bool) (netip.AddrPort, bool) {
	length := 8
	if ipv6 {
		length = 32
	}
	if len(value) != length+5 || value[length] != ':' || value != strings.ToUpper(value) {
		return netip.AddrPort{}, false
	}
	raw, err := hex.DecodeString(value[:length])
	if err != nil {
		return netip.AddrPort{}, false
	}
	// The supported native architectures are both little endian. procfs
	// displays each address word as a host-endian 32-bit hexadecimal value.
	for i := 0; i < len(raw); i += 4 {
		v := binary.BigEndian.Uint32(raw[i : i+4])
		binary.LittleEndian.PutUint32(raw[i:i+4], v)
	}
	ip, ok := netip.AddrFromSlice(raw)
	port, err := strconv.ParseUint(value[length+1:], 16, 16)
	if !ok || err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip, uint16(port)), true
}

// Bounded kernel table decoder only. UID/inode text is NOT process ownership,
// port admission, an authorization grant or a service/forwarding health check.
// TCP TIME_WAIT may legitimately have inode0 and no userspace owner; callers
// must not adopt it as an owned listener or silently call its port free.
func decodeStreamSocketTable(raw []byte, protocol string) ([]loadBalanceStreamHostSocket, error) {
	if protocol != "tcp" && protocol != "tcp6" && protocol != "udp" && protocol != "udp6" || len(raw) == 0 || len(raw) > streamSocketTableBytes || !strings.HasSuffix(string(raw), "\n") || strings.ContainsAny(string(raw), "\x00\r") {
		return nil, loadbalancestream.ErrService
	}
	lines := strings.Split(string(raw), "\n")
	if len(lines) > streamSocketTableRows+2 {
		return nil, loadbalancestream.ErrService
	}
	header := strings.Fields(lines[0])
	headerTail := "st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode"
	if strings.HasPrefix(protocol, "udp") {
		headerTail += " ref pointer drops"
	}
	if len(header) < 12 || header[0] != "sl" || header[1] != "local_address" || header[2] != "rem_address" && header[2] != "remote_address" || strings.Join(header[3:], " ") != headerTail {
		return nil, loadbalancestream.ErrService
	}
	var out []loadBalanceStreamHostSocket
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 || len(fields) > 24 || len(line) > 2048 {
			return nil, loadbalancestream.ErrService
		}
		slot, ok := strings.CutSuffix(fields[0], ":")
		if !ok {
			return nil, loadbalancestream.ErrService
		}
		if n, err := strconv.ParseUint(slot, 10, 32); err != nil || strconv.FormatUint(n, 10) != slot {
			return nil, loadbalancestream.ErrService
		}
		local, ok := streamSocketAddress(fields[1], strings.HasSuffix(protocol, "6"))
		remote, ok2 := streamSocketAddress(fields[2], strings.HasSuffix(protocol, "6"))
		state, err := strconv.ParseUint(fields[3], 16, 8)
		if !ok || !ok2 || err != nil || len(fields[3]) != 2 || fields[3] != strings.ToUpper(fields[3]) || state == 0 || state > 12 || local.Port() == 0 {
			return nil, loadbalancestream.ErrService
		}
		uid, e1 := strconv.ParseUint(fields[7], 10, 32)
		inode, e2 := strconv.ParseUint(fields[9], 10, 64)
		if e1 != nil || e2 != nil || strconv.FormatUint(uid, 10) != fields[7] || strconv.FormatUint(inode, 10) != fields[9] {
			return nil, loadbalancestream.ErrService
		}
		// These are actual server/bound socket shapes; they cannot be inferred
		// from a successful HTTP fingerprint or an account's UID alone.
		if state == 10 && strings.HasPrefix(protocol, "tcp") && (inode == 0 || !remote.Addr().IsUnspecified() || remote.Port() != 0) {
			return nil, loadbalancestream.ErrService
		}
		if state == 7 && strings.HasPrefix(protocol, "udp") && (inode == 0 || !remote.Addr().IsUnspecified() || remote.Port() != 0) {
			return nil, loadbalancestream.ErrService
		}
		out = append(out, loadBalanceStreamHostSocket{protocol, local, remote, uint8(state), uint32(uid), inode})
	}
	return out, nil
}
