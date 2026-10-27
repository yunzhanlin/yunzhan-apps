// Package loadbalancestream defines closed, bounded layer-4 configuration data.
// It does not grant filesystem, Nginx reload, listener ownership or health authority.
package loadbalancestream

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const (
	MaxEntries      = 128
	MaxEntryBytes   = 16 << 10
	BytesPerSession = int64(128 << 10)
	// Two 1MiB shared zones also support Nginx on 64KiB-page ARM64 hosts.
	FixedBytesPerEntry = int64(2<<20) + MaxEntryBytes
	MaxMemoryBudget    = int64(1 << 30)
)

var ErrEntry = errors.New("TCP/UDP 入口的规范身份、私有端口、节点或有限资源策略无效")
var ErrSet = errors.New("TCP/UDP 入口与现有监听、控制端口、内存预算或转发环路冲突")

type Node struct {
	Address string `json:"address"`
	Weight  int    `json:"weight"`
	Backup  bool   `json:"backup"`
}

// Entry is privileged immutable metadata, never a browser mutation request.
// ProbePort is selected and conflict-checked by the controller, not the client.
type Entry struct {
	Format              int    `json:"format"`
	Revision            int64  `json:"revision"`
	Name                string `json:"name"`
	Protocol            string `json:"protocol"`
	Port                int    `json:"port"`
	ProbePort           int    `json:"probe_port"`
	Nodes               []Node `json:"nodes"`
	Method              string `json:"method"`
	ConnectMilliseconds int    `json:"connect_milliseconds"`
	SessionSeconds      int    `json:"session_seconds"`
	MaxSessions         int    `json:"max_sessions"`
	UDPRequests         int    `json:"udp_requests"`
	UDPResponses        int    `json:"udp_responses"`
	Removed             bool   `json:"removed"`
}

// ValidationContext contains fresh server facts, NOT request fields or authority.
// The controller must supply actual custom control ports and an independently
// measured buffer/zone planning budget. This is NOT an RSS/kernel-memory cap;
// the caller still needs host and service resource admission. No existing
// source, native-read or programme-upgrade policy is increased.
type ValidationContext struct {
	PanelControlPorts []int
	OccupiedTCPPorts  []int
	OccupiedUDPPorts  []int
	MemoryBudgetBytes int64
}

type Configuration struct {
	Stream      []byte
	HTTP        []byte
	Fingerprint string
}

func validName(name string) bool {
	if len(name) < 3 || len(name) > 253 || name != strings.ToLower(name) || net.ParseIP(name) != nil {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func nodeAddress(raw string) (netip.Addr, int, error) {
	host, port, err := net.SplitHostPort(raw)
	ip, ipErr := netip.ParseAddr(host)
	number, numberErr := strconv.Atoi(port)
	if err != nil || ipErr != nil || numberErr != nil || number < 1 || number > 65535 ||
		port != strconv.Itoa(number) || raw != net.JoinHostPort(ip.String(), port) ||
		ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.Is4In6() || ip.Zone() != "" ||
		ip == netip.MustParseAddr("255.255.255.255") || ip == netip.MustParseAddr("fd00:ec2::254") ||
		ip == netip.MustParseAddr("100.100.100.200") {
		return netip.Addr{}, 0, ErrEntry
	}
	return ip, number, nil
}

func standardControlPort(port int) bool { return port == 19100 || port == 19102 || port == 19080 }

func Validate(entry Entry) error {
	if entry.Format != 1 || entry.Revision < 1 || entry.Revision >= 1<<60 || !validName(entry.Name) ||
		(entry.Protocol != "tcp" && entry.Protocol != "udp") || entry.Port < 20000 || entry.Port > 60000 ||
		entry.ProbePort < 20000 || entry.ProbePort > 60000 || entry.Port == entry.ProbePort ||
		standardControlPort(entry.Port) || standardControlPort(entry.ProbePort) ||
		len(entry.Nodes) < 2 || len(entry.Nodes) > 16 || entry.ConnectMilliseconds < 500 || entry.ConnectMilliseconds > 5000 ||
		entry.SessionSeconds < 2 || entry.SessionSeconds > 600 || entry.MaxSessions < 16 || entry.MaxSessions > 512 {
		return ErrEntry
	}
	if entry.Method != "round-robin" && entry.Method != "least-connections" && entry.Method != "source-ip" {
		return ErrEntry
	}
	if entry.Protocol == "tcp" && (entry.UDPRequests != 0 || entry.UDPResponses != 0) ||
		entry.Protocol == "udp" && (entry.UDPRequests < 1 || entry.UDPRequests > 64 || entry.UDPResponses < 0 || entry.UDPResponses > 64) {
		return ErrEntry
	}
	seen := map[string]bool{}
	primary := 0
	for _, node := range entry.Nodes {
		ip, port, err := nodeAddress(node.Address)
		if err != nil || node.Weight < 1 || node.Weight > 100 || seen[node.Address] || standardControlPort(port) ||
			node.Backup && entry.Method == "source-ip" ||
			ip.IsLoopback() && (port == entry.Port || port == entry.ProbePort || standardControlPort(port)) {
			return ErrEntry
		}
		seen[node.Address] = true
		if !node.Backup {
			primary++
		}
	}
	if primary == 0 {
		return ErrEntry
	}
	raw, err := json.Marshal(entry)
	if err != nil || len(raw) > MaxEntryBytes {
		return ErrEntry
	}
	return nil
}

// ValidateSet checks the COMPLETE current set and caller-owned external TCP/UDP ports.
// It is not a complete graph of foreign/manual Nginx routes. Removed records
// remain validated but reserve no listener or memory; they are never adopted.
func ValidateSet(entries []Entry, facts ValidationContext) error {
	if len(entries) > MaxEntries || len(facts.PanelControlPorts) < 1 || len(facts.PanelControlPorts) > 1024 || len(facts.OccupiedTCPPorts) > 1024 || len(facts.OccupiedUDPPorts) > 1024 ||
		facts.MemoryBudgetBytes < 16*BytesPerSession+FixedBytesPerEntry || facts.MemoryBudgetBytes > MaxMemoryBudget {
		return ErrSet
	}
	protected := map[int]bool{19100: true, 19102: true, 19080: true}
	for _, port := range facts.PanelControlPorts {
		if port < 1 || port > 65535 {
			return ErrSet
		}
		protected[port] = true
	}
	occupied := map[int]bool{}
	for _, port := range facts.OccupiedTCPPorts {
		if port < 1 || port > 65535 {
			return ErrSet
		}
		occupied[port] = true
	}
	occupiedUDP := map[int]bool{}
	for _, port := range facts.OccupiedUDPPorts {
		if port < 1 || port > 65535 {
			return ErrSet
		}
		occupiedUDP[port] = true
	}
	names, listeners, probes := map[string]bool{}, map[string]int{}, map[int]bool{}
	var memory int64
	for index, entry := range entries {
		if Validate(entry) != nil || names[entry.Name] {
			return ErrSet
		}
		names[entry.Name] = true
		if entry.Removed {
			continue
		}
		key := entry.Protocol + ":" + strconv.Itoa(entry.Port)
		if protected[entry.Port] || protected[entry.ProbePort] || probes[entry.ProbePort] || occupied[entry.ProbePort] || entry.Protocol == "tcp" && occupied[entry.Port] || entry.Protocol == "udp" && occupiedUDP[entry.Port] {
			return ErrSet
		}
		if _, duplicate := listeners[key]; duplicate {
			return ErrSet
		}
		listeners[key] = index
		probes[entry.ProbePort] = true
		memory += int64(entry.MaxSessions)*BytesPerSession + FixedBytesPerEntry
		if memory > facts.MemoryBudgetBytes {
			return ErrSet
		}
	}
	for port := range probes {
		if _, collision := listeners["tcp:"+strconv.Itoa(port)]; collision {
			return ErrSet
		}
	}
	edges := make([][]int, len(entries))
	for index, entry := range entries {
		if entry.Removed {
			continue
		}
		for _, node := range entry.Nodes {
			ip, port, err := nodeAddress(node.Address)
			if err != nil || protected[port] {
				return ErrSet
			}
			if !ip.IsLoopback() {
				continue
			}
			if probes[port] {
				return ErrSet
			}
			if next, exists := listeners[entry.Protocol+":"+strconv.Itoa(port)]; exists {
				edges[index] = append(edges[index], next)
			}
		}
	}
	state := make([]uint8, len(entries))
	var visit func(int) bool
	visit = func(index int) bool {
		if state[index] == 1 {
			return false
		}
		if state[index] == 2 {
			return true
		}
		state[index] = 1
		for _, next := range edges[index] {
			if !visit(next) {
				return false
			}
		}
		state[index] = 2
		return true
	}
	for index := range entries {
		if !visit(index) {
			return ErrSet
		}
	}
	return nil
}

// Decode requires byte-exact privileged JSON. Duplicates, aliases, unknown fields,
// null/default omission, alternate number forms and trailing documents cannot
// masquerade as an original metadata record.
func Decode(raw []byte) (Entry, error) {
	var entry Entry
	if len(raw) < 1 || len(raw) > MaxEntryBytes || json.Unmarshal(raw, &entry) != nil {
		return Entry{}, ErrEntry
	}
	canonical, err := json.Marshal(entry)
	if err != nil || !bytes.Equal(raw, canonical) || Validate(entry) != nil {
		return Entry{}, ErrEntry
	}
	return entry, nil
}

func ID(name string) string {
	digest := sha256.Sum256([]byte(name))
	return hex.EncodeToString(digest[:10])
}
func Fingerprint(entry Entry) string {
	raw, _ := json.Marshal(entry)
	digest := sha256.Sum256(raw)
	return ID(entry.Name) + ":" + strconv.FormatInt(entry.Revision, 10) + ":" + hex.EncodeToString(digest[:12])
}
func ProbePath(name string) string { return "/__yunzhan_lb_stream/" + ID(name) }

// Render only constructs bytes. A matching HTTP marker is configuration-generation
// evidence, NOT upstream TCP readiness or UDP application health. Real effects
// still require original-module authority, locks, backups, nginx -t/reload,
// independent listener ownership and exact-generation checks.
func Render(entry Entry) (Configuration, error) {
	if Validate(entry) != nil {
		return Configuration{}, ErrEntry
	}
	marker := Fingerprint(entry)
	if entry.Removed {
		return Configuration{Fingerprint: marker}, nil
	}
	id := ID(entry.Name)
	var stream strings.Builder
	fmt.Fprintf(&stream, "# managed by panel; lb-stream=%s; revision=%d\n", id, entry.Revision)
	fmt.Fprintf(&stream, "limit_conn_zone $server_addr zone=panel_l4_limit_%s:1m;\nupstream panel_l4_%s {\n  zone panel_l4_%s 1m;\n", id, id, id)
	switch entry.Method {
	case "least-connections":
		stream.WriteString("  least_conn;\n")
	case "source-ip":
		stream.WriteString("  hash $remote_addr consistent;\n")
	}
	for _, node := range entry.Nodes {
		backup := ""
		if node.Backup {
			backup = " backup"
		}
		fmt.Fprintf(&stream, "  server %s weight=%d max_conns=%d max_fails=1 fail_timeout=5s%s;\n", node.Address, node.Weight, entry.MaxSessions, backup)
	}
	udp := ""
	if entry.Protocol == "udp" {
		udp = " udp reuseport"
	}
	fmt.Fprintf(&stream, "}\nserver {\n  listen 127.0.0.1:%d%s;\n  limit_conn panel_l4_limit_%s %d;\n  proxy_connect_timeout %dms;\n  proxy_timeout %ds;\n  proxy_buffer_size 64k;\n", entry.Port, udp, id, entry.MaxSessions, entry.ConnectMilliseconds, entry.SessionSeconds)
	if entry.Protocol == "udp" {
		// A failed datagram is NOT permission to replay a business request.
		fmt.Fprintf(&stream, "  proxy_next_upstream off;\n  proxy_requests %d;\n  proxy_responses %d;\n", entry.UDPRequests, entry.UDPResponses)
	} else {
		fmt.Fprintf(&stream, "  proxy_half_close on;\n  proxy_next_upstream on;\n  proxy_next_upstream_timeout %dms;\n  proxy_next_upstream_tries %d;\n", entry.ConnectMilliseconds, len(entry.Nodes))
	}
	fmt.Fprintf(&stream, "  proxy_pass panel_l4_%s;\n}\n", id)
	http := fmt.Sprintf("# managed by panel; lb-stream-verification=%s; revision=%d\nserver {\n  listen 127.0.0.1:%d;\n  server_name %s;\n  location = %s { access_log off; default_type text/plain; return 200 '%s'; }\n  location / { return 404; }\n}\n", id, entry.Revision, entry.ProbePort, entry.Name, ProbePath(entry.Name), marker)
	return Configuration{Stream: []byte(stream.String()), HTTP: []byte(http), Fingerprint: marker}, nil
}
