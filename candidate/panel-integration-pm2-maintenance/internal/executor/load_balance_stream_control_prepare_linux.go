//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

// Original read-only host admission while the actual SH/EX leases are held.
// It reserves no TCP/UDP port and an absent proc row is never called "free".
// The ONE native bind/reload, owned listeners and old-listener-close barrier
// remain mandatory. No supplied PID/path/unit/hash can select these sources.
func (s *loadBalanceStreamConfigurationStore) prepareKernel(ctx context.Context) (loadbalancestream.ServiceFacts, []loadbalancestream.Entry, int, string, error) {
	bad := func() (loadbalancestream.ServiceFacts, []loadbalancestream.Entry, int, string, error) {
		return loadbalancestream.ServiceFacts{}, nil, 0, "", loadbalancestream.ErrService
	}
	if s == nil || s.beforeCurrent(ctx) != nil {
		return bad()
	}
	facts, err := measureLoadBalanceStreamServiceFacts(ctx, s.installed)
	if err != nil {
		return bad()
	}
	ports, err := observeLoadBalanceStreamControlPorts(ctx)
	if err != nil {
		return bad()
	}
	facts.Validation.PanelControlPorts = ports
	before := []loadbalancestream.Entry{}
	generationSHA := ""
	if s.generation != nil {
		// Copy the held canonical original record, not a mutable browser list.
		record, err := loadbalancestream.DecodeGenerationRecord(s.generation.raw)
		if err != nil {
			return bad()
		}
		before = record.Entries
		generationSHA = core.Hash(string(s.generation.raw))
	}
	prior, err := loadbalancestream.RenderRuntime(before, loadbalancestream.ServiceRuntimePrefix, facts.Validation)
	if err != nil || s.observePriorService(ctx, before, prior.SHA256) != nil {
		return bad()
	}
	if s.holdEgress(ctx, facts) != nil {
		return bad()
	}
	census, err := observeLoadBalanceStreamHostSockets(ctx)
	if err != nil {
		return bad()
	}
	defer census.close()
	owned := map[string]bool{}
	var native []byte
	if s.priorService != nil {
		listeners, err := observeLoadBalanceStreamOwnedListeners(ctx, s.priorService, before)
		if err != nil {
			return bad()
		}
		for _, inode := range listeners {
			owned[inode] = true
		}
		native, err = s.priorService.bytes(ctx)
		if err != nil {
			return bad()
		}
	}
	blocked, relevantTCP, relevantUDP := map[int]bool{}, map[int]bool{}, map[int]bool{}
	for _, port := range ports {
		blocked[port] = true
	}
	addEntry := func(protocol string, port, probe int, nodes []loadbalancestream.Node) {
		blocked[port], blocked[probe] = true, true
		if protocol == "tcp" {
			relevantTCP[port] = true
		} else {
			relevantUDP[port] = true
		}
		if probe > 0 {
			relevantTCP[probe] = true
		}
		for _, node := range nodes {
			address, err := netip.ParseAddrPort(node.Address)
			if err == nil && address.Addr().IsLoopback() {
				blocked[int(address.Port())] = true
			}
		}
	}
	for _, entry := range before {
		addEntry(entry.Protocol, entry.Port, entry.ProbePort, entry.Nodes)
	}
	if policy := s.operation.Mutation.Policy; policy != nil {
		addEntry(policy.Protocol, policy.Port, 0, policy.Nodes)
	}
	for _, socket := range census.sockets {
		if socket.Local.Port() != 0 {
			blocked[int(socket.Local.Port())] = true
		}
	}
	probe := 0
	if s.operation.Mutation.Action == "create" {
		for candidate := 60000; candidate >= 20000; candidate-- {
			if !blocked[candidate] {
				probe = candidate
				break
			}
		}
		if probe == 0 {
			return bad()
		}
		relevantTCP[probe] = true
	}
	occupiedTCP, occupiedUDP := map[int]bool{}, map[int]bool{}
	for _, socket := range census.sockets {
		if !streamSocketIsListener(socket) {
			continue
		}
		inode := strconv.FormatUint(socket.Inode, 10)
		if owned[inode] && socket.UID == s.installed.identity.UID {
			continue // ONLY the separately verified actual owned listener.
		}
		port := int(socket.Local.Port())
		switch strings.TrimSuffix(socket.Protocol, "6") {
		case "tcp":
			if relevantTCP[port] {
				occupiedTCP[port] = true
			}
		case "udp":
			if relevantUDP[port] {
				occupiedUDP[port] = true
			}
		}
	}
	for port := range occupiedTCP {
		facts.Validation.OccupiedTCPPorts = append(facts.Validation.OccupiedTCPPorts, port)
	}
	for port := range occupiedUDP {
		facts.Validation.OccupiedUDPPorts = append(facts.Validation.OccupiedUDPPorts, port)
	}
	slices.Sort(facts.Validation.OccupiedTCPPorts)
	slices.Sort(facts.Validation.OccupiedUDPPorts)
	censusRaw, err := json.Marshal(census.sockets)
	if err != nil || !census.current() || s.beforeCurrent(ctx) != nil {
		return bad()
	}
	unit, err := streamInstallUnitProperties(ctx, loadbalancestream.ServiceUnitName)
	if err != nil {
		return bad()
	}
	var cold *loadbalancestream.ColdBootRecord
	if s.priorColdBoot != nil {
		copy := s.priorColdBoot.record
		cold = &copy
	}
	witness := struct {
		Format        int                               `json:"format"`
		Facts         loadbalancestream.ServiceFacts    `json:"facts"`
		GenerationSHA string                            `json:"generation_sha256"`
		SocketSHA     string                            `json:"socket_census_sha256"`
		ProcessSHA    string                            `json:"actual_process_observation_sha256"`
		Unit          map[string]string                 `json:"unit"`
		Egress        streamEgressReceipt               `json:"egress"`
		EgressMissing bool                              `json:"egress_missing"`
		ColdBoot      *loadbalancestream.ColdBootRecord `json:"cold_boot,omitempty"`
	}{1, facts, generationSHA, core.Hash(string(censusRaw)), core.Hash(string(native)), unit, s.egress.receipt, s.egress.missing, cold}
	raw, err := json.Marshal(witness)
	if err != nil || s.beforeCurrent(ctx) != nil || !census.current() {
		return bad()
	}
	return facts, before, probe, core.Hash(string(raw)), nil
}
