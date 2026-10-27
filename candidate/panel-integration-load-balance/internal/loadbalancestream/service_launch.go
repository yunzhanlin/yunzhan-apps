package loadbalancestream

import (
	"fmt"
	"strconv"
	"strings"
)

const ServiceUnitName = "panel-load-balance-stream.service"

// Closed argv only. No shell, environment input, arbitrary path, browser
// command, unit override, boot enablement or restart is accepted. These bytes
// are NOT a grant and do not prove a manager applied the requested policy.
type ServiceLaunchPlan struct {
	Service ServicePlan
	Start   []string
	Syntax  []string
	Policy  []string
}

// Reconstruct the complete policy from validated entries and measured facts,
// rather than accepting a caller's partially edited ServicePlan/argv. systemd
// owns the transient unit and runtime directory; the panel never writes into
// /etc/systemd/system or relaxes its existing service sandbox for this purpose.
func PlanServiceLaunch(current, retiring []Entry, facts ServiceFacts, request string) (ServiceLaunchPlan, error) {
	if !operationID.MatchString(request) {
		return ServiceLaunchPlan{}, ErrService
	}
	plan, err := PlanService(current, retiring, facts)
	if err != nil {
		return ServiceLaunchPlan{}, err
	}
	nginx := serviceNginx(facts.NginxVersion)
	properties := serviceProperties(plan.MemoryHighBytes, plan.MemoryMaxBytes, plan.AllowedIPs)
	makeArgs := func(unit string, syntax bool) []string {
		// No generated argument contains '$'. Do not require the expansion
		// switch added only in systemd254: supported older LTS managers can
		// execute these same fixed, expansion-free arguments safely.
		out := []string{"--quiet", "--unit=" + unit, "--service-type=exec", "--description=Panel private TCP UDP load-balance instance"}
		if syntax {
			out = append(out, "--wait")
		}
		for _, property := range properties {
			if syntax && property == "TimeoutStopSec=630s" {
				property = "TimeoutStopSec=5s"
			}
			if syntax && property == "RemainAfterExit=yes" {
				property = "RemainAfterExit=no"
			}
			out = append(out, "--property="+property)
		}
		config := ServiceConfigPath
		if syntax {
			// This exact fixed-path candidate is created and held by the fresh
			// Root controller. A UUID/path alone is never creation authority.
			config = "/etc/panel/load-balance-stream/.candidate-" + request + ".conf"
			out = append(out, "--property=RuntimeMaxSec=10s")
		}
		out = append(out, "--", nginx, "-e", "stderr", "-p", ServiceRuntimePrefix, "-c", config)
		if syntax {
			out = append(out, "-t")
		} else {
			out = append(out, "-g", "daemon off;")
		}
		return out
	}
	// Clear and replace the complete IP list in ONE manager property batch.
	// Appending alone would retain a grandparent backend after it has drained.
	// Deny=any, identity, capabilities, CPU and task limits never change here.
	policy := []string{"--runtime", "set-property", ServiceUnitName,
		"MemoryHigh=" + strconv.FormatInt(plan.MemoryHighBytes, 10),
		"MemoryMax=" + strconv.FormatInt(plan.MemoryMaxBytes, 10),
		"IPAddressAllow=", "IPAddressAllow=" + strings.Join(plan.AllowedIPs, " ")}
	out := ServiceLaunchPlan{Service: plan, Syntax: makeArgs("panel-load-balance-stream-syntax@"+request+".service", true)}
	// A stop/idle plan is not start or live-policy authority. In particular the
	// low-memory last-removal exception must never expose activation arguments.
	// Root still performs bounded syntax validation and an owned pidfd drain.
	if plan.ShouldRun {
		out.Start, out.Policy = makeArgs(ServiceUnitName, false), policy
	}
	return out, nil
}

// Shared by the persistent policy fingerprint and transient manager request.
// No argument is derived from application text except already validated IPs
// and bounded calculated memory. Actual cgroup/BPF/process checks are still
// mandatory: successfully sending a property is not enforcement evidence.
func serviceProperties(high, maximum int64, ips []string) []string {
	return []string{
		"User=" + ServiceAccount, "Group=" + ServiceAccount,
		"RuntimeDirectory=panel-load-balance-stream", "RuntimeDirectoryMode=0700", "RuntimeDirectoryPreserve=yes", "UMask=0077",
		"Restart=no", "RemainAfterExit=yes", "KillMode=mixed", "KillSignal=SIGQUIT", "TimeoutStartSec=10s", "TimeoutStopSec=630s",
		"NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes",
		"ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectKernelLogs=yes", "ProtectControlGroups=yes", "RestrictSUIDSGID=yes", "RestrictRealtime=yes", "RestrictNamespaces=yes",
		"LockPersonality=yes", "MemoryDenyWriteExecute=yes", "SystemCallArchitectures=native", "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
		"ReadWritePaths=" + ServiceRuntimePrefix, "MemoryAccounting=yes", "MemoryHigh=" + strconv.FormatInt(high, 10), "MemoryMax=" + strconv.FormatInt(maximum, 10), "MemorySwapMax=0",
		"CPUAccounting=yes", "CPUQuota=100%", "TasksAccounting=yes", "TasksMax=32", "LimitNOFILE=" + strconv.Itoa(RuntimeOpenFiles),
		"IPAccounting=yes", "IPAddressDeny=any", "IPAddressAllow=" + strings.Join(ips, " "), "StandardOutput=journal", "StandardError=journal",
	}
}

func renderServiceUnit(nginx string, high, maximum int64, ips []string) []byte {
	var out strings.Builder
	out.WriteString("[Unit]\nDescription=Panel private TCP UDP load-balance instance\nAfter=network.target\n\n[Service]\nType=exec\n")
	fmt.Fprintf(&out, "ExecStart=%s -e stderr -p %s -c %s -g \"daemon off;\"\n", nginx, ServiceRuntimePrefix, ServiceConfigPath)
	for _, property := range serviceProperties(high, maximum, ips) {
		out.WriteString(property)
		out.WriteByte('\n')
	}
	return []byte(out.String())
}
