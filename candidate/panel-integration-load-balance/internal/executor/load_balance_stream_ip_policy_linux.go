//go:build linux

package executor

import (
	"context"

	"local/panel/internal/loadbalancestream"
)

const loadBalanceStreamServiceBusPath = "/org/freedesktop/systemd1/unit/panel_2dload_2dbalance_2dstream_2eservice"

func observeStreamServiceIPPolicy(ctx context.Context, plan loadbalancestream.ServicePlan) error {
	if ctx == nil || ctx.Err() != nil || !plan.ShouldRun {
		return loadbalancestream.ErrService
	}
	read := func(property string) (string, error) {
		return programQueueCommand(ctx, "/usr/bin/busctl", "get-property", "org.freedesktop.systemd1", loadBalanceStreamServiceBusPath, "org.freedesktop.systemd1.Service", property)
	}
	allow, e1 := read("IPAddressAllow")
	deny, e2 := read("IPAddressDeny")
	if e1 != nil || e2 != nil || !streamServiceIPPolicyMatches([]byte(allow), []byte(deny), plan.AllowedIPs) || ctx.Err() != nil {
		return loadbalancestream.ErrService
	}
	return nil
}
