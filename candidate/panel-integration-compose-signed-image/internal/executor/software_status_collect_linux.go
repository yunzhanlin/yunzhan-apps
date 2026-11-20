//go:build linux

package executor

import (
	"context"
	"time"

	"local/panel/internal/core"
)

// Bound native probes across concurrent store/security requests. Completed
// rows are never cached across requests or substituted for a fresh health check.
var softwareStatusSlots = make(chan struct{}, 4)

func softwareStatusCost(id string) int {
	switch id {
	case "nginx-waf", "system-hardening", "intrusion-prevention", "apache-waf",
		"website-statistics-v2", "load-balance", "pm2-manager", "pure-ftpd",
		"nfs-manager", "php-code-security":
		return 1
	default:
		return 0
	}
}

func collectSoftwareStatus(parent context.Context, ids []string, overall, individual time.Duration,
	slots chan struct{}, probe func(context.Context, string) core.SoftwareAppStatus,
) []core.SoftwareAppStatus {
	ctx, cancel := context.WithTimeout(parent, overall)
	defer cancel()
	type completed struct {
		index int
		state core.SoftwareAppStatus
	}
	out := make([]core.SoftwareAppStatus, len(ids))
	work := make(chan int, len(ids))
	result := make(chan completed, len(ids))
	for i, id := range ids {
		out[i] = core.SoftwareAppStatus{ID: id, StateUnknown: true, Detail: "状态暂未确认，请刷新；不会据此重复安装"}
	}
	// Probe cheaper receipt-only modules first. The result stays in its
	// original public catalogue order.
	for weight := 0; weight < 2; weight++ {
		for i, id := range ids {
			if softwareStatusCost(id) == weight {
				work <- i
			}
		}
	}
	close(work)
	for range min(cap(slots), len(ids)) {
		go func() {
			for i := range work {
				select {
				case slots <- struct{}{}:
				case <-ctx.Done():
					return
				}
				if ctx.Err() != nil {
					<-slots
					return
				}
				child, stop := context.WithTimeout(ctx, individual)
				v := probe(child, ids[i])
				valid := child.Err() == nil && v.ID == ids[i]
				stop()
				<-slots
				if !valid {
					v = core.SoftwareAppStatus{}
				}
				result <- completed{i, v}
			}
		}()
	}
	apply := func(row completed) {
		if row.state.ID == ids[row.index] {
			out[row.index] = row.state
		}
	}
	for range ids {
		select {
		case row := <-result:
			apply(row)
		case <-ctx.Done():
			// Preserve results queued before the deadline. No workers can
			// write to the returned slice after this reader has returned.
			for {
				select {
				case row := <-result:
					apply(row)
				default:
					return out
				}
			}
		}
	}
	return out
}
