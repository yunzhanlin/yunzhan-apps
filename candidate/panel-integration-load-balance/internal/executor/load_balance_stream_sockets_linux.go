//go:build linux

package executor

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"local/panel/internal/loadbalancestream"
)

// Point-in-time READ-ONLY census, not a port reservation. No listen/connect,
// namespace switch, sysctl adjustment, netfilter/BPF change or claimed owner.
// The eventual activation barrier must separately bind every owned socket to
// actual original pidfds/cgroup/ELF and repeat occupancy before native effects.
// These proc tables can omit bind-inactive TCP sockets and are not an atomic
// multi-table snapshot. Absence here must NEVER be reported as "port free".
type loadBalanceStreamSocketCensus struct {
	namespace *os.File
	before    os.FileInfo
	sockets   []loadBalanceStreamHostSocket
}

func (c *loadBalanceStreamSocketCensus) close() {
	if c != nil && c.namespace != nil {
		c.namespace.Close()
		c.namespace = nil
	}
}

func (c *loadBalanceStreamSocketCensus) current() bool {
	if c == nil || c.namespace == nil {
		return false
	}
	info, e1 := c.namespace.Stat()
	named, e2 := os.Stat("/proc/self/ns/net")
	return e1 == nil && e2 == nil && os.SameFile(c.before, info) && os.SameFile(info, named)
}

func observeLoadBalanceStreamHostSockets(ctx context.Context) (*loadBalanceStreamSocketCensus, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, loadbalancestream.ErrService
	}
	// Deliberate fixed procfs namespace handle. It is held, never entered or
	// replaced; no caller selects a path or supplies a namespace/PID claim.
	f, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return nil, loadbalancestream.ErrService
	}
	c := &loadBalanceStreamSocketCensus{namespace: f}
	fail := func() (*loadBalanceStreamSocketCensus, error) { c.close(); return nil, loadbalancestream.ErrService }
	var fs unix.Statfs_t
	if unix.Fstatfs(int(f.Fd()), &fs) != nil || fs.Type != unix.NSFS_MAGIC {
		return fail()
	}
	c.before, err = f.Stat()
	if err != nil || !c.current() {
		return fail()
	}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		if ctx.Err() != nil || !c.current() {
			return fail()
		}
		raw, err := streamAccountParentProc(filepath.Join("/proc/self/net", name), streamSocketTableBytes)
		if err != nil {
			return fail()
		}
		sockets, err := decodeStreamSocketTable(raw, name)
		if err != nil {
			return fail()
		}
		c.sockets = append(c.sockets, sockets...)
	}
	if ctx.Err() != nil || !c.current() {
		return fail()
	}
	return c, nil
}
