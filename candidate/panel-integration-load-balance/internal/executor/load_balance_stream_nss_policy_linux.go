//go:build linux

package executor

import (
	"context"
	"io"
	"os"
	"syscall"
)

type loadBalanceStreamNSSConfiguration struct {
	file   *os.File
	before os.FileInfo
}

func (c *loadBalanceStreamNSSConfiguration) close() {
	if c != nil && c.file != nil {
		c.file.Close()
		c.file = nil
	}
}
func (c *loadBalanceStreamNSSConfiguration) current() bool {
	if c == nil || c.file == nil || threatIDSTrustedParents("/etc", false) != nil {
		return false
	}
	held, e1 := c.file.Stat()
	visible, e2 := os.Lstat("/etc/nsswitch.conf")
	return e1 == nil && e2 == nil && geoStoreStableInfo(c.before, held) && geoStoreStableInfo(held, visible)
}
func holdLoadBalanceStreamNSSConfiguration(ctx context.Context) (*loadBalanceStreamNSSConfiguration, error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || threatIDSTrustedParents("/etc", false) != nil {
		return nil, errLoadBalanceStreamNSSPolicy
	}
	f, err := os.OpenFile("/etc/nsswitch.conf", os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errLoadBalanceStreamNSSPolicy
	}
	fail := func() (*loadBalanceStreamNSSConfiguration, error) {
		f.Close()
		return nil, errLoadBalanceStreamNSSPolicy
	}
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || before.Mode().Perm()&0022 != 0 || before.Size() <= 0 || before.Size() > 65536 {
		return fail()
	}
	s, ok := before.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != 0 || s.Nlink != 1 {
		return fail()
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	c := &loadBalanceStreamNSSConfiguration{f, before}
	if err != nil || int64(len(raw)) != before.Size() || validateLoadBalanceStreamNSSPolicy(raw) != nil || !c.current() || ctx.Err() != nil {
		return fail()
	}
	return c, nil
}
