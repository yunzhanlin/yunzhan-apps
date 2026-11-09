//go:build linux

package executor

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"
)

func TestLoadBalanceStreamNativeMissingIdentityRefusesReadOnly(t *testing.T) {
	if os.Getenv("PANEL_LBSTREAM_NSS_QA") != "24blhs" {
		t.Skip("explicit read-only Root missing-account case only; not installed service acceptance")
	}
	if os.Geteuid() != 0 {
		t.Fatal("actual Root context is required")
	}
	paths := []string{"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow"}
	originals := make([][]byte, len(paths))
	defer func() {
		for _, raw := range originals {
			clear(raw)
		}
	}()
	for i, name := range paths {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal("cannot snapshot original fixed NSS file")
		}
		for _, line := range bytes.Split(raw, []byte("\n")) {
			if bytes.HasPrefix(line, []byte("panel-lbstream:")) {
				t.Fatal("original missing-account precondition is not true; no adoption attempted")
			}
		}
		originals[i] = raw
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if identity, err := loadBalanceStreamSystemIdentity(ctx); err != errLoadBalanceStreamIdentity || identity != (loadBalanceStreamIdentity{}) {
		t.Fatal("missing account returned partial service identity")
	}
	for _, ctx := range []context.Context{nil, func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }()} {
		if identity, err := loadBalanceStreamSystemIdentity(ctx); err != errLoadBalanceStreamIdentity || identity != (loadBalanceStreamIdentity{}) {
			t.Fatal("absent or revoked read context returned identity")
		}
	}
	for i, name := range paths {
		current, err := os.ReadFile(name)
		if err != nil || !bytes.Equal(current, originals[i]) {
			clear(current)
			t.Fatal("read-only identity inspection changed original NSS")
		}
		clear(current)
	}
}
