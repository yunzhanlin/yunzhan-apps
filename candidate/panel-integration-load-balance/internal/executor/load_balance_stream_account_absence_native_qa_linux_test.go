//go:build linux

package executor

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"
)

// Explicit QA-only actual getent plus four held OS-file observation. It never
// creates an account or a fixed ownership directory, and starts no service.
func TestLoadBalanceStreamAccountAbsenceNativeReadOnlyHostNSS(t *testing.T) {
	if os.Getenv("PANEL_LBSTREAM_ABSENCE_QA") != "24blir" {
		t.Skip("explicit bounded host NSS read-only native case only")
	}
	if os.Geteuid() != 0 {
		t.Fatal("actual Root context required")
	}
	paths := []string{"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow"}
	data := make([][]byte, 4)
	defer func() {
		for _, raw := range data {
			clear(raw)
		}
	}()
	for i, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("cannot snapshot original private NSS")
		}
		data[i] = raw
	}
	if validateLoadBalanceStreamAccountAbsence(data[0], data[1], data[2], data[3]) != nil {
		t.Fatal("original complete missing-identity precondition is not true")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := loadBalanceStreamAccountAbsent(ctx); err != nil {
		t.Fatal("actual missing passwd/group host NSS with stable four-file absence refused", err)
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	for _, ctx := range []context.Context{nil, cancelled} {
		if err := loadBalanceStreamAccountAbsent(ctx); err == nil {
			t.Fatal("absent/revoked context accepted")
		}
	}
	for i, path := range paths {
		current, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(current, data[i]) {
			clear(current)
			t.Fatal("read-only absent-account observer changed original NSS")
		}
		clear(current)
	}
	if info, err := os.Lstat(loadBalanceStreamAccountStorePath); !os.IsNotExist(err) || info != nil {
		t.Fatal("absence observation initialized or adopted a fixed identity store")
	}
}
