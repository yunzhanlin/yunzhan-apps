//go:build linux

package executor

import (
	"context"
	"testing"
)

func TestLoadBalanceStreamAccountOSRejectsMissingAuthorityBeforeAnyEffect(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, canceled, context.Background()} {
		if got, err := prepareLoadBalanceStreamSystemAccount(ctx, nil); err != errLoadBalanceStreamAccount || got != (loadBalanceStreamIdentity{}) {
			t.Fatal("missing original parent admitted account creation")
		}
		if err := createLoadBalanceStreamAccountOS(ctx, nil); err != errLoadBalanceStreamAccount {
			t.Fatal("missing current original authority admitted account creation")
		}
	}
	checks := 0
	if err := createLoadBalanceStreamAccountOS(context.Background(), func(context.Context) error {
		checks++
		return errLoadBalanceStreamAccount
	}); err != errLoadBalanceStreamAccount || checks != 1 {
		t.Fatal("revoked authority reached local NSS or a command")
	}
	for _, path := range []string{"", "useradd", "/bin/sh", "/usr/sbin/../sbin/useradd", "/tmp/useradd", "/usr/sbin/groupadd"} {
		if got, err := openLoadBalanceStreamAccountTool(path); err != errLoadBalanceStreamAccount || got != nil {
			t.Fatal("caller-selected account tool admitted")
		}
	}
}
