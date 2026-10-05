package executor

import (
	"errors"
	"net"
	"reflect"
	"syscall"
	"testing"
)

func TestPublicIngressProbeAddresses(t *testing.T) {
	unavailable := func(_, _ string) (net.Listener, error) { return nil, syscall.EADDRNOTAVAIL }
	got, err := publicIngressProbeAddresses(unavailable)
	if err != nil || !reflect.DeepEqual(got, []string{"127.0.0.1"}) {
		t.Fatalf("unavailable IPv6 loopback: addresses=%v err=%v", got, err)
	}
	available := func(_, _ string) (net.Listener, error) { return net.Listen("tcp4", "127.0.0.1:0") }
	got, err = publicIngressProbeAddresses(available)
	if err != nil || !reflect.DeepEqual(got, []string{"127.0.0.1", "::1"}) {
		t.Fatalf("available IPv6 loopback: addresses=%v err=%v", got, err)
	}
	failure := errors.New("unexpected socket failure")
	got, err = publicIngressProbeAddresses(func(_, _ string) (net.Listener, error) { return nil, failure })
	if got != nil || !errors.Is(err, failure) {
		t.Fatalf("unexpected socket failure must not be skipped: addresses=%v err=%v", got, err)
	}
}
