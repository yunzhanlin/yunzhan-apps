package core

import "testing"

func TestLoadBalanceAutomaticTrafficRequiresExplicitTrue(t *testing.T) {
	if LoadBalanceAutomaticTraffic(nil) || LoadBalanceAutomaticTraffic(&LoadBalanceHTTPHealth{}) {
		t.Fatal("historical observation implicitly expanded")
	}
	off, on := false, true
	if LoadBalanceAutomaticTraffic(&LoadBalanceHTTPHealth{AutoTraffic: &off}) || !LoadBalanceAutomaticTraffic(&LoadBalanceHTTPHealth{AutoTraffic: &on}) {
		t.Fatal("explicit authority not preserved")
	}
}

func TestLoadBalanceHealthRoutingVersionIsClosed(t *testing.T) {
	for _, version := range []string{"1.7.0", "1.7.1"} {
		if !LoadBalanceHealthRoutingVersion(version) {
			t.Fatal("reviewed compatible implementation rejected", version)
		}
	}
	for _, version := range []string{"", "1.6.0", "1.7.2", "1.8.0", "v1.7.0", "1.7.01", "1.7.1 extra"} {
		if LoadBalanceHealthRoutingVersion(version) {
			t.Fatal("unreviewed version expanded routing authority", version)
		}
	}
}
