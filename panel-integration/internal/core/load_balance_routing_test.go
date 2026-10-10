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
