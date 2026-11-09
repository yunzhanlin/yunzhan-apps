package executor

import "testing"

func TestLoadBalanceStreamIndependentLifecycleNeverImplicitlyPromotesLegacy(t *testing.T) {
	for _, version := range []string{"", "1.0", "1.0.0", "1.7.0", "1.8.4", "1.8.5", "1.8.5-compat1"} {
		if loadBalanceStreamIndependentLifecycle(version) {
			t.Fatal("old HTTP identity changed", version)
		}
	}
	for _, version := range []string{"1.9.0", "1.9.0-rc1", "1.9.1", "1.10.0", "2.0.0", "99.0.0", "1.9", "unknown", "1.8.5\n", "999999999999999999999999.0.0"} {
		if !loadBalanceStreamIndependentLifecycle(version) {
			t.Fatal("new, malformed or future version borrowed legacy authority", version)
		}
	}
}

func TestLoadBalanceStreamLegacyDefaultNeverBecomesFourLayerInstallation(t *testing.T) {
	for _, action := range []string{"install", "configure", "uninstall"} {
		for _, original := range []string{"", "1.8.4", "1.8.5", "1.9.0"} {
			got, err := resolveLoadBalanceStreamLegacyLifecycle("1.9.0", original, action, true)
			if action == "install" || original == "1.9.0" {
				if err != errLoadBalanceStreamIndependentLifecycle || got != "" {
					t.Fatal("compiled/default L4 identity borrowed legacy installation authority")
				}
			} else {
				want := original
				if want == "" {
					want = "1.0"
				}
				if err != nil || got != want {
					t.Fatal("legacy configuration promoted its original installed version")
				}
			}
		}
	}
	if got, err := resolveLoadBalanceStreamLegacyLifecycle("1.9.0", "", "install", false); got != "" || err != errLoadBalanceStreamIndependentLifecycle {
		t.Fatal("unversioned future default installed L4 through the generic interface")
	}
	if got, err := resolveLoadBalanceStreamLegacyLifecycle("1.8.5", "", "install", false); got != "1.8.5" || err != nil {
		t.Fatal("old explicit HTTP install contract changed")
	}
}
