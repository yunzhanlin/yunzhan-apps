package executor

import (
	"testing"
	"time"
)

func TestThreatIDSEngineSupportSeparateIdentityFromSecurityAndFailClosed(t *testing.T) {
	now := time.Date(2026, 10, 9, 7, 0, 0, 0, time.UTC)
	for _, version := range []string{"8.0.7", "1:8.0.7-1~bpo13+1", "1:8.0.7-0ubuntu0", "8.0.8-1"} {
		if v := threatIDSSupport(version, now); !v.Supported || v.Status != "supported-branch-and-version-floor" {
			t.Fatal(version, v)
		}
	}
	for version, status := range map[string]string{"1:7.0.10-1+deb13u4": "end-of-life", "7.0.17": "end-of-life", "1:8.0.6-1": "security-update-required", "8.1.7": "unreviewed-version", "9.0.7": "unreviewed-version", "8.00.7": "unreviewed-version", "8.0.07": "unreviewed-version", "8.0.7rc1": "unreviewed-version", "8.0.7~rc1": "unreviewed-version", "8.0.7-rc1": "unreviewed-version", "2:8.0.7": "unreviewed-version", "8.0.7;id": "unreviewed-version", "8.0.7\n": "unreviewed-version"} {
		if v := threatIDSSupport(version, now); v.Supported || v.Status != status {
			t.Fatal(version, v)
		}
	}
	for _, at := range []time.Time{now.AddDate(-1, 0, 0), time.Date(2027, 1, 9, 0, 0, 0, 0, time.UTC), now.AddDate(1, 0, 0), {}} {
		if v := threatIDSSupport("8.0.7", at); v.Supported {
			t.Fatal("unchecked clock or expired policy accepted", at)
		}
	}
}
