package executor

import (
	"testing"
	"time"
)

func TestThreatIDSEngineSupportSeparateIdentityFromSecurityAndFailClosed(t *testing.T) {
	now := time.Date(2026, 11, 12, 7, 0, 0, 0, time.UTC)
	for _, version := range []string{"8.0.8", "1:8.0.8-1~bpo13+1", "1:8.0.8-0ubuntu0", "8.0.9-1"} {
		if v := threatIDSSupport(version, now); !v.Supported || v.Status != "supported-branch-and-version-floor" {
			t.Fatal(version, v)
		}
	}
	statuses := map[string]string{
		"1:7.0.10-1+deb13u4": "end-of-life",
		"7.0.17":             "end-of-life",
		"1:8.0.7-1~bpo13+1":  "security-update-required",
		"1:8.0.7-0ubuntu0":   "security-update-required",
		"8.1.8":              "unreviewed-version",
		"9.0.8":              "unreviewed-version",
		"8.00.8":             "unreviewed-version",
		"8.0.08":             "unreviewed-version",
		"8.0.8rc1":           "unreviewed-version",
		"8.0.8~rc1":          "unreviewed-version",
		"8.0.8-rc1":          "unreviewed-version",
		"2:8.0.8":            "unreviewed-version",
		"8.0.8;id":           "unreviewed-version",
		"8.0.8\n":            "unreviewed-version",
	}
	for version, status := range statuses {
		if v := threatIDSSupport(version, now); v.Supported || v.Status != status {
			t.Fatal(version, v)
		}
	}
	for _, at := range []time.Time{now.AddDate(0, 0, -1), time.Date(2027, 2, 12, 0, 0, 0, 0, time.UTC), now.AddDate(1, 0, 0), {}} {
		if v := threatIDSSupport("8.0.8", at); v.Supported {
			t.Fatal("unchecked clock or expired policy accepted", at)
		}
	}
}
