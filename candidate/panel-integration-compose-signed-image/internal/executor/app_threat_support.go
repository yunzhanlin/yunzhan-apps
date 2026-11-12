package executor

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// Runtime identity and security support are different claims. Keep obsolete
// manifests readable for stopping capture and recovering retained evidence.
// Neither an authenticated package nor fresh packet counters establish that
// an obsolete parser is safe to expose to untrusted network traffic.
// OISF released Suricata 8.0.8 with security fixes on 2026-10-29.
const threatIDSMinimumVersion = "8.0.8"
const threatIDSSupportReviewed = "2026-11-12"
const threatIDSSupportReviewDeadline = "2027-02-12"

type threatIDSEngineSupport struct {
	Version        string `json:"package_version"`
	Minimum        string `json:"minimum_engine_version"`
	Status         string `json:"status"`
	ReviewedAt     string `json:"reviewed_at"`
	ReviewDeadline string `json:"review_deadline"`
	Supported      bool   `json:"supported"`
}

var threatIDSEngineVersion = regexp.MustCompile(`^(?:1:)?(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})(?:-[0-9][A-Za-z0-9.+~_-]{0,99})?$`)

func threatIDSSupport(version string, now time.Time) threatIDSEngineSupport {
	v := threatIDSEngineSupport{Version: version, Minimum: threatIDSMinimumVersion, Status: "unreviewed-version", ReviewedAt: threatIDSSupportReviewed, ReviewDeadline: threatIDSSupportReviewDeadline}
	m := threatIDSEngineVersion.FindStringSubmatch(version)
	if len(m) != 4 {
		return v
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	if major < 8 {
		v.Status = "end-of-life"
		return v
	}
	if major != 8 || minor != 0 {
		return v
	}
	floor := threatIDSEngineVersion.FindStringSubmatch(threatIDSMinimumVersion)
	if len(floor) != 4 {
		return v
	}
	minimumPatch, _ := strconv.Atoi(floor[3])
	if patch < minimumPatch {
		v.Status = "security-update-required"
		return v
	}
	first, _ := time.Parse("2006-01-02", threatIDSSupportReviewed)
	deadline, _ := time.Parse("2006-01-02", threatIDSSupportReviewDeadline)
	if now.Before(first) {
		v.Status = "clock-unverified"
		return v
	}
	if !now.Before(deadline) {
		v.Status = "support-review-expired"
		return v
	}
	v.Status, v.Supported = "supported-branch-and-version-floor", true
	return v
}

func threatIDSRequireSupported(version string) error {
	if !threatIDSSupport(version, time.Now().UTC()).Supported {
		return fmt.Errorf("IDS 引擎需要 Suricata %s 或同分支更新版及有效维护审核，才能启动或设为开机启动", threatIDSMinimumVersion)
	}
	return nil
}
