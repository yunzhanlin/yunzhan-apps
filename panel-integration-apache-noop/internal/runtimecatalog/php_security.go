package runtimecatalog

import "fmt"

// These four official source archives were read back and SHA-256 verified
// against php.net's 21 October 2026 security-release metadata. Detached PGP
// verification also passed with the official per-branch primary fingerprints,
// including the certified signing subkey for 8.3.36. Corrupt and cross-version
// negative samples were rejected. This source receipt is not an installation.
//
// Keep historical PHP entries immutable for existing installation identities,
// rollback references and diagnostic readers. Admission policy and frontend
// safety labels are separate from whether a historical source is recognized.
var PHPSecurity20261021 = []Release{
	{"php-8.2.35", "php", "8.2.35", "8.2", "security", "https://www.php.net/distributions/php-8.2.35.tar.gz", "9db4204f0a2d1911277ae832185e07bb4c3b3559772753a70d2968ca346d6910", "PHP 官方安全补丁 · 2026-10-21 · CVE-2026-109618 / CVE-2026-109619 · 官方 SHA-256 核对"},
	{"php-8.3.36", "php", "8.3.36", "8.3", "security", "https://www.php.net/distributions/php-8.3.36.tar.gz", "c93f3441f87f6ab156bef4432db215d7e61ca2c0183bb3a2aa28d9886ab59f53", "PHP 官方安全补丁 · 2026-10-21 · CVE-2026-109618 / CVE-2026-109619 · 官方 SHA-256 核对"},
	{"php-8.4.27", "php", "8.4.27", "8.4", "active", "https://www.php.net/distributions/php-8.4.27.tar.gz", "5bafed9994c1a49796b25b5f61c22c9183bfe046b6acc7b363842d03c77f972f", "PHP 官方安全补丁 · 2026-10-21 · CVE-2026-109618 / CVE-2026-109619 · 官方 SHA-256 核对"},
	{"php-8.5.12", "php", "8.5.12", "8.5", "active", "https://www.php.net/distributions/php-8.5.12.tar.gz", "81a0f450349e84b08eb43faa85f8a4c835684f3cc1c50471775d1317a046c525", "PHP 官方安全补丁 · 2026-10-21 · CVE-2026-109618 / CVE-2026-109619 · 官方 SHA-256 核对"},
}

func PHPReleases() []Release {
	all := append([]Release{}, PHPSecurity20261021...)
	return append(all, PHP...)
}

// Security here describes this dated advisory, not general runtime health or
// whether a website has actually switched to the patched executable.
type PHPSecurityStatus struct {
	Status       string   `json:"status"`
	Advisory     string   `json:"advisory"`
	CVEs         []string `json:"cves"`
	FixedVersion string   `json:"fixed_version"`
	Message      string   `json:"message"`
}

type PHPReleaseChoice struct {
	Release
	InstallationAllowed bool              `json:"installation_allowed"`
	Security            PHPSecurityStatus `json:"security"`
}

func PHPReleaseSecurity(r Release) PHPSecurityStatus {
	v := PHPSecurityStatus{Status: "unknown", Advisory: "https://www.php.net/archive/2026.php", CVEs: []string{"CVE-2026-109618", "CVE-2026-109619"}}
	known, ok := Find(r.ID)
	if !ok || known != r || r.Family != "php" {
		v.Message = "PHP 来源身份尚未审核，不能据此认定已修复安全公告"
		return v
	}
	for _, fixed := range PHPSecurity20261021 {
		if fixed.Series == r.Series {
			v.FixedVersion = fixed.Version
		}
		if fixed == r {
			v.Status = "fixed-for-advisory"
			v.FixedVersion = r.Version
			v.Message = "已包含 2026-10-21 官方公告补丁；安装完成后仍需逐站切换并验证，不能据此认定所有网站已修复"
			return v
		}
	}
	v.Status = "affected"
	v.Message = fmt.Sprintf("此历史版本受 CVE-2026-109618 / CVE-2026-109619 影响，禁止新建或重建该版本；请安装 PHP %s。已运行网站、历史记录及回退文件保留，安装新版本不会自动迁移网站", v.FixedVersion)
	return v
}

// Recognition of an old manifest is deliberately independent of permission to
// build it again. Existing verified installations may still be observed, and
// exact old idempotency tickets remain readable without granting a new build.
func RuntimeInstallAdmission(r Release) error {
	if r.Family != "php" {
		return nil
	}
	v := PHPReleaseSecurity(r)
	if v.Status != "fixed-for-advisory" {
		return fmt.Errorf("%s", v.Message)
	}
	return nil
}

func PHPReleaseChoices() []PHPReleaseChoice {
	rows := []PHPReleaseChoice{}
	for _, r := range PHPReleases() {
		rows = append(rows, PHPReleaseChoice{Release: r, InstallationAllowed: RuntimeInstallAdmission(r) == nil, Security: PHPReleaseSecurity(r)})
	}
	return rows
}
