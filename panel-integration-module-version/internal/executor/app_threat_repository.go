package executor

import (
	"errors"
	"path/filepath"
	"strings"
)

type threatIDSRepository struct{ URL, Suite, Keyring, Key string }

// Only vendor channels for the exact host ABI are eligible. This temporary
// catalog is download-only: never append it to /etc/apt or use it to install
// dependencies. Debian 12's now-EOL Backports cannot inherit Debian 13 support.
func threatIDSRepositoryFor(platform, arch string) (threatIDSRepository, error) {
	if arch != "amd64" && arch != "arm64" {
		return threatIDSRepository{}, errors.New("IDS 原生架构尚未审核")
	}
	switch platform {
	case "debian-13":
		return threatIDSRepository{"https://deb.debian.org/debian", "trixie-backports", "/usr/share/keyrings/debian-archive-keyring.gpg", ""}, nil
	case "ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04":
		suite := map[string]string{"ubuntu-22.04": "jammy", "ubuntu-24.04": "noble", "ubuntu-26.04": "resolute"}[platform]
		return threatIDSRepository{"https://ppa.launchpadcontent.net/oisf/suricata-stable/ubuntu", suite, "", threatIDSOISFKey}, nil
	default:
		return threatIDSRepository{}, errors.New("当前系统没有已审核且仍维护的 IDS 原生包来源；不借用其他发行版或停止维护的软件源")
	}
}

func threatIDSPrivateAPTArgs(work string) ([]string, error) {
	if !filepath.IsAbs(work) || filepath.Clean(work) != work || strings.ContainsAny(work, "\r\n\x00") || len(work) > 1024 {
		return nil, errors.New("IDS 临时 APT 路径无效")
	}
	options := []string{
		"Dir::Etc::main=-", "Dir::Etc::parts=-", "Dir::Etc::sourcelist=" + filepath.Join(work, "sources.list"),
		"Dir::Etc::sourceparts=-", "Dir::Etc::preferences=-", "Dir::Etc::preferencesparts=-",
		"Dir::State::lists=" + filepath.Join(work, "lists"), "Dir::Cache=" + filepath.Join(work, "cache"),
		"Dir::Cache::pkgcache=" + filepath.Join(work, "cache/pkgcache.bin"), "Dir::Cache::srcpkgcache=" + filepath.Join(work, "cache/srcpkgcache.bin"),
		"APT::Sandbox::User=root", "APT::Get::AllowUnauthenticated=false", "Acquire::AllowInsecureRepositories=false",
		"Acquire::AllowDowngradeToInsecureRepositories=false", "Acquire::Check-Valid-Until=true", "Acquire::Check-Date=true",
		"Acquire::Retries=1", "Acquire::https::Timeout=20", "APT::Update::Error-Mode=any",
	}
	args := make([]string, 0, len(options)*2)
	for _, option := range options {
		args = append(args, "-o", option)
	}
	return args, nil
}

// Fingerprint 121504ADE276E141AD704A75AC10378CF205C960 was checked against
// OISF's official stable PPA and the Ubuntu keyserver on 2026-10-09. Embedded
// public trust only; runtime preparation never obtains a replacement key.
const threatIDSOISFKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xsFNBGY0ZbYBEACfztvW2rCJ/FF06V8hTOzPP0jhYowy4SkOuYEWcXt+25o7nKSI
xXnzMFKDzVDdy8tybEiUogpHh4XM97cb28+tP4KgEwgXnOxAvThXMVfvnEVnNrB4
M5lCNaO94rsuog1x+QtCNS+wJlQMkzyJaVWTvtomihKbTVx0Lvtsxe/X6yNHtXVk
nmS0377qWmtpEjDcdaiXW6R/yh/pcFhe6uKRwTclZWoVD7yiR4m5lCuZ2X7hMjbV
vOY69UBhd66AsvtF63rMVFYArCL0AISmNqZhkqNgvHieSx0W3aioPS4ZwZi63ExQ
ptAiuDjYcvHgdmrktJI/ZxdLw8OW7Nm4Y2TcTjYOx9EvlQWz3u0bbPZBHrSq9n8H
wLd1lbBROhus/qnXl+ZzIAy60TvUXyZV3bNqmuTSwu0S3OUcCrfFQFseQuqVK23Q
UoQR2YqrkFu2XWcEYNoLR5uc53Dulv+b3tw55TKI8+fKWpfapq/fKC8KRNauq6vN
qpG79sNYm+K6vC6mfra9pPvSNL/rZ8Jtcvg6n/WThwFHYQu+xhmBQxdqAcTmGHuK
oc+H28NrTq3DeRECO/4A0vzO9utvaIUJxhnoR3YYefrKWY5nc6EGeG8BQ/p/V2ts
fzkFo+SM2QUHn9wNX6yXdd5jGzmw50tR/P4m7S5QOfg4Y8jbZD1b5Hw8pQARAQAB
zRZMYXVuY2hwYWQgUFBBIGZvciBPSVNGwsGOBBMBCgA4FiEEEhUEreJ24UGtcEp1
rBA3jPIFyWAFAmY0ZbYCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQrBA3
jPIFyWDLxQ/+NFCcX5KNMWJHWzJoYVX6rsirwbKsyyQ5JOdk+kHB6BEsHREYQkzr
n3Dr1qATatgxy/HbCxdgTC7rjuK/vbbwAmmmlEh7TG+lfAdRIn5GQvl0o4IFtWIi
UjJ72Hq0TaPTrT4fyfdjKcF9LvTvN6Bv53Vg26MKrKQhyhl9UmHc8sRlt9YxgdEg
j6FYkVNmX1oofM/1jL4Yy+XIlNJvdWMDLxv6B3WmomoSxPUKEWkcym/OENCFlgxx
GJe4ZgkrDV+jM1N0oZUMNvGZRgsIbF2dEa6+A7kh+L4Yo9lDFQmHGh9kpewxVo05
HjSmFxEiWNPxAIzPtilPM7G8P1SCn5ahrySnwTL9LAsSAFw51yJyAwyRXkxC6V9k
eKm6NTzTcXvoYS11vNtEIsOA2BIcb+XoJ8KFLSXRl4JR4HzhCZPi9huBkifq+G+P
tzIxrohWKIrLCvBq1IHx6L5EWDlDijDIA9P4/UuvGx8tXruxhCvjTjhL9ftHY50E
L+C12UWUV41j9sYj7cMovnlV8p7e+rFn0lK8QC1JGSV/U06gFzBn0xuYrtBSm5Kc
LwRCDNebF95jR9LD+aW3UOJXEOtUB4w7i3C1gKSSESMOklifK7tLjaRqCcyhPNJy
6DONQeu5njzodGZq2D+JJHEXIFhyV9VUBKNLZ8XTxWZ82MNc1dMBc24=
=A1RB
-----END PGP PUBLIC KEY BLOCK-----
`
