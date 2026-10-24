package executor

import (
	"strings"
	"testing"
)

func TestThreatIDSRepositoryClosedHostABIAndIsolatedDownloadOptions(t *testing.T) {
	for platform, suite := range map[string]string{"debian-13": "trixie-backports", "ubuntu-22.04": "jammy", "ubuntu-24.04": "noble", "ubuntu-26.04": "resolute"} {
		for _, arch := range []string{"amd64", "arm64"} {
			v, err := threatIDSRepositoryFor(platform, arch)
			if err != nil || v.Suite != suite || !strings.HasPrefix(v.URL, "https://") || (v.Key == "") == (v.Keyring == "") {
				t.Fatal(v, err)
			}
		}
	}
	for _, platform := range []string{"debian-12", "debian-14", "ubuntu-20.04", "ubuntu-24.10", "ubuntu-24.04\n", "", "linux", "mint-22"} {
		if _, err := threatIDSRepositoryFor(platform, "amd64"); err == nil {
			t.Fatal(platform)
		}
	}
	for _, arch := range []string{"x86_64", "aarch64", "386", "amd64;id", ""} {
		if _, err := threatIDSRepositoryFor("debian-13", arch); err == nil {
			t.Fatal(arch)
		}
	}
	args, err := threatIDSPrivateAPTArgs("/opt/panel/app-modules/network-threat-detection/.prepare-123/catalog")
	if err != nil || len(args)%2 != 0 {
		t.Fatal(args, err)
	}
	options := map[string]string{}
	for i := 0; i < len(args); i += 2 {
		if args[i] != "-o" {
			t.Fatal(args)
		}
		k, v, ok := strings.Cut(args[i+1], "=")
		if !ok || options[k] != "" {
			t.Fatal(args)
		}
		options[k] = v
	}
	for key, value := range map[string]string{"Dir::Etc::main": "-", "Dir::Etc::parts": "-", "Dir::Etc::sourceparts": "-", "Dir::Etc::preferences": "-", "Dir::Etc::preferencesparts": "-", "APT::Get::AllowUnauthenticated": "false", "Acquire::AllowInsecureRepositories": "false", "Acquire::AllowDowngradeToInsecureRepositories": "false", "Acquire::Check-Valid-Until": "true", "Acquire::Check-Date": "true", "APT::Update::Error-Mode": "any"} {
		if options[key] != value {
			t.Fatal(key, options[key])
		}
	}
	for _, p := range []string{"relative", "/opt/../etc", "/tmp/a\n", ""} {
		if _, err := threatIDSPrivateAPTArgs(p); err == nil {
			t.Fatal(p)
		}
	}
}
