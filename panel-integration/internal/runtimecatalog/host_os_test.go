package runtimecatalog

import (
	"runtime"
	"testing"
)

func TestDebianHostReleaseAndDockerAvailability(t *testing.T) {
	for _, item := range []struct {
		data  string
		major string
	}{
		{`ID=debian` + "\n" + `VERSION_ID="12"`, "12"},
		{`ID=debian` + "\n" + `VERSION_ID="13"`, "13"},
		{`ID=ubuntu` + "\n" + `VERSION_ID="24.04"`, ""},
		{`ID=debian` + "\n" + `VERSION_ID="11"`, ""},
	} {
		if got := DebianMajorFromOSRelease([]byte(item.data)); got != item.major {
			t.Fatalf("got Debian release %q, want %q", got, item.major)
		}
	}
	if DockerAvailableOn("12") != (runtime.GOARCH == "amd64") || !DockerAvailableOn("13") || DockerAvailableOn("14") {
		t.Fatal("Docker must only be advertised where a reviewed package set exists")
	}
	if got := DockerReleaseOn("12"); runtime.GOARCH == "amd64" && (len(got) != 1 || got[0].ID != "docker-ce-29.8.2-bookworm") || runtime.GOARCH != "amd64" && len(got) != 0 {
		t.Fatalf("Debian 12 Docker release mismatch on %s: %+v", runtime.GOARCH, got)
	}
	if got := DockerReleaseOn("13"); len(got) != 1 || got[0].ID != "docker-debian-26.1.5" {
		t.Fatalf("Debian 13 Docker release mismatch: %+v", got)
	}
	if DebianNginxPackageURL("12") != "https://packages.debian.org/bookworm/nginx" {
		t.Fatal("Debian 12 Nginx inventory source must use bookworm")
	}
}

func TestDockerInstallSpecsUseExactDistributionDaemonVersions(t *testing.T) {
	for major, expected := range map[string]string{"12": "29.8.2", "13": "26.1.5+dfsg1"} {
		spec, ok := DockerSpecOn(major)
		if !ok || spec.EngineVersion != expected || spec.ComposeVersion == "" || len(spec.Packages) < 3 {
			t.Fatalf("incorrect exact Docker install spec on Debian %s: %+v", major, spec)
		}
	}
	spec, _ := DockerSpecOn("13")
	if spec.ComposeVersion != DockerComposePackageVersion {
		t.Fatal("Debian Compose daemon must report the reviewed package revision")
	}
}
