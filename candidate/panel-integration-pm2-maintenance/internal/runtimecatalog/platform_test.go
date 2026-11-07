package runtimecatalog

import "testing"

func TestMainstreamPlatformsRequireExactOSIdentity(t *testing.T) {
	for _, platform := range []string{"debian-12", "debian-13", "ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04"} {
		id, version := "debian", platform[len("debian-"):]
		if platform[:6] == "ubuntu" {
			id, version = "ubuntu", platform[len("ubuntu-"):]
		}
		if got := PlatformFromOSRelease([]byte("ID=" + id + "\nVERSION_ID=\"" + version + "\"\n")); got != platform {
			t.Fatalf("%s: %s", platform, got)
		}
		spec, ok := DockerSpecOn(platform)
		if !ok || len(spec.Packages) < 3 || len(DockerReleaseOn(platform)) != 1 {
			t.Fatalf("missing reviewed Docker spec: %s", platform)
		}
	}
	for _, data := range []string{"ID=rocky\nVERSION_ID=9\nID_LIKE=debian", "ID=debian\nVERSION_ID=14", "ID=ubuntu\nVERSION_ID=25.10", "ID=linuxmint\nVERSION_ID=24.04\nID_LIKE=ubuntu"} {
		if got := PlatformFromOSRelease([]byte(data)); got != "" {
			t.Fatalf("unreviewed OS accepted: %q", got)
		}
	}
}
