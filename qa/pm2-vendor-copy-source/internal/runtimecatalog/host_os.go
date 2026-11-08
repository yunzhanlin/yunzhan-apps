package runtimecatalog

import (
	"os"
	"runtime"
	"strings"
)

func DebianMajorFromOSRelease(contents []byte) string {
	values := map[string]string{}
	for _, line := range strings.Split(string(contents), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[key] = strings.Trim(value, `"'`)
	}
	if values["ID"] != "debian" {
		return ""
	}
	if values["VERSION_ID"] == "12" || values["VERSION_ID"] == "13" {
		return values["VERSION_ID"]
	}
	return ""
}

func HostDebianMajor() string {
	contents, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	return DebianMajorFromOSRelease(contents)
}

// Platform IDs are exact, reviewed distribution versions, not ID_LIKE guesses.
// An Ubuntu derivative or an unknown future release must not inherit support.
func PlatformFromOSRelease(contents []byte) string {
	values := map[string]string{}
	for _, line := range strings.Split(string(contents), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			values[key] = strings.Trim(value, `"'`)
		}
	}
	id := values["ID"] + "-" + values["VERSION_ID"]
	switch id {
	case "debian-12", "debian-13", "ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04":
		return id
	}
	return ""
}

func HostPlatform() string {
	contents, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	return PlatformFromOSRelease(contents)
}

func NginxPackageURL(platform string) string {
	switch platform {
	case "ubuntu-22.04":
		return "https://packages.ubuntu.com/jammy/nginx"
	case "ubuntu-24.04":
		return "https://packages.ubuntu.com/noble/nginx"
	case "ubuntu-26.04":
		return "https://packages.ubuntu.com/resolute/nginx"
	}
	return DebianNginxPackageURL(strings.TrimPrefix(platform, "debian-"))
}

func DebianNginxPackageURL(major string) string {
	switch major {
	case "12":
		return "https://packages.debian.org/bookworm/nginx"
	case "13":
		return "https://packages.debian.org/trixie/nginx"
	default:
		return "https://packages.debian.org/nginx"
	}
}

func DockerAvailableOn(major string) bool {
	_, ok := DockerSpecOn(major)
	return ok && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")
}

func DockerReleaseOn(major string) []Release {
	if !DockerAvailableOn(major) {
		return nil
	}
	spec, ok := DockerSpecOn(major)
	if !ok {
		return nil
	}
	for _, release := range Docker {
		if release.ID == spec.ReleaseID {
			return []Release{release}
		}
	}
	return nil
}
