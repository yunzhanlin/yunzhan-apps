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
	return ok && (major != "12" || runtime.GOARCH == "amd64")
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
