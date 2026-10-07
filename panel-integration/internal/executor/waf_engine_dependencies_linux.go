//go:build linux

package executor

import (
	"context"
	"strings"
	"time"
)

// Only distribution-signed, fixed build dependencies; never API package names.
var wafBuildDependencies = []string{"build-essential", "pkg-config", "libpcre2-dev", "libxml2-dev", "libyajl-dev", "libssl-dev", "zlib1g-dev", "patch"}

func (s *Service) wafBuildDependenciesReady() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	args := append([]string{"-W", "-f=${Package}\t${Status}\n"}, wafBuildDependencies...)
	out, err := s.moduleCommand(ctx, 5*time.Second, "/usr/bin/dpkg-query", args...)
	if err != nil {
		return false
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 2 || fields[1] != "install ok installed" || seen[fields[0]] {
			return false
		}
		seen[fields[0]] = true
	}
	if len(seen) != len(wafBuildDependencies) {
		return false
	}
	for _, pkg := range wafBuildDependencies {
		if !seen[pkg] {
			return false
		}
	}
	return true
}
