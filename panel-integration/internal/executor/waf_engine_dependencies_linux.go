//go:build linux

package executor

import (
	"context"
	"errors"
	"strings"
	"time"
)

// Only distribution-signed, fixed build dependencies; never API package names.
var wafBuildDependencies = []string{"build-essential", "pkg-config", "libpcre2-dev", "libxml2-dev", "libyajl-dev", "libssl-dev", "zlib1g-dev", "patch"}

// Nginx 1.18 predates PCRE2 support. Add only this distribution package for
// its reviewed source; never substitute an API-supplied package or Nginx.
func wafBuildDependenciesForNginx(version string) []string {
	packages := append([]string{}, wafBuildDependencies...)
	if version == "1.18.0" {
		packages = append(packages, "libpcre3-dev")
	}
	return packages
}

func (s *Service) wafBuildDependenciesReady() bool {
	return s.wafBuildPackagesReady(wafBuildDependencies)
}

func (s *Service) wafCurrentBuildPackages(ctx context.Context) ([]string, error) {
	nginx, err := s.nginxBinary()
	if err != nil {
		return nil, err
	}
	output, err := s.moduleCommand(ctx, 5*time.Second, nginx, "-v")
	match := wafNginxVersionPattern.FindStringSubmatch(strings.TrimSpace(output))
	if err != nil || len(match) != 2 {
		return nil, errors.New("不能核对实际 Nginx，未尝试安装额外构建依赖")
	}
	return wafBuildDependenciesForNginx(match[1]), nil
}

func (s *Service) wafCurrentBuildDependenciesReady() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	packages, err := s.wafCurrentBuildPackages(ctx)
	return err == nil && s.wafBuildPackagesReady(packages)
}

func (s *Service) wafBuildPackagesReady(packages []string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	args := append([]string{"-W", "-f=${Package}\t${Status}\n"}, packages...)
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
	if len(seen) != len(packages) {
		return false
	}
	for _, pkg := range packages {
		if !seen[pkg] {
			return false
		}
	}
	return true
}
