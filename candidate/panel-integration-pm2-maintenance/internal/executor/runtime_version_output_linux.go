//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"local/panel/internal/runtimecatalog"
)

// A manifest/file-presence check is not proof that an existing programme can
// run at the reviewed version. The normal native job must observe it before
// it can report success (and before Core can issue an application receipt).
// This helper never repairs, downloads, changes a service or creates a receipt.
func verifyExistingRuntime(ctx context.Context, r runtimecatalog.Release, load func(string) (RuntimeManifest, error), probe func(context.Context, runtimecatalog.Release) error) (bool, error) {
	if load == nil || probe == nil {
		return true, errors.New("已有运行时核对器缺失，未认定安装成功")
	}
	if _, err := load(r.ID); err != nil {
		return false, nil // The existing incomplete-prefix refusal remains in InstallJob.
	}
	if err := ctx.Err(); err != nil {
		return true, err
	}
	if err := probe(ctx, r); err != nil {
		return true, fmt.Errorf("已有精确目录的实际程序核对失败；原文件保留，未重建或认定安装成功: %w", err)
	}
	return true, nil
}

// Match complete programme version tokens, not substrings: 1.30.60 must never
// satisfy 1.30.6, nor may a diagnostic mentioning the expected version do so.
// This only parses output of the fixed version command, never arbitrary input
// URLs, commands, executable paths, package revisions or install permissions.
func runtimeVersionOutputMatches(r runtimecatalog.Release, raw string) bool {
	if len(raw) == 0 || len(raw) > 32768 || !utf8.ValidString(raw) || strings.ContainsAny(raw, "\x00\r") {
		return false
	}
	output := strings.TrimSpace(raw)
	lines := strings.Split(output, "\n")
	if len(lines) > 8 {
		return false
	}
	if r.Family != "apache" && len(lines) != 1 {
		return false
	}
	fields := strings.Fields(lines[0])
	switch r.Family {
	case "php":
		return output == r.Version
	case "node":
		return output == "v"+r.Version
	case "nginx":
		return output == "nginx version: nginx/"+r.Version
	case "apache":
		return len(fields) >= 3 && fields[0] == "Server" && fields[1] == "version:" && fields[2] == "Apache/"+r.Version
	case "mysql":
		return len(fields) >= 4 && (fields[0] == "mysql" || fields[0] == r.CLI()) && fields[1] == "Ver" && fields[2] == r.Version && fields[3] == "for"
	case "mariadb":
		if len(fields) < 4 || fields[0] != "mariadb" && fields[0] != r.CLI() {
			return false
		}
		if fields[1] == "from" {
			return fields[2] == r.Version+"-MariaDB," && fields[3] == "client"
		}
		return len(fields) >= 6 && fields[1] == "Ver" && fields[3] == "Distrib" && fields[4] == r.Version+"-MariaDB," && fields[5] == "for"
	case "redis":
		if len(fields) < 3 || fields[0] != "Redis" || fields[1] != "server" {
			return false
		}
		versions, exact := 0, false
		for _, field := range fields[2:] {
			if strings.HasPrefix(field, "v=") {
				versions++
				exact = field == "v="+r.Version
			}
		}
		return versions == 1 && exact
	case "docker":
		// Debian's reviewed engine really reports +dfsg1; this is an exact
		// per-release allowlist, not a general prefix/suffix exemption.
		for _, platform := range []string{"12", "13", "ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04"} {
			spec, ok := runtimecatalog.DockerSpecOn(platform)
			if ok && spec.ReleaseID == r.ID {
				return output == spec.EngineVersion
			}
		}
	}
	return false
}
