package executor

import (
	"errors"
	"local/panel/internal/runtimecatalog"
	"strings"
)

// The committed managed ServerRoot is the selection authority. Merely installing
// a newer runtime must never move existing sites or reinterpret an old DSO.
// Accept only one literal reviewed root, with no includes, expansion or aliases.
func apacheSourceRelease(source string) (runtimecatalog.Release, error) {
	var selected runtimecatalog.Release
	if len(source) > 2<<20 || !strings.HasPrefix(source, "# managed by panel\n") || strings.ContainsRune(source, '\x00') {
		return selected, errors.New("Apache 配置不是完整有界的受管配置")
	}
	count := 0
	for _, line := range strings.Split(source, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.EqualFold(fields[0], "ServerRoot") {
			continue
		}
		count++
		if len(fields) != 2 {
			return selected, errors.New("Apache ServerRoot 含非字面参数")
		}
		for _, r := range runtimecatalog.Apache {
			if fields[1] == r.Prefix() || fields[1] == `"`+r.Prefix()+`"` {
				selected = r
			}
		}
		if selected.ID == "" {
			return selected, errors.New("Apache ServerRoot 不在审核目录中")
		}
	}
	if count != 1 {
		return runtimecatalog.Release{}, errors.New("Apache 必须有且只有一个受管 ServerRoot")
	}
	return selected, nil
}

func apacheRecordRelease(version string) (runtimecatalog.Release, error) {
	r, ok := runtimecatalog.Find("apache-" + version)
	if !ok || r.Family != "apache" {
		return runtimecatalog.Release{}, errors.New("Apache 构建版本不在审核目录中")
	}
	return r, nil
}
