package executor

import (
	"local/panel/internal/core"
	"strconv"
	"strings"
	"time"
)

// Read-only ingestion recognizes conventional logrotate suffixes as well as
// the panel's timestamp suffix. This does NOT broaden cleanup/deletion APIs.
func statisticsLogArchiveName(id, name string) bool {
	if !core.ValidID(id) {
		return false
	}
	prefix := "panel-" + id + ".access.log"
	if strings.HasPrefix(name, prefix+".") && core.ValidSiteLogArchiveName(id, name) {
		return true
	}
	suffix := strings.TrimPrefix(name, prefix)
	if suffix == name {
		return false
	}
	suffix = strings.TrimSuffix(suffix, ".gz")
	if strings.HasPrefix(suffix, ".") {
		value := strings.TrimPrefix(suffix, ".")
		number, err := strconv.Atoi(value)
		return err == nil && number >= 1 && number <= 4096 && strconv.Itoa(number) == value
	}
	if strings.HasPrefix(suffix, "-") {
		value := strings.TrimPrefix(suffix, "-")
		parsed, err := time.Parse("20060102", value)
		return err == nil && len(value) == 8 && parsed.Format("20060102") == value
	}
	return false
}
