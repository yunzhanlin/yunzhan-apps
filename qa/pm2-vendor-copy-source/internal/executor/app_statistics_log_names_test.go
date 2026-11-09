package executor

import (
	"local/panel/internal/core"
	"strings"
	"testing"
)

func TestStatisticsLogrotateReadNamesDoNotBroadenDeletionAuthority(t *testing.T) {
	id := strings.Repeat("a", 32)
	prefix := "panel-" + id + ".access.log"
	for _, suffix := range []string{".1", ".1.gz", ".14.gz", ".4096", "-20261013", "-20261013.gz", ".20261013-135501", ".20261013-135501.gz"} {
		if !statisticsLogArchiveName(id, prefix+suffix) {
			t.Fatal("conventional archive refused", suffix)
		}
	}
	for _, suffix := range []string{".0", ".01", ".4097", ".-1", ".1.gz.gz", ".1/escape", "-20261313", "-2026101", "-20260230", ".backup", ".gz", "-20261013/escape"} {
		if statisticsLogArchiveName(id, prefix+suffix) {
			t.Fatal("unknown/unsafe archive accepted", suffix)
		}
	}
	for _, name := range []string{"panel-" + strings.Repeat("b", 32) + ".access.log.1", "panel-" + id + ".error.log.1"} {
		if statisticsLogArchiveName(id, name) {
			t.Fatal("another site or error log admitted")
		}
	}
	if core.ValidSiteLogArchiveName(id, prefix+".1.gz") || core.ValidSiteLogArchiveName(id, prefix+"-20261013.gz") {
		t.Fatal("read-only compatibility broadened cleanup authority")
	}
}
