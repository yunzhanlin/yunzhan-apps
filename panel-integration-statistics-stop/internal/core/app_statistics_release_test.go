package core

import (
	"strings"
	"testing"
)

func TestStatisticsCursorRetirementReleaseVersionMatchesActualUpdateHandler(t *testing.T) {
	if version := SoftwareImplementationVersion("website-statistics-v2"); version != "2.6.0" {
		t.Fatal("implemented cursor retirement cannot be installed through version binding", version)
	}
	for _, version := range []string{"2.3.0", "2.4.0", "2.4.1", "2.5.0", "2.6.0"} {
		if err := ValidateSoftwareUpdate("website-statistics-v2", version); err != nil {
			t.Fatal("reviewed current or older statistics handler refused", version, err)
		}
	}
	for _, version := range []string{"2.5", "2.5.0-compat1", "2.5.1", "2.6", "2.6.0-compat1", "2.6.1", "2.7.0", "3.0", "invalid", "18446744073709551616.0"} {
		if err := ValidateSoftwareUpdate("website-statistics-v2", version); err == nil {
			t.Fatal("unimplemented statistics version accepted", version)
		}
	}
	guide := ModuleGuidance("website-statistics-v2")
	limits := strings.Join(guide.Limitations, " ")
	for _, boundary := range []string{"4096", "已消失", "已读完", "无冲突", "一分钟", "同事务", "不删原始日志", "未读证据"} {
		if !strings.Contains(limits, boundary) {
			t.Fatal("cursor retirement guidance lost an implemented safety boundary", boundary)
		}
	}
}
