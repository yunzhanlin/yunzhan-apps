package core

import (
	"strings"
	"testing"
)

func TestPM2ProjectReadQueryCannotDispatchAConfigurationOrUnboundedInventory(t *testing.T) {
	for _, raw := range []string{"", "resource_id=owned-project&limit=64&offset=512", "limit=0"} {
		in, err := ParsePM2ProjectsQuery(raw)
		if err != nil || in.Limit < 1 || in.Limit > 64 || in.PM2OperationID != "" {
			t.Fatal(raw, in, err)
		}
	}
	for _, raw := range []string{"pm2_operation_id=" + strings.Repeat("a", 32), "limit=65", "limit=-1", "offset=513", "offset=-1", "limit=1&limit=1", "resource_id=../../service", "resource_id=valid-owned&action=start", "limit=01", "Offset=0"} {
		if _, err := ParsePM2ProjectsQuery(raw); err == nil {
			t.Fatal("unsafe project read accepted", raw)
		}
	}
}
