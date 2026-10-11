package executor

import (
	"bytes"
	"local/panel/internal/core"
	"time"
)

// Accept only the exact eight-key YZ5 numeric writer contract. Pointer fields
// distinguish missing/null fields from legitimate zero/false values.
func parseApacheBodyEvent(line []byte) (core.ApacheBodyEvent, bool) {
	var empty core.ApacheBodyEvent
	if len(line) == 0 || len(line) > 255 || bytes.ContainsAny(line, "\r\n\x00") {
		return empty, false
	}
	var record struct {
		TimeUS   *int64  `json:"time_us"`
		Engine   *string `json:"engine"`
		SiteID   *string `json:"site_id"`
		RuleID   *int    `json:"rule_id"`
		Phase    *int    `json:"phase"`
		Severity *int    `json:"severity"`
		Mode     *string `json:"mode"`
		Blocked  *bool   `json:"blocked"`
	}
	if apacheBodyDecodeJSON(line, &record) != nil || record.TimeUS == nil || record.Engine == nil || record.SiteID == nil || record.RuleID == nil || record.Phase == nil || record.Severity == nil || record.Mode == nil || record.Blocked == nil {
		return empty, false
	}
	if *record.TimeUS <= 0 || *record.TimeUS > 253402300799999999 || *record.Engine != apacheBodyEngineVersion || !core.ValidID(*record.SiteID) || *record.RuleID < 1 || *record.RuleID > 99999999 || *record.Phase < 1 || *record.Phase > 5 || *record.Severity < 0 || *record.Severity > 7 || (*record.Mode != "block" && *record.Mode != "observe") || *record.Blocked && *record.Mode != "block" {
		return empty, false
	}
	return core.ApacheBodyEvent{Time: time.UnixMicro(*record.TimeUS).UTC().Format(time.RFC3339Nano), Engine: *record.Engine, SiteID: *record.SiteID, RuleID: *record.RuleID, Phase: *record.Phase, Severity: *record.Severity, Mode: *record.Mode, Intercepted: *record.Blocked}, true
}
