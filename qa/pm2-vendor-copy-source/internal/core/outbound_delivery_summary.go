package core

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
)

// Reconstruct the summary from closed kind/subtype values, never saved titles,
// task output, domains, raw executor errors or arbitrary JSON extension fields.
func outboundDeliverySummary(payload, eventID string) (OutboundMessage, error) {
	var source OutboundMessage
	if len(payload) < 1 || len(payload) > 4096 || !outboundJSONUniqueKeys(payload) {
		return source, errors.New("原推送摘要大小不可核对")
	}
	d := json.NewDecoder(strings.NewReader(payload))
	d.DisallowUnknownFields()
	if d.Decode(&source) != nil || d.Decode(new(any)) != io.EOF || source.SchemaVersion != 1 || !ValidID(source.EventID) || eventID != "" && source.EventID != eventID || (!containsMenu(outboundKinds, source.Kind) && source.Kind != "test") || !containsMenu([]string{"info", "warning", "critical"}, source.Severity) || source.CreatedAt < 1 || source.Report != nil && source.Kind != "daily" {
		return OutboundMessage{}, errors.New("原推送事件身份、范围或摘要不可核对")
	}
	subtype, e := outboundEventSource(source.Kind, source.EventType)
	if e != nil {
		return OutboundMessage{}, e
	}
	expected := map[string]string{"traffic_committed": "info", "traffic_recovered": "warning", "traffic_pending": "critical", "source_ready": "info", "source_unavailable": "critical"}
	if severity, fixed := expected[source.EventType]; fixed && source.Severity != severity || source.EventType == "worker_observation" && source.Severity != "info" && source.Severity != "critical" {
		return OutboundMessage{}, errors.New("原推送事件状态与严重性不可核对")
	}
	if source.Report != nil {
		r := source.Report
		if !validDailyReportDay(r.Day) {
			return OutboundMessage{}, errors.New("原日报摘要日期不可核对")
		}
		for _, count := range []int{r.Sites, r.RunningSites, r.FailedSiteJobs, r.FailedRuntimeJobs, r.AuditEvents, r.CertificatesDue} {
			if count < 0 || count > 1000000000 {
				return OutboundMessage{}, errors.New("原日报摘要统计不可核对")
			}
		}
		for key := range r.CountAvailable {
			if !containsMenu([]string{"sites", "running_sites", "failed_site_jobs", "failed_runtime_jobs", "audit_events_24h", "certificates_due_14_days"}, key) {
				return OutboundMessage{}, errors.New("原日报摘要可用性范围不可核对")
			}
		}
		for _, value := range []*float64{r.Resources.CPU, r.Resources.Memory, r.Resources.Disk} {
			if value != nil && (math.IsNaN(*value) || math.IsInf(*value, 0) || *value < 0 || *value > 100) {
				return OutboundMessage{}, errors.New("原日报资源摘要不可核对")
			}
		}
	}
	m := safeOutboundMessage(Notification{ID: source.EventID, Kind: source.Kind, Source: subtype, Severity: source.Severity, CreatedAt: source.CreatedAt})
	m.Test, m.Report = source.Test, source.Report
	return m, nil
}

func outboundJSONUniqueKeys(payload string) bool {
	d := json.NewDecoder(strings.NewReader(payload))
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 16 {
			return false
		}
		token, e := d.Token()
		if e != nil {
			return false
		}
		delimiter, composite := token.(json.Delim)
		if !composite {
			return true
		}
		switch delimiter {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				name, ok := key.(string)
				name = strings.ToLower(name) // Go JSON field matching is case-insensitive.
				if e != nil || !ok || keys[name] || !value(depth+1) {
					return false
				}
				keys[name] = true
			}
		case '[':
			for d.More() {
				if !value(depth + 1) {
					return false
				}
			}
		default:
			return false
		}
		end, e := d.Token()
		return e == nil && (delimiter == '{' && end == json.Delim('}') || delimiter == '[' && end == json.Delim(']'))
	}
	if !value(0) {
		return false
	}
	_, e := d.Token()
	return e == io.EOF
}
