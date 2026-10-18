package executor

// The IDS reader returns only a closed set of event metadata. It never returns
// packets, payloads, HTTP/DNS contents, headers, usernames or the original JSON.
import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const threatEVEByteLimit = 8 << 20
const threatEVELineLimit = 32 << 10
const threatEVERecordLimit = 20000

type threatEVEFilter struct {
	From, To      time.Time
	Search        string
	Severity      int
	Limit, Offset int
}
type threatEVEAlert struct {
	Timestamp       string `json:"timestamp"`
	SourceIP        string `json:"source_ip"`
	DestinationIP   string `json:"destination_ip"`
	SourcePort      uint16 `json:"source_port"`
	DestinationPort uint16 `json:"destination_port"`
	Protocol        string `json:"protocol"`
	SignatureID     uint32 `json:"signature_id"`
	Signature       string `json:"signature"`
	Category        string `json:"category"`
	Severity        int    `json:"severity"`
	Action          string `json:"action"`
	order           int
	at              time.Time
}
type threatEVEStats struct {
	Timestamp           string  `json:"timestamp"`
	KernelPackets       *uint64 `json:"kernel_packets"`
	KernelDrops         *uint64 `json:"kernel_drops"`
	DecodedPackets      *uint64 `json:"decoded_packets"`
	InvalidTCPChecksums *uint64 `json:"invalid_tcp_checksums"`
	ReassemblyGaps      *uint64 `json:"reassembly_gaps"`
	StreamMemcapDrops   *uint64 `json:"stream_memcap_drops"`
	AlertQueueOverflow  *uint64 `json:"alert_queue_overflow"`
}

// JavaScript cannot represent every uint64. Keep exact counters as decimal
// strings on the wire; a missing counter remains null, never invented zero.
func (s threatEVEStats) MarshalJSON() ([]byte, error) {
	decimal := func(n *uint64) *string {
		if n == nil {
			return nil
		}
		v := strconv.FormatUint(*n, 10)
		return &v
	}
	return json.Marshal(struct {
		Timestamp   string  `json:"timestamp"`
		Packets     *string `json:"kernel_packets"`
		Drops       *string `json:"kernel_drops"`
		Decoded     *string `json:"decoded_packets"`
		Checksums   *string `json:"invalid_tcp_checksums"`
		Gaps        *string `json:"reassembly_gaps"`
		MemcapDrops *string `json:"stream_memcap_drops"`
		Overflow    *string `json:"alert_queue_overflow"`
	}{s.Timestamp, decimal(s.KernelPackets), decimal(s.KernelDrops), decimal(s.DecodedPackets), decimal(s.InvalidTCPChecksums), decimal(s.ReassemblyGaps), decimal(s.StreamMemcapDrops), decimal(s.AlertQueueOverflow)})
}

// Real Suricata EVE timestamps use +0800, not just RFC3339's +08:00.
// Accept both explicit-zone forms; never guess a zone for a bare timestamp.
func parseThreatEVETime(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999-0700"} {
		at, err := time.Parse(layout, value)
		if err == nil && at.Year() >= 2000 && at.Year() <= 2100 {
			return at, nil
		}
	}
	return time.Time{}, errors.New("IDS 明确时区的实际时间字段无效")
}

// systemd active alone does not prove that packets are being observed.
// Require an identity-verified running process and fresh counters from this
// start, including real zero samples; old/future/missing stats stay unknown.
func threatIDSCaptureState(stats *threatEVEStats, now, started time.Time, processVerified bool) string {
	if !processVerified {
		return "not-running"
	}
	if stats == nil || stats.KernelPackets == nil || stats.KernelDrops == nil || stats.DecodedPackets == nil || stats.InvalidTCPChecksums == nil || stats.ReassemblyGaps == nil || stats.StreamMemcapDrops == nil || stats.AlertQueueOverflow == nil || started.IsZero() || now.Before(started) {
		return "unknown"
	}
	at, err := parseThreatEVETime(stats.Timestamp)
	if err != nil || at.Before(started) || at.After(now.Add(2*time.Second)) {
		return "unknown"
	}
	if now.Sub(at) > 25*time.Second {
		return "stale"
	}
	if *stats.KernelDrops > 0 {
		return "capture-drops"
	}
	if *stats.InvalidTCPChecksums > 0 {
		return "capture-checksum-errors"
	}
	if *stats.ReassemblyGaps > 0 || *stats.StreamMemcapDrops > 0 {
		return "capture-incomplete"
	}
	if *stats.AlertQueueOverflow > 0 {
		return "alert-overflow"
	}
	return "observing"
}

type threatEVEReport struct {
	Alerts         []threatEVEAlert `json:"alerts"`
	Stats          *threatEVEStats  `json:"capture_stats"`
	MatchingAlerts int              `json:"matching_alerts"`
	ScannedRecords int              `json:"scanned_records"`
	InvalidRecords int              `json:"invalid_records"`
	Partial        bool             `json:"partial"`
	PageLimited    bool             `json:"page_limited"`
	Limit          int              `json:"limit"`
	Offset         int              `json:"offset"`
	SeverityCounts map[int]int      `json:"severity_counts"`
}

func threatEVEText(s string, max int, required bool) bool {
	if (required && s == "") || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func validateThreatEVEFilter(in threatEVEFilter) (threatEVEFilter, error) {
	if !threatEVEText(in.Search, 128, false) || in.Severity < 0 || in.Severity > 4 || in.Limit < 0 || in.Limit > 200 || in.Offset < 0 || in.Offset > threatEVERecordLimit || !in.From.IsZero() && !in.To.IsZero() && in.From.After(in.To) {
		return in, errors.New("IDS 筛选或分页范围无效")
	}
	if in.Limit == 0 {
		in.Limit = 50
	}
	return in, nil
}

func parseThreatEVEAlert(data []byte, order int) (threatEVEAlert, error) {
	var raw struct {
		Timestamp       string `json:"timestamp"`
		Source          string `json:"src_ip"`
		Destination     string `json:"dest_ip"`
		SourcePort      uint16 `json:"src_port"`
		DestinationPort uint16 `json:"dest_port"`
		Protocol        string `json:"proto"`
		Alert           struct {
			ID        uint32 `json:"signature_id"`
			Signature string `json:"signature"`
			Category  string `json:"category"`
			Severity  int    `json:"severity"`
			Action    string `json:"action"`
		} `json:"alert"`
	}
	if json.Unmarshal(data, &raw) != nil {
		return threatEVEAlert{}, errors.New("IDS 事件类型无效")
	}
	at, err := parseThreatEVETime(raw.Timestamp)
	source, e1 := netip.ParseAddr(raw.Source)
	dest, e2 := netip.ParseAddr(raw.Destination)
	if err != nil || at.Year() < 2000 || at.Year() > 2100 || e1 != nil || e2 != nil || source.Zone() != "" || dest.Zone() != "" || source.IsUnspecified() || dest.IsUnspecified() || raw.Alert.ID == 0 || raw.Alert.Severity < 1 || raw.Alert.Severity > 4 || !threatEVEText(raw.Alert.Signature, 256, true) || !threatEVEText(raw.Alert.Category, 128, false) {
		return threatEVEAlert{}, errors.New("IDS 事件身份、时间或风险字段无效")
	}
	switch raw.Protocol {
	case "TCP", "UDP", "ICMP", "ICMPv6", "SCTP":
	default:
		return threatEVEAlert{}, errors.New("IDS 协议字段无效")
	}
	switch raw.Alert.Action {
	case "allowed", "blocked", "drop", "rejected":
	default:
		return threatEVEAlert{}, errors.New("IDS 事件动作无效")
	}
	return threatEVEAlert{Timestamp: at.UTC().Format(time.RFC3339Nano), SourceIP: source.Unmap().String(), DestinationIP: dest.Unmap().String(), SourcePort: raw.SourcePort, DestinationPort: raw.DestinationPort, Protocol: raw.Protocol, SignatureID: raw.Alert.ID, Signature: raw.Alert.Signature, Category: raw.Alert.Category, Severity: raw.Alert.Severity, Action: raw.Alert.Action, order: order, at: at}, nil
}
func parseThreatEVEStats(data []byte) (*threatEVEStats, error) {
	var raw struct {
		Timestamp string `json:"timestamp"`
		Stats     struct {
			Capture struct {
				Packets *uint64 `json:"kernel_packets"`
				Drops   *uint64 `json:"kernel_drops"`
			} `json:"capture"`
			Decoder struct {
				Packets *uint64 `json:"pkts"`
			} `json:"decoder"`
			TCP struct {
				Checksums   *uint64 `json:"invalid_checksum"`
				Gaps        *uint64 `json:"reassembly_gap"`
				MemcapDrops *uint64 `json:"ssn_memcap_drop"`
			} `json:"tcp"`
			Detect struct {
				Overflow *uint64 `json:"alert_queue_overflow"`
			} `json:"detect"`
		} `json:"stats"`
	}
	if json.Unmarshal(data, &raw) != nil {
		return nil, errors.New("IDS 计数类型无效")
	}
	at, err := parseThreatEVETime(raw.Timestamp)
	if err != nil || at.Year() < 2000 || at.Year() > 2100 || raw.Stats.Capture.Packets == nil && raw.Stats.Capture.Drops == nil && raw.Stats.Decoder.Packets == nil {
		return nil, errors.New("IDS 实际采集计数缺失")
	}
	return &threatEVEStats{Timestamp: at.UTC().Format(time.RFC3339Nano), KernelPackets: raw.Stats.Capture.Packets, KernelDrops: raw.Stats.Capture.Drops, DecodedPackets: raw.Stats.Decoder.Packets, InvalidTCPChecksums: raw.Stats.TCP.Checksums, ReassemblyGaps: raw.Stats.TCP.Gaps, StreamMemcapDrops: raw.Stats.TCP.MemcapDrops, AlertQueueOverflow: raw.Stats.Detect.Overflow}, nil
}
func readThreatEVE(ctx context.Context, reader io.Reader, in threatEVEFilter, tailPartial bool) (threatEVEReport, error) {
	return readThreatEVESources(ctx, []threatEVESource{{Reader: reader, Live: true}}, in, tailPartial)
}

type threatEVESource struct {
	Reader io.Reader
	Live   bool
}

// Newest sources first; only live output supplies current process counters.
// The global record/page budget spans all archives, each bounded to 8 MiB.
func readThreatEVESources(ctx context.Context, sources []threatEVESource, in threatEVEFilter, tailPartial bool) (threatEVEReport, error) {
	if len(sources) < 1 || len(sources) > 5 || !sources[0].Live {
		return threatEVEReport{}, errors.New("IDS 查询源数量或当前计数来源不明确")
	}
	for i, source := range sources {
		if source.Reader == nil || i > 0 && source.Live {
			return threatEVEReport{}, errors.New("IDS 查询来源不闭合")
		}
	}
	if err := ctx.Err(); err != nil {
		return threatEVEReport{}, err
	}
	in, err := validateThreatEVEFilter(in)
	if err != nil {
		return threatEVEReport{}, err
	}
	out := threatEVEReport{Alerts: []threatEVEAlert{}, SeverityCounts: map[int]int{}, Limit: in.Limit, Offset: in.Offset, Partial: tailPartial}
	matched := []threatEVEAlert{}
Sources:
	for sourceIndex, source := range sources {
		bounded := &io.LimitedReader{R: source.Reader, N: threatEVEByteLimit + 1}
		scanner := bufio.NewScanner(bounded)
		scanner.Buffer(make([]byte, 4096), threatEVELineLimit)
		sourceRecord := 0
		for scanner.Scan() {
			if err = ctx.Err(); err != nil {
				return out, err
			}
			if bounded.N <= 0 {
				out.Partial = true
				break
			}
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}
			if out.ScannedRecords >= threatEVERecordLimit {
				out.Partial = true
				break Sources
			}
			out.ScannedRecords++
			sourceRecord++
			var head struct {
				Kind string `json:"event_type"`
			}
			if !utf8.Valid(line) || json.Unmarshal(line, &head) != nil || !threatEVEText(head.Kind, 32, true) {
				out.InvalidRecords++
				continue
			}
			switch head.Kind {
			case "alert":
				event, e := parseThreatEVEAlert(line, (len(sources)-sourceIndex)*threatEVERecordLimit+sourceRecord)
				if e != nil {
					out.InvalidRecords++
					continue
				}
				if !in.From.IsZero() && event.at.Before(in.From) || !in.To.IsZero() && event.at.After(in.To) || in.Severity != 0 && event.Severity != in.Severity {
					continue
				}
				if in.Search != "" && !strings.Contains(strings.ToLower(event.Signature+" "+event.Category+" "+event.SourceIP+" "+event.DestinationIP), strings.ToLower(in.Search)) {
					continue
				}
				matched = append(matched, event)
				out.MatchingAlerts++
				out.SeverityCounts[event.Severity]++
			case "stats":
				stats, e := parseThreatEVEStats(line)
				if e != nil {
					out.InvalidRecords++
					continue
				}
				if !source.Live {
					continue
				}
				stamp, _ := time.Parse(time.RFC3339Nano, stats.Timestamp)
				if out.Stats == nil {
					out.Stats = stats
				} else {
					previous, _ := time.Parse(time.RFC3339Nano, out.Stats.Timestamp)
					if !stamp.Before(previous) {
						out.Stats = stats
					}
				}
			}
		}
		if err = scanner.Err(); err != nil {
			return out, errors.New("IDS 记录读取失败或单行超过 32 KiB；未宣称扫描完整")
		}
	}
	if out.InvalidRecords > 0 {
		out.Partial = true
	}
	sort.SliceStable(matched, func(i, j int) bool {
		if matched[i].at.Equal(matched[j].at) {
			return matched[i].order > matched[j].order
		}
		return matched[i].at.After(matched[j].at)
	})
	if in.Offset < len(matched) {
		out.Alerts = matched[in.Offset:min(len(matched), in.Offset+in.Limit)]
	}
	out.PageLimited = out.MatchingAlerts > len(out.Alerts)
	return out, nil
}
