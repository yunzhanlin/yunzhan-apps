package diskjob

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"local/panel/internal/diskusage"
)

// Fixed bound includes 200 long display paths after JSON HTML escaping.
// Older 128KiB bounds could reject legitimate top-100 reports after a scan.
const ReceiptBytesMax = 1 << 20

var ErrReceipt = errors.New("原全盘结果的格式、任务绑定或终态证据无法核对")

type Policy struct {
	Host               Host   `json:"host"`
	Cgroup             string `json:"control_group"`
	Threads            int    `json:"threads_checked"`
	Capabilities       string `json:"capabilities"`
	NoNewPrivileges    bool   `json:"no_new_privileges"`
	CPUQuota           string `json:"cpu_max"`
	MemoryMax          string `json:"memory_max"`
	MemoryHigh         string `json:"memory_high"`
	MemorySwapMax      string `json:"memory_swap_max"`
	TasksMax           string `json:"pids_max"`
	IOWeight           string `json:"io_weight"`
	FileDescriptorsMax uint64 `json:"file_descriptors_max"`
	FileBytesMax       uint64 `json:"file_bytes_max"`
}

type Dispatch struct {
	Format      int    `json:"format"`
	JobID       string `json:"job_id"`
	ActorID     string `json:"actor_id"`
	RequestSHA  string `json:"request_sha256"`
	ExecutorSHA string `json:"executor_sha256"`
}

type Started struct {
	Format      int    `json:"format"`
	JobID       string `json:"job_id"`
	RequestSHA  string `json:"request_sha256"`
	ExecutorSHA string `json:"executor_sha256"`
	PID         string `json:"pid"`
	StartTicks  string `json:"start_ticks"`
	At          string `json:"at"`
	Policy      Policy `json:"policy"`
}

// The fixed Root producer writes this only after Start failed, or Wait on its
// ORIGINAL exec.Cmd returned. It is launch evidence, never a scan result.
type Launcher struct {
	Format      int    `json:"format"`
	RequestSHA  string `json:"request_sha256"`
	ExecutorSHA string `json:"executor_sha256"`
	State       string `json:"state"` // not_started or exited
	ExitCode    *int   `json:"exit_code"`
	At          string `json:"at"`
}

type Progress struct {
	Format     int                  `json:"format"`
	RequestSHA string               `json:"request_sha256"`
	Started    Started              `json:"started"`
	At         string               `json:"at"`
	Report     diskusage.ScanReport `json:"report"`
}

type Result struct {
	Format     int                   `json:"format"`
	Request    Request               `json:"request"`
	RequestSHA string                `json:"request_sha256"`
	Started    Started               `json:"started"`
	State      string                `json:"state"`
	ErrorCode  string                `json:"error_code"`
	At         string                `json:"at"`
	Capacity   diskusage.Capacity    `json:"capacity"`
	Report     *diskusage.ScanReport `json:"report"`
}

// This is a trusted executor-to-Core observation, never public user input.
// Absence/failed commands do not imply success; an original result is necessary
// but not sufficient until its process and entire scope have stopped.
type Observation struct {
	Format           int       `json:"format"`
	Request          Request   `json:"request"`
	State            string    `json:"state"`
	TerminalVerified bool      `json:"terminal_verified"`
	Process          string    `json:"original_process"` // alive, gone, unknown
	Scope            string    `json:"original_scope"`   // busy, empty, unknown
	RunLeaseFree     bool      `json:"run_lease_free"`
	ResultSHA        string    `json:"result_sha256"`
	Started          *Started  `json:"started"`
	Progress         *Progress `json:"progress"`
	Result           *Result   `json:"result"`
	Launcher         *Launcher `json:"launcher"`
}

func DecodeLauncher(raw []byte, d Dispatch, in Request) (Launcher, error) {
	var out Launcher
	if decodeReceipt(raw, &out, 8192) != nil || ValidateDispatch(d, in) != nil || out.Format != 1 || out.RequestSHA != d.RequestSHA || out.ExecutorSHA != d.ExecutorSHA {
		return Launcher{}, ErrReceipt
	}
	if _, ok := receiptTime(out.At); !ok {
		return Launcher{}, ErrReceipt
	}
	switch out.State {
	case "not_started":
		if out.ExitCode != nil {
			return Launcher{}, ErrReceipt
		}
	case "exited":
		if out.ExitCode == nil || *out.ExitCode < -1 || *out.ExitCode > 255 {
			return Launcher{}, ErrReceipt
		}
	default:
		return Launcher{}, ErrReceipt
	}
	return out, nil
}

func RequestSHA(in Request) string {
	raw, _ := json.Marshal(in)
	return hashBytes(raw)
}

func hashBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func ResultSHA(in Result) string {
	raw, _ := json.Marshal(in)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Internal immutable receipts are emitted by json.Marshal. Requiring the exact
// canonical encoding recursively rejects missing/unknown fields, duplicate keys,
// case aliases, numeric coercions, null-for-zero and trailing data, even nested.
// This does not impose canonical encoding on public Selection requests.
func decodeReceipt(raw []byte, out any, max int) error {
	if len(raw) < 2 || len(raw) > max || json.Unmarshal(raw, out) != nil {
		return ErrReceipt
	}
	encoded, err := json.Marshal(out)
	if err != nil || !bytes.Equal(raw, encoded) {
		return ErrReceipt
	}
	return nil
}

func receiptTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil && t.Year() >= 2026 && strings.HasSuffix(s, "Z")
}

func notEarlier(a, b string) bool {
	x, ok := receiptTime(a)
	y, other := receiptTime(b)
	return ok && other && !x.Before(y)
}

func ValidateDispatch(d Dispatch, in Request) error {
	if ValidateRequest(in) != nil || d.Format != 1 || d.JobID != in.JobID || d.ActorID != in.ActorID || d.RequestSHA != RequestSHA(in) || !ValidSHA(d.ExecutorSHA) {
		return ErrReceipt
	}
	return nil
}

func DecodeDispatch(raw []byte, in Request) (Dispatch, error) {
	var d Dispatch
	if decodeReceipt(raw, &d, 8192) != nil || ValidateDispatch(d, in) != nil {
		return Dispatch{}, ErrReceipt
	}
	return d, nil
}

func ValidateStarted(s Started, d Dispatch, in Request) error {
	unit, err := UnitName(in.JobID, false)
	p := s.Policy
	pid, e := strconv.ParseUint(s.PID, 10, 31)
	_, validTime := receiptTime(s.At)
	if ValidateDispatch(d, in) != nil || err != nil || s.Format != 1 || s.JobID != in.JobID || s.RequestSHA != d.RequestSHA || s.ExecutorSHA != d.ExecutorSHA || e != nil || pid < 2 || !CanonicalInteger(s.PID, true) || !CanonicalInteger(s.StartTicks, true) || !validTime ||
		p.Host != (Host{in.Selection.BootID, in.Selection.NamespaceID}) || p.Cgroup != "/system.slice/"+unit || p.Threads < 1 || p.Threads > 32 || p.Capabilities != "CAP_DAC_READ_SEARCH" || !p.NoNewPrivileges ||
		p.CPUQuota != "20000 100000" || p.MemoryMax != "536870912" || p.MemoryHigh != "402653184" || p.MemorySwapMax != "0" || p.TasksMax != "32" || p.IOWeight != "default 10" || p.FileDescriptorsMax != 2048 || p.FileBytesMax != 1<<30 {
		return ErrReceipt
	}
	return nil
}

func DecodeStarted(raw []byte, d Dispatch, in Request) (Started, error) {
	var s Started
	if decodeReceipt(raw, &s, 8192) != nil || ValidateStarted(s, d, in) != nil {
		return Started{}, ErrReceipt
	}
	return s, nil
}

func safeDisplayPath(s string, actionable bool) bool {
	if len(s) < 1 || len(s) > 515 || !utf8.ValidString(s) || !strings.HasPrefix(s, "/") || strings.ContainsAny(s, "\x00\r\n") {
		return false
	}
	for _, c := range s {
		if c < 32 || c == 127 {
			return false
		}
	}
	return !actionable || diskusage.ValidHostPath(s)
}

func validateReport(r diskusage.ScanReport, in Request, started Started, final bool) error {
	if r.Format != 1 || r.MountID != in.Selection.MountID || r.BindingSHA != in.Selection.MountSHA || !safeDisplayPath(r.SelectedPath, false) || !notEarlier(r.StartedAt, started.At) || r.SnapshotConsistent || r.ExclusivePhysicalBytes ||
		r.Budget != diskusage.DefaultScanBudget() || r.EntriesRead > r.Budget.Entries || r.Accounting != "st_blocks_512_per_inode_not_exclusive_extents" || r.DirectoryAttribution != "first_observed_inode_within_this_scan" ||
		r.Reasons == nil || len(r.Reasons) > 64 || r.TopFiles == nil || r.TopDirectories == nil || len(r.TopFiles) > 100 || len(r.TopDirectories) > 100 {
		return ErrReceipt
	}
	for _, reason := range r.Reasons {
		if len(reason) < 1 || len(reason) > 64 {
			return ErrReceipt
		}
		for _, c := range reason {
			if c != '_' && (c < 'a' || c > 'z') {
				return ErrReceipt
			}
		}
	}
	for _, rows := range [][]diskusage.UsageRow{r.TopFiles, r.TopDirectories} {
		for _, row := range rows {
			if !safeDisplayPath(row.Path, row.Actionable) {
				return ErrReceipt
			}
		}
	}
	if !final {
		if r.State != "running" || r.Complete || r.FinishedAt != "" || !r.IndexFlushed {
			return ErrReceipt
		}
		return nil
	}
	if !notEarlier(r.FinishedAt, r.StartedAt) {
		return ErrReceipt
	}
	switch r.State {
	case "complete":
		if !r.Complete || !r.IndexFlushed || len(r.Reasons) != 0 || r.UnknownEntries != 0 || r.SkippedDirectories != 0 || r.MountBoundaries != 0 || r.OwnWorkerDirectories != 0 || r.Cycles != 0 {
			return ErrReceipt
		}
	case "partial":
		if r.Complete || !r.IndexFlushed || len(r.Reasons) == 0 {
			return ErrReceipt
		}
	case "failed", "canceled":
		if r.Complete || len(r.Reasons) == 0 {
			return ErrReceipt
		}
	default:
		return ErrReceipt
	}
	return nil
}

func decimal(s *string) (uint64, bool) {
	if s == nil || !CanonicalInteger(*s, false) {
		return 0, false
	}
	n, err := strconv.ParseUint(*s, 10, 64)
	return n, err == nil
}

func validateCapacity(c diskusage.Capacity) error {
	if !c.MayOverlap || c.SnapshotConsistent {
		return ErrReceipt
	}
	values := []*string{c.TotalBytes, c.FreeBytes, c.AvailableBytes, c.UsedBytes, c.ReservedFreeBytes}
	switch c.State {
	case "unavailable":
		for _, v := range values {
			if v != nil {
				return ErrReceipt
			}
		}
		if c.ViewSHA != "" || c.InodeState != "unavailable" {
			return ErrReceipt
		}
	case "available":
		n := make([]uint64, 5)
		for i, v := range values {
			var ok bool
			if n[i], ok = decimal(v); !ok {
				return ErrReceipt
			}
		}
		if !ValidSHA(c.ViewSHA) || n[0] == 0 || n[1] > n[0] || n[2] > n[1] || n[3] != n[0]-n[1] || n[4] != n[1]-n[2] {
			return ErrReceipt
		}
	default:
		return ErrReceipt
	}
	switch c.InodeState {
	case "unavailable":
		if c.TotalInodes != nil || c.FreeInodes != nil || c.UsedInodes != nil {
			return ErrReceipt
		}
	case "available":
		t, a := decimal(c.TotalInodes)
		f, b := decimal(c.FreeInodes)
		u, d := decimal(c.UsedInodes)
		if c.State != "available" || !a || !b || !d || t == 0 || t == math.MaxUint64 || f > t || u != t-f {
			return ErrReceipt
		}
	default:
		return ErrReceipt
	}
	return nil
}

func DecodeProgress(raw []byte, s Started, d Dispatch, in Request) (Progress, error) {
	var p Progress
	if decodeReceipt(raw, &p, ReceiptBytesMax) != nil || ValidateStarted(s, d, in) != nil || p.Format != 1 || p.RequestSHA != d.RequestSHA || p.Started != s || !notEarlier(p.At, s.At) || validateReport(p.Report, in, s, false) != nil || !notEarlier(p.At, p.Report.StartedAt) {
		return Progress{}, ErrReceipt
	}
	return p, nil
}

func ValidateResult(r Result, s Started, d Dispatch, in Request) error {
	if ValidateStarted(s, d, in) != nil || r.Format != 1 || r.Request != in || r.RequestSHA != d.RequestSHA || r.Started != s || !notEarlier(r.At, s.At) || validateCapacity(r.Capacity) != nil {
		return ErrReceipt
	}
	switch r.State {
	case "complete", "partial":
		if r.Report == nil || r.ErrorCode != "" {
			return ErrReceipt
		}
	case "failed", "canceled":
		switch r.ErrorCode {
		case "canceled", "deadline_reached", "progress_or_authority_rejected", "index_unavailable_or_full", "mount_changed_or_boundary", "scan_or_authority_unavailable":
		default:
			return ErrReceipt
		}
		if (r.State == "canceled") != (r.ErrorCode == "canceled") {
			return ErrReceipt
		}
	default:
		return ErrReceipt
	}
	if r.Report != nil && (validateReport(*r.Report, in, s, true) != nil || r.State != r.Report.State || !notEarlier(r.At, r.Report.FinishedAt)) {
		return ErrReceipt
	}
	return nil
}

func DecodeResult(raw []byte, s Started, d Dispatch, in Request) (Result, error) {
	var r Result
	if decodeReceipt(raw, &r, ReceiptBytesMax) != nil || ValidateResult(r, s, d, in) != nil {
		return Result{}, ErrReceipt
	}
	return r, nil
}

func ValidateObservation(o Observation, in Request) error {
	if ValidateRequest(in) != nil || o.Format != 1 || o.Request != in {
		return ErrReceipt
	}
	if o.Process != "alive" && o.Process != "gone" && o.Process != "unknown" {
		return ErrReceipt
	}
	if o.Scope != "busy" && o.Scope != "empty" && o.Scope != "unknown" {
		return ErrReceipt
	}
	if o.Launcher != nil {
		d := Dispatch{1, in.JobID, in.ActorID, RequestSHA(in), o.Launcher.ExecutorSHA}
		if o.Started != nil && o.Started.ExecutorSHA != d.ExecutorSHA {
			return ErrReceipt
		}
		raw, _ := json.Marshal(o.Launcher)
		if _, err := DecodeLauncher(raw, d, in); err != nil {
			return err
		}
		if o.Started != nil && o.Launcher.State == "not_started" {
			return ErrReceipt
		}
	}
	if o.Started == nil {
		if o.Process != "unknown" || o.Progress != nil || o.Result != nil {
			return ErrReceipt
		}
	} else {
		s := *o.Started
		d := Dispatch{1, in.JobID, in.ActorID, RequestSHA(in), s.ExecutorSHA}
		if ValidateStarted(s, d, in) != nil {
			return ErrReceipt
		}
		if o.Progress != nil {
			raw, _ := json.Marshal(o.Progress)
			if _, err := DecodeProgress(raw, s, d, in); err != nil {
				return err
			}
		}
		if o.Result != nil && ValidateResult(*o.Result, s, d, in) != nil {
			return ErrReceipt
		}
	}
	if o.Result == nil {
		if o.ResultSHA != "" || o.TerminalVerified || o.State != "starting" && o.State != "running" && o.State != "uncertain" {
			return ErrReceipt
		}
		if o.State == "running" && (o.Started == nil || o.Process != "alive" || o.Scope != "busy") {
			return ErrReceipt
		}
		if o.State == "starting" && o.Started != nil {
			return ErrReceipt
		}
		if o.State == "starting" && o.Launcher != nil {
			return ErrReceipt
		}
		return nil
	}
	if o.ResultSHA != ResultSHA(*o.Result) {
		return ErrReceipt
	}
	verified := o.Process == "gone" && o.Scope == "empty" && o.RunLeaseFree
	if o.TerminalVerified != verified || verified && o.State != o.Result.State || !verified && o.State != "settling" {
		return ErrReceipt
	}
	return nil
}
