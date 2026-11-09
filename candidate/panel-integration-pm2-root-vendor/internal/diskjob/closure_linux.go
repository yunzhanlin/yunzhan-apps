//go:build linux

package diskjob

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"
)

// A failed transient scope is drainable only with its retained, bound closure
// and actual empty original native scope. No reset-failed or state coercion.
func ClosedScope(name string) bool {
	id := strings.TrimSuffix(strings.TrimPrefix(name, "panel-disk-host-"), ".scope")
	wanted, err := UnitName(id, false)
	if err != nil || wanted != name {
		return false
	}
	j, err := OpenRootJob(id)
	if err != nil {
		return false
	}
	defer j.Close()
	in, err := j.Request()
	if err != nil {
		return false
	}
	_, err = j.Closure(in)
	return err == nil
}

// Recovery accepts bounded, private zero-byte report/start evidence only for
// cancellation/failure, never as a valid original receipt. Unsafe ownership,
// links, replacement, unknown leaves or changed request/dispatch still refuse.
func (j *Journal) recoveryContents() error {
	d, err := j.root.Open(".")
	if err != nil {
		return ErrJournal
	}
	defer d.Close()
	names, err := d.Readdirnames(len(journalLimits) + 2)
	if err != nil && !errors.Is(err, io.EOF) || len(names) > len(journalLimits)+1 {
		return ErrJournal
	}
	for _, name := range names {
		limit, ok := journalLimits[name]
		if name == "progress.pending" {
			limit = ReceiptBytesMax
			ok = true
		}
		info, err := j.root.Lstat(name)
		if !ok || err != nil || !journalInfo(info, false) || info.Size() > limit {
			return ErrJournal
		}
	}
	if !j.current() {
		return ErrJournal
	}
	return nil
}

func (j *Journal) closureOriginal(in Request) (*Dispatch, *Started, string, string, error) {
	original, err := j.Request()
	if err != nil || original != in || j.recoveryContents() != nil {
		return nil, nil, "", "", ErrReceipt
	}
	var d *Dispatch
	if raw, err := j.Read("dispatch.json"); err == nil {
		decoded, err := DecodeDispatch(raw, in)
		if err != nil {
			return nil, nil, "", "", err
		}
		d = &decoded
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, "", "", err
	}
	var started *Started
	startedSHA, resultSHA := "", ""
	if raw, err := j.recoveryRead("started.json"); err == nil {
		startedSHA = hashBytes(raw)
		if d != nil {
			if decoded, err := DecodeStarted(raw, *d, in); err == nil {
				started = &decoded
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, "", "", err
	}
	if raw, err := j.recoveryRead("result.json"); err == nil {
		resultSHA = hashBytes(raw)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, "", "", err
	}
	return d, started, startedSHA, resultSHA, nil
}

// Caller must FIRST persist a Core cancellation fence under the unchanged
// original intent, and authorize the CURRENT full operator. Holding run.lock
// atomically excludes any scanner before writing the immutable admission seal.
func (j *Journal) SealClosure(in Request) (Closure, error) {
	if j.AdmissionBlocked() {
		return j.Closure(in)
	}
	launch, err := j.LaunchLease()
	if err != nil {
		return Closure{}, err
	}
	defer launch.Close()
	lease, err := j.Lease()
	if err != nil {
		return Closure{}, err
	}
	defer lease.Close()
	d, s, startedSHA, resultSHA, err := j.closureOriginal(in)
	if err != nil || ObserveScope(in.JobID) != "empty" {
		return Closure{}, ErrReceipt
	}
	c := Closure{Format: 1, JobID: in.JobID, RequestSHA: RequestSHA(in), OwnerID: in.ActorID, Kind: "admission_closed", State: "canceled", At: time.Now().UTC().Format(time.RFC3339Nano), ResultSHA: resultSHA, StartedSHA: startedSHA, ScopeEmpty: true, AdmissionSealed: true}
	if d != nil {
		c.ExecutorSHA = d.ExecutorSHA
	}
	if s != nil {
		n := ObserveNative(in, *d, *s)
		if n.Process != "gone" || n.Scope != "empty" {
			return Closure{}, ErrReceipt
		}
		c.Started = s
		c.Kind = "interrupted"
		c.State = "failed"
		if raw, err := j.Read("result.json"); err == nil {
			if result, err := DecodeResult(raw, *s, *d, in); err == nil {
				c.Kind = "result_summary"
				c.State = result.State
			}
		}
	}
	if ValidateClosure(c, in) != nil || !j.current() || ObserveScope(in.JobID) != "empty" {
		return Closure{}, ErrReceipt
	}
	raw, _ := json.Marshal(c)
	if err := j.WriteImmutable("closure.json", raw); err != nil {
		return Closure{}, err
	}
	return c, nil
}

func (j *Journal) Closure(in Request) (Closure, error) {
	raw, err := j.Read("closure.json")
	if err != nil {
		return Closure{}, err
	}
	c, err := DecodeClosure(raw, in)
	if err != nil {
		return Closure{}, err
	}
	d, s, startedSHA, resultSHA, err := j.closureOriginal(in)
	if err != nil || startedSHA != c.StartedSHA || resultSHA != c.ResultSHA {
		return Closure{}, ErrReceipt
	}
	if d == nil && c.ExecutorSHA != "" || d != nil && c.ExecutorSHA != d.ExecutorSHA {
		return Closure{}, ErrReceipt
	}
	if c.Started != nil {
		if s == nil || *s != *c.Started {
			return Closure{}, ErrReceipt
		}
		n := ObserveNative(in, *d, *s)
		if n.Process != "gone" || n.Scope != "empty" {
			return Closure{}, ErrReceipt
		}
	}
	if c.Kind == "result_summary" {
		raw, err := j.Read("result.json")
		if err != nil {
			return Closure{}, err
		}
		result, err := DecodeResult(raw, *s, *d, in)
		if err != nil || result.State != c.State {
			return Closure{}, ErrReceipt
		}
	}
	free, err := j.RunLeaseFree()
	if err != nil || !free || ObserveScope(in.JobID) != "empty" {
		return Closure{}, ErrReceipt
	}
	free, err = j.leaseFree("launch.lock")
	if err != nil || !free {
		return Closure{}, ErrReceipt
	}
	return c, nil
}
