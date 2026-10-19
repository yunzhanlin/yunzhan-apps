//go:build linux

package diskjob

import (
	"errors"
	"io"
	"os"
)

// Read original, root-private receipts and native identity. No queue creation,
// app installation, recovery, process mutation, lock creation or redispatch.
func (j *Journal) Observe(in Request) (Observation, error) {
	o := Observation{Format: 1, Request: in, State: "uncertain", Process: "unknown", Scope: "unknown"}
	request, err := j.Request()
	if err != nil || request != in {
		return o, ErrReceipt
	}
	if err := j.checkContents(); err != nil {
		return o, err
	}
	raw, err := j.Read("dispatch.json")
	if errors.Is(err, os.ErrNotExist) {
		return o, nil
	}
	if err != nil {
		return o, err
	}
	d, err := DecodeDispatch(raw, in)
	if err != nil {
		return o, err
	}
	if raw, err = j.Read("launcher.json"); err == nil {
		launcher, err := DecodeLauncher(raw, d, in)
		if err != nil {
			return o, err
		}
		o.Launcher = &launcher
	} else if !errors.Is(err, os.ErrNotExist) {
		return o, err
	}
	raw, err = j.Read("started.json")
	if errors.Is(err, os.ErrNotExist) {
		// An out-of-order report/result cannot be explained as still starting.
		for _, name := range []string{"progress.json", "result.json"} {
			if _, err := j.Read(name); !errors.Is(err, os.ErrNotExist) {
				return o, ErrReceipt
			}
		}
		if o.Launcher == nil {
			o.State = "starting"
		} else {
			o.Scope = ObserveScope(in.JobID)
		}
		if ValidateObservation(o, in) != nil {
			return o, ErrReceipt
		}
		return o, nil
	}
	if err != nil {
		return o, err
	}
	s, err := DecodeStarted(raw, d, in)
	if err != nil {
		return o, err
	}
	o.Started = &s
	if raw, err = j.Read("progress.json"); err == nil {
		p, err := DecodeProgress(raw, s, d, in)
		if err != nil {
			return o, err
		}
		o.Progress = &p
	} else if !errors.Is(err, os.ErrNotExist) {
		return o, err
	}
	if raw, err = j.Read("result.json"); err == nil {
		r, err := DecodeResult(raw, s, d, in)
		if err != nil {
			return o, err
		}
		o.Result = &r
		o.ResultSHA = ResultSHA(r)
	} else if !errors.Is(err, os.ErrNotExist) {
		return o, err
	}
	native := ObserveNative(in, d, s)
	o.Process, o.Scope = native.Process, native.Scope
	free, err := j.RunLeaseFree()
	if err != nil {
		return o, err
	}
	o.RunLeaseFree = free
	if o.Result != nil {
		o.State = "settling"
		if free && o.Process == "gone" && o.Scope == "empty" {
			o.State = o.Result.State
			o.TerminalVerified = true
		}
	} else if o.Process == "alive" && o.Scope == "busy" {
		o.State = "running"
	}
	if !j.current() || ValidateObservation(o, in) != nil {
		return o, ErrReceipt
	}
	return o, nil
}

func CheckRootJobs() error { return (jobTree{JobsRoot}).checkJobs() }

func (j *Journal) checkContents() error {
	dir, err := j.root.Open(".")
	if err != nil {
		return ErrJournal
	}
	defer dir.Close()
	names, err := dir.Readdirnames(len(journalLimits) + 1)
	if err != nil && !errors.Is(err, io.EOF) || len(names) > len(journalLimits) {
		return ErrJournal
	}
	for _, name := range names {
		limit, ok := journalLimits[name]
		info, err := j.root.Lstat(name)
		if !ok || err != nil || !journalInfo(info, false) || info.Size() > limit || info.Size() == 0 && name != "run.lock" && name != "launch.lock" {
			return ErrJournal
		}
	}
	if !j.current() {
		return ErrJournal
	}
	return nil
}

func (t jobTree) checkJobs() error {
	base, before, err := t.open(false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer base.Close()
	dir, err := base.Open(".")
	if err != nil {
		return ErrJournal
	}
	defer dir.Close()
	names, err := dir.Readdirnames(ActiveJobsMax + 3)
	if err != nil && !errors.Is(err, io.EOF) {
		return ErrJournal
	}
	if len(names) > ActiveJobsMax+2 {
		return ErrJournal
	}
	jobs := 0
	for _, name := range names {
		if name == "instance.lock" || name == "slot.lock" {
			info, err := base.Lstat(name)
			if err != nil || !journalInfo(info, false) || info.Size() != 0 {
				return ErrJournal
			}
			continue
		}
		if !ValidID(name) {
			return ErrJournal
		}
		jobs++
		if jobs > ActiveJobsMax {
			return ErrJournal
		}
		j, err := t.openJob(name, false)
		if err != nil {
			return err
		}
		request, err := j.Request()
		if err != nil {
			j.Close()
			return err
		}
		if j.AdmissionBlocked() {
			_, err := j.Closure(request)
			j.Close()
			if err != nil {
				return err
			}
			continue
		}
		o, err := j.Observe(request)
		j.Close()
		if err != nil || !o.TerminalVerified {
			return ErrJournal
		}
	}
	// Check directory identity after complete enumeration. Concurrent additions
	// are not a drain proof; caller also holds the lifecycle/upgrade barrier.
	visible, err := os.Lstat(t.name)
	opened, e := base.Stat(".")
	if err != nil || e != nil || !os.SameFile(visible, opened) || !os.SameFile(before, opened) || !journalInfo(visible, true) || before.ModTime() != visible.ModTime() {
		return ErrJournal
	}
	return nil
}
