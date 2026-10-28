//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/diskjob"
	"local/panel/internal/diskusage"
	"local/panel/internal/upgradeguard"
)

var errDiskHostWorker = errors.New("原全盘工作任务、授权或程序身份无法核对；未重放或降级扫描")

type diskHostDispatch = diskjob.Dispatch
type diskHostStarted = diskjob.Started
type diskHostResult = diskjob.Result

func diskHostRequestSHA(in diskjob.Request) string {
	return diskjob.RequestSHA(in)
}

func diskHostExecutableSHA() (string, error) {
	// Fixed kernel executable handle; never hash a request-controlled path.
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		return "", errDiskHostWorker
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return "", errDiskHostWorker
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || info.Size() < 1 || info.Size() > 256<<20 {
		return "", errDiskHostWorker
	}
	h := sha256.New()
	if n, err := io.Copy(h, io.LimitReader(f, (256<<20)+1)); err != nil || n != info.Size() {
		return "", errDiskHostWorker
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func diskHostStartTicks() (string, error) {
	raw, err := os.ReadFile("/proc/self/stat")
	if err != nil || len(raw) > 8192 {
		return "", errDiskHostWorker
	}
	end := strings.LastIndex(string(raw), ") ")
	if end < 1 {
		return "", errDiskHostWorker
	}
	fields := strings.Fields(string(raw)[end+2:])
	if len(fields) < 20 || !diskjob.CanonicalInteger(fields[19], true) {
		return "", errDiskHostWorker
	}
	return fields[19], nil
}

type diskHostCoreReader struct {
	db                *sql.DB
	owner             uint32
	directory, dbInfo os.FileInfo
}

func openDiskHostCoreReader() (*diskHostCoreReader, error) {
	account, err := user.Lookup("panel")
	if err != nil {
		return nil, errDiskHostWorker
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return nil, errDiskHostWorker
	}
	dir, err := os.Lstat("/var/lib/panel")
	if err != nil || !dir.IsDir() || dir.Mode().Perm()&0022 != 0 {
		return nil, errDiskHostWorker
	}
	ds, ok := dir.Sys().(*syscall.Stat_t)
	if !ok || ds.Uid != uint32(uid) || dir.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return nil, errDiskHostWorker
	}
	info, err := os.Lstat("/var/lib/panel/panel.db")
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0027 != 0 {
		return nil, errDiskHostWorker
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != uint32(uid) || s.Nlink != 1 || info.Size() < 4096 {
		return nil, errDiskHostWorker
	}
	db, err := sql.Open("sqlite", "file:/var/lib/panel/panel.db?mode=ro&_pragma=busy_timeout(1000)")
	if err != nil {
		return nil, errDiskHostWorker
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	r := &diskHostCoreReader{db: db, owner: uint32(uid), directory: dir, dbInfo: info}
	if !r.current() {
		db.Close()
		return nil, errDiskHostWorker
	}
	return r, nil
}

func (r *diskHostCoreReader) current() bool {
	dir, e1 := os.Lstat("/var/lib/panel")
	db, e2 := os.Lstat("/var/lib/panel/panel.db")
	if e1 != nil || e2 != nil || !os.SameFile(dir, r.directory) || !os.SameFile(db, r.dbInfo) || !dir.IsDir() || !db.Mode().IsRegular() || dir.Mode().Perm()&0022 != 0 || db.Mode().Perm()&0027 != 0 {
		return false
	}
	s, ok := db.Sys().(*syscall.Stat_t)
	ds, ok2 := dir.Sys().(*syscall.Stat_t)
	return ok && ok2 && s.Uid == r.owner && ds.Uid == r.owner && s.Nlink == 1
}

func (r *diskHostCoreReader) authority(ctx context.Context, in diskjob.Request) error {
	if !r.current() || upgradeguard.Blocked() {
		return diskHostFailure(diskHostAuthorityIdentity, ctx, errDiskHostWorker)
	}
	if err := (&core.Store{DB: r.db}).ValidateHostDiskNative(ctx, in); err != nil {
		return diskHostFailure(diskHostAuthorityCore, ctx, err)
	}
	var version, sha, target string
	if r.db.QueryRowContext(ctx, "SELECT version,sha256,target FROM app_registry_receipts WHERE app_id='disk-analysis' AND scope='disk-analysis'").Scan(&version, &sha, &target) != nil || version != in.Selection.AppVersion || sha != in.Selection.AppSHA || target != "disk-analysis" {
		return diskHostFailure(diskHostAuthorityReceipt, ctx, errDiskHostWorker)
	}
	installed, err := New(Config{}).moduleInstalledRecord("disk-analysis")
	if err != nil || installed["version"] != in.Selection.AppVersion || !diskjob.HostAppVersionSupported(in.Selection.AppVersion) || installed["installation_id"] != in.Selection.InstallationID || core.SoftwareImplementationVersion("disk-analysis") != diskjob.HostAppVersion {
		return diskHostFailure(diskHostAuthorityInstallation, ctx, errDiskHostWorker)
	}
	if !r.current() {
		return diskHostFailure(diskHostAuthorityIdentity, ctx, errDiskHostWorker)
	}
	return nil
}

// Fixed collector invoked only through the constrained PID1-entry pipeline.
// No root/path/namespace override, application installation, recovery or server.
func RunDiskHostInventory(id string, out io.Writer) error {
	if !diskjob.ValidID(id) || upgradeguard.Blocked() || diskjob.HardenWorker() != nil {
		return errDiskHostWorker
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if _, err := diskjob.VerifyWorker(ctx, id, true); err != nil {
		return err
	}
	i, err := diskjob.ReadHostInventory()
	if err != nil {
		return err
	}
	raw, err := diskjob.EncodeInventory(i)
	if err != nil {
		return err
	}
	n, err := out.Write(raw)
	if err != nil || n != len(raw) {
		return errDiskHostWorker
	}
	return nil
}

func RunDiskHostJob(id string) error {
	if !diskjob.ValidID(id) || upgradeguard.Blocked() || diskjob.HardenWorker() != nil {
		return errDiskHostWorker
	}
	admission, err := diskjob.OpenRootJob(id)
	if err != nil {
		return err
	}
	blocked := admission.AdmissionBlocked()
	admission.Close()
	if blocked {
		return errDiskHostWorker
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 28*time.Minute)
	defer cancel()
	policy, err := diskjob.VerifyWorker(ctx, id, false)
	if err != nil {
		return err
	}
	j, err := diskjob.OpenRootJob(id)
	if err != nil {
		return err
	}
	defer j.Close()
	request, err := j.Request()
	if err != nil || request.JobID != id || request.Selection.BootID != policy.Host.BootID || request.Selection.NamespaceID != policy.Host.NamespaceID {
		return errDiskHostWorker
	}
	instance, err := diskjob.InstanceLease(false)
	if err != nil {
		return err
	}
	defer instance.Close()
	slot, err := diskjob.WorkerSlot()
	if err != nil {
		return err
	}
	defer slot.Close()
	lease, err := j.Lease()
	if err != nil {
		return err
	}
	defer lease.Close()
	if j.AdmissionBlocked() {
		return errDiskHostWorker
	}
	if present, err := j.HasOriginalResult(); err != nil || present {
		return errDiskHostWorker
	}
	if _, err := j.Read("started.json"); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errDiskHostWorker
	}
	raw, err := j.Read("dispatch.json")
	if err != nil {
		return err
	}
	dispatch, err := diskjob.DecodeDispatch(raw, request)
	if err != nil {
		return errDiskHostWorker
	}
	exeSHA, err := diskHostExecutableSHA()
	if err != nil || exeSHA != dispatch.ExecutorSHA {
		return errDiskHostWorker
	}
	reader, err := openDiskHostCoreReader()
	if err != nil {
		return err
	}
	defer reader.db.Close()
	guard := func() error {
		if err := ctx.Err(); err != nil {
			return diskHostFailure(diskHostAuthorityContext, ctx, err)
		}
		check, done := context.WithTimeout(ctx, 2*time.Second)
		defer done()
		return reader.authority(check, request)
	}
	if err := guard(); err != nil {
		return err
	}
	ticks, err := diskHostStartTicks()
	if err != nil {
		return err
	}
	started := diskHostStarted{Format: 1, JobID: id, RequestSHA: dispatch.RequestSHA, ExecutorSHA: exeSHA, PID: strconv.Itoa(os.Getpid()), StartTicks: ticks, At: time.Now().UTC().Format(time.RFC3339Nano), Policy: policy}
	startedRaw, _ := json.Marshal(started)
	if err := j.WriteImmutable("started.json", startedRaw); err != nil {
		return err
	}
	result := diskHostResult{Format: 1, Request: request, RequestSHA: dispatch.RequestSHA, Started: started, State: "failed", ErrorCode: "scan_or_authority_unavailable", Capacity: diskusage.Capacity{State: "unavailable", InodeState: "unavailable", MayOverlap: true}}
	work := func() error {
		i, err := diskjob.ReadHostInventory()
		if err != nil || i.Host != policy.Host {
			return errDiskHostWorker
		}
		scope, err := i.Mounts.OpenMount(ctx, request.Selection.MountID, request.Selection.MountSHA)
		if err != nil {
			return err
		}
		defer scope.Close()
		result.Capacity, err = scope.Capacity(ctx)
		if err != nil {
			return err
		}
		root, err := j.SpoolRoot()
		if err != nil {
			return err
		}
		defer root.Close()
		index, err := diskusage.NewLedger(ctx, root, 131072)
		if err != nil {
			return err
		}
		defer index.Close()
		observer := func(report diskusage.ScanReport) error {
			if err := guard(); err != nil {
				return err
			}
			progress := diskjob.Progress{Format: 1, RequestSHA: dispatch.RequestSHA, Started: started, At: time.Now().UTC().Format(time.RFC3339Nano), Report: report}
			raw, err := json.Marshal(progress)
			if err != nil {
				return diskHostFailure(diskHostProgressEncode, ctx, errDiskHostWorker)
			}
			if _, err := diskjob.DecodeProgress(raw, started, dispatch, request); err != nil {
				return diskHostFailure(diskHostProgressValidate, ctx, err)
			}
			return diskHostFailure(diskHostProgressPublish, ctx, j.WriteProgress(raw))
		}
		report, err := diskusage.ScanObserved(ctx, scope, request.Selection.Directory, index, diskusage.DefaultScanBudget(), observer)
		result.Report = &report
		if err != nil {
			return err
		}
		if err := guard(); err != nil {
			return err
		}
		result.State = report.State
		result.ErrorCode = ""
		return nil
	}
	err = work()
	if err != nil {
		result.State = "failed"
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, core.ErrHostDiskCancelRequested):
			result.State = "canceled"
			result.ErrorCode = "canceled"
		case errors.Is(err, context.DeadlineExceeded):
			result.ErrorCode = "deadline_reached"
		case errors.Is(err, diskusage.ErrObserver):
			result.ErrorCode = "progress_or_authority_rejected"
		case errors.Is(err, diskusage.ErrLedgerUnavailable):
			result.ErrorCode = "index_unavailable_or_full"
		case errors.Is(err, diskusage.ErrMountChanged), errors.Is(err, diskusage.ErrMountBoundary):
			result.ErrorCode = "mount_changed_or_boundary"
		default:
			result.ErrorCode = "scan_or_authority_unavailable"
		}
		markDiskHostFailureReport(&result)
	}
	result.At = time.Now().UTC().Format(time.RFC3339Nano)
	if diskjob.ValidateResult(result, started, dispatch, request) != nil {
		return errors.New("原全盘结果未通过绑定和终态检查；未写入假完成记录")
	}
	resultRaw, encodeErr := json.Marshal(result)
	if encodeErr != nil || j.WriteImmutable("result.json", resultRaw) != nil {
		return errors.New("原全盘任务终态不能持久保存；需核对原ID，未重放")
	}
	return diskHostRootDiagnostic(err)
}
