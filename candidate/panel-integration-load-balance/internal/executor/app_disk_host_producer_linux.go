//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/diskjob"
	"local/panel/internal/upgradeguard"
)

var diskHostRootDiagnostics = newDiskHostDiagnosticMailbox(func(e diskHostDiagnosticEvent) {
	log.Printf("disk_host_worker_failure job=%s request_sha256=%s phase=%s reason=%s", e.jobID, e.requestSHA, e.phase, e.reason)
})

func diskHostEnvironment() []string {
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "SYSTEMD_COLORS=0", "GOMEMLIMIT=384MiB"}
}

// Same currently installed executable, not an arbitrary retained release or
// source/test ELF. Normal signed installation remains the program trust anchor.
func diskHostProgram() (string, string, error) {
	name, err := statisticsGeoVerifierProgram()
	if err != nil {
		return "", "", err
	}
	if _, err := diskjob.LaunchArguments(strings.Repeat("1", 32), name, false); err != nil {
		return "", "", err
	}
	if name != "/opt/panel/bin/panel-executor" {
		current, err := os.Lstat("/opt/panel/current")
		st, ok := infoSysStat(current)
		if err != nil || !ok || current.Mode()&os.ModeSymlink == 0 || st.Uid != 0 {
			return "", "", errDiskHostWorker
		}
		target, err := os.Readlink("/opt/panel/current")
		if err != nil || target != filepath.Dir(filepath.Dir(name)) {
			return "", "", errDiskHostWorker
		}
	}
	visible, err := os.Lstat(name)
	self, e := os.Stat("/proc/self/exe")
	if err != nil || e != nil || !os.SameFile(visible, self) {
		return "", "", errDiskHostWorker
	}
	sha, err := diskHostExecutableSHA()
	if err != nil {
		return "", "", err
	}
	after, e1 := os.Lstat(name)
	if e1 != nil || !os.SameFile(visible, after) || visible.ModTime() != after.ModTime() || visible.Size() != after.Size() {
		return "", "", errDiskHostWorker
	}
	return name, sha, nil
}

func (s *Service) diskHostFixedEnvironment() bool {
	return os.Geteuid() == 0 && s.Config.SystemRoot == "/" && s.Config.SecurityDir == "/etc/panel/security-apps" && !upgradeguard.Blocked()
}

func (s *Service) diskHostAppIdentity(ctx context.Context, reader *diskHostCoreReader) (diskjob.HostState, error) {
	out := diskjob.HostState{Format: 1}
	if !s.diskHostFixedEnvironment() || !reader.current() {
		return out, errDiskHostWorker
	}
	record, err := s.moduleInstalledRecord("disk-analysis")
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.Installed = true
	out.AppVersion, _ = record["version"].(string)
	if out.AppVersion == "" {
		out.AppVersion = "1.0"
	}
	if !diskjob.HostAppVersionSupported(out.AppVersion) {
		return out, nil
	}
	out.InstallationID, _ = record["installation_id"].(string)
	var version, target string
	if reader.db.QueryRowContext(ctx, "SELECT version,sha256,target FROM app_registry_receipts WHERE app_id='disk-analysis' AND scope='disk-analysis'").Scan(&version, &out.AppSHA, &target) != nil || version != out.AppVersion || target != "disk-analysis" || !diskjob.ValidSHA(out.AppSHA) || !diskjob.ValidID(out.InstallationID) || core.SoftwareImplementationVersion("disk-analysis") != diskjob.HostAppVersion || !reader.current() {
		return diskjob.HostState{}, errDiskHostWorker
	}
	return out, nil
}

func (s *Service) diskHostInventory(ctx context.Context, in diskjob.InventoryRequest) (diskjob.HostState, error) {
	if !s.diskHostFixedEnvironment() {
		return diskjob.HostState{}, errDiskHostWorker
	}
	reader, err := openDiskHostCoreReader()
	if err != nil {
		return diskjob.HostState{}, err
	}
	defer reader.db.Close()
	guard := func() error {
		if !reader.current() || !s.diskHostFixedEnvironment() {
			return errDiskHostWorker
		}
		return (&core.Store{DB: reader.db}).ValidateHostDiskInventory(ctx, in)
	}
	if err := guard(); err != nil {
		return diskjob.HostState{}, err
	}
	state, err := s.diskHostAppIdentity(ctx, reader)
	if err != nil {
		return state, err
	}
	if !diskjob.HostAppVersionSupported(state.AppVersion) {
		return state, guard()
	}
	lease, err := diskjob.InstanceLease(false)
	if err != nil {
		return diskjob.HostState{}, err
	}
	defer lease.Close()
	before, err := s.diskHostAppIdentity(ctx, reader)
	if err != nil || before.AppVersion != state.AppVersion || before.InstallationID != state.InstallationID || before.AppSHA != state.AppSHA {
		return diskjob.HostState{}, errDiskHostWorker
	}
	program, _, err := diskHostProgram()
	if err != nil {
		return diskjob.HostState{}, err
	}
	args, err := diskjob.LaunchArguments(core.ID(), program, true)
	if err != nil {
		return diskjob.HostState{}, err
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/systemd-run", args...)
	cmd.Env = diskHostEnvironment()
	stdout := &boundedBuffer{max: diskjob.InventoryBytesMax}
	cmd.Stdout = stdout
	// No raw native errors (mount options, paths or credentials) in responses.
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil || stdout.truncated {
		return diskjob.HostState{}, errDiskHostWorker
	}
	inventory, err := diskjob.DecodeInventory([]byte(stdout.String()))
	if err != nil {
		return diskjob.HostState{}, err
	}
	after, err := s.diskHostAppIdentity(ctx, reader)
	if err != nil || after.AppVersion != state.AppVersion || after.InstallationID != state.InstallationID || after.AppSHA != state.AppSHA || guard() != nil {
		return diskjob.HostState{}, errDiskHostWorker
	}
	state.Inventory = &inventory
	return state, diskjob.ValidateHostState(state)
}

func (s *Service) diskHostDispatch(ctx context.Context, in diskjob.Request) (diskjob.DispatchAck, error) {
	ack := diskjob.DispatchAck{Format: 1, JobID: in.JobID, RequestSHA: diskjob.RequestSHA(in)}
	if !s.diskHostFixedEnvironment() || diskjob.ValidateRequest(in) != nil {
		return ack, errDiskHostWorker
	}
	s.diskHostMu.Lock()
	defer s.diskHostMu.Unlock()
	reader, err := openDiskHostCoreReader()
	if err != nil {
		return ack, err
	}
	defer reader.db.Close()
	// Existing Root ID is observation only, even after crash before dispatch.
	// Re-read current original owner before revealing/reusing that private ID.
	if old, err := diskjob.OpenRootJob(in.JobID); err == nil {
		defer old.Close()
		request, err := old.Request()
		if err != nil || request != in || !reader.current() || (&core.Store{DB: reader.db}).ValidateHostDiskObservation(ctx, in) != nil {
			return ack, errDiskHostWorker
		}
		ack.ObserveOnly = true
		return ack, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return ack, err
	}
	if err := reader.authority(ctx, in); err != nil {
		return ack, err
	}
	lease, err := diskjob.InstanceLease(false)
	if err != nil {
		return ack, err
	}
	owned := true
	defer func() {
		if owned {
			lease.Close()
		}
	}()
	if err := reader.authority(ctx, in); err != nil {
		return ack, err
	}
	if err := diskjob.CheckRootJobs(); err != nil {
		return ack, err
	}
	program, sha, err := diskHostProgram()
	if err != nil {
		return ack, err
	}
	args, err := diskjob.LaunchArguments(in.JobID, program, false)
	if err != nil {
		return ack, err
	}
	journal, replay, err := diskjob.PublishRootRequest(in)
	if err != nil {
		return ack, err
	}
	if replay {
		journal.Close()
		ack.ObserveOnly = true
		return ack, nil
	}
	launch, err := journal.LaunchLease()
	if err != nil {
		journal.Close()
		return ack, err
	}
	launchOwned := true
	defer func() {
		if launchOwned {
			launch.Close()
		}
	}()
	dispatch := diskjob.Dispatch{Format: 1, JobID: in.JobID, ActorID: in.ActorID, RequestSHA: ack.RequestSHA, ExecutorSHA: sha}
	raw, _ := json.Marshal(dispatch)
	if err := journal.WriteImmutable("dispatch.json", raw); err != nil {
		journal.Close()
		return ack, err
	}
	if err := reader.authority(ctx, in); err != nil {
		journal.Close()
		return ack, err
	}
	// Independent of HTTP timeout; the scope owns its native deadline. No
	// request cancellation may turn a lost response into a redispatch.
	if journal.AdmissionBlocked() {
		journal.Close()
		return ack, errDiskHostWorker
	}
	cmd := exec.Command("/usr/bin/systemd-run", args...)
	cmd.Env = diskHostEnvironment()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stderr = newDiskHostCommandDiagnosticWriter(in.JobID, ack.RequestSHA, diskHostRootDiagnostics)
	if err := cmd.Start(); err != nil {
		launch := diskjob.Launcher{Format: 1, RequestSHA: ack.RequestSHA, ExecutorSHA: sha, State: "not_started", At: time.Now().UTC().Format(time.RFC3339Nano)}
		raw, _ := json.Marshal(launch)
		journal.WriteImmutable("launcher.json", raw)
		journal.Close()
		return ack, errDiskHostWorker
	}
	owned = false
	launchOwned = false
	go func() {
		defer lease.Close()
		defer launch.Close()
		defer journal.Close()
		_ = cmd.Wait()
		if cmd.ProcessState == nil {
			return
		}
		code := cmd.ProcessState.ExitCode()
		launch := diskjob.Launcher{Format: 1, RequestSHA: ack.RequestSHA, ExecutorSHA: sha, State: "exited", ExitCode: &code, At: time.Now().UTC().Format(time.RFC3339Nano)}
		raw, _ := json.Marshal(launch)
		// A persistence failure stays missing/unknown; never overwrite, repair
		// or relaunch this request and never synthesize a successful scan.
		_ = journal.WriteImmutable("launcher.json", raw)
	}()
	return ack, nil
}

func (s *Service) diskHostProducerRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/disk-host-jobs/inventory", func(w http.ResponseWriter, r *http.Request) {
		var raw json.RawMessage
		if !readJSON(w, r, &raw) {
			return
		}
		in, err := diskjob.DecodeInventoryRequest(raw)
		if err != nil {
			respond(w, 400, map[string]string{"error": "全盘清单请求无效"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 14*time.Second)
		defer cancel()
		state, err := s.diskHostInventory(ctx, in)
		if err != nil {
			respond(w, 409, map[string]string{"error": "全盘安装、授权或受限清单不能核对；未降级或返回部分清单"})
			return
		}
		respond(w, 200, state)
	})
	m.HandleFunc("POST /v1/disk-host-jobs/dispatch", func(w http.ResponseWriter, r *http.Request) {
		var raw json.RawMessage
		if !readJSON(w, r, &raw) {
			return
		}
		in, err := diskjob.DecodeRequest(raw)
		if err != nil {
			respond(w, 400, map[string]string{"error": "原全盘任务请求无效"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		ack, err := s.diskHostDispatch(ctx, in)
		if err != nil {
			respond(w, 409, map[string]string{"error": "原全盘派发无法核对；保留原ID，未重放或认定完成"})
			return
		}
		respond(w, 202, ack)
	})
}
