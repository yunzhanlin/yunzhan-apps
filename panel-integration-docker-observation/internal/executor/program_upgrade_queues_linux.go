//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/core"
	"local/panel/internal/diskjob"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

// This is an upgrade preflight, not recovery: it never constructs a Service,
// starts workers, creates locks/directories, edits records or replays jobs.
// The exported entrypoint has only fixed production paths. Tests instantiate
// the unexported reader on a private root; there is no alternate-root CLI.
func CheckProgramUpgradeQueues() error {
	if os.Geteuid() != 0 {
		return errors.New("program queue preflight requires root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	coreQueue := func() error {
		reader, err := openDiskHostCoreReader()
		if err != nil {
			return err
		}
		defer reader.db.Close()
		if !reader.current() {
			return errDiskHostWorker
		}
		if err := (&core.Store{DB: reader.db}).CheckHostDiskUpgrade(ctx); err != nil {
			return err
		}
		if err := (&core.Store{DB: reader.db}).CheckMemcachedUpdateUpgrade(ctx); err != nil {
			return err
		}
		if !reader.current() {
			return errDiskHostWorker
		}
		return nil
	}
	if err := coreQueue(); err != nil {
		return err
	}
	if err := checkProgramUpgradeQueues(ctx, "/"); err != nil {
		return err
	}
	if err := diskjob.CheckRootJobs(); err != nil {
		return err
	}
	if err := (memcachedUpdateJournalStore{base: memcachedUpdateJobsRoot}).checkProgramUpgrade(ctx); err != nil {
		return err
	}
	if err := checkProgramUpgradeNativeUnits(ctx, programQueueCommand); err != nil {
		return err
	}
	// Native commands cannot turn an earlier filesystem snapshot into a lease.
	// Recheck both authorities before returning; installer repeats under locks
	// and after strict stops. No claim covers a hostile root ignoring leases.
	if err := checkProgramUpgradeQueues(ctx, "/"); err != nil {
		return err
	}
	if err := diskjob.CheckRootJobs(); err != nil {
		return err
	}
	if err := (memcachedUpdateJournalStore{base: memcachedUpdateJobsRoot}).checkProgramUpgrade(ctx); err != nil {
		return err
	}
	if err := checkProgramUpgradeNativeUnits(ctx, programQueueCommand); err != nil {
		return err
	}
	return coreQueue()
}

var programQueueUnitPrefixes = []string{"panel-install@", "panel-docker-install@", "panel-pm2-deploy@", "panel-app-dependencies@", "panel-network-rulefeed-install@", "panel-statistics-geodata@", "panel-waf-engine-build@", "panel-apache-body-build@", "panel-analytics-html-build@", "panel-docker-job@", "panel-compose-job@", "panel-sftp-job@", "panel-mysql-job@", "panel-mariadb-init@", "panel-site-user@", "panel-mysql-user@", "panel-nginx-rollback@", "panel-firewall-rollback@", "panel-own-runtime", "panel-own-apache-runtime", "panel-own-apache-body-worker", "panel-own-waf-engine-build", "panel-own-analytics-html-build", "panel-own-analytics-html-worker"}
var programQueueRecoveryUnits = []string{"panel-compose-recovery.service", "panel-mysql-overwrite-recovery.service", "panel-firewall-recovery.service", "panel-nginx-recovery.service", "panel-nfs-server-recover.service", "panel-pure-ftpd-recover.service"}
var programQueueUnitName = regexp.MustCompile(`^panel-[a-z0-9@_-]+\.service$`)

func programQueueCompletedRecovery(name string) bool {
	for _, unit := range []string{"panel-firewall-recovery.service", "panel-nginx-recovery.service", "panel-nfs-server-recover.service", "panel-pure-ftpd-recover.service"} {
		if name == unit {
			return true
		}
	}
	return false
}

func programQueueCriticalUnit(name string) bool {
	if strings.HasPrefix(name, "panel-disk-host-") {
		return true
	}
	if strings.HasPrefix(name, statisticsGeoVerifyPrefix) {
		return true
	}
	for _, prefix := range programQueueUnitPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	for _, unit := range programQueueRecoveryUnits {
		if name == unit {
			return true
		}
	}
	return false
}
func programQueueCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "SYSTEMD_COLORS=0"}
	cmd.WaitDelay = time.Second
	stdout := &boundedBuffer{max: 64 << 10}
	stderr := &boundedBuffer{max: 4096}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil || stdout.truncated || stderr.truncated {
		return "", errors.New("native upgrade queue inventory unavailable or exceeds budget")
	}
	return stdout.String(), nil
}
func checkProgramUpgradeNativeUnits(ctx context.Context, run Command) error {
	args := []string{"list-units", "--all", "--plain", "--no-legend", "--no-pager", "--type=service,scope", "panel-disk-host-*.scope"}
	// Classification alone is insufficient: independent bounded dataset readers
	// use a different fixed namespace from install workers. Query their actual
	// units too, so a live/orphan verifier cannot disappear from drain proof.
	args = append(args, statisticsGeoVerifyPrefix+"*.service")
	for _, prefix := range programQueueUnitPrefixes {
		args = append(args, prefix+"*.service")
	}
	args = append(args, programQueueRecoveryUnits...)
	units, err := run(ctx, "/usr/bin/systemctl", args...)
	if err != nil {
		return errors.New("native program unit inventory cannot be verified")
	}
	if err := decodeProgramQueueUnitsWithTerminalProof(units, diskjob.ClosedScope, func(name string) bool {
		return closedStatisticsGeoFailedInstall(ctx, name, run)
	}); err != nil {
		return err
	}
	jobs, err := run(ctx, "/usr/bin/systemctl", "list-jobs", "--no-legend", "--no-pager")
	if err != nil {
		return errors.New("native program pending jobs cannot be verified")
	}
	if err := decodeProgramQueueJobs(jobs); err != nil {
		return err
	}
	return ctx.Err()
}
func decodeProgramQueueUnits(text string) error {
	return decodeProgramQueueUnitsWithDiskProof(text, nil)
}

func decodeProgramQueueUnitsWithDiskProof(text string, closed func(string) bool) error {
	return decodeProgramQueueUnitsWithTerminalProof(text, closed, nil)
}

func decodeProgramQueueUnitsWithTerminalProof(text string, closedDisk, closedGeo func(string) bool) error {
	if len(text) > 64<<10 || !utf8.ValidString(text) || strings.ContainsAny(text, "\x00\r") {
		return errors.New("invalid native program unit inventory")
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 || !programQueueCriticalUnit(fields[0]) || !programQueueValidUnit(fields[0]) || seen[fields[0]] || len(seen) >= 1024 {
			return errors.New("unknown, duplicate or excessive native program unit inventory")
		}
		seen[fields[0]] = true
		// Failed and unsupported states need explicit attention, not coercion to
		// inactive. The observer never resets failures, stops or starts units.
		completed := fields[2] == "inactive" && fields[3] == "dead" || programQueueCompletedRecovery(fields[0]) && fields[2] == "active" && fields[3] == "exited"
		if fields[1] == "loaded" && fields[2] == "failed" && fields[3] == "failed" {
			if strings.HasPrefix(fields[0], "panel-disk-host-") && closedDisk != nil && closedDisk(fields[0]) {
				completed = true
			}
			if _, valid := statisticsGeoFailedUnitID(fields[0]); valid && closedGeo != nil && closedGeo(fields[0]) {
				completed = true
			}
		}
		if fields[1] != "loaded" || !completed {
			return errors.New("native program operation is active, failed or transitional; upgrade refused")
		}
	}
	return nil
}

func programQueueValidUnit(name string) bool {
	if !strings.HasPrefix(name, "panel-disk-host-") {
		return programQueueUnitName.MatchString(name)
	}
	for _, inventory := range []bool{false, true} {
		prefix := "panel-disk-host-"
		if inventory {
			prefix += "inventory-"
		}
		id := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".scope")
		if wanted, err := diskjob.UnitName(id, inventory); err == nil && name == wanted {
			return true
		}
	}
	return false
}
func decodeProgramQueueJobs(text string) error {
	if len(text) > 64<<10 || !utf8.ValidString(text) || strings.ContainsAny(text, "\x00\r") {
		return errors.New("invalid native pending job inventory")
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 4 || len(seen) >= 2048 {
			return errors.New("incomplete native pending job inventory")
		}
		id, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || id == 0 || strconv.FormatUint(id, 10) != fields[0] || seen[fields[0]] {
			return errors.New("duplicate or invalid native pending job identity")
		}
		seen[fields[0]] = true
		if programQueueCriticalUnit(fields[1]) {
			return errors.New("native program operation is queued; upgrade refused")
		}
	}
	return nil
}

type programQueueSnapshot struct {
	path string
	info os.FileInfo // nil is an observed missing component, not a partial list.
}
type programQueueReader struct {
	ctx           context.Context
	root          string
	snapshots     []programQueueSnapshot
	bytes         int
	deliveryBytes int64
}

func programQueueSame(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	x, ok := a.Sys().(*syscall.Stat_t)
	y, other := b.Sys().(*syscall.Stat_t)
	return ok && other && x.Dev == y.Dev && x.Ino == y.Ino && x.Mode == y.Mode && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && x.Size == y.Size && x.Mtim == y.Mtim && x.Ctim == y.Ctim
}

func (r *programQueueReader) directory(relative string) (*os.Root, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	current := r.root
	for _, part := range strings.Split(relative, "/") {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			r.snapshots = append(r.snapshots, programQueueSnapshot{path: current})
			return nil, nil
		}
		if err != nil {
			return nil, errors.New("unverifiable program queue parent")
		}
		x, ok := info.Sys().(*syscall.Stat_t)
		if !ok || x.Uid != 0 || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return nil, errors.New("untrusted program queue parent")
		}
		r.snapshots = append(r.snapshots, programQueueSnapshot{current, info})
	}
	info, err := os.Lstat(current)
	if err != nil || info.Mode() != os.ModeDir|0700 {
		return nil, errors.New("program queue directory is not private")
	}
	root, err := os.OpenRoot(current)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !programQueueSame(info, opened) {
		root.Close()
		return nil, errors.New("program queue directory changed while opening")
	}
	return root, nil
}

func (r *programQueueReader) records(relative string, maximum int, limit int64, validate func(string, []byte) error) error {
	root, err := r.directory(relative)
	if err != nil || root == nil {
		return err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := dir.ReadDir(maximum + 1)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > maximum {
		return errors.New("program queue exceeds complete inventory budget")
	}
	for _, entry := range entries {
		if err := r.ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		id := strings.TrimSuffix(name, ".json")
		if name != id+".json" || entry.IsDir() || !syncPlanID.MatchString(id) {
			return errors.New("program queue contains unknown or unfinished record")
		}
		data, err := r.record(root, relative, name, limit)
		if err != nil {
			return err
		}
		if err := validate(id, data); err != nil {
			return err
		}
	}
	return nil
}

func (r *programQueueReader) record(root *os.Root, relative, name string, limit int64) ([]byte, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !runtimeInstallPrivateFile(before) {
		return nil, errors.New("program queue record has non-private type or ownership")
	}
	data, err := ruleFeedStoreRead(root, name, limit, 0600)
	if err != nil {
		return nil, errors.New("program queue record has unsafe identity, size or permissions")
	}
	r.bytes += len(data)
	if r.bytes > 16<<20 {
		return nil, errors.New("program queue complete read exceeds byte budget")
	}
	after, err := root.Lstat(name)
	if err != nil || !programQueueSame(before, after) {
		return nil, errors.New("program queue record changed while checking")
	}
	r.snapshots = append(r.snapshots, programQueueSnapshot{filepath.Join(r.root, relative, name), after})
	return data, nil
}

func (r *programQueueReader) pm2Deployments() error {
	relative := "etc/panel/security-apps/modules/pm2-manager/deployments"
	root, err := r.directory(relative)
	if err != nil || root == nil {
		return err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := dir.ReadDir(1025)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 1024 {
		return errors.New("PM2 deployment complete inventory exceeds budget")
	}
	jobs := map[string]pm2Deployment{}
	latest := map[string]pm2Deployment{}
	for _, entry := range entries {
		if err := r.ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		if name == "archive" {
			info, err := root.Lstat(name)
			if err != nil || !runtimeInstallPrivateDirectory(info) {
				return errors.New("PM2 deployment archive is not a private directory")
			}
			r.snapshots = append(r.snapshots, programQueueSnapshot{filepath.Join(r.root, relative, name), info})
			continue
		}
		if id, ok := strings.CutSuffix(name, ".npm.log"); ok {
			info, err := root.Lstat(name)
			if err != nil || !core.ValidID(id) || !runtimeInstallPrivateFile(info) || info.Size() > 4<<20 {
				return errors.New("PM2 deployment log identity cannot be verified")
			}
			r.snapshots = append(r.snapshots, programQueueSnapshot{filepath.Join(r.root, relative, name), info})
			continue
		}
		id, ok := strings.CutSuffix(name, ".json")
		if !ok || entry.IsDir() {
			return errors.New("unknown or unfinished PM2 deployment record")
		}
		app, index := strings.CutSuffix(id, "-latest")
		if index && !moduleResourceID.MatchString(app) || !index && !core.ValidID(id) {
			return errors.New("PM2 deployment filename identity cannot be verified")
		}
		data, err := r.record(root, relative, name, 4<<20)
		if err != nil {
			return err
		}
		var job pm2Deployment
		if decodeProgramQueueJSON(data, &job) != nil || !core.ValidID(job.ID) || !moduleResourceID.MatchString(job.AppID) || !core.ValidID(job.SiteID) || job.Revision < 1 || !coreSHA.MatchString(job.PackageSHA) || !coreSHA.MatchString(job.LockSHA) {
			return errors.New("PM2 deployment binding cannot be verified")
		}
		if index && job.AppID != app || !index && job.ID != id {
			return errors.New("PM2 deployment identity differs from filename")
		}
		if _, err := time.Parse(time.RFC3339, job.CreatedAt); err != nil {
			return errors.New("PM2 deployment timestamp cannot be verified")
		}
		// Existing PM2 writers deliberately retain the original latest locator;
		// actual state is read from ID.json. Never promote a stale locator to a
		// completion receipt, nor reject a completed original just for that view.
		if index {
			switch job.State {
			case "queued", "running", "switching", "needs_attention", "succeeded", "failed":
			default:
				return errors.New("unknown PM2 deployment locator state")
			}
			latest[app] = job
			continue
		}
		switch job.State {
		case "queued", "running", "switching", "needs_attention":
			return errors.New("PM2 deployment is pending or needs attention; upgrade refused")
		case "succeeded", "failed":
		default:
			return errors.New("unknown PM2 deployment state")
		}
		if _, err := time.Parse(time.RFC3339, job.FinishedAt); err != nil {
			return errors.New("PM2 terminal deployment lacks completion evidence")
		}
		jobs[id] = job
	}
	for app, view := range latest {
		job, ok := jobs[view.ID]
		if !ok || job.AppID != app || job.ID != view.ID || job.SiteID != view.SiteID || job.Revision != view.Revision || job.CreatedAt != view.CreatedAt || job.PackageSHA != view.PackageSHA || job.LockSHA != view.LockSHA || job.AllowInstallScripts != view.AllowInstallScripts {
			return errors.New("PM2 latest index differs from original retained deployment")
		}
	}
	return nil
}

func (r *programQueueReader) unchanged() error {
	for _, snap := range r.snapshots {
		if err := r.ctx.Err(); err != nil {
			return err
		}
		current, err := os.Lstat(snap.path)
		if snap.info == nil && errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !programQueueSame(snap.info, current) {
			return errors.New("program queue inventory changed; not a drain proof")
		}
	}
	return nil
}

// Match encoding/json's Unicode simple-fold equivalence for struct fields.
// Dynamic map keys (including case-sensitive website paths) remain exact.
func programQueueJSONKey(name string) string {
	var out strings.Builder
	for _, character := range name {
		least := character
		for next := unicode.SimpleFold(character); next != character; next = unicode.SimpleFold(next) {
			if next < least {
				least = next
			}
		}
		out.WriteRune(least)
	}
	return out.String()
}

func programQueueJSONType(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

func programQueueJSONFields(t reflect.Type, fields map[string]reflect.Type) {
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		child := programQueueJSONType(field.Type)
		if field.Anonymous && name == "" && child.Kind() == reflect.Struct {
			programQueueJSONFields(child, fields)
			continue
		}
		if field.PkgPath != "" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[programQueueJSONKey(name)] = field.Type
	}
}

// Bounded, schema-aware duplicate detection precedes closed typed decoding.
// Null remains compatible with legacy nil slices; required fields belong to
// validators. Map keys never use struct-field folding or truncate inventories.
func decodeProgramQueueJSON(data []byte, out any) error {
	if !utf8.Valid(data) {
		return errors.New("program queue JSON has invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	fieldCache := map[reflect.Type]map[string]reflect.Type{}
	var value func(int, reflect.Type) error
	value = func(depth int, schema reflect.Type) error {
		schema = programQueueJSONType(schema)
		if depth > 16 {
			return errors.New("program queue JSON exceeds nesting budget")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				var fields map[string]reflect.Type
				if schema != nil && schema.Kind() == reflect.Struct {
					fields = fieldCache[schema]
					if fields == nil {
						fields = map[string]reflect.Type{}
						programQueueJSONFields(schema, fields)
						fieldCache[schema] = fields
					}
				}
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					name, ok := key.(string)
					identity := name
					var child reflect.Type
					if fields != nil {
						identity = programQueueJSONKey(name)
						child = fields[identity]
					} else if schema != nil && schema.Kind() == reflect.Map {
						child = schema.Elem()
					}
					if err != nil || !ok || seen[identity] {
						return errors.New("program queue JSON contains duplicate keys")
					}
					seen[identity] = true
					if err := value(depth+1, child); err != nil {
						return err
					}
				}
			case '[':
				if depth == 0 {
					return errors.New("program queue JSON must be an object")
				}
				var child reflect.Type
				if schema != nil && (schema.Kind() == reflect.Array || schema.Kind() == reflect.Slice) {
					child = schema.Elem()
				}
				for d.More() {
					if err := value(depth+1, child); err != nil {
						return err
					}
				}
			default:
				return errors.New("invalid program queue JSON")
			}
			end, err := d.Token()
			if err != nil || delimiter == '{' && end != json.Delim('}') || delimiter == '[' && end != json.Delim(']') {
				return errors.New("incomplete program queue JSON")
			}
		} else if depth == 0 {
			return errors.New("program queue JSON must be an object")
		}
		return nil
	}
	if err := value(0, reflect.TypeOf(out)); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("program queue JSON contains trailing data")
	}
	return decodeFTPPrivateJSON(data, out)
}

func checkProgramUpgradeQueues(ctx context.Context, root string) error {
	if os.Geteuid() != 0 || !filepath.IsAbs(root) || filepath.Clean(root) != root || ruleFeedStoreParents(root) != nil {
		return errors.New("untrusted program queue root")
	}
	r := programQueueReader{ctx: ctx, root: root}
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	r.snapshots = append(r.snapshots, programQueueSnapshot{root, info})
	checks := []struct {
		path     string
		maximum  int
		limit    int64
		validate func(string, []byte) error
	}{
		{"var/lib/panel-executor/php-worker-operations", 1024, 128 << 10, checkProgramQueuePHP},
		{"var/lib/panel-executor/network-ids-operations", 128, 48 << 10, checkProgramQueueIDS},
		{"etc/panel/security-apps/modules/files-sync/plans", 32, 128 << 10, checkProgramQueueLocalPlan},
		{"etc/panel/security-apps/modules/files-sync/remote/plans", 16, 128 << 10, checkProgramQueueRemotePlan},
		{"etc/panel/security-apps/modules/files-sync/remote/jobs", 128, 4 << 20, checkProgramQueueRemoteJob},
		{"etc/panel/security-apps/modules/files-sync/remote/checkpoints", 16, 4 << 20, checkProgramQueueRemoteCheckpoint},
	}
	for _, check := range checks {
		if err := r.records(check.path, check.maximum, check.limit, check.validate); err != nil {
			return err
		}
	}
	if err := r.pm2Deployments(); err != nil {
		return err
	}
	if err := r.nativeBuilds(); err != nil {
		return err
	}
	if err := r.ruleFeedJobs(); err != nil {
		return err
	}
	if err := r.statisticsGeoJobs(); err != nil {
		return err
	}
	if err := r.platformMaintenanceJobs(); err != nil {
		return err
	}
	return r.unchanged()
}

func checkProgramQueuePHP(id string, data []byte) error {
	var v phpWorkerOperationRecord
	if decodeProgramQueueJSON(data, &v) != nil || validatePHPWorkerOperationRecord(id, v) != nil {
		return errors.New("PHP operation record cannot be verified")
	}
	if phpWorkerOperationReference(v.State) {
		return errors.New("PHP operation is pending or needs attention; upgrade refused")
	}
	return nil
}
func checkProgramQueueIDS(id string, data []byte) error {
	var v threatIDSOperationRecord
	if decodeProgramQueueJSON(data, &v) != nil || v.Operation.ID != id || validateThreatIDSOperation(v) != nil {
		return errors.New("IDS operation record cannot be verified")
	}
	if v.Operation.State == "queued" || v.Operation.State == "running" || v.Operation.State == "needs-attention" {
		return errors.New("IDS operation is pending or needs attention; upgrade refused")
	}
	return nil
}
func checkProgramQueueLocalPlan(id string, data []byte) error {
	var v moduleSyncPlan
	if decodeProgramQueueJSON(data, &v) != nil || v.ID != id || validateSyncPlan(v) != nil {
		return errors.New("local sync plan cannot be verified")
	}
	switch v.LastState {
	case "running", "interrupted":
		return errors.New("local sync plan is running or interrupted; upgrade refused")
	case "pending", "paused", "paused-error", "succeeded", "conflicts", "failed":
	default:
		return errors.New("unknown local sync plan state; upgrade refused")
	}
	return nil
}
func checkProgramQueueRemotePlan(id string, data []byte) error {
	var v remoteSyncPlan
	if decodeProgramQueueJSON(data, &v) != nil || v.ID != id || validateRemotePlan(v) != nil {
		return errors.New("remote sync plan cannot be verified")
	}
	if v.PendingJobID != "" || v.LastState == "queueing" || v.LastState == "queued" {
		return errors.New("remote sync plan retains a pending reservation; upgrade refused")
	}
	return nil
}
func checkProgramQueueRemoteJob(id string, data []byte) error {
	var v remoteSyncJob
	if decodeProgramQueueJSON(data, &v) != nil || v.ID != id || validateRemoteJob(v) != nil {
		return errors.New("remote sync job cannot be verified")
	}
	if v.State == "queued" || v.State == "running" || v.State == "interrupted" {
		return errors.New("remote sync job is pending or interrupted; upgrade refused")
	}
	return nil
}
func checkProgramQueueRemoteCheckpoint(id string, data []byte) error {
	var v remoteSyncCheckpoint
	if decodeProgramQueueJSON(data, &v) != nil || v.TargetID != id || !syncPlanID.MatchString(id) || !core.ValidID(v.SiteID) || !coreSHA.MatchString(v.SpecSHA) || v.Files == nil || len(v.Files) > 10000 {
		return errors.New("remote sync checkpoint cannot be verified")
	}
	for name, file := range v.Files {
		if !core.ValidFilePath(name, false) || !validRemoteFile(file) {
			return errors.New("remote sync checkpoint contains invalid file evidence")
		}
	}
	if v.Pending != nil {
		return errors.New("remote sync checkpoint retains an unfinished transaction; upgrade refused")
	}
	return nil
}
