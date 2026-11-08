//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var offlineUpgradeVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([.-][a-z0-9]+)*$`)
var offlineUpgradeBootID = regexp.MustCompile(`^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)

type offlineUpgradeWriterRequest struct {
	Format   int    `json:"format"`
	Version  string `json:"version"`
	PlanSHA  string `json:"plan_sha256"`
	LeaseFDs [2]int `json:"lease_fds"`
}

// No caller-selected path or alternate host root exists in this protocol.
func decodeOfflineWriterRequest(raw []byte) (offlineUpgradeWriterRequest, error) {
	var out offlineUpgradeWriterRequest
	fields, err := offlineClosedObject(raw, 512, "format", "version", "plan_sha256", "lease_fds")
	var descriptors []int
	if err != nil || json.Unmarshal(fields["format"], &out.Format) != nil || json.Unmarshal(fields["version"], &out.Version) != nil || json.Unmarshal(fields["plan_sha256"], &out.PlanSHA) != nil || out.Format != 1 || len(out.Version) > 160 || !offlineUpgradeVersion.MatchString(out.Version) || !coreSHA.MatchString(out.PlanSHA) {
		return out, errors.New("离线写入仅接受固定版本和完整原升级计划摘要")
	}
	if json.Unmarshal(fields["lease_fds"], &descriptors) != nil || len(descriptors) != 2 || descriptors[0] < 3 || descriptors[1] < 3 || descriptors[0] > 1<<20 || descriptors[1] > 1<<20 || descriptors[0] == descriptors[1] {
		return out, errors.New("离线写入需要两个独立原继承描述符；不接受路径或标准输入输出")
	}
	out.LeaseFDs = [2]int{descriptors[0], descriptors[1]}
	return out, nil
}

func offlineClosedObject(raw []byte, limit int, keys ...string) (map[string]json.RawMessage, error) {
	var out map[string]json.RawMessage
	if len(raw) == 0 || len(raw) > limit || decodeProgramQueueJSON(raw, &out) != nil || len(out) != len(keys) {
		return nil, errors.New("离线私有对象不是完整固定格式")
	}
	for _, key := range keys {
		if value, ok := out[key]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, errors.New("离线私有对象缺少原固定字段或携带未知字段")
		}
	}
	return out, nil
}

// Hold and revalidate each ordinary Root-owned parent. An independently
// substituted named directory must not make a detached open tree current.
type offlineRootTree struct {
	roots []*os.Root
	paths []string
}

func offlineDirectorySafe(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.IsDir() && s.Uid == 0 && info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 && info.Mode().Perm()&0022 == 0 && info.Mode().Perm()&0700 == 0700
}

func openOfflineRootTree(path string) (*offlineRootTree, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("离线原目录路径不是固定规范绝对路径")
	}
	t := &offlineRootTree{}
	parts := append([]string{"/"}, strings.Split(strings.TrimPrefix(path, "/"), "/")...)
	for _, name := range parts {
		if name == "" {
			continue
		}
		current := "/"
		if len(t.paths) > 0 {
			current = filepath.Join(t.paths[len(t.paths)-1], name)
		}
		info, err := os.Lstat(current)
		if err != nil || !offlineDirectorySafe(info) {
			t.Close()
			return nil, errors.New("离线原目录含链接、外部写权限或未知属主")
		}
		var root *os.Root
		if len(t.roots) == 0 {
			root, err = os.OpenRoot(current)
		} else {
			root, err = t.roots[len(t.roots)-1].OpenRoot(name)
		}
		if err != nil {
			t.Close()
			return nil, err
		}
		opened, err := root.Stat(".")
		if err != nil || !offlineDirectorySafe(opened) || !os.SameFile(info, opened) {
			root.Close()
			t.Close()
			return nil, errors.New("离线目录在打开期间变化")
		}
		t.roots, t.paths = append(t.roots, root), append(t.paths, current)
	}
	if !t.current() {
		t.Close()
		return nil, errors.New("离线原目录身份已变化")
	}
	return t, nil
}

func (t *offlineRootTree) Close() {
	for i := len(t.roots) - 1; i >= 0; i-- {
		t.roots[i].Close()
	}
}

func (t *offlineRootTree) current() bool {
	if len(t.roots) == 0 || len(t.roots) != len(t.paths) {
		return false
	}
	for i, root := range t.roots {
		visible, err := os.Lstat(t.paths[i])
		held, heldErr := root.Stat(".")
		if err != nil || heldErr != nil || !offlineDirectorySafe(visible) || !offlineDirectorySafe(held) || !os.SameFile(visible, held) {
			return false
		}
	}
	return true
}

func (t *offlineRootTree) read(name string, mode os.FileMode, limit int64) ([]byte, os.FileInfo, error) {
	var empty os.FileInfo
	if !t.current() || filepath.Base(name) != name || name == "." || name == ".." {
		return nil, empty, errors.New("离线原文件名或父目录身份异常")
	}
	root := t.roots[len(t.roots)-1]
	f, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, empty, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode() != mode || before.Sys().(*syscall.Stat_t).Uid != 0 || before.Sys().(*syscall.Stat_t).Nlink != 1 || before.Size() < 1 || before.Size() > limit {
		return nil, empty, errors.New("离线原文件的属主、链接、权限或完整容量异常")
	}
	raw, err := readOfflineBounded(f, limit)
	after, e1 := f.Stat()
	visible, e2 := root.Lstat(name)
	if err != nil || e1 != nil || e2 != nil || int64(len(raw)) != before.Size() || !programQueueSame(before, after) || !programQueueSame(before, visible) || !t.current() {
		return nil, empty, errors.New("离线原文件读取期间身份或完整内容变化")
	}
	return raw, before, nil
}

type offlineUpgradeOwner struct {
	PID        int        `json:"pid"`
	StartTicks uint64     `json:"start_ticks"`
	Boot       string     `json:"boot_id"`
	Leases     [][]uint64 `json:"leases"`
}

type offlineUpgradeAuthority struct {
	request   offlineUpgradeWriterRequest
	condition remoteUnpublishedOfflineCondition
	owner     offlineUpgradeOwner
	backup    *offlineRootTree
	plan      []byte
	device    uint64
	inode     uint64
}

func loadOfflineUpgradeAuthority(request offlineUpgradeWriterRequest) (*offlineUpgradeAuthority, error) {
	t, err := openOfflineRootTree("/var/backups/panel/system/production-" + request.Version)
	if err != nil {
		return nil, err
	}
	a := &offlineUpgradeAuthority{request: request, backup: t}
	ok := false
	defer func() {
		if !ok {
			t.Close()
		}
	}()
	for _, path := range []string{"/var/backups/panel/system", t.paths[len(t.paths)-1]} {
		info, err := os.Lstat(path)
		if err != nil || !offlineDirectorySafe(info) || info.Mode().Perm() != 0700 {
			return nil, errors.New("离线升级证据不是原Root私有目录")
		}
	}
	raw, _, err := t.read("recovery-plan.json", 0600, 8<<20)
	if err != nil || hexDigest(raw) != request.PlanSHA {
		return nil, errors.New("原私有升级计划摘要已变化")
	}
	fields, err := offlineClosedObject(raw, 8<<20, "format", "layout", "version", "backup_device", "backup_inode", "owner", "services", "nginx_pid", "database_owner", "database_group", "database_inode", "candidate", "original_units", "original_marker", "previous", "original_pointer", "previous_inventory", "filesync_unpublished")
	var format int
	var layout, version string
	if err != nil || json.Unmarshal(fields["format"], &format) != nil || json.Unmarshal(fields["layout"], &layout) != nil || json.Unmarshal(fields["version"], &version) != nil || format != 1 || layout != "production" || version != request.Version {
		return nil, errors.New("离线写入不属于原签名生产升级计划")
	}
	if _, err := offlineClosedObject(fields["owner"], 2048, "pid", "start_ticks", "boot_id", "leases"); err != nil || json.Unmarshal(fields["owner"], &a.owner) != nil || a.owner.PID != os.Getppid() || a.owner.PID <= 1 || a.owner.StartTicks == 0 || !offlineUpgradeBootID.MatchString(a.owner.Boot) || len(a.owner.Leases) != 2 {
		return nil, errors.New("离线写入父进程不是原Root升级事务")
	}
	for _, pair := range a.owner.Leases {
		if len(pair) != 2 || pair[0] == 0 || pair[1] == 0 {
			return nil, errors.New("原升级租约不是完整设备和inode对")
		}
	}
	if json.Unmarshal(fields["backup_device"], &a.device) != nil || json.Unmarshal(fields["backup_inode"], &a.inode) != nil {
		return nil, errors.New("原升级目录设备或inode不是固定整数")
	}
	a.condition, err = decodeUnpublishedOfflineCondition(fields["filesync_unpublished"])
	if err != nil {
		return nil, err
	}
	var inventory map[string]json.RawMessage
	if json.Unmarshal(fields["candidate"], &inventory) != nil || len(inventory) < 2 || len(inventory) > 10000 {
		return nil, errors.New("原升级候选代码库存不完整")
	}
	entry, err := offlineClosedObject(inventory["bin/panel-executor"], 2048, "kind", "mode", "size", "sha256", "identity")
	var kind, digest string
	var mode uint32
	var size int64
	var identity []uint64
	if err != nil || json.Unmarshal(entry["kind"], &kind) != nil || json.Unmarshal(entry["mode"], &mode) != nil || json.Unmarshal(entry["size"], &size) != nil || json.Unmarshal(entry["sha256"], &digest) != nil || json.Unmarshal(entry["identity"], &identity) != nil || kind != "file" || mode != 0755 || size < 1 || size > 128<<20 || !coreSHA.MatchString(digest) || len(identity) != 9 {
		return nil, errors.New("原升级执行器身份不完整")
	}
	self, err := os.Open("/proc/self/exe") // intentional kernel-selected executable, never a caller path
	if err != nil {
		return nil, err
	}
	defer self.Close()
	info, err := self.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0755 || info.Size() != size {
		return nil, errors.New("当前执行器不是完整保留的原候选")
	}
	s := info.Sys().(*syscall.Stat_t)
	if s.Uid != 0 || s.Nlink != 1 || s.Dev != identity[0] || s.Ino != identity[1] || uint64(s.Mode) != identity[2] || uint64(s.Uid) != identity[3] || uint64(s.Gid) != identity[4] || uint64(s.Nlink) != identity[5] || uint64(size) != identity[6] {
		return nil, errors.New("当前执行器inode不属于原Root保留计划")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(self, size+1))
	if err != nil || n != size || hex.EncodeToString(h.Sum(nil)) != digest {
		return nil, errors.New("当前执行器完整摘要不属于原Root保留计划")
	}
	a.plan = raw
	if err := a.current(); err != nil {
		return nil, err
	}
	ok = true
	return a, nil
}

func hexDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func offlineProcRead(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readOfflineBounded(f, limit)
}

func (a *offlineUpgradeAuthority) current() error {
	if !a.backup.current() {
		return errors.New("原升级私有父目录已变化")
	}
	raw, _, err := a.backup.read("recovery-plan.json", 0600, 8<<20)
	if err != nil || !bytes.Equal(raw, a.plan) {
		return errors.New("原私有升级计划已变化")
	}
	info, err := a.backup.roots[len(a.backup.roots)-1].Stat(".")
	if err != nil || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Dev != a.device || info.Sys().(*syscall.Stat_t).Ino != a.inode {
		return errors.New("原升级目录设备或inode已变化")
	}
	if err := offlineUpgradeParentLive(a.owner); err != nil {
		return err
	}
	for index, path := range []string{"/opt/panel/releases/.release.lock", "/var/lib/panel-executor/runtime-lifecycle.lock"} {
		tree, err := openOfflineRootTree(filepath.Dir(path))
		if err != nil {
			return err
		}
		// Empty lease files are normal. Content is never read or interpreted;
		// the named and inherited kernel inode identities are the authority.
		named, err := tree.roots[len(tree.roots)-1].Lstat(filepath.Base(path))
		var held unix.Stat_t
		fd := a.request.LeaseFDs[index]
		flags, flagsErr := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if err != nil || !named.Mode().IsRegular() || named.Mode() != 0600 || !tree.current() || unix.Fstat(fd, &held) != nil || flagsErr != nil || flags&unix.O_ACCMODE != unix.O_RDWR || held.Mode != unix.S_IFREG|0600 || held.Uid != 0 || held.Nlink != 1 || named.Sys().(*syscall.Stat_t).Uid != 0 || named.Sys().(*syscall.Stat_t).Nlink != 1 || held.Dev != a.owner.Leases[index][0] || held.Ino != a.owner.Leases[index][1] || held.Dev != named.Sys().(*syscall.Stat_t).Dev || held.Ino != named.Sys().(*syscall.Stat_t).Ino {
			tree.Close()
			return errors.New("离线写入没有继承原事务的两个独立租约")
		}
		locks, locksErr := offlineProcRead("/proc/locks", 4<<20)
		if locksErr != nil || !offlineParentExclusiveLease(locks, a.owner.PID, held.Dev, held.Ino) || unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
			tree.Close()
			return errors.New("原升级父进程没有持续持有相同描述符的独占租约")
		}
		// Never LOCK_UN: these are the parent's inherited open descriptions.
		tree.Close()
	}
	marker, err := openOfflineRootTree("/opt/panel/releases")
	if err != nil {
		return err
	}
	defer marker.Close()
	data, _, err := marker.read(".program-upgrade.pending", 0644, 2048)
	if err != nil || string(data) != "version="+a.request.Version+"\n" {
		return errors.New("离线写入没有原升级初始维护标记")
	}
	if _, err := os.Lstat("/opt/panel/.development-upgrade.pending"); !errors.Is(err, os.ErrNotExist) {
		return errors.New("离线生产恢复不接管其他布局的维护状态")
	}
	return nil
}

func offlineUpgradeParentLive(owner offlineUpgradeOwner) error {
	if owner.PID != os.Getppid() || owner.PID <= 1 {
		return errors.New("原升级父进程身份已变化")
	}
	boot, err := offlineProcRead("/proc/sys/kernel/random/boot_id", 128)
	if err != nil || strings.TrimSpace(string(boot)) != owner.Boot {
		return errors.New("原升级父进程不属于当前启动")
	}
	base := "/proc/" + strconv.Itoa(owner.PID)
	status, err := offlineProcRead(base+"/status", 65536)
	if err != nil {
		return err
	}
	root := false
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 5 && fields[0] == "Uid:" && strings.Join(fields[1:], " ") == "0 0 0 0" {
			root = true
		}
	}
	process, err := offlineProcRead(base+"/stat", 65536)
	end := strings.LastIndex(string(process), ") ")
	if err != nil || !root || !strings.HasPrefix(string(process), strconv.Itoa(owner.PID)+" (") || end < 0 {
		return errors.New("原升级父进程不是存活的Root安装进程")
	}
	fields := strings.Fields(string(process)[end+2:])
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" || fields[0] == "x" || fields[19] != strconv.FormatUint(owner.StartTicks, 10) {
		return errors.New("原升级父进程启动身份不一致")
	}
	return nil
}

func offlineParentExclusiveLease(raw []byte, pid int, device, inode uint64) bool {
	matches := 0
	expected := fmt.Sprintf("%x:%x:%d", unix.Major(device), unix.Minor(device), inode)
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 8 || fields[1] != "FLOCK" || fields[2] != "ADVISORY" || fields[3] != "WRITE" || fields[4] != strconv.Itoa(pid) || fields[6] != "0" || fields[7] != "EOF" {
			continue
		}
		parts := strings.Split(fields[5], ":")
		if len(parts) != 3 {
			continue
		}
		major, e1 := strconv.ParseUint(parts[0], 16, 32)
		minor, e2 := strconv.ParseUint(parts[1], 16, 32)
		ino, e3 := strconv.ParseUint(parts[2], 10, 64)
		if e1 == nil && e2 == nil && e3 == nil && fmt.Sprintf("%x:%x:%d", major, minor, ino) == expected {
			matches++
		}
	}
	return matches == 1
}

func checkOfflineUpgradeStopped(ctx context.Context, run Command) error {
	programs := []string{"panel-terminal.service", "panel-terminal-root.service", "panel-executor.service", "panel.service", "panel-mysql-overwrite-recovery.timer", "panel-mysql-overwrite-recovery.service"}
	for _, unit := range programs {
		properties := "LoadState,ActiveState,SubState,MainPID,ControlPID,ControlGroup"
		if strings.HasSuffix(unit, ".timer") {
			properties = "LoadState,ActiveState,SubState"
		}
		raw, err := run(ctx, "/usr/bin/systemctl", "show", unit, "--property="+properties)
		if err != nil || len(raw) > 4096 {
			return errors.New("离线写入无法完整核对固定程序停写状态")
		}
		values := map[string]string{}
		allowed := map[string]bool{}
		for _, key := range strings.Split(properties, ",") {
			allowed[key] = true
		}
		for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
			key, value, ok := strings.Cut(line, "=")
			_, seen := values[key]
			if !ok || seen || !allowed[key] {
				return errors.New("固定程序停写状态含重复或未知字段")
			}
			values[key] = value
		}
		if len(values) != len(allowed) || values["LoadState"] != "loaded" || values["ActiveState"] != "inactive" || values["SubState"] != "dead" || !strings.HasSuffix(unit, ".timer") && (values["MainPID"] != "0" || values["ControlPID"] != "0" || values["ControlGroup"] != "") {
			return errors.New("固定程序仍有进程、控制组或过渡状态；禁止离线写入")
		}
	}
	raw, err := run(ctx, "/usr/bin/systemctl", "list-jobs", "--no-legend", "--no-pager")
	if err != nil || len(raw) > 64<<10 {
		return errors.New("离线写入不能完整核对systemd任务")
	}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 4 {
			return errors.New("离线写入的systemd任务库存格式未知")
		}
		id, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || id == 0 || fields[0] != strconv.FormatUint(id, 10) {
			return errors.New("离线写入的systemd任务库存格式未知")
		}
		for _, unit := range programs {
			if fields[1] == unit {
				return errors.New("固定程序或数据库恢复仍有systemd任务")
			}
		}
	}
	return nil
}

func checkOfflineUpgradeCoreQueues(ctx context.Context) error {
	r, err := openDiskHostCoreReader()
	if err != nil {
		return err
	}
	defer r.db.Close()
	if !r.current() {
		return errors.New("离线核对的原数据库身份变化")
	}
	if err := checkOfflineCoreSidecars(r); err != nil {
		return err
	}
	var check string
	if r.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check) != nil || check != "ok" {
		return errors.New("原数据库完整性尚未核对")
	}
	for _, table := range []string{"jobs", "runtime_jobs", "mysql_jobs", "acme_orders"} {
		var count int
		if r.db.QueryRowContext(ctx, "SELECT count(*) FROM "+table+" WHERE state IN ('queued','running')").Scan(&count) != nil || count != 0 {
			return errors.New("原面板、运行时、数据库或证书任务尚未退出")
		}
	}
	if !r.current() {
		return errors.New("离线核对的原数据库已被替换")
	}
	return checkOfflineCoreSidecars(r)
}

func checkOfflineCoreSidecars(r *diskHostCoreReader) error {
	for _, path := range []string{"/var/lib/panel/panel.db-wal", "/var/lib/panel/panel.db-shm"} {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode() != 0600 || info.Sys().(*syscall.Stat_t).Uid != r.owner || info.Sys().(*syscall.Stat_t).Nlink != 1 {
			return errors.New("离线原数据库日志含链接、错误属主或权限；未交给SQLite读取")
		}
	}
	return nil
}

// Called exclusively by the original signed production upgrade, after all
// fixed writers stop. Neither the app HTTP API nor ordinary upgrades call it.
func RunFilesSyncUnpublishedOfflineRetention(input io.Reader, output io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("离线原片段保留仅允许本机Root签名升级事务")
	}
	raw, err := readOfflineBounded(input, 512)
	if err != nil {
		return err
	}
	request, err := decodeOfflineWriterRequest(raw)
	if err != nil {
		return err
	}
	authority, err := loadOfflineUpgradeAuthority(request)
	if err != nil {
		return err
	}
	defer authority.backup.Close()
	authorize := func() error {
		if err := authority.current(); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := checkOfflineUpgradeStopped(ctx, programQueueCommand); err != nil {
			return err
		}
		return checkOfflineUpgradeCoreQueues(ctx)
	}
	if err := authorize(); err != nil {
		return err
	}
	if err := checkCompleteProgramUpgradeQueues(func(s *Service) error {
		_, err := s.matchUnpublishedOfflineCondition(authority.condition)
		return err
	}); err != nil {
		return err
	}
	s := &Service{Config: Config{SecurityDir: "/etc/panel/security-apps"}}
	witness, written, err := s.retainUnpublishedOfflineCondition(authority.condition, authorize)
	if err != nil {
		return err
	}
	if err := CheckProgramUpgradeQueues(); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		Format    int                             `json:"format"`
		Written   bool                            `json:"new_retention"`
		Witness   remoteUnpublishedOfflineWitness `json:"witness"`
		Preserved bool                            `json:"original_fragments_preserved"`
	}{1, written, witness, true})
}
