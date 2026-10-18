//go:build linux

package executor

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type runtimeCompilerScope struct {
	Path   string
	Root   *os.Root
	mu     sync.Mutex
	pidfds map[int]compilerProcessReference
	// Numeric kernel witnesses only, never source arguments or output. These
	// diagnostics do not authorize signals or alter collection/publication.
	collectionMemberSnapshots int
	collectionReapedTotal     int
	collectionReaped          []compilerWaitWitness
}

type compilerWaitWitness struct {
	pid    int
	status syscall.WaitStatus
}

type compilerProcessReference struct {
	fd               int
	signalAuthorized bool
}

type nativeCompilerAuthority uint8

const (
	nativeRuntimeCompilerAuthority nativeCompilerAuthority = iota
	nativeApacheCompilerAuthority
	nativeNginxWAFCompilerAuthority
	nativeAnalyticsHTMLCompilerAuthority
)

func (s *runtimeCompilerScope) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	for pid, reference := range s.pidfds {
		err = errors.Join(err, unix.Close(reference.fd))
		delete(s.pidfds, pid)
	}
	return errors.Join(err, s.Root.Close())
}

func compilerPIDFDTask(fd int) (int, error) {
	f, err := os.OpenFile(filepath.Join("/proc/self/fdinfo", strconv.Itoa(fd)), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return 0, err
	}
	return runtimeCompilerPIDFDTask(data)
}

// WNOWAIT is essential during preflight: an unknown zombie is retained, not
// consumed to manufacture an empty service. WALL also includes clone children.
func compilerHasNoChildren() (bool, error) {
	for {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_ALL, 0, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT|unix.WALL, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.ECHILD) {
			return true, nil
		}
		return false, err
	}
}

func beginRuntimeCompilerScope() (*runtimeCompilerScope, error) {
	return beginNativeCompilerScope(nativeRuntimeCompilerAuthority)
}

func beginApacheBodyCompilerScope() (*runtimeCompilerScope, error) {
	return beginNativeCompilerScope(nativeApacheCompilerAuthority)
}

func beginNginxWAFCompilerScope() (*runtimeCompilerScope, error) {
	return beginNativeCompilerScope(nativeNginxWAFCompilerAuthority)
}

func beginNativeCompilerScope(authority nativeCompilerAuthority) (*runtimeCompilerScope, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("编译监督必须在专用 root 服务内执行")
	}
	text, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return nil, err
	}
	var path string
	switch authority {
	case nativeApacheCompilerAuthority:
		path, err = decodeApacheBodyCompilerCgroup(string(text))
	case nativeRuntimeCompilerAuthority:
		path, err = decodeRuntimeCompilerCgroup(string(text))
	case nativeNginxWAFCompilerAuthority:
		path, err = decodeNginxWAFCompilerCgroup(string(text))
	case nativeAnalyticsHTMLCompilerAuthority:
		path, err = decodeAnalyticsHTMLCompilerCgroup(string(text))
	default:
		return nil, errors.New("编译监督授权类别未知，未执行或回收进程")
	}
	if err != nil {
		return nil, err
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs("/sys/fs/cgroup", &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, errors.New("运行时构建需要可核实的 cgroup v2；未退回宽泛进程终止")
	}
	root, err := os.OpenRoot(filepath.Join("/sys/fs/cgroup", path))
	if err != nil {
		return nil, err
	}
	scope := &runtimeCompilerScope{Path: path, Root: root, pidfds: map[int]compilerProcessReference{}}
	// Refuse an unavailable stable-PID interface before launching a compiler;
	// discovering it only during cancellation would leave collection unproved.
	pidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		root.Close()
		return nil, errors.New("本内核不能提供稳定进程引用，未执行编译或退回宽泛进程终止")
	}
	task, taskErr := compilerPIDFDTask(pidfd)
	unix.Close(pidfd)
	if taskErr != nil || task != os.Getpid() {
		root.Close()
		return nil, errors.New("内核不能提供稳定进程引用的完整回收状态，未执行编译")
	}
	members, err := scope.members()
	if err != nil || len(members) != 1 || members[0] != os.Getpid() {
		root.Close()
		return nil, errors.New("构建服务已有其他进程，未启动新编译或终止未知成员")
	}
	if err := apacheBodyCompilerSubreaper(); err != nil {
		root.Close()
		return nil, err
	}
	if empty, err := compilerHasNoChildren(); err != nil || !empty {
		root.Close()
		return nil, errors.New("构建服务已有其他进程或未回收子进程，未启动新编译或消费未知退出状态")
	}
	return scope, nil
}

func (s *runtimeCompilerScope) members() ([]int, error) {
	current, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || string(current) != "0::"+s.Path+"\n" {
		return nil, errors.New("编译监督服务身份变化，未终止其他服务")
	}
	entries, err := fs.ReadDir(s.Root.FS(), ".")
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return nil, errors.New("构建服务含未知子 cgroup，未忽略未核实的进程")
		}
	}
	f, err := s.Root.OpenFile("cgroup.procs", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 128*1024+1))
	if err != nil || len(data) > 128*1024 {
		return nil, errors.New("构建进程清单不可读取或超出固定容量")
	}
	seen := map[int]bool{}
	members := []int{}
	self := false
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		pid, err := strconv.Atoi(line)
		if err != nil || pid < 2 || line != strconv.Itoa(pid) {
			return nil, errors.New("构建进程清单身份字段异常")
		}
		if !seen[pid] {
			members = append(members, pid)
			seen[pid] = true
		}
		self = self || pid == os.Getpid()
	}
	if !self || len(members) > 4096 {
		return nil, errors.New("构建进程清单缺少监督进程或超过固定限额")
	}
	return members, nil
}

// A stable pidfd plus a fresh exact cgroup check prevents numeric PID reuse
// from authorizing a signal to a process in a different service. Compiler
// payloads cannot migrate cgroups: their inherited/effective capability sets
// are cleared and the unit makes the cgroup filesystem read-only.
func (s *runtimeCompilerScope) signalMembers() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.signalMembersLocked()
}

func (s *runtimeCompilerScope) signalMembersLocked() (bool, error) {
	if err := s.pruneReapedLocked(); err != nil {
		return false, err
	}
	members, err := s.members()
	if err != nil {
		return false, err
	}
	found := false
	for _, pid := range members {
		if pid == os.Getpid() {
			continue
		}
		found = true
		if _, retained := s.pidfds[pid]; retained {
			continue
		}
		if len(s.pidfds) >= 4096 {
			return found, errors.New("稳定进程引用超过固定回收限额，未发布运行时")
		}
		fd, err := unix.PidfdOpen(pid, 0)
		if errors.Is(err, unix.ESRCH) {
			continue
		}
		if err != nil {
			return found, fmt.Errorf("无法获得本构建子进程的稳定引用: %w", err)
		}
		current, readErr := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
		if errors.Is(readErr, os.ErrNotExist) {
			// Retain the exit reference even when /proc already disappeared.
			// No signal is authorized by a missing cgroup identity.
			s.pidfds[pid] = compilerProcessReference{fd: fd}
			continue
		}
		if readErr != nil || string(current) != "0::"+s.Path+"\n" {
			unix.Close(fd)
			return found, errors.New("子进程已退出本构建服务或身份不可读取，未终止其他服务")
		}
		s.pidfds[pid] = compilerProcessReference{fd: fd, signalAuthorized: true}
	}
	// Acquire every member reference before the first signal. Killing a parent
	// must not erase the identity/reaping witness for its dying descendants.
	for _, reference := range s.pidfds {
		task, err := compilerPIDFDTask(reference.fd)
		if err != nil {
			return found, err
		}
		if task == -1 || !reference.signalAuthorized {
			continue
		}
		// This stable task was authorized immediately after PidfdOpen and
		// cannot migrate the read-only cgroup. Do not authorize a new PID lookup
		// here: cgroup_exit may already have removed a dying task's membership.
		err = unix.PidfdSendSignal(reference.fd, unix.SIGKILL, nil, 0)
		if err != nil && !errors.Is(err, unix.ESRCH) {
			return found, fmt.Errorf("本构建服务的子进程终止失败，未发布运行时: %w", err)
		}
	}
	return found, nil
}

func (s *runtimeCompilerScope) pruneReapedLocked() error {
	for pid, reference := range s.pidfds {
		task, err := compilerPIDFDTask(reference.fd)
		if err != nil {
			return err
		}
		if task == -1 {
			if err := unix.Close(reference.fd); err != nil {
				return err
			}
			delete(s.pidfds, pid)
		} else if task != pid {
			return errors.New("保留的稳定进程引用身份变化，未判定回收完成")
		}
	}
	return nil
}

func (s *runtimeCompilerScope) collect() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	deadline := time.Now().Add(3 * time.Second)
	leftovers := false
	for {
		found, err := s.signalMembersLocked()
		leftovers = leftovers || found
		if found {
			s.collectionMemberSnapshots++
		}
		if err != nil {
			return leftovers, err
		}
		// The direct os/exec child was already waited. Reap only the orphaned
		// descendants adopted by this dedicated single-supervisor service.
		noChildren := false
		for {
			var status syscall.WaitStatus
			pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG|unix.WALL, nil)
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			if err != nil && !errors.Is(err, syscall.ECHILD) {
				return leftovers, err
			}
			if pid <= 0 {
				// pid=0 means a child still exists but is not yet waitable.
				// Only ECHILD proves there are no remaining adopted children.
				noChildren = errors.Is(err, syscall.ECHILD)
				break
			}
			leftovers = true
			s.collectionReapedTotal++
			if len(s.collectionReaped) < 64 {
				s.collectionReaped = append(s.collectionReaped, compilerWaitWitness{pid: pid, status: status})
			}
		}
		members, err := s.members()
		if err != nil {
			return leftovers, err
		}
		if err := s.pruneReapedLocked(); err != nil {
			return leftovers, err
		}
		if len(members) == 1 && members[0] == os.Getpid() && len(s.pidfds) == 0 && noChildren {
			// Recheck children after the live-member snapshot: cgroup_exit
			// precedes exit_notify/adoption in Linux, so the earlier snapshot
			// must not turn a late zombie adoption into success.
			if empty, err := compilerHasNoChildren(); err != nil {
				return leftovers, err
			} else if empty {
				return leftovers, nil
			}
		}
		if time.Now().After(deadline) {
			return leftovers, errors.New("本构建服务的子进程未在固定时限内完全回收，未发布运行时")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The caller has already opened and validated its private bounded log. Keep
// this fixed numeric diagnostic below 8 KiB even for the 4096-member limit;
// never log /proc cmdlines, source labels, environment or request contents.
func (s *runtimeCompilerScope) writeCollectionDiagnostics(log *os.File) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := log.Stat()
	if err != nil || st.Size() >= 64<<20 {
		return errors.New("私有编译回收诊断日志达到固定上限或不可读取")
	}
	var out strings.Builder
	fmt.Fprintf(&out, "\ncompiler-collection-v2 member_snapshots=%d reaped=%d sampled=%d\n", s.collectionMemberSnapshots, s.collectionReapedTotal, len(s.collectionReaped))
	for _, witness := range s.collectionReaped {
		exit, signal := -1, 0
		if witness.status.Exited() {
			exit = witness.status.ExitStatus()
		}
		if witness.status.Signaled() {
			signal = int(witness.status.Signal())
		}
		fmt.Fprintf(&out, "compiler-wait pid=%d wait_status=%d exit=%d signal=%d\n", witness.pid, uint32(witness.status), exit, signal)
	}
	if out.Len() > 8<<10 {
		return errors.New("私有编译回收诊断超出固定容量")
	}
	_, err = io.WriteString(&cappedLog{File: log, Remaining: (64 << 20) - st.Size()}, out.String())
	return err
}
