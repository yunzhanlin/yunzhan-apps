//go:build linux

package executor

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"local/panel/internal/core"
)

const ftpRuntimeVersion = "1.0.54-yz1"
const ftpRuntimeSource = "https://download.pureftpd.org/pub/pure-ftpd/releases/pure-ftpd-1.0.54.tar.gz"

// Pinned from the upstream HTTPS release download. Not an upstream PGP claim.
const ftpRuntimeSourceSHA = "dc9140420ec44f7829579591ff378aa6396b4604b9c6aeae847368e0f35bd7b2"

//go:embed assets/pure-ftpd-throttle-accounted-bytes.patch
var ftpThrottlePatch []byte

//go:embed assets/pure-ftpd-low-rate-chunks.patch
var ftpLowRatePatch []byte

//go:embed assets/pure-ftpd-tls-buffer-v2.patch
var ftpTLSBufferPatch []byte

//go:embed assets/pure-ftpd-NOTICES.txt
var ftpThirdPartyNotices []byte

//go:embed assets/pure-ftpd-unprivileged-version.patch
var ftpCLIVersionPatch []byte

func ensureFTPRuntimeNotices(dir string) error {
	path := filepath.Join(dir, "THIRD-PARTY-NOTICES")
	data, e := ftpRuntimeFile(path)
	if e == nil {
		if !bytes.Equal(data, ftpThirdPartyNotices) {
			return errors.New("FTP 许可通知被修改，拒绝覆盖")
		}
		return nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return atomicWrite(path, ftpThirdPartyNotices, 0644)
}

func ftpRuntimePatchSHA() string {
	return core.Hash(string(ftpThrottlePatch) + string(ftpLowRatePatch) + string(ftpTLSBufferPatch) + string(ftpCLIVersionPatch))
}

type ftpRuntimeManifest struct {
	Version      string            `json:"version"`
	Architecture string            `json:"architecture"`
	SourceSHA    string            `json:"source_sha256"`
	PatchSHA     string            `json:"patch_sha256"`
	Files        map[string]string `json:"files"`
	BuiltAt      string            `json:"built_at"`
}
type ftpRuntimeTransaction struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	Old       []byte `json:"old"`
	OldExists bool   `json:"old_exists"`
	NextSHA   string `json:"next_sha256"`
	WasActive bool   `json:"was_active"`
	Time      string `json:"time"`
}

func decodeFTPPrivateJSON(data []byte, to any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(to); err != nil {
		return err
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return errors.New("FTP 私有记录有多余内容")
	}
	return nil
}
func ftpRuntimeFile(path string) ([]byte, error) {
	if e := ownedRuntimePath(path, false); e != nil {
		return nil, e
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || st.Size() > 8<<20 {
		return nil, errors.New("FTP 独立程序身份、权限或大小异常")
	}
	return io.ReadAll(io.LimitReader(f, 8<<20+1))
}
func (s *Service) validateFTPRuntime() error {
	dir := s.systemPath(filepath.Join(appNativeRoot, "pure-ftpd", ftpRuntimeVersion))
	for _, path := range []string{s.systemPath(appNativeRoot), filepath.Dir(dir), dir} {
		if e := ownedRuntimePath(path, true); e != nil {
			return e
		}
	}
	b, e := ftpPrivateRead(filepath.Join(dir, "manifest.json"), 16<<10)
	if e != nil {
		return e
	}
	var m ftpRuntimeManifest
	if decodeFTPPrivateJSON(b, &m) != nil || m.Version != ftpRuntimeVersion || m.Architecture != runtime.GOARCH || m.SourceSHA != ftpRuntimeSourceSHA || m.PatchSHA != ftpRuntimePatchSHA() || len(m.Files) != 4 {
		return errors.New("FTP 独立程序固定来源清单不匹配")
	}
	for _, name := range []string{"pure-ftpd", "pure-pw", "pure-ftpwho", "COPYING"} {
		st, e := os.Stat(filepath.Join(dir, name))
		if e != nil {
			return e
		}
		if name != "COPYING" && st.Mode().Perm()&0111 == 0 {
			return errors.New("FTP 固定程序没有执行权限")
		}
		data, e := ftpRuntimeFile(filepath.Join(dir, name))
		if e != nil {
			return e
		}
		if len(m.Files[name]) != 64 || m.Files[name] != core.Hash(string(data)) {
			return errors.New("FTP 独立程序完整性校验失败")
		}
	}
	return nil
}
func (s *Service) ftpBinary(name string) (string, error) {
	system := map[string]string{"pure-ftpd": "/usr/sbin/pure-ftpd", "pure-pw": "/usr/bin/pure-pw", "pure-ftpwho": "/usr/sbin/pure-ftpwho"}[name]
	if system == "" {
		return "", errors.New("FTP 固定程序名称无效")
	}
	b, e := ftpPrivateRead(filepath.Join(s.moduleDir("pure-ftpd"), "runtime.json"), 1024)
	if errors.Is(e, os.ErrNotExist) {
		return s.systemPath(system), nil
	}
	if e != nil {
		return "", e
	}
	var v struct {
		Version string `json:"version"`
	}
	if decodeFTPPrivateJSON(b, &v) != nil || v.Version != ftpRuntimeVersion {
		return "", errors.New("FTP 活动运行时记录无效")
	}
	if e = s.validateFTPRuntime(); e != nil {
		return "", e
	}
	return s.systemPath(filepath.Join(appNativeRoot, "pure-ftpd", ftpRuntimeVersion, name)), nil
}

// Executed only by the fixed root dependency unit. Configure and compile run
// as panel-build; only the selected regular binaries and full license promote.
func installPrivateFTPRuntime(ctx context.Context) error {
	s := New(Config{})
	if s.validateFTPRuntime() == nil {
		return ensureFTPRuntimeNotices(filepath.Join(appNativeRoot, "pure-ftpd", ftpRuntimeVersion))
	}
	target := filepath.Join(appNativeRoot, "pure-ftpd", ftpRuntimeVersion)
	if _, e := os.Lstat(target); !errors.Is(e, os.ErrNotExist) {
		return errors.New("FTP 独立程序目录已存在但清单不符，拒绝覆盖")
	}
	if e := os.MkdirAll("/var/cache/panel-build", 0755); e != nil {
		return e
	}
	base, e := os.MkdirTemp("/var/cache/panel-build", "ftp-"+core.ID()+"-")
	if e != nil {
		return e
	}
	if e = os.Chmod(base, 0755); e != nil {
		return e
	}
	archive := filepath.Join(base, "source.tar.gz")
	if e = downloadVerified(ctx, ftpRuntimeSource, ftpRuntimeSourceSHA, archive); e != nil {
		return e
	}
	work := filepath.Join(base, "work")
	if e = os.Mkdir(work, 0755); e != nil {
		return e
	}
	if e = extractSource(archive, work); e != nil {
		return e
	}
	source := filepath.Join(work, "pure-ftpd-1.0.54")
	patches := [][]byte{ftpThrottlePatch, ftpTLSBufferPatch, ftpLowRatePatch, ftpCLIVersionPatch}
	for i, b := range patches {
		if e = atomicWrite(filepath.Join(source, fmt.Sprintf(".yunzhan-%d.patch", i)), b, 0644); e != nil {
			return e
		}
	}
	if _, e = RunCommand(ctx, "/usr/bin/chown", "-R", "panel-build:panel-build", work); e != nil {
		return e
	}
	log := filepath.Join(base, "build.log")
	for i := range patches {
		if e = buildCommand(ctx, source, log, "/usr/bin/patch", "--fuzz=0", "-p1", "-i", filepath.Join(source, fmt.Sprintf(".yunzhan-%d.patch", i))); e != nil {
			return e
		}
	}
	args := []string{"--prefix=" + target, "--with-tls", "--with-puredb", "--with-quotas", "--with-throttling", "--with-peruserlimits", "--with-ftpwho", "--with-privsep", "--without-capabilities", "--with-sodium"}
	if e = buildCommand(ctx, source, log, filepath.Join(source, "configure"), args...); e != nil {
		return e
	}
	if e = buildCommand(ctx, source, log, "/usr/bin/make", "-j"+strconv.Itoa(runtimeBuildJobs())); e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(target), 0755); e != nil {
		return e
	}
	for _, path := range []string{appNativeRoot, filepath.Dir(target)} {
		if e = ownedRuntimePath(path, true); e != nil {
			return e
		}
		// These directories contain only public program files, never FTP
		// accounts or keys. The build user must traverse them for the dropped-
		// privilege version check even with the dependency unit's 0027 umask.
		if e = os.Chmod(path, 0755); e != nil {
			return e
		}
	}
	stage, e := os.MkdirTemp(filepath.Dir(target), ".pending-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(stage)
	if e = os.Chmod(stage, 0755); e != nil {
		return e
	}
	m := ftpRuntimeManifest{ftpRuntimeVersion, runtime.GOARCH, ftpRuntimeSourceSHA, ftpRuntimePatchSHA(), map[string]string{}, core.Now()}
	for _, name := range []string{"pure-ftpd", "pure-pw", "pure-ftpwho", "COPYING"} {
		from := filepath.Join(source, "src", name)
		mode := os.FileMode(0755)
		if name == "COPYING" {
			from = filepath.Join(source, name)
			mode = 0644
		}
		st, e := os.Lstat(from)
		if e != nil {
			return e
		}
		if !st.Mode().IsRegular() || st.Size() > 8<<20 {
			return errors.New("FTP 构建输出不是允许的常规文件")
		}
		b, e := os.ReadFile(from)
		if e != nil {
			return e
		}
		m.Files[name] = core.Hash(string(b))
		if e = atomicWrite(filepath.Join(stage, name), b, mode); e != nil {
			return e
		}
	}
	// Install-prefix parents may restrict access to the build user. Check an
	// identical root-owned copy in the traversable build directory, and never
	// run the version check as root.
	checkBinary := filepath.Join(base, "verify-pure-ftpd")
	data, e := ftpRuntimeFile(filepath.Join(stage, "pure-ftpd"))
	if e != nil {
		return e
	}
	if e = atomicWrite(checkBinary, data, 0755); e != nil {
		return e
	}
	version, e := RunCommand(ctx, "/usr/sbin/runuser", "-u", "panel-build", "--", checkBinary, "--help")
	if e != nil || !strings.Contains(version, "1.0.54") {
		return fmt.Errorf("FTP 非特权构建版本核对失败: %v", e)
	}
	if e = ensureFTPRuntimeNotices(stage); e != nil {
		return e
	}
	if e = moduleWrite(filepath.Join(stage, "manifest.json"), m); e != nil {
		return e
	}
	if e = os.Rename(stage, target); e != nil {
		return e
	}
	parent, e := os.Open(filepath.Dir(target))
	if e != nil {
		return e
	}
	defer parent.Close()
	if e = parent.Sync(); e != nil {
		return e
	}
	return s.validateFTPRuntime()
}
func (s *Service) finishFTPRuntime(t ftpRuntimeTransaction) error {
	dir := s.moduleDir("pure-ftpd")
	if e := moduleWrite(filepath.Join(dir, "pending-runtime.json"), t); e != nil {
		return e
	}
	if e := moduleWrite(filepath.Join(dir, "runtime-transactions", t.ID+".json"), t); e != nil {
		return e
	}
	return os.Remove(filepath.Join(dir, "pending-runtime.json"))
}
func (s *Service) recoverFTPRuntime() (bool, error) {
	dir := s.moduleDir("pure-ftpd")
	b, e := ftpPrivateRead(filepath.Join(dir, "pending-runtime.json"), 4096)
	if errors.Is(e, os.ErrNotExist) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	var t ftpRuntimeTransaction
	if decodeFTPPrivateJSON(b, &t) != nil || !core.ValidID(t.ID) || len(t.Old) > 1024 || len(t.NextSHA) != 64 || (t.State != "applying" && t.State != "committed" && t.State != "recovered") {
		return false, errors.New("FTP 运行时恢复记录无效")
	}
	if t.State != "applying" {
		return false, s.finishFTPRuntime(t)
	}
	current, e := ftpPrivateRead(filepath.Join(dir, "runtime.json"), 1024)
	if e != nil && !(errors.Is(e, os.ErrNotExist) && !t.OldExists) {
		return false, e
	}
	if e == nil && core.Hash(string(current)) != t.NextSHA && (!t.OldExists || core.Hash(string(current)) != core.Hash(string(t.Old))) {
		return false, errors.New("FTP 运行时被外部修改，未覆盖")
	}
	if t.OldExists {
		if e = atomicWrite(filepath.Join(dir, "runtime.json"), t.Old, 0600); e != nil {
			return false, e
		}
	} else if e = os.Remove(filepath.Join(dir, "runtime.json")); e != nil && !errors.Is(e, os.ErrNotExist) {
		return false, e
	}
	t.State = "recovered"
	return t.WasActive, s.finishFTPRuntime(t)
}
func (s *Service) activateFTPRuntime(ctx context.Context) error {
	lock, e := s.lockFTP()
	if e != nil {
		return e
	}
	defer lock.Close()
	dir := s.moduleDir("pure-ftpd")
	for _, name := range []string{"pending-runtime.json", "pending-accounts.json", "pending-service.json"} {
		if exists(filepath.Join(dir, name)) {
			return errors.New("FTP 有待恢复事务，未切换运行时")
		}
	}
	if e = s.validateFTPRuntime(); e != nil {
		return e
	}
	path := filepath.Join(dir, "runtime.json")
	old, e := ftpPrivateRead(path, 1024)
	oldExists := e == nil
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	next := []byte(fmt.Sprintf("{\"version\":%q}\n", ftpRuntimeVersion))
	if bytes.Equal(old, next) {
		return nil
	}
	state, _ := s.Config.Run(ctx, "/usr/bin/systemctl", "is-active", "panel-pure-ftpd.service")
	t := ftpRuntimeTransaction{core.ID(), "applying", old, oldExists, core.Hash(string(next)), strings.TrimSpace(state) == "active", core.Now()}
	if e = moduleWrite(filepath.Join(dir, "pending-runtime.json"), t); e != nil {
		return e
	}
	// The service may run the candidate while this journal is applying. Boot
	// recovery always restores the prior selection before the daemon can start.
	if e = atomicWrite(path, next, 0600); e != nil {
		_, _ = s.recoverFTPRuntime()
		return e
	}
	if t.WasActive {
		_, e = s.Config.Run(ctx, "/usr/bin/systemctl", "restart", "panel-pure-ftpd.service")
		if e == nil {
			var c ftpServiceConfig
			c, e = s.ftpConfig()
			if e == nil {
				var data []byte
				data, _, e = s.ftpCertificate(c)
				if e == nil {
					e = s.ftpReady(ctx, c, data)
				}
			}
		}
		if e != nil {
			_, restore := s.recoverFTPRuntime()
			if restore != nil {
				return errors.New("FTP 新运行时启动失败且恢复未完成，备份已保留")
			}
			_, restore = s.Config.Run(context.WithoutCancel(ctx), "/usr/bin/systemctl", "restart", "panel-pure-ftpd.service")
			if restore != nil {
				return errors.New("FTP 新运行时启动失败；已恢复原选择，但原服务重启失败")
			}
			return e
		}
	}
	t.State = "committed"
	return s.finishFTPRuntime(t)
}

func (s *Service) ftpRecoveryPending() bool {
	for _, n := range []string{"pending-runtime.json", "pending-accounts.json", "pending-service.json"} {
		if exists(filepath.Join(s.moduleDir("pure-ftpd"), n)) {
			return true
		}
	}
	return false
}
