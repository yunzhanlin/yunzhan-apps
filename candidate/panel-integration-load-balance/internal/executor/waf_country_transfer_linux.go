//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/geodata"
)

// The Root supervisor has ONLY read/search, changed-UID cancellation and UID/GID
// switching. No DAC write override, file-owner, mount, network-raw or ptrace cap.
const countrySupervisorCapabilities = "00000000000000e4"
const countryTransferProtocolLimit = appcatalog.MaxGeoDataEnvelopeBytes + 8192

type countryTransferInput struct {
	Format    int                          `json:"format"`
	Selection core.WAFCountryDataSelection `json:"selection"`
	Code      string                       `json:"code"`
	Envelope  json.RawMessage              `json:"envelope"`
}

type countryTransferReceipt struct {
	Format          int    `json:"format"`
	DataManifestSHA string `json:"data_manifest_sha256"`
	Code            string `json:"code"`
	SHA256          string `json:"sha256"`
	Bytes           int64  `json:"bytes"`
	Networks        int    `json:"networks"`
	UID             uint32 `json:"uid"`
	GID             uint32 `json:"gid"`
}

// A closed /proc status contract, not a caller-supplied permission assertion.
// The child's bounding set is inherited but cannot be activated (non-root,
// no permitted/effective/inheritable/ambient capabilities and NNP1).
func countryProcessStatus(raw []byte, uid, gid uint32, supervisor bool) bool {
	if len(raw) < 1 || len(raw) > 32<<10 || !strings.HasSuffix(string(raw), "\n") || strings.ContainsAny(string(raw), "\r\x00") || supervisor != (uid == 0 && gid == 0) || !supervisor && (uid == 0 || gid == 0) {
		return false
	}
	wanted := map[string]bool{"Uid": true, "Gid": true, "Groups": true, "NoNewPrivs": true, "CapInh": true, "CapPrm": true, "CapEff": true, "CapBnd": true, "CapAmb": true}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found || !wanted[key] {
			continue
		}
		if seen[key] {
			return false
		}
		seen[key] = true
		parts := strings.Fields(value)
		switch key {
		case "Uid", "Gid":
			want := strconv.FormatUint(uint64(uid), 10)
			if key == "Gid" {
				want = strconv.FormatUint(uint64(gid), 10)
			}
			if len(parts) != 4 || parts[0] != want || parts[1] != want || parts[2] != want || parts[3] != want {
				return false
			}
		case "Groups":
			if !supervisor && len(parts) != 0 {
				return false
			}
			if supervisor && (len(parts) > 1 || len(parts) == 1 && parts[0] != "0") {
				return false
			}
		case "NoNewPrivs":
			if len(parts) != 1 || parts[0] != "1" {
				return false
			}
		default:
			want := "0000000000000000"
			if key == "CapBnd" || supervisor {
				want = countrySupervisorCapabilities
			}
			if len(parts) != 1 || parts[0] != want {
				return false
			}
		}
	}
	return len(seen) == len(wanted)
}

func countryCheckOwnProcess(supervisor bool) error {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || !countryProcessStatus(status, uint32(os.Geteuid()), uint32(os.Getegid()), supervisor) {
		return errors.New("国家数据监督/传输进程不是固定最小权限身份，未传输")
	}
	return nil
}

func decodeCountryTransfer(raw []byte) (countryTransferInput, error) {
	var in countryTransferInput
	bad := errors.New("国家数据传输协议不是完整原签名选择")
	if len(raw) < 1 || len(raw) > countryTransferProtocolLimit || decodeProgramQueueJSON(raw, &in) != nil || in.Format != 1 || core.ValidateWAFCountryDataSelection(in.Selection) != nil || len(in.Envelope) < 1 || len(in.Envelope) > appcatalog.MaxGeoDataEnvelopeBytes {
		return countryTransferInput{}, bad
	}
	found := false
	for _, code := range in.Selection.Countries {
		found = found || code == in.Code
	}
	if !found {
		return countryTransferInput{}, bad
	}
	if _, err := appcatalog.DecodeGeoDataEnvelope(in.Envelope); err != nil {
		return countryTransferInput{}, bad
	}
	canonical, err := json.Marshal(in)
	if err != nil || !bytes.Equal(raw, canonical) {
		return countryTransferInput{}, bad
	}
	return in, nil
}

func countryTransferFileIdentity(file *os.File, empty bool) (os.FileInfo, error) {
	if file == nil {
		return nil, errors.New("国家数据原始输出描述符缺失")
	}
	info, err := file.Stat()
	if err != nil {
		return nil, errors.New("国家数据原始输出身份不可读")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	// Unlike moduleRecordInfo, this handle MUST remain Root-owned even when
	// inspected by its non-root recipient. Never chown a cache file to a child.
	if !ok || owner.Uid != 0 || owner.Gid != 0 || owner.Nlink != 1 || !info.Mode().IsRegular() || info.Mode() != 0600 || empty && info.Size() != 0 {
		return nil, errors.New("国家数据输出不是私有Root普通文件")
	}
	position, err := file.Seek(0, io.SeekCurrent)
	if err != nil || empty && position != 0 {
		return nil, errors.New("国家数据输出描述符位置无效")
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_WRONLY || flags&(unix.O_APPEND|unix.O_PATH) != 0 {
		return nil, errors.New("国家数据子进程只接受原始只写文件描述符")
	}
	return info, nil
}

// Early fixed CLI entry; no Service/database/Root socket constructor. No key,
// URL, path, executable, cookie or network proxy is accepted from stdin/argv.
func RunWAFCountryTransfer(input io.Reader, output io.Writer, destination *os.File) error {
	if input == nil || output == nil || countryCheckOwnProcess(false) != nil {
		return errors.New("国家数据低权限传输入口无效")
	}
	account, err := countryNetworkNamedIdentity()
	if err != nil || uint32(os.Geteuid()) != account.UID || uint32(os.Getegid()) != account.GID {
		return errors.New("国家数据传输未使用独立专用账户")
	}
	before, err := countryTransferFileIdentity(destination, true)
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(input, countryTransferProtocolLimit+1))
	if err != nil {
		return err
	}
	in, err := decodeCountryTransfer(raw)
	if err != nil {
		return err
	}
	envelope, err := appcatalog.DecodeGeoDataEnvelope(in.Envelope)
	if err != nil {
		return err
	}
	client := appcatalog.Default()
	authority, err := client.VerifyCountryDataEnvelope(envelope, in.Selection.AppVersion, in.Selection.AppManifestSHA, time.Now(), nil)
	if err != nil {
		return err
	}
	m := authority.Data().Manifest()
	assets, err := authority.Data().Select([]string{in.Code})
	if err != nil || authority.Data().SHA256() != in.Selection.DataManifestSHA || m.Release != in.Selection.Release || m.Revision != in.Selection.Revision {
		return errors.New("国家数据子进程原签名与选择不同")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	defer cancel()
	if err := client.DownloadCountryAssetFile(ctx, authority, in.Code, destination); err != nil {
		return err
	}
	after, err := countryTransferFileIdentity(destination, false)
	if err != nil || !os.SameFile(before, after) || after.Size() != assets[0].Bytes {
		return errors.New("国家数据传输原始输出身份改变")
	}
	receipt := countryTransferReceipt{1, authority.Data().SHA256(), in.Code, assets[0].SHA256, assets[0].Bytes, assets[0].Networks, account.UID, account.GID}
	raw, err = json.Marshal(receipt)
	if err != nil {
		return err
	}
	_, err = output.Write(append(raw, '\n'))
	return err
}

// Root hands a write-only handle to ONE empty original cache file, not its
// directory or metadata. All readback/publication still happens in Root.
func countryWriteOnlyHandle(file *os.File) (*os.File, error) {
	if file == nil {
		return nil, errors.New("国家数据原始文件缺失")
	}
	before, err := file.Stat()
	if err != nil || !moduleRecordInfo(before, false, false) || before.Size() != 0 {
		return nil, errors.New("国家数据原始空文件身份无效")
	}
	fd, err := unix.Open("/proc/self/fd/"+strconv.FormatUint(uint64(file.Fd()), 10), unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	out := os.NewFile(uintptr(fd), "country-original-write-only")
	after, err := countryTransferFileIdentity(out, true)
	if err != nil || !os.SameFile(before, after) {
		out.Close()
		return nil, errors.New("国家数据只写描述符未绑定原始文件")
	}
	return out, nil
}

func countryTransferCommand(ctx context.Context, account countryNetworkIdentity, file *os.File) (*exec.Cmd, *os.File, error) {
	if ctx == nil || ctx.Err() != nil || account.UID == 0 || account.GID == 0 || countryCheckOwnProcess(true) != nil {
		return nil, nil, errors.New("国家数据子进程原始权限边界无效")
	}
	if _, err := countryTransferFileIdentity(file, true); err != nil {
		return nil, nil, err
	}
	// setpriv clears inheritable/ambient bits AFTER changing UID and BEFORE
	// the Go/network runtime starts. fd4 pins THIS executable; /proc/self/exe
	// inside the wrapper would incorrectly refer to setpriv itself.
	executable, err := os.Open("/proc/self/exe")
	if err != nil {
		return nil, nil, err
	}
	info, err := executable.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 256<<20 || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0005 != 0005 {
		executable.Close()
		return nil, nil, errors.New("国家数据固定程序描述符身份不可核对")
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/setpriv", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--", "/proc/self/fd/4", "--waf-country-transfer")
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "HOME=/nonexistent", "TMPDIR=/nonexistent", "GOMEMLIMIT=128MiB", "GOGC=50", "GOMAXPROCS=2"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: account.UID, Gid: account.GID, Groups: []uint32{}}}
	cmd.ExtraFiles = []*os.File{file, executable}
	cmd.WaitDelay = 2 * time.Second
	return cmd, executable, nil
}

func (s *Service) countryIsolatedDownload(in core.WAFCountryDataSelection, authority appcatalog.CountryDataAuthority) func(context.Context, geodata.CountryAuthority, string, *os.File) error {
	return func(ctx context.Context, data geodata.CountryAuthority, code string, file *os.File) error {
		if ctx == nil || ctx.Err() != nil || countryCheckOwnProcess(true) != nil || data.SHA256() != authority.Data().SHA256() || data.KeySHA256() != authority.Data().KeySHA256() {
			return errors.New("国家数据独立下载进程授权无效")
		}
		account, err := s.countryNetworkAccount(ctx)
		if err != nil {
			return err
		}
		assets, err := authority.Data().Select([]string{code})
		if err != nil {
			return err
		}
		envelope, err := json.Marshal(authority.Envelope())
		if err != nil {
			return err
		}
		raw, err := json.Marshal(countryTransferInput{1, in, code, envelope})
		if err != nil {
			return err
		}
		if _, err := decodeCountryTransfer(raw); err != nil {
			return err
		}
		outputFile, err := countryWriteOnlyHandle(file)
		if err != nil {
			return err
		}
		defer outputFile.Close()
		bounded, cancel := context.WithTimeout(ctx, 70*time.Second)
		defer cancel()
		cmd, executable, err := countryTransferCommand(bounded, account, outputFile)
		if err != nil {
			return err
		}
		defer executable.Close()
		cmd.Stdin = bytes.NewReader(raw)
		out, diagnostic := &boundedBuffer{max: 2048}, &boundedBuffer{max: 2048}
		cmd.Stdout, cmd.Stderr = out, diagnostic
		if err := cmd.Run(); err != nil || out.truncated || diagnostic.truncated {
			return errors.New("低权限国家数据子进程未完整确认；保留原文件，不重试")
		}
		var receipt countryTransferReceipt
		want := countryTransferReceipt{1, data.SHA256(), code, assets[0].SHA256, assets[0].Bytes, assets[0].Networks, account.UID, account.GID}
		canonical, encodeErr := json.Marshal(want)
		if decodeProgramQueueJSON(out.Bytes(), &receipt) != nil || receipt != want || encodeErr != nil || !bytes.Equal(out.Bytes(), append(canonical, '\n')) || bounded.Err() != nil {
			return errors.New("低权限国家数据回执与原始签名不符；未发布")
		}
		return nil // cache.publish independently opens/verifies ALL actual bytes.
	}
}
