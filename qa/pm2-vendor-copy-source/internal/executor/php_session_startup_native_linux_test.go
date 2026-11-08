//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"mime/multipart"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Explicit opt-in requires all four installed reviewed PHP security releases,
// their Redis extensions, and an existing non-root site account. Only temporary
// private FPM pools are started; no website binding, service or file is changed.
func TestPHPSessionStartupRealFPM(t *testing.T) {
	id := os.Getenv("PANEL_PHP_SESSION_ACCEPT_SITE")
	if id == "" {
		t.Skip("installed PHP security releases and isolated site account required")
	}
	if os.Geteuid() != 0 || !core.ValidID(id) {
		t.Fatal("root and exact existing site identity required")
	}
	account, err := user.Lookup(siteUser(id))
	if err != nil || account.Uid == "0" || account.Gid == "0" {
		t.Fatal("non-root site account required", err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range runtimecatalog.PHPSecurity20261021 {
		if _, err := LoadRuntime(r.ID); err != nil {
			t.Fatal(r.ID, err)
		}
		for _, configured := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/configured=%v", r.ID, configured), func(t *testing.T) {
				site := core.Site{ID: id, PHPVersionID: r.ID}
				if configured {
					settings := core.DefaultPHPSettings()
					settings.MemoryMB = 256
					settings.Extensions = []string{"redis-6.3.0"}
					site.Settings.PHP = &settings
				}
				testPHPSessionPrivatePool(t, site, r, uid, gid, false)
			})
		}
	}
	// A positive control proves the multipart fixture actually reaches PHP's
	// pre-script session-upload-progress path when the setting is enabled.
	r := runtimecatalog.PHPSecurity20261021[0]
	t.Run("enabled-positive-control-rejected-by-candidate-probe", func(t *testing.T) {
		testPHPSessionPrivatePool(t, core.Site{ID: id, PHPVersionID: r.ID}, r, uid, gid, true)
	})
}

func testPHPSessionPrivatePool(t *testing.T, site core.Site, r runtimecatalog.Release, uid, gid int, enableControl bool) {
	t.Helper()
	// A short path keeps the native Unix socket below sockaddr_un's limit.
	// /tmp is traversable by the existing non-root worker; Go's private parent
	// for t.TempDir would block the worker before PHP can read the probe.
	dir, err := os.MkdirTemp("/tmp", "panel-php-session-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"public", "private"} {
		path := filepath.Join(dir, name)
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if name == "public" {
			// The worker may read the fixed scripts, never replace them while
			// this Root fixture is creating or verifying files.
			if err := os.Chmod(path, 0755); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := os.Chown(path, uid, gid); err != nil {
				t.Fatal(err)
			}
		}
	}
	socket := filepath.Join(dir, "fpm.sock")
	config := phpPoolConfiguration(site, dir)
	config = strings.Replace(config, "error_log = syslog", "error_log = "+filepath.Join(dir, "fpm.log"), 1)
	config = strings.Replace(config, poolSocket(site), socket, 1)
	config += "php_admin_value[upload_tmp_dir] = " + filepath.Join(dir, "private") + "\n"
	cfg := filepath.Join(dir, "fpm.conf")
	if err := os.WriteFile(cfg, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(dir, "public", "probe.php")
	if err := writePHPSessionNativeScript(probe, []byte(phpProbeScript(site))); err != nil {
		t.Fatal(err)
	}
	upload := filepath.Join(dir, "public", "upload.php")
	script := `<?php header('Content-Type: application/json'); echo json_encode(['enabled'=>filter_var(ini_get('session.upload_progress.enabled'),FILTER_VALIDATE_BOOL),'files'=>count($_FILES),'error'=>$_FILES['sample']['error']??-1,'sha256'=>isset($_FILES['sample']['tmp_name'])?hash_file('sha256',$_FILES['sample']['tmp_name']):'']);`
	if err := writePHPSessionNativeScript(upload, []byte(script)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	args, err := phpExtensionArgs(ctx, r, site.Settings.PHP)
	if err != nil {
		t.Fatal(err)
	}
	if enableControl {
		args = append(args, "-d", "session.upload_progress.enabled=1")
	}
	args = append(args, "-d", "session.upload_progress.cleanup=0", "-d", "session.upload_progress.freq=1", "-d", "session.upload_progress.min_freq=0", "--nodaemonize", "--fpm-config", cfg)
	cmd := exec.CommandContext(ctx, r.FPM(), args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGQUIT)
		select {
		case err := <-done:
			if err != nil {
				t.Error("temporary FPM exit", err, output.String())
			}
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			t.Error("temporary FPM did not stop normally")
		}
	}()
	want := phpProbeExpected(site)
	if enableControl {
		want = strings.TrimSuffix(want, "|0") + "|1"
	}
	if err := fastCGIProbe(ctx, socket, probe, want); err != nil {
		actual, readErr := phpSessionNativeFastCGI(socket, [][2]string{{"SCRIPT_FILENAME", probe}, {"SCRIPT_NAME", "/probe.php"}, {"REQUEST_METHOD", "GET"}, {"SERVER_PROTOCOL", "HTTP/1.1"}, {"SERVER_NAME", "localhost"}, {"REMOTE_ADDR", "127.0.0.1"}, {"GATEWAY_INTERFACE", "CGI/1.1"}}, nil)
		log, _ := os.ReadFile(filepath.Join(dir, "fpm.log"))
		t.Fatalf("actual FPM parameters: %v; response=%q read=%v FPM=%q", err, actual, readErr, log)
	}
	if enableControl && fastCGIOnce(ctx, socket, probe, phpProbeExpected(site)) == nil {
		t.Fatal("candidate accepted an enabled upload-progress setting")
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("PHP_SESSION_UPLOAD_PROGRESS", "native-protection-probe"); err != nil {
		t.Fatal(err)
	}
	part, err := writer.CreateFormFile("sample", "sample.txt")
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("normal-upload\n"), 128)
	if _, err := part.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	sessionID := core.ID()
	params := [][2]string{{"SCRIPT_FILENAME", upload}, {"SCRIPT_NAME", "/upload.php"}, {"REQUEST_METHOD", "POST"}, {"CONTENT_TYPE", writer.FormDataContentType()}, {"CONTENT_LENGTH", strconv.Itoa(body.Len())}, {"HTTP_COOKIE", "PHPSESSID=" + sessionID}, {"SERVER_PROTOCOL", "HTTP/1.1"}, {"SERVER_NAME", "localhost"}, {"REMOTE_ADDR", "127.0.0.1"}, {"GATEWAY_INTERFACE", "CGI/1.1"}}
	response, err := phpSessionNativeFastCGI(socket, params, body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var actual struct {
		Enabled      bool
		Files, Error int
		SHA256       string
	}
	if err := json.Unmarshal(response, &actual); err != nil {
		t.Fatal("actual multipart response", string(response), err)
	}
	digest := sha256.Sum256(payload)
	if actual.Enabled != enableControl || actual.Files != 1 || actual.Error != 0 || actual.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("normal file upload or startup protection failed", actual)
	}
	session, err := readPHPSessionNativeProgress(dir, sessionID, uid)
	if enableControl {
		if err != nil || !bytes.Contains(session, []byte("native-protection-probe")) {
			t.Fatal("positive control did not exercise pre-script session progress", err)
		}
	} else if !os.IsNotExist(err) {
		t.Fatal("disabled progress wrote a session before the script", err)
	}
	if after, err := os.ReadFile(cfg); err != nil || string(after) != config {
		t.Fatal("startup protection rewrote FPM configuration", err)
	}
	t.Logf("actual PHP %s: configured=%v enabled-control=%v, non-root account %d:%d, FPM parameters and normal multipart upload verified", r.Version, site.Settings.PHP != nil, enableControl, uid, gid)
}

func writePHPSessionNativeScript(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(0644)
	}
	return errors.Join(err, f.Close())
}

func readPHPSessionNativeProgress(dir, id string, uid int) ([]byte, error) {
	if !core.ValidID(id) {
		return nil, errors.New("invalid native session identity")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.OpenFile("private/sess_"+id, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil {
		return nil, err
	}
	native, ok := s.Sys().(*syscall.Stat_t)
	if !s.Mode().IsRegular() || !ok || native.Uid != uint32(uid) || native.Nlink != 1 {
		return nil, errors.New("unexpected native session file ownership or type")
	}
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if len(data) > 65536 {
		return nil, errors.New("native session file exceeds limit")
	}
	return data, err
}

func TestPHPSessionNativeScriptRejectsLinksAndExistingFiles(t *testing.T) {
	for _, link := range []bool{false, true} {
		dir := t.TempDir()
		canary := filepath.Join(dir, "canary")
		if err := os.WriteFile(canary, []byte("unchanged"), 0600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "probe.php")
		if link {
			if err := os.Symlink(canary, path); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
			t.Fatal(err)
		}
		if writePHPSessionNativeScript(path, []byte("replacement")) == nil {
			t.Fatal("native fixture overwrote an existing file or link")
		}
		data, err := os.ReadFile(canary)
		s, statErr := os.Stat(canary)
		if err != nil || statErr != nil || string(data) != "unchanged" || s.Mode().Perm() != 0600 {
			t.Fatal("native fixture changed the outside canary", err, statErr)
		}
	}
}

func TestPHPSessionNativeProgressRejectsLinksAndOversize(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "private"), 0700); err != nil {
		t.Fatal(err)
	}
	id := core.ID()
	path := filepath.Join(dir, "private", "sess_"+id)
	outside := filepath.Join(t.TempDir(), "canary")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if data, err := readPHPSessionNativeProgress(dir, id, os.Geteuid()); err == nil || data != nil {
		t.Fatal("native session read followed a link")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), 65537), 0600); err != nil {
		t.Fatal(err)
	}
	if data, err := readPHPSessionNativeProgress(dir, id, os.Geteuid()); err == nil || data != nil {
		t.Fatal("native session read accepted oversized data")
	}
}

func phpSessionNativeFastCGI(socket string, params [][2]string, body []byte) ([]byte, error) {
	conn, err := net.DialTimeout("unix", socket, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	write := func(kind byte, data []byte) error {
		if len(data) > 65535 {
			return fmt.Errorf("test FastCGI record exceeds limit")
		}
		_, err := io.Copy(conn, bytes.NewReader(append([]byte{1, kind, 0, 1, byte(len(data) >> 8), byte(len(data)), 0, 0}, data...)))
		return err
	}
	var encoded bytes.Buffer
	for _, pair := range params {
		for _, value := range pair {
			if len(value) < 128 {
				encoded.WriteByte(byte(len(value)))
			} else {
				var size [4]byte
				binary.BigEndian.PutUint32(size[:], uint32(len(value))|0x80000000)
				encoded.Write(size[:])
			}
		}
		encoded.WriteString(pair[0])
		encoded.WriteString(pair[1])
	}
	for _, record := range []struct {
		kind byte
		data []byte
	}{{1, []byte{0, 1, 0, 0, 0, 0, 0, 0}}, {4, encoded.Bytes()}, {4, nil}, {5, body}, {5, nil}} {
		if err := write(record.kind, record.data); err != nil {
			return nil, err
		}
	}
	var stdout bytes.Buffer
	for n := 0; n < 100; n++ {
		var header [8]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return nil, err
		}
		if header[0] != 1 || header[2] != 0 || header[3] != 1 {
			return nil, fmt.Errorf("invalid test FastCGI response")
		}
		data := make([]byte, int(binary.BigEndian.Uint16(header[4:6])))
		if _, err := io.ReadFull(conn, data); err != nil {
			return nil, err
		}
		if _, err := io.CopyN(io.Discard, conn, int64(header[6])); err != nil {
			return nil, err
		}
		if header[1] == 6 {
			stdout.Write(data)
			if stdout.Len() > 65536 {
				return nil, fmt.Errorf("test FastCGI output exceeds limit")
			}
		}
		if header[1] == 3 {
			_, result, ok := strings.Cut(stdout.String(), "\r\n\r\n")
			if !ok {
				return nil, fmt.Errorf("missing test FastCGI response headers")
			}
			return []byte(result), nil
		}
	}
	return nil, fmt.Errorf("test FastCGI response record limit")
}
