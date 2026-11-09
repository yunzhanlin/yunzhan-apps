//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"local/panel/internal/runtimecatalog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This opt-in private fixture runs the genuine pinned configure, not a patched
// script or an installed runtime. Its archive and output live only in the
// controller's bind-mounted scratch directory. The normal install/API path
// must still be accepted separately after the programme upgrade.
func TestRuntimeCompilerNativeOfficialPHPConfigureReapsExitedProbe(t *testing.T) {
	if os.Getenv("PANEL_QA_RUNTIME_PHP_CONFIGURE_NATIVE") != "1" {
		t.Skip("explicit private pinned PHP source and confined native compiler service required")
	}
	identity := nativeRuntimeCompilerIdentity(t)
	if os.Geteuid() != 0 || identity["CapEff"] != "00000000000000e5" || identity["CapBnd"] != "00000000000000e5" || identity["NoNewPrivs"] != "1" {
		t.Fatal("official configure fixture lacks the closed native supervisor")
	}
	r, ok := runtimecatalog.Find("php-8.4.27")
	if !ok || runtimecatalog.RuntimeInstallAdmission(r) != nil {
		t.Fatal("approved exact official PHP release missing")
	}
	const fixture = "/run/panel-runtime-collection24amv"
	archive := filepath.Join(fixture, "php-8.4.27.tar.gz")
	f, err := os.OpenFile(archive, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	st, err := f.Stat()
	if err != nil || !runtimeBuildPrivateFile(st) || st.Size() != 22708176 {
		f.Close()
		t.Fatal("official archive identity changed", err)
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	f.Close()
	if err != nil || hex.EncodeToString(h.Sum(nil)) != r.SHA256 {
		t.Fatal("official archive does not match the normal release pin", err)
	}
	work := filepath.Join(fixture, "official-configure-work")
	if err := os.Mkdir(work, 0755); err != nil {
		t.Fatal(err)
	}
	if err := extractSource(archive, work); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	if _, err := RunCommand(ctx, "/usr/bin/chown", "-R", "panel-build:panel-build", work); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(work, "php-8.4.27")
	log := filepath.Join(fixture, "official-configure.log")
	// Exact normal PHP installation feature set; configure cannot write the
	// installed prefix in this private read-only-system fixture.
	flags := []string{"--prefix=" + r.Prefix(), "--with-config-file-path=" + r.Prefix() + "/etc", "--with-config-file-scan-dir=" + r.Prefix() + "/etc/conf.d", "--enable-fpm", "--disable-cgi", "--disable-phpdbg", "--without-pear", "--with-openssl", "--with-curl", "--with-zlib", "--enable-mbstring", "--enable-bcmath", "--enable-sockets", "--enable-pcntl", "--enable-exif", "--enable-ftp", "--with-mysqli=mysqlnd", "--with-pdo-mysql=mysqlnd", "--with-zip", "--enable-intl", "--enable-gd", "--with-jpeg", "--with-freetype"}
	if err := buildCommand(ctx, source, log, source+"/configure", flags...); err != nil {
		t.Fatal("actual official configure did not close all exited descendants", err)
	}
	data, err := os.ReadFile(log)
	if err != nil || !strings.Contains(string(data), "Thank you for using PHP.") || !strings.Contains(string(data), "compiler-collection-v2 member_snapshots=0 ") || !strings.Contains(string(data), "compiler-wait pid=") {
		t.Fatal("complete real configure/collection witness missing", err)
	}
	if st, err := os.Stat(filepath.Join(source, "Makefile")); err != nil || !st.Mode().IsRegular() || st.Size() == 0 {
		t.Fatal("configure did not generate the ordinary native Makefile", err)
	}
	if empty, err := compilerHasNoChildren(); err != nil || !empty {
		t.Fatal("official configure left a live or unreaped child", err)
	}
	logSHA := sha256.Sum256(data)
	proof, err := json.MarshalIndent(map[string]any{"passed": true, "official_release": r.ID, "source_sha256": r.SHA256, "configure_log_sha256": hex.EncodeToString(logSHA[:]), "direct_command_success": true, "all_owned_descendants_fully_reaped": true, "runtime_built_or_installed": false, "scope": "Genuine pinned PHP configure under the ordinary confined native compiler only; no make, runtime publication, app update or site migration."}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(fixture, "official-configure-proof.json"), proof, 0600); err != nil {
		t.Fatal(err)
	}
}
