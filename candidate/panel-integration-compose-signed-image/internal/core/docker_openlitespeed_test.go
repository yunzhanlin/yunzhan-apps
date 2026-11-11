package core

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenLiteSpeedBootstrapPreservesRotatedAdminCredentials(t *testing.T) {
	root := t.TempDir()
	lsws := filepath.Join(root, "lsws")
	admin := filepath.Join(lsws, "admin", "conf")
	pending := filepath.Join(admin, ".yunzhan-admin-initializing")
	write := func(name, value string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(value), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(lsws, "conf", "httpd_config.conf"), "vhRoot Example/\n", 0o600)
	write(filepath.Join(lsws, "Example", "html", "index.html"), "test page\n", 0o600)
	write(filepath.Join(lsws, "admin", ".conf", "htpasswd"), "admin:factory-default\n", 0o600)
	write(filepath.Join(lsws, "admin", "fcgi-bin", "admin_php"), "#!/bin/sh\nprintf 'test-hash-%s' \"$3\"\n", 0o700)
	write(filepath.Join(root, "entrypoint.sh"), "#!/bin/sh\nprintf 'server started'\n", 0o700)
	if err := os.MkdirAll(admin, 0o700); err != nil {
		t.Fatal(err)
	}
	bootstrap := strings.NewReplacer(
		"/usr/local/lsws", lsws,
		"/var/www/vhosts/cloudstack", filepath.Join(root, "site"),
		"/entrypoint.sh", filepath.Join(root, "entrypoint.sh"),
		"sed -i ", "sed -i.bak ",
	).Replace(openLiteSpeedBootstrap)
	start := func(password string) (string, error) {
		cmd := exec.Command("/bin/sh", "-c", bootstrap)
		cmd.Env = append(os.Environ(), "CLOUDSTACK_ADMIN_PASSWORD="+password)
		output, err := cmd.CombinedOutput()
		return string(output), err
	}
	requireStarted := func(password string) {
		t.Helper()
		out, err := start(password)
		if err != nil || out != "server started" {
			t.Fatalf("bootstrap: %v, %s", err, out)
		}
	}
	htpasswd := filepath.Join(admin, "htpasswd")
	requirePasswordFile := func(expected string) os.FileInfo {
		t.Helper()
		actual, err := os.ReadFile(htpasswd)
		if err != nil || string(actual) != expected {
			t.Fatalf("WebAdmin password file: %v, %q", err, actual)
		}
		info, err := os.Stat(htpasswd)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("WebAdmin password mode: %o", info.Mode().Perm())
		}
		return info
	}

	requireStarted("generated")
	requirePasswordFile("admin:test-hash-generated\n")
	if _, err := os.Lstat(pending); !os.IsNotExist(err) {
		t.Fatalf("bootstrap marker remains: %v", err)
	}
	write(htpasswd, "admin:rotated\nmaintainer:existing\n", 0o600)
	original := requirePasswordFile("admin:rotated\nmaintainer:existing\n")
	requireStarted("different-environment-value")
	after := requirePasswordFile("admin:rotated\nmaintainer:existing\n")
	if !os.SameFile(original, after) {
		t.Fatal("restart replaced the existing WebAdmin credential file")
	}
}

func TestOpenLiteSpeedTemplatePreventsDockerCopyUpOfFactoryCredentials(t *testing.T) {
	compose, err := dockerTemplate("openlitespeed", 18888)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(compose, "source: admin-conf\n        target: /usr/local/lsws/admin/conf\n        volume:\n          nocopy: true") {
		t.Fatal("Docker must leave an unused admin volume empty for first startup")
	}
}

func TestOpenLiteSpeedAdminComposeUpgradeKeepsOriginalImagePortsAndCredential(t *testing.T) {
	current, err := dockerTemplate("openlitespeed", 18888)
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.Replace(current, openLiteSpeedComposeCommand(openLiteSpeedBootstrap), openLiteSpeedComposeCommand(previousOpenLiteSpeedBootstrap), 1)
	legacy = strings.Replace(legacy, openLiteSpeedAdminVolume, previousOpenLiteSpeedAdminVolume, 1)
	next, changed := UpgradeOpenLiteSpeedAdminCompose(legacy)
	if !changed || next != current {
		t.Fatal("OpenLiteSpeed update changed more than the known bootstrap and admin volume")
	}
	if next, changed := UpgradeOpenLiteSpeedAdminCompose(current); changed || next != current {
		t.Fatal("OpenLiteSpeed update changed an already-upgraded template")
	}
	foreign := strings.Replace(legacy, dockerOpenLiteSpeedImage, "litespeedtech/openlitespeed:custom", 1)
	if next, changed := UpgradeOpenLiteSpeedAdminCompose(foreign); changed || next != foreign {
		t.Fatal("OpenLiteSpeed update adopted a different image")
	}
	if OpenLiteSpeedAdminCommandVersion(dockerOpenLiteSpeedImage, []string{previousOpenLiteSpeedBootstrap}) != 1 ||
		OpenLiteSpeedAdminCommandVersion(dockerOpenLiteSpeedImage, []string{openLiteSpeedBootstrap}) != 2 ||
		OpenLiteSpeedAdminCommandVersion(dockerOpenLiteSpeedImage, []string{openLiteSpeedBootstrap, "foreign"}) != 0 {
		t.Fatal("OpenLiteSpeed runtime bootstrap revisions are ambiguous")
	}
}
