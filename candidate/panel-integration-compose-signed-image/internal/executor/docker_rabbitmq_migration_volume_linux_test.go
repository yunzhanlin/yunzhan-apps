//go:build linux

package executor

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRabbitMQMigrationVolumeRequiresPrivateDockerOwnedPath(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires native root")
	}
	const name = "panel_rabbitmq_0123456789abcdef0123456789abcdef"
	base := t.TempDir()
	parent := filepath.Join(base, "volumes", name)
	path := filepath.Join(parent, "_data")
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	volume := rabbitMQMigrationVolume{Name: name, Mountpoint: path}
	original, err := openRabbitMQMigrationVolume(base, volume)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()

	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	if untrusted, err := openRabbitMQMigrationVolume(base, volume); err == nil {
		untrusted.Close()
		t.Fatal("accepted a writable parent around the Docker data volume")
	}
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chown(path, 100, 101); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chmod(path, 01777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0710); err != nil {
		t.Fatal(err)
	}
	legacy, err := openRabbitMQMigrationVolume(base, volume)
	if err != nil {
		t.Fatalf("private Docker data root did not admit the official legacy volume: %v", err)
	}
	legacy.Close()
	if err := os.Chmod(base, 0711); err != nil {
		t.Fatal(err)
	}
	if exposed, err := openRabbitMQMigrationVolume(base, volume); err == nil {
		exposed.Close()
		t.Fatal("accepted a world-traversable Docker data root around a legacy sticky volume")
	}
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}

	alternate := filepath.Join(parent, "different")
	if err := os.Rename(path, alternate); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(alternate, path); err != nil {
		t.Fatal(err)
	}
	if unsafe, err := openRabbitMQMigrationVolume(base, volume); err == nil {
		unsafe.Close()
		t.Fatal("followed a replacement link in the volume mount point")
	}
	linkRoot := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(base, linkRoot); err != nil {
		t.Fatal(err)
	}
	volume.Mountpoint = filepath.Join(linkRoot, "volumes", name, "_data")
	if unsafe, err := openRabbitMQMigrationVolume(linkRoot, volume); err == nil {
		unsafe.Close()
		t.Fatal("followed a link in the Docker root")
	}
}
