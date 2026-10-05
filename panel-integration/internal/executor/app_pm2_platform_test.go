package executor

import "testing"

func TestPM2DoesNotUseObsoleteJammySystemNode(t *testing.T) {
	if pm2NodeBinaryOn("ubuntu-22.04") == "/usr/bin/node" {
		t.Fatal("PM2 7 requires Node >=18")
	}
	for _, platform := range []string{"debian-12", "debian-13", "ubuntu-24.04", "ubuntu-26.04"} {
		if pm2NodeBinaryOn(platform) != "/usr/bin/node" {
			t.Fatal("must preserve existing PM2 runtime on", platform)
		}
	}
}
