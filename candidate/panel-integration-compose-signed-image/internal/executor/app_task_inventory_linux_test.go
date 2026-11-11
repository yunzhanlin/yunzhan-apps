//go:build linux

package executor

import (
	"context"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestTaskCronInventoryOnlyReturnsScheduleAndOwner(t *testing.T) {
	out := taskInventory{View: "cron"}
	out.cronFile("/etc/cron.d/task-fixture", []byte("# test\nTOKEN=secret\n30 4 * * * root /opt/backup --key secret\n@reboot daemon /opt/start\n"))
	if out.Partial || len(out.Rows) != 2 {
		t.Fatal("valid cron entries did not produce two rows")
	}
	for _, row := range out.Rows {
		if len(row) != 3 || row["source"] != "/etc/cron.d/task-fixture" || row["timing"] == "" || row["account"] == "" {
			t.Fatal("incomplete schedule or unexpected command data", row)
		}
		for _, field := range row {
			if strings.Contains(field, "secret") || strings.Contains(field, "/opt/") {
				t.Fatal("private cron command or variable appeared in the inventory")
			}
		}
	}
}

func TestTaskInventoryReadsActualLinuxSources(t *testing.T) {
	if os.Getenv("PANEL_TASK_INVENTORY_NATIVE") != "isolated-arm64" {
		t.Skip("requires an explicit isolated native Linux host")
	}
	host, err := os.Hostname()
	if err != nil || host != "lima-panel-openlitespeed-c92r2-arm64-qa" || os.Geteuid() != 0 {
		t.Fatal("unexpected native test host")
	}
	service := New(Config{})
	ctx := context.Background()
	for _, view := range []string{"services", "startup"} {
		out := taskInventory{View: view}
		if err := service.taskSystemdInventory(ctx, &out); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, row := range out.Rows {
			if row["name"] == "panel.service" {
				found = view == "services" && row["active_state"] == "active" ||
					view == "startup" && row["startup_state"] == "enabled"
			}
		}
		if !found {
			t.Fatal("the actual panel service was missing or had an unexpected state", view)
		}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	networks := taskInventory{View: "network"}
	if err := service.taskNetworkInventory(ctx, &networks); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(networks.Rows, func(row map[string]string) bool {
		return row["protocol"] == "tcp" && row["state"] == "LISTEN" && row["local"] == listener.Addr().String()
	}) {
		t.Fatal("the independent TCP listener did not appear in the real inventory")
	}
	accounts := taskInventory{View: "accounts"}
	if err := service.taskLocalAccounts(&accounts); err != nil {
		t.Fatal(err)
	}
	if len(accounts.Rows) == 0 || accounts.Rows[0]["name"] != "root" || accounts.Rows[0]["uid"] != "0" {
		t.Fatal("expected the real local root account")
	}
	cron := taskInventory{View: "cron"}
	if err := service.taskCronInventory(&cron); err != nil {
		t.Fatal(err)
	}
	ssh := taskInventory{View: "ssh"}
	if err := service.taskSSHInventory(ctx, &ssh); err != nil {
		t.Fatal(err)
	}
	t.Logf("Real services, startup, TCP listener, %d local accounts, %d system cron entries and %d SSH sessions", len(accounts.Rows), len(cron.Rows), len(ssh.Rows))
}
