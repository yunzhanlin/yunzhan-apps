//go:build linux

package executor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// PRIVATE test executable only. The fixture must independently create fresh
// network, PID AND mount namespaces before the fixed host socket pathname may
// resolve to its own daemon. This never installs or updates an application.
func TestOwnedIntrusionScalarMutationNative(t *testing.T) {
	if os.Getenv("PANEL_OWNED_INTRUSION_SCALAR_FIXTURE") != "24bhna" {
		t.Skip("explicit owned triple-namespace fixture required; not installed acceptance")
	}
	if os.Geteuid() != 0 {
		t.Fatal("owned root namespace required")
	}
	for _, kind := range []string{"net", "pid", "mnt"} {
		host, err := strconv.ParseUint(os.Getenv("PANEL_OWNED_HOST_"+strings.ToUpper(kind)+"_INODE"), 10, 64)
		if err != nil || host == 0 {
			t.Fatal("original host namespace missing", kind)
		}
		info, err := os.Stat("/proc/self/ns/" + kind)
		if err != nil || info.Sys().(*syscall.Stat_t).Ino == host {
			t.Fatal("host namespace forbidden", kind, err)
		}
	}
	host, err := os.ReadFile("/etc/hostname")
	if err != nil || strings.TrimSpace(string(host)) != "lima-panel-compat-ubuntu24" && strings.TrimSpace(string(host)) != "lima-panel-store-apps-debian13" {
		t.Fatal("not declared owned QA VM")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) != os.Getenv("PANEL_OWNED_INTRUSION_BOOT") {
		t.Fatal("original boot changed")
	}
	var input struct {
		PID            string `json:"pid"`
		StartTicks     string `json:"start_ticks"`
		Field          string `json:"field"`
		Action         string `json:"action"`
		From           string `json:"from"`
		To             string `json:"to"`
		ExpectRejected bool   `json:"expect_rejected"`
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1025))
	if err != nil || len(raw) > 1024 || decodeProgramQueueJSON(raw, &input) != nil {
		t.Fatal("fixed bounded native scalar request required")
	}
	change := intrusionScalarChange{Key: input.Field, From: input.From, To: input.To}
	args, err := intrusionScalarMutationArgs(input.PID, input.StartTicks, input.Action, change)
	if err != nil {
		t.Fatal("nonfixed scalar request refused", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	result, runErr := RunCommand(ctx, "/usr/bin/python3", args...)
	if input.ExpectRejected {
		if runErr == nil || ctx.Err() != nil || strings.TrimSpace(result) != "{\"format\":0}" {
			t.Fatal("expected third-state refusal not observed", runErr)
		}
		t.Log("OWNED_INTRUSION_SCALAR_REJECTED_WITHOUT_RETRY")
		return
	}
	if runErr != nil {
		t.Fatal("one-shot scalar outcome unknown; no retry", runErr)
	}
	receipt, err := intrusionScalarMutationDecode([]byte(result), input.PID, input.StartTicks, input.Action, change)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("OWNED_INTRUSION_SCALAR_RECEIPT:" + base64.StdEncoding.EncodeToString(encoded))
}
