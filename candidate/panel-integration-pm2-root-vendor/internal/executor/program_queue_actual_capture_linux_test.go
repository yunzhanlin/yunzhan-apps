//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// QA-only observation, not an installer, recovery or an admission exemption.
// The production parser receives each exact original systemctl response once;
// no later successful query replaces the original rejected observation.
func TestProgramUpgradeNativeQueueActualReadOnlyObservation(t *testing.T) {
	scope := os.Getenv("PANEL_QA_QUEUE_NATIVE_CAPTURE")
	if scope == "" {
		t.Skip("explicit owned private native read-only capture required")
	}
	if os.Geteuid() != 0 || !regexp.MustCompile(`^/var/lib/panel-executor/waf-queue24bikf-amd64\.[a-f0-9]{32}$`).MatchString(scope) {
		t.Fatal("invalid native capture scope")
	}
	if err := statisticsGeoParents(scope); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(scope)
	if err != nil || !moduleRecordInfo(info, true, false) {
		t.Fatal("capture scope is not an owned private directory", err)
	}
	type call struct {
		At      string   `json:"at"`
		Program string   `json:"program"`
		Args    []string `json:"args"`
		Output  string   `json:"output"`
		Error   string   `json:"error"`
	}
	type observation struct {
		Attempt int    `json:"attempt"`
		Calls   []call `json:"calls"`
		Error   string `json:"error"`
	}
	type report struct {
		ReadOnly                        bool          `json:"read_only"`
		ProductionPerObservationSeconds int           `json:"production_per_observation_seconds"`
		Rejected                        bool          `json:"rejected"`
		Observations                    []observation `json:"observations"`
		ApplicationOrInstallAcceptance  bool          `json:"application_or_install_acceptance"`
	}
	out := report{ReadOnly: true, ProductionPerObservationSeconds: 5, Observations: []observation{}}
	end := time.Now().Add(70 * time.Second)
	for n := 0; n < 60 && time.Now().Before(end); n++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		one := observation{Attempt: n + 1, Calls: []call{}}
		err := checkProgramUpgradeNativeUnits(ctx, func(ctx context.Context, name string, args ...string) (string, error) {
			text, e := programQueueCommand(ctx, name, args...)
			c := call{At: time.Now().UTC().Format(time.RFC3339Nano), Program: name, Args: append([]string{}, args...), Output: text}
			if e != nil {
				c.Error = e.Error()
			}
			one.Calls = append(one.Calls, c)
			return text, e
		})
		cancel()
		if err != nil {
			one.Error = ProgramUpgradeQueueFailureText(err)
			out.Rejected = true
		}
		out.Observations = append(out.Observations, one)
		if err != nil {
			break
		}
		time.Sleep(time.Second)
	}
	raw, err := json.Marshal(out)
	if err != nil || len(raw) == 0 || len(raw) > 1<<20 {
		t.Fatal("native capture exceeds fixed private budget", err)
	}
	file, err := os.OpenFile(filepath.Join(scope, "native-queue-observation.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write(raw); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err = file.Sync(); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	t.Log(fmt.Sprintf("read_only_native_original_command_capture=true observations=%d rejection_observed=%t sha256=%s original_per_observation_deadline_seconds=5 application_or_install_acceptance=false", len(out.Observations), out.Rejected, hex.EncodeToString(digest[:])))
}
