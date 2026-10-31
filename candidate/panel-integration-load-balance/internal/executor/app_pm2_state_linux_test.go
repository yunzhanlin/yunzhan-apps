//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func pm2TestState(active, boot string) pm2UnitState {
	v := pm2UnitState{LoadState: "loaded", ActiveState: active, SubState: "dead", MainPID: "0", UnitFileState: boot}
	if active == "active" {
		v.SubState, v.MainPID, v.InvocationID = "running", "101", strings.Repeat("a", 32)
	} else if active == "failed" {
		v.SubState = "failed"
	}
	return v
}

func pm2TestStateText(v pm2UnitState) string {
	return fmt.Sprintf("LoadState=%s\nMainPID=%s\nInvocationID=%s\nActiveState=%s\nSubState=%s\nUnitFileState=%s\n", v.LoadState, v.MainPID, v.InvocationID, v.ActiveState, v.SubState, v.UnitFileState)
}

func TestPM2UnitStateRejectsIncompleteAndTransitionalObservations(t *testing.T) {
	valid := pm2TestStateText(pm2TestState("inactive", "disabled"))
	for name, output := range map[string]string{
		"transition": strings.Replace(valid, "ActiveState=inactive", "ActiveState=activating", 1),
		"masked":     strings.Replace(valid, "UnitFileState=disabled", "UnitFileState=masked", 1),
		"missing":    strings.Replace(valid, "InvocationID=\n", "UnknownField=\n", 1),
		"duplicate":  valid + "ActiveState=inactive\n",
		"bad_pid":    strings.Replace(valid, "MainPID=0", "MainPID=-1", 1),
		"live_pid":   strings.Replace(valid, "MainPID=0", "MainPID=231", 1),
		"bad_id":     strings.Replace(valid, "InvocationID=\n", "InvocationID=unknown\n", 1),
		"not_loaded": strings.Replace(valid, "LoadState=loaded", "LoadState=not-found", 1),
	} {
		t.Run(name, func(t *testing.T) {
			s := New(Config{Run: func(context.Context, string, ...string) (string, error) { return output, nil }})
			if _, err := s.readPM2UnitState(context.Background(), "panel-pm2@qa-state.service"); err == nil {
				t.Fatal("incomplete service was accepted as stopped")
			}
		})
	}
	for _, state := range []pm2UnitState{pm2TestState("active", "enabled"), pm2TestState("inactive", "disabled"), pm2TestState("failed", "enabled")} {
		s := New(Config{Run: func(context.Context, string, ...string) (string, error) { return pm2TestStateText(state), nil }})
		got, err := s.readPM2UnitState(context.Background(), "panel-pm2@qa-state.service")
		if err != nil || got != state {
			t.Fatal(got, err)
		}
	}
}

func pm2StateAppFixture(t *testing.T) (*Service, pm2App, string) {
	t.Helper()
	s, site, _ := appReliabilityFixture(t)
	fixtureWrite(t, s, site, "app.js", "require('node:http');\n")
	app := pm2App{ID: "qa-stopped-state", SiteID: site, Entry: "app.js", Port: 24431, Instances: 1, MemoryMB: 128, Revision: 7}
	secret := "private-environment-before-state-save"
	if err := s.patchPM2Environment(&app, map[string]*string{"TOKEN": &secret}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.moduleDir("pm2-manager"), "apps", app.ID+".json")
	if err := moduleWrite(path, app); err != nil {
		t.Fatal(err)
	}
	return s, app, path
}

func TestPM2StoppedUpdateSavesEncryptedConfigWithoutStarting(t *testing.T) {
	s, app, path := pm2StateAppFixture(t)
	shows := 0
	s.Config.Run = func(_ context.Context, command string, args ...string) (string, error) {
		if command != "/usr/bin/systemctl" || len(args) != 3 || args[0] != "show" {
			t.Fatalf("stopped save tried to start or probe a service: %s %v", command, args)
		}
		shows++
		return pm2TestStateText(pm2TestState("inactive", "disabled")), nil
	}
	secret := "replacement-private-environment"
	result, err := s.modulePM2(context.Background(), "update", core.AppModuleInput{ResourceID: app.ID, ExpectedRevision: app.Revision, MemoryMB: 192, EnvironmentPatch: map[string]*string{"TOKEN": &secret}})
	if err != nil {
		t.Fatal(err)
	}
	report := result.(map[string]any)
	if shows != 2 || report["preserved_stopped"] != true || report["runtime_validated"] != false || report["boot_enabled"] != false {
		t.Fatal(report, shows)
	}
	var after pm2App
	if err := moduleRead(path, &after); err != nil || after.Revision != 8 || after.MemoryMB != 192 || after.SiteID != app.SiteID || after.Entry != app.Entry {
		t.Fatal(after, err)
	}
	environment, err := s.readPM2Environment(after)
	if err != nil || environment["TOKEN"] != secret {
		t.Fatal("encrypted settings did not survive stopped save", err)
	}
	raw, _ := os.ReadFile(path)
	response, _ := json.Marshal(result)
	if strings.Contains(string(raw), secret) || strings.Contains(string(response), secret) || strings.Contains(string(response), "environment_cipher") {
		t.Fatal("environment leaked during stopped save")
	}
}

func TestPM2UpdateRefusesChangedServiceBeforeSaving(t *testing.T) {
	s, app, path := pm2StateAppFixture(t)
	before, _ := os.ReadFile(path)
	shows := 0
	s.Config.Run = func(_ context.Context, command string, args ...string) (string, error) {
		if command != "/usr/bin/systemctl" || args[0] != "show" {
			t.Fatal("changed service caused a mutation", command, args)
		}
		shows++
		state := pm2TestState("inactive", "disabled")
		if shows == 2 {
			state = pm2TestState("active", "enabled")
		}
		return pm2TestStateText(state), nil
	}
	_, err := s.modulePM2(context.Background(), "update", core.AppModuleInput{ResourceID: app.ID, ExpectedRevision: app.Revision, MemoryMB: 192})
	after, _ := os.ReadFile(path)
	if err == nil || shows != 2 || string(before) != string(after) {
		t.Fatal("service change was not refused before persistence", err, shows)
	}
}

func TestPM2UnknownObservationDoesNotReportBootDisabled(t *testing.T) {
	s, _, _ := pm2StateAppFixture(t)
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		return "", errors.New("systemd observation unavailable")
	}
	result, err := s.modulePM2(context.Background(), "run", core.AppModuleInput{})
	if err != nil {
		t.Fatal(err)
	}
	apps := result.(map[string]any)["apps"].([]any)
	if len(apps) != 1 {
		t.Fatal(apps)
	}
	row := apps[0].(map[string]any)
	if row["state"] != "unknown" || row["state_known"] != false || row["boot_enabled"] != nil || row["error"] == "" {
		t.Fatal("unknown observation was presented as stopped or boot disabled", row)
	}
	public, _ := json.Marshal(row)
	if strings.Contains(string(public), "environment_cipher") || strings.Contains(string(public), "private-environment-before-state-save") {
		t.Fatal("unknown report exposed environment")
	}
}

func TestPM2ActiveUpdateRestoresOldEncryptedConfigAfterRestartFailure(t *testing.T) {
	s, app, path := pm2StateAppFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	app.Port = listener.Addr().(*net.TCPAddr).Port
	if err := moduleWrite(path, app); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	restarts := 0
	s.Config.Run = func(_ context.Context, command string, args ...string) (string, error) {
		if command != "/usr/bin/systemctl" {
			t.Fatal(command)
		}
		switch args[0] {
		case "show":
			return pm2TestStateText(pm2TestState("active", "enabled")), nil
		case "restart":
			restarts++
			if restarts == 1 {
				return "", errors.New("injected candidate process failure")
			}
		case "is-active":
			return "active\n", nil
		default:
			t.Fatal("active update changed boot policy", args)
		}
		return "", nil
	}
	secret := "candidate-secret-must-roll-back"
	_, err = s.modulePM2(context.Background(), "update", core.AppModuleInput{ResourceID: app.ID, ExpectedRevision: app.Revision, MemoryMB: 192, EnvironmentPatch: map[string]*string{"TOKEN": &secret}})
	after, _ := os.ReadFile(path)
	if err == nil || restarts != 2 || string(before) != string(after) {
		t.Fatal("failed active update lost original encrypted manifest", err, restarts)
	}
	var restored pm2App
	if err := json.Unmarshal(after, &restored); err != nil {
		t.Fatal(err)
	}
	environment, err := s.readPM2Environment(restored)
	if err != nil || environment["TOKEN"] != "private-environment-before-state-save" {
		t.Fatal("old secret was not readable after rollback", err)
	}
}

func TestPM2ControlStopDisablesBootAndExplicitStartEnablesIt(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	state := pm2TestState("active", "enabled")
	commands := []string{}
	s := New(Config{Run: func(_ context.Context, _ string, args ...string) (string, error) {
		commands = append(commands, strings.Join(args, " "))
		switch args[0] {
		case "show":
			return pm2TestStateText(state), nil
		case "disable":
			if len(args) != 3 || args[1] != "--now" {
				t.Fatal("stop must also disable boot", args)
			}
			state = pm2TestState("inactive", "disabled")
		case "enable":
			if len(args) != 3 || args[1] != "--now" {
				t.Fatal("explicit start must enable boot", args)
			}
			state = pm2TestState("active", "enabled")
		case "is-active":
			return "active\n", nil
		default:
			t.Fatal(args)
		}
		return "", nil
	}})
	app := pm2App{ID: "qa-state", Port: listener.Addr().(*net.TCPAddr).Port}
	for _, action := range []string{"stop", "start"} {
		result, err := s.controlPM2(context.Background(), app, action, "panel-pm2@qa-state.service")
		if err != nil || result.(map[string]any)["boot_enabled"] != (action == "start") {
			t.Fatal(result, err)
		}
	}
	if !strings.Contains(strings.Join(commands, "\n"), "disable --now panel-pm2@qa-state.service") || !strings.Contains(strings.Join(commands, "\n"), "enable --now panel-pm2@qa-state.service") {
		t.Fatal(commands)
	}
}

func TestPM2FailedStartRestoresBootWithoutStoppingOriginalActiveProcess(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(fmt.Sprint(active), func(t *testing.T) {
			before := pm2TestState("inactive", "disabled")
			if active {
				before = pm2TestState("active", "disabled")
			}
			state := before
			commands := []string{}
			s := New(Config{Run: func(_ context.Context, _ string, args ...string) (string, error) {
				commands = append(commands, strings.Join(args, " "))
				switch args[0] {
				case "show":
					return pm2TestStateText(state), nil
				case "enable":
					state.UnitFileState = "enabled"
					return "", errors.New("injected original start failure")
				case "stop":
					if active {
						t.Fatal("failed start stopped an original active service")
					}
					state = pm2TestState("inactive", "enabled")
				case "disable":
					state.UnitFileState = "disabled"
				default:
					t.Fatal(args)
				}
				return "", nil
			}})
			_, err := s.controlPM2(context.Background(), pm2App{ID: "qa-state"}, "start", "panel-pm2@qa-state.service")
			if err == nil || !reflect.DeepEqual(state, before) {
				t.Fatal("failed start changed original state", state, before, err, commands)
			}
		})
	}
}
