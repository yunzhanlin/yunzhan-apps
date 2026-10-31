//go:build linux

package main

import (
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestExecutorCLIArgumentHelperProcess(t *testing.T) {
	if os.Getenv("PANEL_TEST_EXECUTOR_CLI_ARGUMENTS") != "1" {
		return
	}
	var argv []string
	if err := json.Unmarshal([]byte(os.Getenv("PANEL_TEST_EXECUTOR_CLI_ARGV")), &argv); err != nil {
		t.Fatal(err)
	}
	os.Args = append([]string{"panel-executor"}, argv...)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	main()
	os.Exit(0)
}

func TestExecutorCLIEntryRejectsAmbiguityBeforeAnyHostDispatch(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, argv := range [][]string{
		{"--site-cli=invalid-site", "--prepare-site=invalid-site", "--", "child.php"},
		{"--database-cli=invalid-database", "--waf-country-account=invalid-job", "--", "child"},
		{"--site-cli=invalid-site", "child.php"},
		{"--database-cli=invalid-database", "--database-cli=invalid-database", "--", "child"},
	} {
		encoded, _ := json.Marshal(argv)
		command := exec.Command(self, "-test.run=^TestExecutorCLIArgumentHelperProcess$")
		command.Env = append(os.Environ(), "PANEL_TEST_EXECUTOR_CLI_ARGUMENTS=1", "PANEL_TEST_EXECUTOR_CLI_ARGV="+string(encoded))
		output, err := command.CombinedOutput()
		if err == nil || !strings.Contains(string(output), "executor CLI requires one nonempty exclusive selector and -- before child arguments") {
			t.Fatal("production entry did not reject before dispatch", argv, err, string(output))
		}
	}
}
