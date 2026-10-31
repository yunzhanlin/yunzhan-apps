package main

import (
	"flag"
	"io"
	"reflect"
	"testing"
)

func executorArgumentFlags(t *testing.T, argv []string) *flag.FlagSet {
	t.Helper()
	f := flag.NewFlagSet("executor", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	for _, n := range []string{"site-cli", "database-cli", "install-job", "prepare-site", "socket", "waf-country-account", "waf-country-job", "load-balance-stream-account-job", "load-balance-stream-install-job", "install-app-dependencies"} {
		f.String(n, "", "fixture")
	}
	f.Bool("check-program-upgrade-queues", false, "fixture")
	if err := f.Parse(argv); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestExecutorCLIArgumentsReachOnlyTheirExplicitChild(t *testing.T) {
	for _, selector := range []string{"site-cli", "database-cli"} {
		for _, prefix := range [][]string{{"--" + selector + "=identity"}, {"--" + selector, "identity"}, {"-" + selector + "=identity"}, {"-" + selector, "identity"}} {
			for _, child := range [][]string{nil, {"-r", "echo 'one argument with spaces';"}, {"script.php", "two words", "--install-job=opaque-child-argument"}, {"--execute=SELECT 1", "--batch"}} {
				argv := append(append(append([]string{}, prefix...), "--"), child...)
				f := executorArgumentFlags(t, argv)
				before := append([]string(nil), f.Args()...)
				if err := validateExecutorCLIArguments(f, argv); err != nil {
					t.Fatal(argv, err)
				}
				if !reflect.DeepEqual(before, append([]string(nil), f.Args()...)) || len(f.Args()) != len(child) {
					t.Fatal("child argv was reinterpreted or changed", argv, f.Args())
				}
			}
			f := executorArgumentFlags(t, prefix)
			if err := validateExecutorCLIArguments(f, prefix); err != nil {
				t.Fatal("interactive CLI regressed", prefix, err)
			}
		}
	}
}

func TestExecutorCLIArgumentsRejectMixedDuplicateEmptyAndUnseparatedSelectors(t *testing.T) {
	cases := [][]string{
		{"--site-cli=", "--", "script.php"},
		{"--database-cli=", "--", "--execute=SELECT 1"},
		{"--site-cli=one", "--site-cli=two", "--", "script.php"},
		{"--site-cli=one", "--site-cli=one"},
		{"--site-cli=one", "--database-cli=two", "--", "script.php"},
		{"--site-cli=one", "--socket=/tmp/not-an-override", "--", "script.php"},
		{"--check-program-upgrade-queues", "--database-cli=two", "--", "--execute=SELECT 1"},
		{"--site-cli=one", "script.php"},
		{"--database-cli=two", "database_name"},
		{"positional", "--site-cli=one", "--", "script.php"},
	}
	for _, selector := range []string{"site-cli", "database-cli"} {
		for _, fixed := range []string{"install-job", "prepare-site", "waf-country-account", "waf-country-job", "load-balance-stream-account-job", "load-balance-stream-install-job", "install-app-dependencies"} {
			cases = append(cases, []string{"--" + selector + "=one", "--" + fixed + "=two", "--", "child"})
		}
	}
	for _, argv := range cases {
		if err := validateExecutorCLIArguments(executorArgumentFlags(t, argv), argv); err == nil {
			t.Fatal("ambiguous host dispatch accepted", argv)
		}
	}
}

func TestExecutorNonCLIArgumentBoundaryRemainsClosed(t *testing.T) {
	for _, argv := range [][]string{nil, {"--socket=/run/panel-executor/control.sock"}, {"--waf-country-account=original"}, {"--load-balance-stream-account-job=original"}, {"--check-program-upgrade-queues"}} {
		if err := validateExecutorCLIArguments(executorArgumentFlags(t, argv), argv); err != nil {
			t.Fatal("ordinary non-CLI flag parsing changed", argv, err)
		}
	}
	for _, argv := range [][]string{{"unexpected"}, {"--waf-country-account=original", "--", "extra"}, {"--load-balance-stream-install-job=original", "extra"}, {"positional", "--install-job=hidden"}, {"--check-program-upgrade-queues", "--", "extra"}} {
		if err := validateExecutorCLIArguments(executorArgumentFlags(t, argv), argv); err == nil {
			t.Fatal("fixed host mode accepted positional arguments", argv)
		}
	}
}
