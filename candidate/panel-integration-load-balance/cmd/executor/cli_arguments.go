package main

import (
	"errors"
	"flag"
	"slices"
)

// Only the existing site and local database CLIs consume child arguments.
// Their selector must be exclusive, precede an explicit -- separator, and
// match the raw argv. Fixed account/data/install jobs keep their own exact
// entry checks and can never be selected by an argument after the separator.
func validateExecutorCLIArguments(flags *flag.FlagSet, argv []string) error {
	name, value := "", ""
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "site-cli" || f.Name == "database-cli" {
			name, value = f.Name, f.Value.String()
		}
	})
	if name == "" {
		if flags.NArg() != 0 {
			return errors.New("executor rejects unexpected positional arguments")
		}
		return nil
	}
	bad := errors.New("executor CLI requires one nonempty exclusive selector and -- before child arguments")
	if value == "" || flags.NFlag() != 1 || len(argv) == 0 {
		return bad
	}
	head := 0
	switch argv[0] {
	case "--" + name + "=" + value, "-" + name + "=" + value:
		head = 1
	case "--" + name, "-" + name:
		if len(argv) > 1 && argv[1] == value {
			head = 2
		}
	}
	if head == 0 {
		return bad
	}
	if len(argv) == head && flags.NArg() == 0 {
		return nil // Existing interactive CLI invocation, without child args.
	}
	if len(argv) <= head || argv[head] != "--" || !slices.Equal(argv[head+1:], flags.Args()) {
		return bad
	}
	return nil
}
