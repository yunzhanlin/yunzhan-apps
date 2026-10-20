package executor

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

// These arguments are compiled callers' arguments, never request-supplied
// commands. Do not alter TLS/signature/sandbox/host APT configuration. APT's
// delayed-retry warning queue is unbounded in Debian #1111554 (2.6.1/3.0.3).
func fixedAPTArguments(args []string) []string {
	result := append([]string(nil), args...)
	return append(result, "-o", "Acquire::Retries=0", "-o", "APT::Update::Error-Mode=any")
}

func aptAcquisitionOnly(args []string) bool {
	command, downloadOnly := "", false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--", "--no-download", "--simulate", "--just-print", "--dry-run", "--recon", "--no-act", "-s":
			return false
		case "-o", "--option", "-c", "--config-file":
			if i+1 >= len(args) {
				return false
			}
			i++
			// Never let an acquisition helper replay a boolean action override.
			option := strings.ToLower(args[i])
			if strings.HasPrefix(option, "apt::get::download") || strings.HasPrefix(option, "apt::get::simulate") {
				return false
			}
		case "--download-only", "-d":
			downloadOnly = true
		default:
			if strings.HasPrefix(arg, "-") {
				if strings.HasPrefix(arg, "--download-only=") || strings.HasPrefix(arg, "--option=") || strings.HasPrefix(arg, "-o") {
					return false // Require explicit, unambiguous compiled options.
				}
				continue
			}
			if command == "" {
				command = arg
			}
		}
	}
	return command == "update" || command == "download" || (command == "install" && downloadOnly)
}

// Only read-only acquisition receives up to three independent attempts, inside
// the caller's original context deadline. Dpkg/service mutations run once.
// An unknown failure, killed process or cancelled context is never retried.
func fixedAPTCommand(ctx context.Context, name string, args []string, run func([]string) (string, error)) (string, error) {
	if name != "/usr/bin/apt-get" {
		return run(args)
	}
	args = fixedAPTArguments(args)
	if !aptAcquisitionOnly(args) {
		return run(args)
	}
	var output string
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if err = ctx.Err(); err != nil {
			return "", err
		}
		output, err = run(append([]string(nil), args...))
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if err == nil {
			return output, nil
		}
		var exited *exec.ExitError
		if !errors.As(err, &exited) || exited.ExitCode() != 100 || attempt == 2 {
			return output, err
		}
		timer := time.NewTimer(time.Duration((attempt+1)*2) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
	}
	return output, err
}
