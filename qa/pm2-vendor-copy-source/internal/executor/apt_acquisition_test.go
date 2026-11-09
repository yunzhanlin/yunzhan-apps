package executor

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"testing"
	"time"
)

func TestAPTArgumentsPreserveInputAndTrust(t *testing.T) {
	args := []string{"-o", "Acquire::AllowInsecureRepositories=false", "install", "--no-upgrade", "--no-download", "nodejs=1.2.3"}
	before := append([]string(nil), args...)
	fixed := fixedAPTArguments(args)
	if !reflect.DeepEqual(args, before) || !reflect.DeepEqual(fixed[:len(args)], before) {
		t.Fatal("Original compiled identity/trust arguments changed")
	}
	if !reflect.DeepEqual(fixed[len(args):], []string{"-o", "Acquire::Retries=0", "-o", "APT::Update::Error-Mode=any"}) {
		t.Fatal("Unexpected APT policy or security override")
	}
	fixed[0] = "changed"
	if !reflect.DeepEqual(args, before) {
		t.Fatal("Caller arguments were aliased")
	}
}

func TestAPTAcquisitionClassificationNeverRetriesMutations(t *testing.T) {
	for _, args := range [][]string{{"update"}, {"download", "nodejs=1.2.3"}, {"-o", "Dir::State::lists=/private/lists", "update"}, {"install", "-y", "--no-upgrade", "--download-only", "nodejs"}} {
		if !aptAcquisitionOnly(fixedAPTArguments(args)) {
			t.Fatalf("Compiled acquisition incorrectly rejected: %v", args)
		}
	}
	for _, args := range [][]string{{}, {"install", "-y", "nodejs"}, {"install", "--no-download", "nodejs"}, {"remove", "nginx"}, {"purge", "nginx"}, {"dist-upgrade"}, {"install", "--download-only", "--no-download", "nodejs"}, {"install", "--download-only=false", "nodejs"}, {"install", "--download-only", "-o", "APT::Get::Download-Only=false", "nodejs"}, {"--simulate", "install", "--download-only", "nodejs"}, {"--", "update"}, {"-o"}} {
		if aptAcquisitionOnly(fixedAPTArguments(args)) {
			t.Fatalf("Mutation/ambiguous action classified as acquisition: %v", args)
		}
	}
}

func aptTestExit(t *testing.T, code string) error {
	t.Helper()
	err := exec.Command("/bin/sh", "-c", "exit "+code).Run()
	if err == nil {
		t.Fatal("Controlled exit fixture did not fail")
	}
	return err
}

func TestAPTMutationsUnknownErrorsAndOtherCommandsRunOnce(t *testing.T) {
	for _, row := range []struct {
		name string
		args []string
		err  error
	}{{"/usr/bin/apt-get", []string{"install", "--no-download", "nodejs"}, aptTestExit(t, "100")}, {"/usr/bin/apt-get", []string{"update"}, errors.New("unknown read failure")}, {"/usr/bin/apt-get", []string{"update"}, aptTestExit(t, "137")}, {"/usr/bin/systemctl", []string{"restart", "nginx"}, aptTestExit(t, "100")}} {
		calls := 0
		_, err := fixedAPTCommand(context.Background(), row.name, row.args, func(args []string) (string, error) {
			calls++
			if row.name != "/usr/bin/apt-get" && !reflect.DeepEqual(args, row.args) {
				t.Fatal("Non-APT arguments modified")
			}
			return "", row.err
		})
		if calls != 1 || !errors.Is(err, row.err) {
			t.Fatal("Mutation or unknown failure retried", calls, err)
		}
	}
}

func TestAPTAcquisitionCancellationKeepsOriginalDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	calls := 0
	start := time.Now()
	_, err := fixedAPTCommand(ctx, "/usr/bin/apt-get", []string{"update"}, func([]string) (string, error) {
		calls++
		return "", aptTestExit(t, "100")
	})
	if !errors.Is(err, context.DeadlineExceeded) || calls != 1 || time.Since(start) > time.Second {
		t.Fatal("Acquisition outlived its deadline or retried after cancellation", calls, err)
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	_, err = fixedAPTCommand(cancelled, "/usr/bin/apt-get", []string{"download", "nodejs"}, func([]string) (string, error) {
		t.Fatal("Cancelled acquisition executed")
		return "", nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("Cancellation lost", err)
	}
}

func TestAPTAcquisitionCannotPublishSuccessAfterCallerCancellation(t *testing.T) {
	for _, result := range []error{nil, aptTestExit(t, "100")} {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		output, err := fixedAPTCommand(ctx, "/usr/bin/apt-get", []string{"update"}, func([]string) (string, error) {
			calls++
			cancel()
			return "late result must not become readiness", result
		})
		if calls != 1 || output != "" || !errors.Is(err, context.Canceled) {
			t.Fatal("Cancelled caller received late acquisition success/foreign error", calls, output, err)
		}
	}
}

func TestAPTAcquisitionRecoveryAndThreeAttemptLimit(t *testing.T) {
	err100 := aptTestExit(t, "100")
	for _, successes := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		calls := 0
		original := fixedAPTArguments([]string{"install", "--download-only", "nodejs"})
		start := time.Now()
		output, err := fixedAPTCommand(ctx, "/usr/bin/apt-get", []string{"install", "--download-only", "nodejs"}, func(args []string) (string, error) {
			calls++
			if !reflect.DeepEqual(args, original) {
				t.Fatal("Retry altered original compiled acquisition identity")
			}
			args[0] = "mutated fixture copy"
			if successes && calls == 2 {
				return "real-result-fixture", nil
			}
			return "failed-result-fixture", err100
		})
		cancel()
		if successes {
			if calls != 2 || err != nil || output != "real-result-fixture" || time.Since(start) < 2*time.Second {
				t.Fatal("Bounded recovery did not preserve matching successful result", calls, err)
			}
		} else if calls != 3 || !errors.Is(err, err100) || time.Since(start) < 6*time.Second {
			t.Fatal("Permanent failure was not limited to three independent attempts", calls, err)
		}
	}
}
