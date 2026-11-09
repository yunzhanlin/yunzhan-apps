package executor

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/runtimecatalog"
)

func TestRuntimePHPCompilerGCExactOfficialReleaseAndUnchangedOptimization(t *testing.T) {
	for _, id := range []string{"php-8.2.35", "php-8.3.36"} {
		t.Run(id, func(t *testing.T) {
			r, found := runtimecatalog.Find(id)
			if !found {
				t.Fatal("fixed official release missing")
			}
			ctx, err := withRuntimePHPCompilerGC(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			policy, err := runtimePHPCompilerGCPolicy(ctx)
			if err != nil || policy == nil || policy.ID != "php-gcc-bounded-memory-v1" || policy.ReleaseID != id || policy.SourceSHA256 != r.SHA256 || policy.CFLAGS != "-O2 -ftrack-macro-expansion=0 --param=ggc-min-expand=10 --param=ggc-min-heapsize=32768" {
				t.Fatal("source-bound fixed collection policy changed", policy, err)
			}
			raw, err := json.Marshal(policy)
			if err != nil || strings.Contains(string(raw), "-O1") || strings.Contains(string(raw), "-O0") || strings.Contains(string(raw), "memory.max") {
				t.Fatal("code generation/resource override in metadata", err)
			}
			original := *policy
			policy.CFLAGS = "caller-flags"
			again, err := runtimePHPCompilerGCPolicy(ctx)
			if err != nil || again == nil || *again != original {
				t.Fatal("returned observation mutated the private bound context")
			}
		})
	}
}

func TestRuntimePHPCompilerGCLeavesOtherBuildersAndOldInstalledReleasesUnchanged(t *testing.T) {
	base := context.Background()
	for _, id := range []string{"php-8.2.33", "php-8.3.33", "php-8.4.27", "php-8.5.12", "nginx-1.30.6", "apache-2.4.68", "mysql-8.4.11", "redis-8.2.10"} {
		t.Run(id, func(t *testing.T) {
			r, found := runtimecatalog.Find(id)
			if !found {
				t.Fatal("original release missing")
			}
			ctx, err := withRuntimePHPCompilerGC(base, r)
			policy, readErr := runtimePHPCompilerGCPolicy(ctx)
			if err != nil || readErr != nil || ctx != base || policy != nil {
				t.Fatal("unselected original builder changed", err, readErr)
			}
		})
	}
	if policy, err := runtimePHPCompilerGCPolicy(base); err != nil || policy != nil {
		t.Fatal("original buildCommand context gained flags")
	}
}

func TestRuntimePHPCompilerGCRejectsForeignReleaseFieldsAndContextBindings(t *testing.T) {
	r, _ := runtimecatalog.Find("php-8.2.35")
	value := reflect.ValueOf(r)
	for i := range value.NumField() {
		t.Run(value.Type().Field(i).Name, func(t *testing.T) {
			forged := r
			field := reflect.ValueOf(&forged).Elem().Field(i)
			// Keep the selected ID so all other mismatches exercise the full
			// release equality, not an unsupported-family default.
			if value.Type().Field(i).Name == "ID" {
				field.SetString("php-8.3.36")
			} else {
				field.SetString("foreign")
			}
			if _, err := withRuntimePHPCompilerGC(context.Background(), forged); err == nil {
				t.Fatal("foreign release fields selected compiler tuning")
			}
		})
	}
	for i, invalid := range []any{true, "caller-flags", RuntimeCompilerPolicy{}, runtimePHPCompilerGCBound{}, runtimePHPCompilerGCBound{r.ID, strings.Repeat("0", 64)}, runtimePHPCompilerGCBound{"php-8.5.12", r.SHA256}} {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			ctx := context.WithValue(context.Background(), runtimePHPCompilerGCKey{}, invalid)
			if _, err := runtimePHPCompilerGCPolicy(ctx); err == nil {
				t.Fatal("foreign/unsupported private binding accepted")
			}
			if _, err := withRuntimePHPCompilerGC(ctx, r); err == nil {
				t.Fatal("old marker silently replaced")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, invalid := range []context.Context{nil, ctx} {
		if _, err := withRuntimePHPCompilerGC(invalid, r); err == nil {
			t.Fatal("invalid/canceled caller accepted")
		}
		if _, err := runtimePHPCompilerGCPolicy(invalid); err == nil {
			t.Fatal("invalid/canceled observer accepted")
		}
	}
}
