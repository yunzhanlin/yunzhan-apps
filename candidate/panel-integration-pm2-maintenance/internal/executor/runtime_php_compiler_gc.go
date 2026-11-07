package executor

import (
	"context"
	"errors"

	"local/panel/internal/runtimecatalog"
)

const runtimePHPCompilerGCID = "php-gcc-bounded-memory-v1"
const runtimePHPCompilerGCFlags = "-O2 -ftrack-macro-expansion=0 --param=ggc-min-expand=10 --param=ggc-min-heapsize=32768"

// GCC's own collection thresholds and diagnostic-only macro location tracking,
// not an optimization downgrade, resource limit override, source transform or
// command/URL capability. The selected worker must independently verify its
// fixed finite 1 GiB unit and host reserve before spawning a compiler.
// All -O2/features and existing process/sandbox boundaries remain unchanged.
// https://gcc.gnu.org/onlinedocs/gcc-15.1.0/gcc/Optimize-Options.html
// https://gcc.gnu.org/onlinedocs/gcc-15.1.0/gcc/Preprocessor-Options.html
type RuntimeCompilerPolicy struct {
	ID           string `json:"id"`
	ReleaseID    string `json:"release_id"`
	SourceSHA256 string `json:"source_sha256"`
	CFLAGS       string `json:"cflags"`
}

type runtimePHPCompilerGCKey struct{}
type runtimePHPCompilerGCBound struct{ ID, SourceSHA256 string }

var errRuntimePHPCompilerGC = errors.New("PHP 编译器内存回收策略缺少当前固定官方源码绑定，未使用调用方编译参数")

func withRuntimePHPCompilerGC(ctx context.Context, r runtimecatalog.Release) (context.Context, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errRuntimePHPCompilerGC
	}
	spec, selected := runtimeMagicSpecification(r.ID)
	if !selected {
		if ctx.Value(runtimePHPCompilerGCKey{}) != nil {
			return nil, errRuntimePHPCompilerGC
		}
		return ctx, nil
	}
	official, found := runtimecatalog.Find(r.ID)
	if !found || r != official || r.Family != "php" || r.SHA256 != spec.archiveSHA || ctx.Value(runtimePHPCompilerGCKey{}) != nil {
		return nil, errRuntimePHPCompilerGC
	}
	return context.WithValue(ctx, runtimePHPCompilerGCKey{}, runtimePHPCompilerGCBound{r.ID, r.SHA256}), nil
}

func runtimePHPCompilerGCPolicy(ctx context.Context) (*RuntimeCompilerPolicy, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errRuntimePHPCompilerGC
	}
	value := ctx.Value(runtimePHPCompilerGCKey{})
	if value == nil {
		return nil, nil
	}
	bound, ok := value.(runtimePHPCompilerGCBound)
	if !ok {
		return nil, errRuntimePHPCompilerGC
	}
	r, found := runtimecatalog.Find(bound.ID)
	spec, selected := runtimeMagicSpecification(bound.ID)
	if !found || !selected || r.Family != "php" || bound.SourceSHA256 != r.SHA256 || bound.SourceSHA256 != spec.archiveSHA {
		return nil, errRuntimePHPCompilerGC
	}
	// Return a fresh observation. Mutating it cannot alter the bound context.
	return &RuntimeCompilerPolicy{runtimePHPCompilerGCID, bound.ID, bound.SourceSHA256, runtimePHPCompilerGCFlags}, nil
}
