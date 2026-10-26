package executor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"local/panel/internal/runtimecatalog"
)

const runtimePHPCompilerMemoryWait = 90 * time.Second
const runtimePHPCompilerMemoryPoll = 2 * time.Second
const runtimePHPCompilerMemoryRetries = 45

var errRuntimePHPCompilerMemoryWaitContract = errors.New("PHP 编译内存等待缺少完整内部策略，未启动构建命令")

// Internal decision loop only: no command, credential, filesystem mutation,
// cache purge, controller write, publication, retry of a job or time extension.
// The callbacks are private implementation seams, never caller/UI parameters.
// Both elapsed time and probe count are bounded. Every success must be a fresh
// full admission before the SAME original installation context expires.
func awaitRuntimePHPCompilerMemory(ctx context.Context, r runtimecatalog.Release, probe func() error, wait func(context.Context, time.Duration) error) error {
	if ctx == nil {
		return errRuntimePHPCompilerMemoryWaitContract
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	selected, err := runtimePHPCompilerNeedsMemoryAdmission(r)
	if err != nil || !selected {
		return err
	}
	if probe == nil || wait == nil {
		return errRuntimePHPCompilerMemoryWaitContract
	}
	bounded, cancel := context.WithTimeout(ctx, runtimePHPCompilerMemoryWait)
	defer cancel()
	var last error
	for attempt := 0; attempt <= runtimePHPCompilerMemoryRetries; attempt++ {
		if err := bounded.Err(); err != nil {
			return errors.Join(last, err)
		}
		err := probe()
		if expired := bounded.Err(); expired != nil {
			return errors.Join(err, expired)
		}
		if err == nil {
			return nil
		}
		shortage, retryable := err.(*runtimePHPCompilerMemoryShortage)
		if !retryable {
			return err
		}
		if shortage == nil || shortage.message == "" {
			return errRuntimePHPCompilerMemoryWaitContract
		}
		last = err
		if attempt == runtimePHPCompilerMemoryRetries {
			break
		}
		if err := wait(bounded, runtimePHPCompilerMemoryPoll); err != nil {
			return errors.Join(last, err)
		}
	}
	return fmt.Errorf("PHP 构建命令等待内存余量达到固定 %d 秒上限；未启动当前命令、未延长安装时限: %w", int(runtimePHPCompilerMemoryWait/time.Second), last)
}
