package core

import (
	"context"
	"errors"
	"sync"
)

const platformHealthConcurrency = 3
const platformHealthHostLimit = 12

type platformHealthHost struct {
	id, url, created string
	token            []byte
}

// Only a bounded snapshot of already registered hosts may be read. A canceled
// aggregate is unavailable, never a partial inventory presented as complete.
// Each slot has exactly one writer; the wait joins all readers before return.
// The caller still owns HTTPS identity, response budgets and the 5s timeout.
func readPlatformHealthFleet(ctx context.Context, hosts []platformHealthHost, read func(context.Context, platformHealthHost) map[string]any) ([]map[string]any, error) {
	if len(hosts) > platformHealthHostLimit {
		return nil, errors.New("原主机记录超过 12 个上限；保留原记录，未扫描部分主机冒充完整结果")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if read == nil {
		return nil, errors.New("主机健康读取器不可用；未发出请求")
	}
	out := make([]map[string]any, len(hosts))
	work := make(chan int, len(hosts))
	for i := range hosts {
		work <- i
	}
	close(work)
	var wg sync.WaitGroup
	for worker := 0; worker < min(platformHealthConcurrency, len(hosts)); worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				if ctx.Err() != nil {
					return
				}
				out[i] = read(ctx, hosts[i])
			}
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, entry := range out {
		if entry == nil {
			return nil, errors.New("主机健康读取未返回可核对状态；未将部分清单作为完整结果")
		}
	}
	return out, nil
}
