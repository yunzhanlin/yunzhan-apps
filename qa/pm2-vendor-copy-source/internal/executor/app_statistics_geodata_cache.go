package executor

import (
	"local/panel/internal/geodata"
	"sync"
	"time"
)

type statisticsGeoCache struct {
	mu                         sync.RWMutex
	snapshot                   *geodata.Snapshot
	instance, selected, appSHA string
	loading                    bool
	error                      string
	checkedAt                  string
	loadedAt                   time.Time
	selectorRaw                []byte
	fallbackRaw                []byte // One deferred, explicitly referenced disk fallback after a timed-out cold load.
}
