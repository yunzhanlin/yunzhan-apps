//go:build linux

package executor

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// An already-open /proc/<pid> file may return ESRCH when its task exits before
// Read. Keep that kernel fact distinct from permission, corrupt and oversized
// records. Only the reload observer uses this reader: transaction ownership and
// other applications retain their existing, stricter readers.
// The public text deliberately contains no path, command line or raw data.
type wafReloadProcReadError struct{ cause error }

func (e wafReloadProcReadError) Error() string { return "Nginx 进程信息读取失败" }
func (e wafReloadProcReadError) Unwrap() error { return e.cause }

func wafReloadProcReadFailure(err error) error {
	if errors.Is(err, syscall.ESRCH) {
		return wafReloadProcReadError{errors.Join(os.ErrNotExist, syscall.ESRCH)}
	}
	return wafReloadProcReadError{err}
}

func readWAFReloadProcData(reader io.Reader, limit int64) ([]byte, error) {
	if reader == nil || limit <= 0 || limit > 16<<20 {
		return nil, errors.New("Nginx 进程读取预算无效")
	}
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, wafReloadProcReadFailure(err)
	}
	if int64(len(data)) > limit {
		return nil, errors.New("Nginx 进程信息超过读取预算")
	}
	return data, nil
}

func readWAFReloadProcFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, wafReloadProcReadFailure(err)
	}
	defer f.Close()
	return readWAFReloadProcData(f, limit)
}
