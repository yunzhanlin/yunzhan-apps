//go:build linux

package executor

import (
	"errors"
	"io"
	"os"
	"strings"
)

func readSiteLog(id, kind string) (string, error) {
	root, e := os.OpenRoot("/var/log/nginx")
	if e != nil {
		return "", e
	}
	defer root.Close()
	file, e := regularFile(root, "panel-"+id+"."+kind+".log")
	if os.IsNotExist(e) {
		return "", nil
	}
	if e != nil {
		return "", e
	}
	defer file.Close()
	st, e := file.Stat()
	if e != nil {
		return "", e
	}
	start := int64(0)
	if st.Size() > 65536 {
		start = st.Size() - 65536
	}
	if _, e = file.Seek(start, io.SeekStart); e != nil {
		return "", e
	}
	b, e := io.ReadAll(io.LimitReader(file, 65536))
	if e != nil {
		return "", e
	}
	if len(b) > 65536 {
		return "", errors.New("日志读取超限")
	}
	if start > 0 {
		if end := strings.IndexByte(string(b), '\n'); end >= 0 {
			b = b[end+1:]
		}
	}
	return redactSiteLog(string(b)), nil
}
