//go:build linux

package executor

import (
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Counts describe direct, visible children before search or pagination. Links
// and special files are separate; they are never opened to discover a target.
type fileDirectorySummary struct {
	Directories int  `json:"directories"`
	Files       int  `json:"files"`
	Links       int  `json:"links"`
	Special     int  `json:"special"`
	Skipped     int  `json:"skipped"`
	Truncated   bool `json:"truncated"`
	Complete    bool `json:"complete"`
}

func readFileDirectory(dir *os.File, path string, managed bool) ([]core.FileEntry, fileDirectorySummary, int, error) {
	items, err := dir.ReadDir(10001)
	if err != nil && err != io.EOF {
		return nil, fileDirectorySummary{}, 0, err
	}
	summary := fileDirectorySummary{Truncated: len(items) > 10000}
	if summary.Truncated {
		items = items[:10000]
	}
	out := make([]core.FileEntry, 0, len(items))
	for _, item := range items {
		name := item.Name()
		entryPath := filepath.Join(path, name)
		if managed && !core.ValidFilePath(entryPath, false) || !managed && strings.ContainsAny(name, "\n\r") {
			continue
		}
		var st unix.Stat_t
		if err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			summary.Skipped++
			continue
		}
		kind := "special"
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			kind = "directory"
			summary.Directories++
		case unix.S_IFREG:
			kind = "file"
			summary.Files++
		case unix.S_IFLNK:
			kind = "link"
			summary.Links++
		default:
			summary.Special++
		}
		out = append(out, core.FileEntry{Name: name, Path: entryPath, Kind: kind, Size: st.Size, Mode: fmt.Sprintf("%04o", st.Mode&07777), Owner: strconv.FormatUint(uint64(st.Uid), 10), ModifiedAt: time.Unix(st.Mtim.Sec, st.Mtim.Nsec).UTC().Format(time.RFC3339)})
	}
	summary.Complete = !summary.Truncated && summary.Skipped == 0
	return out, summary, len(items), nil
}
