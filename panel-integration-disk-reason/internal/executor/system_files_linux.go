//go:build linux

package executor

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// listSystemDirectory uses directory descriptors all the way from root.
// Its read-only result never follows symlinks or opens regular files.
func listSystemDirectory(root, directory, search string) (map[string]any, error) {
	if !core.ValidSystemDirectory(directory) || len(search) > 128 {
		return nil, errors.New("无效服务器目录")
	}
	fd, e := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	for _, part := range strings.Split(strings.Trim(directory, "/"), "/") {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), directory)
	defer f.Close()
	dirInfo, e := f.Stat()
	if e != nil {
		return nil, e
	}
	items, e := f.ReadDir(10001)
	if e != nil && e != io.EOF {
		return nil, e
	}
	truncated := len(items) > 10000
	if truncated {
		items = items[:10000]
	}
	out := make([]core.FileEntry, 0, len(items))
	for _, item := range items {
		name := item.Name()
		if strings.ContainsAny(name, "\n\r") || !strings.Contains(strings.ToLower(name), strings.ToLower(search)) {
			continue
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(int(f.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			continue
		}
		kind := "special"
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			kind = "directory"
		case unix.S_IFREG:
			kind = "file"
		case unix.S_IFLNK:
			kind = "link"
		}
		out = append(out, core.FileEntry{Name: name, Path: filepath.Join(directory, name), Kind: kind, Size: stat.Size, Mode: fmt.Sprintf("%04o", stat.Mode&0777), ModifiedAt: time.Unix(stat.Mtim.Sec, stat.Mtim.Nsec).UTC().Format(time.RFC3339)})
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i].Kind == "directory") != (out[j].Kind == "directory") {
			return out[i].Kind == "directory"
		}
		return out[i].Name < out[j].Name
	})
	return map[string]any{"path": directory, "directory": core.FileEntry{Name: filepath.Base(directory), Path: directory, Kind: "directory", Size: dirInfo.Size(), Mode: fmt.Sprintf("%04o", dirInfo.Mode().Perm()), ModifiedAt: dirInfo.ModTime().UTC().Format(time.RFC3339)}, "entries": out, "truncated": truncated, "scanned": len(items)}, nil
}

func (s *Service) systemFileRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/filesystem", func(w http.ResponseWriter, r *http.Request) {
		listing, e := listSystemDirectory("/", r.URL.Query().Get("path"), r.URL.Query().Get("search"))
		if e != nil {
			respond(w, 409, map[string]string{"error": "目录不可访问: " + e.Error()})
			return
		}
		page := filePage(r, listing["entries"].([]core.FileEntry))
		for _, key := range []string{"path", "directory", "truncated", "scanned"} {
			page[key] = listing[key]
		}
		respond(w, 200, page)
	})
}
