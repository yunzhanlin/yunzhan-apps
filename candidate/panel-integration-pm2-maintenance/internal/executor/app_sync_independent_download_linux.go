//go:build linux

package executor

import (
	"errors"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"

	"golang.org/x/sys/unix"
)

func (s *Service) remoteIndependentChunk(target, transaction, name string, part int, intentSHA string) (core.RemoteIndependentChunk, error) {
	var out core.RemoteIndependentChunk
	if err := s.remoteCopyInstalled(); err != nil {
		return out, err
	}
	r, err := s.readRemoteCopyRecord(target, transaction)
	if err != nil || r.SHA != intentSHA || r.Result == nil {
		return out, errors.New("所选独立副本原意图改变或未完整提交；未返回字节")
	}
	var selected *remoteCopyFile
	for i := range r.Result.Files {
		if r.Result.Files[i].Name == name {
			selected = &r.Result.Files[i]
		}
	}
	if selected == nil || part < 0 || part >= core.RemoteCopyFileBytes/core.RemoteCopyChunkBytes {
		return out, errors.New("独立备份文件或分段不存在")
	}
	offset := int64(part * core.RemoteCopyChunkBytes)
	count := min(int64(core.RemoteCopyChunkBytes), selected.Bytes-offset)
	if count < 0 || count == 0 && part != 0 {
		return out, errors.New("独立副本分段越界")
	}
	d, err := s.remoteCopyDirectory(target, transaction, r.Result.AttemptID, false)
	if err != nil {
		return out, err
	}
	defer d.Close()
	info, err := d.Lstat(name)
	if err != nil {
		return out, err
	}
	metadata, err := remoteCopyFileMetadata(info, name, selected.SHA)
	if err != nil || metadata != *selected {
		return out, errors.New("独立副本封存后inode或权限改变，未下载")
	}
	f, err := d.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return out, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !programQueueSame(info, opened) {
		return out, errors.New("独立副本打开期间变化")
	}
	data := make([]byte, int(count))
	n, err := f.ReadAt(data, offset)
	after, statErr := f.Stat()
	visible, visibleErr := d.Lstat(name)
	if err != nil && !errors.Is(err, io.EOF) || n != len(data) || statErr != nil || visibleErr != nil || !programQueueSame(info, after) || !programQueueSame(info, visible) || !d.current() {
		return out, errors.New("独立备份分段读取期间变化，未返回不完整内容")
	}
	out = core.RemoteIndependentChunk{Target: target, Transaction: transaction, Name: name, IntentSHA: intentSHA, FileSHA: selected.SHA, FileBytes: selected.Bytes, Part: part, Bytes: data, ChunkSHA: core.Hash(string(data)), FilesChanged: false}
	return out, core.ValidateRemoteIndependentChunk(out, target, transaction, name, part, intentSHA)
}
func (s *Service) remoteIndependentDownloadRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/app-modules/files-sync/independent-backups/{target}/{transaction}/{name}/chunks/{part}", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if len(query) != 1 || len(query["sha"]) != 1 {
			respond(w, 400, map[string]string{"error": "独立备份下载不接受额外参数"})
			return
		}
		target, transaction, name := r.PathValue("target"), r.PathValue("transaction"), r.PathValue("name")
		part, err := core.RemoteIndependentReadPath(target, transaction, name, r.PathValue("part"), query.Get("sha"))
		if err != nil {
			respond(w, 400, map[string]string{"error": err.Error()})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		out, err := s.remoteIndependentChunk(target, transaction, name, part, query.Get("sha"))
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		if r.Context().Err() != nil {
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		respond(w, 200, out)
	})
}
