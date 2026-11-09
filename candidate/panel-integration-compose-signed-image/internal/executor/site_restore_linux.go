//go:build linux

package executor

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type siteRestoreReceipt struct {
	JobID    string `json:"job_id"`
	SiteID   string `json:"site_id"`
	BackupID string `json:"backup_id"`
	State    string `json:"state"`
	Error    string `json:"error,omitempty"`
}

func rootedExists(root *os.Root, path string) (bool, error) {
	_, e := root.Lstat(path)
	if e == nil {
		return true, nil
	}
	if errors.Is(e, os.ErrNotExist) {
		return false, nil
	}
	return false, e
}

func (s *Service) restoreSiteBackup(ctx context.Context, request core.SiteRestoreRequest) (core.ApplyResult, error) {
	result := core.ApplyResult{Steps: []core.Step{}}
	add := func(message string) {
		result.Steps = append(result.Steps, core.Step{Time: core.Now(), Message: message})
	}
	if !core.ValidID(request.JobID) || !core.ValidID(request.Site.ID) || request.Backup.SiteID != request.Site.ID || !core.ValidID(request.Backup.ID) {
		return result, errors.New("网站恢复身份无效")
	}
	files, e := s.openFiles(request.Site.ID)
	if e != nil {
		return result, e
	}
	defer files.Close()
	stateDir := filepath.Join(s.Config.StateDir, "site-restores")
	if e = os.MkdirAll(stateDir, 0700); e != nil {
		return result, e
	}
	receiptPath := filepath.Join(stateDir, request.JobID+".json")
	receipt := siteRestoreReceipt{JobID: request.JobID, SiteID: request.Site.ID, BackupID: request.Backup.ID}
	if raw, readErr := os.ReadFile(receiptPath); readErr == nil {
		var old siteRestoreReceipt
		if json.Unmarshal(raw, &old) != nil || old.JobID != receipt.JobID || old.SiteID != receipt.SiteID || old.BackupID != receipt.BackupID {
			return result, errors.New("网站恢复回执与任务不一致")
		}
		receipt = old
		if receipt.State == "completed" {
			result.Status = request.Site.Status
			add("同一恢复任务已完成，执行器按回执返回")
			return result, nil
		}
		if receipt.State == "rolled_back" {
			return result, errors.New("上次恢复验证失败且已恢复原目录：" + receipt.Error)
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return result, readErr
	}
	restoreDir := filePrivate + "/site-restores/" + request.JobID
	newDir, previousDir := restoreDir+"/new", restoreDir+"/previous"
	if receipt.State == "" {
		actual, verifyErr := verifySiteBackup(ctx, request.Backup)
		if verifyErr != nil {
			return result, verifyErr
		}
		if e = files.root.RemoveAll(restoreDir); e != nil {
			return result, e
		}
		if e = files.root.MkdirAll(newDir, 0700); e != nil {
			return result, e
		}
		archivePath := filepath.Join(siteBackups, actual.SiteID, actual.ID+".zip")
		archive, openErr := zip.OpenReader(archivePath)
		if openErr != nil {
			return result, openErr
		}
		var total int64
		for index, item := range archive.File {
			if index >= 100000 || !strings.HasPrefix(item.Name, "public/") {
				e = errors.New("网站备份条目范围无效")
				break
			}
			rel := strings.TrimPrefix(item.Name, "public/")
			rel = strings.TrimSuffix(rel, "/")
			if rel == "" {
				continue
			}
			if !core.ValidFilePath(rel, false) || (!item.FileInfo().IsDir() && !item.Mode().IsRegular()) {
				e = errors.New("网站备份包含越界、链接或特殊条目")
				break
			}
			dest := newDir + "/" + filepath.FromSlash(rel)
			if item.FileInfo().IsDir() {
				e = files.root.MkdirAll(dest, item.Mode().Perm()&0755)
				if e != nil {
					break
				}
				continue
			}
			if item.UncompressedSize64 > uint64(2*1024*1024*1024-total) {
				e = errors.New("网站备份解压内容超过 2 GiB")
				break
			}
			total += int64(item.UncompressedSize64)
			if e = files.root.MkdirAll(filepath.Dir(dest), 0755); e != nil {
				break
			}
			reader, openErr := item.Open()
			if openErr != nil {
				e = openErr
				break
			}
			out, openErr := files.root.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, item.Mode().Perm()&0755)
			if openErr != nil {
				reader.Close()
				e = openErr
				break
			}
			written, copyErr := io.Copy(out, io.LimitReader(reader, int64(item.UncompressedSize64)+1))
			reader.Close()
			if copyErr == nil && written != int64(item.UncompressedSize64) {
				copyErr = errors.New("网站备份条目长度不一致")
			}
			if copyErr == nil {
				copyErr = out.Chown(files.uid, files.gid)
			}
			if copyErr == nil {
				copyErr = out.Sync()
			}
			closeErr := out.Close()
			if copyErr != nil {
				e = copyErr
			} else {
				e = closeErr
			}
			if e != nil {
				break
			}
		}
		archive.Close()
		if e != nil {
			_ = files.root.RemoveAll(restoreDir)
			return result, e
		}
		receipt.State = "prepared"
		raw, _ := json.Marshal(receipt)
		if e = atomicWrite(receiptPath, raw, 0600); e != nil {
			return result, e
		}
		add(fmt.Sprintf("备份摘要通过，%d 个条目已解压到隔离目录", actual.Files))
	}
	publicExists, e := rootedExists(files.root, "public")
	if e != nil {
		return result, e
	}
	previousExists, e := rootedExists(files.root, previousDir)
	if e != nil {
		return result, e
	}
	newExists, e := rootedExists(files.root, newDir)
	if e != nil {
		return result, e
	}
	if receipt.State == "prepared" {
		if previousExists && !publicExists {
			receipt.State = "old_moved"
		} else if publicExists && !previousExists {
			if e = renameBetween(files.root, "public", files.root, previousDir, false); e != nil {
				return result, e
			}
			receipt.State = "old_moved"
		} else {
			return result, errors.New("网站恢复目录状态无法安全判定")
		}
		raw, _ := json.Marshal(receipt)
		if e = atomicWrite(receiptPath, raw, 0600); e != nil {
			return result, e
		}
		add("原网站目录已保留为本次恢复点")
		publicExists, previousExists = false, true
	}
	if receipt.State == "old_moved" {
		if newExists && !publicExists {
			if e = renameBetween(files.root, newDir, files.root, "public", false); e != nil {
				return result, e
			}
			publicExists, newExists = true, false
		} else if !newExists && publicExists && previousExists {
			// The directory switch completed before the prior process persisted its receipt.
		} else {
			return result, errors.New("网站恢复切换状态无法安全判定")
		}
		add("备份目录已切换为网站公开目录")
	}
	verifyErr := verifySiteIngress(ctx, request.Site, true)
	if verifyErr == nil && request.Site.Status != "stopped" {
		client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
		var status int
		status, verifyErr = verifySiteHomepage(ctx, client, request.Site)
		if verifyErr == nil && status >= 400 {
			verifyErr = fmt.Errorf("恢复后网站首页 HTTP %d", status)
		}
		client.CloseIdleConnections()
	}
	if verifyErr != nil {
		failedDir := restoreDir + "/failed"
		_ = files.root.RemoveAll(failedDir)
		if publicExists {
			_ = renameBetween(files.root, "public", files.root, failedDir, false)
		}
		if previousExists {
			_ = renameBetween(files.root, previousDir, files.root, "public", false)
		}
		receipt.State, receipt.Error = "rolled_back", verifyErr.Error()
		raw, _ := json.Marshal(receipt)
		_ = atomicWrite(receiptPath, raw, 0600)
		add("验证失败，已恢复原网站目录")
		result.Steps = append(result.Steps, core.Step{Time: core.Now(), Message: verifyErr.Error()})
		return result, errors.New("网站恢复验证失败，已恢复原目录")
	}
	receipt.State, receipt.Error = "completed", ""
	raw, _ := json.Marshal(receipt)
	if e = atomicWrite(receiptPath, raw, 0600); e != nil {
		return result, e
	}
	result.Status = request.Site.Status
	add("站点入口与首页响应通过，网站文件恢复完成")
	return result, nil
}

func (s *Service) siteRestoreRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/sites/{id}/restore", func(w http.ResponseWriter, r *http.Request) {
		var request core.SiteRestoreRequest
		if !readJSON(w, r, &request) {
			return
		}
		if request.Site.ID != r.PathValue("id") {
			respond(w, 400, map[string]string{"error": "网站恢复归属不匹配"})
			return
		}
		lock := fileMutex(request.Site.ID)
		lock.Lock()
		defer lock.Unlock()
		result, e := s.restoreSiteBackup(r.Context(), request)
		if e != nil {
			respond(w, 409, map[string]any{"error": e.Error(), "steps": result.Steps})
			return
		}
		respond(w, 200, result)
	})
}
