//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/core"
	"net/http"
	"os"
	"path/filepath"
)

func (s *Service) siteArchiveRoutes(m *http.ServeMux) {
	// Advisory preflight avoids queuing a known no-mutation rejection as a
	// failed lifecycle job. ArchiveSite repeats its guard under the same lock.
	m.HandleFunc("GET /v1/sites/{id}/archive-check", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !core.ValidID(id) || len(r.URL.Query()) != 0 {
			respond(w, 400, map[string]string{"error": "网站归档预检标识或参数无效"})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		finish, err := s.lockWAFSiteMutation()
		if err == nil {
			defer finish()
			finishApache, apacheErr := s.lockApacheWAFSiteMutation()
			if apacheErr != nil {
				err = apacheErr
			} else {
				defer finishApache()
				err = s.wafSiteArchiveReference(id)
			}
		}
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, map[string]any{"site_id": id, "waf_reference_clear": true, "no_site_files_changed": true})
	})
	m.HandleFunc("POST /v1/sites/{id}/archive", func(w http.ResponseWriter, r *http.Request) {
		var in core.SiteArchiveRequest
		if !readJSON(w, r, &in) {
			return
		}
		if in.Site.ID != r.PathValue("id") {
			respond(w, 400, map[string]string{"error": "归档网站身份不匹配"})
			return
		}
		result, e := s.ArchiveSite(r.Context(), in)
		if e != nil {
			respond(w, 409, map[string]any{"error": e.Error(), "steps": result.Steps})
			return
		}
		respond(w, 200, result)
	})
}

func (s *Service) ArchiveSite(ctx context.Context, in core.SiteArchiveRequest) (core.ApplyResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := core.ApplyResult{Status: "archived", Restored: true, Steps: []core.Step{}}
	add := func(message string) {
		result.Steps = append(result.Steps, core.Step{Time: core.Now(), Message: message})
	}
	finishWAF, wafErr := s.lockWAFSiteMutation()
	if wafErr != nil {
		return result, wafErr
	}
	defer finishWAF()
	finishApache, apacheErr := s.lockApacheWAFSiteMutation()
	if apacheErr != nil {
		return result, apacheErr
	}
	defer finishApache()
	if err := s.wafSiteArchiveReference(in.Site.ID); err != nil {
		return result, err
	}
	unlock, lockErr := s.lockRuntimeUse()
	if lockErr != nil {
		return result, lockErr
	}
	defer unlock()
	if err := s.phpQuarantineReference(in.Site.ID); err != nil {
		return result, err
	}
	if s.moduleInstalled("nfs-manager") {
		v, e := s.nfsServerConfig()
		if e != nil {
			return result, e
		}
		if s.nfsPending() {
			return result, errors.New("NFS 有待恢复导出清单，请先恢复再归档网站")
		}
		for _, export := range v.Exports {
			if export.SiteID == in.Site.ID {
				return result, errors.New("网站仍被 NFS 导出引用，先移除共享导出再归档；网站文件不会删除")
			}
		}
	}
	if !core.ValidID(in.Site.ID) || !core.ValidID(in.JobID) || !core.ValidDomain(in.Site.Domain) || in.Site.Settings.WebServer != "nginx" || in.Site.PHPVersionID != "" {
		return result, errors.New("归档站点身份或类型无效")
	}
	if s.Config.SitesDir == "/srv/panel/sites" {
		workers, err := phpWorkerRecords()
		if err != nil {
			return result, err
		}
		for _, worker := range workers {
			if worker.SiteID == in.Site.ID {
				return result, errors.New("请先删除该网站的 PHP 进程配置，再归档网站")
			}
		}
	}
	for _, dir := range []string{s.Config.SitesDir, s.Config.ConfDir, s.Config.StateDir} {
		if e := ordinary(dir, true); e != nil {
			return result, e
		}
	}
	configArchiveRoot := filepath.Join(filepath.Dir(s.Config.ConfDir), "sites-archive")
	siteArchiveRoot := filepath.Join(s.Config.SitesDir, ".archives")
	for _, root := range []string{configArchiveRoot, siteArchiveRoot} {
		if e := os.MkdirAll(root, 0700); e != nil {
			return result, e
		}
		if e := ordinary(root, true); e != nil {
			return result, e
		}
	}
	configuration := filepath.Join(s.Config.ConfDir, in.Site.ID+".conf")
	archivedConfiguration := filepath.Join(configArchiveRoot, in.Site.ID+".conf")
	siteDir := filepath.Join(s.Config.SitesDir, in.Site.ID)
	archivedSiteDir := filepath.Join(siteArchiveRoot, in.Site.ID)
	if e := ordinary(configuration, false); e != nil && !errors.Is(e, os.ErrNotExist) {
		return result, e
	}
	if e := ordinary(archivedConfiguration, false); e != nil && !errors.Is(e, os.ErrNotExist) {
		return result, e
	}
	if e := ordinary(siteDir, true); e != nil && !errors.Is(e, os.ErrNotExist) {
		return result, e
	}
	if e := ordinary(archivedSiteDir, true); e != nil && !errors.Is(e, os.ErrNotExist) {
		return result, e
	}
	if exists(configuration) && exists(archivedConfiguration) || exists(siteDir) && exists(archivedSiteDir) {
		return result, errors.New("归档目标与仍生效的网站文件同时存在，请人工核对")
	}
	if !exists(configuration) && !exists(archivedConfiguration) || !exists(siteDir) && !exists(archivedSiteDir) {
		return result, errors.New("网站配置或目录缺失，拒绝归档")
	}
	markerDir := siteDir
	if !exists(siteDir) {
		markerDir = archivedSiteDir
	}
	marker := filepath.Join(markerDir, ".panel-site.json")
	if e := ordinary(marker, false); e != nil {
		return result, e
	}
	b, e := os.ReadFile(marker)
	if e != nil {
		return result, e
	}
	var owner map[string]string
	if json.Unmarshal(b, &owner) != nil || owner["id"] != in.Site.ID || owner["domain"] != in.Site.Domain {
		return result, errors.New("网站目录归属标记不匹配")
	}
	if exists(configuration) {
		if e = os.Rename(configuration, archivedConfiguration); e != nil {
			return result, e
		}
		add("已从 Nginx 生效目录移出网站配置")
	}
	rollback := func(cause error) (core.ApplyResult, error) {
		if exists(archivedConfiguration) && !exists(configuration) {
			if re := os.Rename(archivedConfiguration, configuration); re != nil {
				return result, fmt.Errorf("%w；配置恢复失败: %v", cause, re)
			}
			_, _ = s.Config.Run(context.Background(), "/usr/bin/systemctl", "reload", "nginx")
		}
		return result, cause
	}
	nginx, e := s.nginxBinary()
	if e != nil {
		return rollback(e)
	}
	if _, e = s.Config.Run(ctx, nginx, "-t"); e != nil {
		return rollback(e)
	}
	if _, e = s.Config.Run(ctx, "/usr/bin/systemctl", "reload", "nginx"); e != nil {
		return rollback(e)
	}
	add("Nginx 配置校验与重载成功")
	if exists(siteDir) {
		if e = os.Rename(siteDir, archivedSiteDir); e != nil {
			return rollback(e)
		}
		add("网站目录已移入仅 root 可访问的归档区")
	}
	return result, nil
}

func exists(path string) bool { _, e := os.Lstat(path); return e == nil }
