package core

import (
	"local/panel/internal/runtimecatalog"
	"net/http"
)

func (a *Server) previewPHP(w http.ResponseWriter, r *http.Request, u identity) {
	var in struct {
		ReleaseID string `json:"release_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	site, err := a.Store.Site(r.PathValue("id"))
	if err != nil {
		fail(w, 404, "站点不存在")
		return
	}
	if site.Status != "running" && site.Status != "stopped" {
		fail(w, 409, "请先处理该站点已有异常或创建任务")
		return
	}
	if in.ReleaseID != "" {
		version, ok := runtimecatalog.Find(in.ReleaseID)
		if !ok || version.Family != "php" || !a.Store.RuntimeInstalled(in.ReleaseID) {
			fail(w, 409, "请先安装所选 PHP 精确版本")
			return
		}
	}
	if err = ValidateSiteSettings(site.Settings, site.Domain, in.ReleaseID); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if err = a.Store.validatePHPExtensions(in.ReleaseID, site.Settings.PHP); err != nil {
		fail(w, 409, err.Error())
		return
	}
	if err = a.Store.validateSiteCertificate(site.Domain, site.Settings); err != nil {
		fail(w, 409, err.Error())
		return
	}
	previous := site
	site.PHPVersionID = in.ReleaseID
	request := ApplyRequest{Site: site, Enabled: site.Status == "running"}
	if previous.PHPVersionID != "" && site.PHPVersionID != "" && site.Settings.WebServer == "nginx" {
		request.PreserveNginx = true
		request.PreviousSite = &previous
	}
	var result any
	if err = a.Executor.Call(r.Context(), "POST", "/v1/sites/php-preview", request, &result); err != nil {
		fail(w, 409, err.Error())
		return
	}
	send(w, 200, result)
}
