package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"local/panel/internal/geodata"
)

type wafCountryAvailable struct {
	AppVersion      string                 `json:"app_version"`
	AppManifestSHA  string                 `json:"app_manifest_sha256"`
	DataManifestSHA string                 `json:"data_manifest_sha256"`
	Release         string                 `json:"release"`
	Revision        int                    `json:"revision"`
	License         string                 `json:"license"`
	AttributionURL  string                 `json:"attribution_url"`
	Files           []geodata.CountryAsset `json:"files"`
}

func (a *Server) wafCountryInstalledState(ctx context.Context) (WAFCountryDataState, error) {
	var raw json.RawMessage
	if a.Executor == nil {
		return WAFCountryDataState{}, errors.New("国家数据执行服务不可用")
	}
	if err := a.Executor.Call(ctx, "GET", "/v1/waf/country", nil, &raw); err != nil {
		return WAFCountryDataState{}, err
	}
	return DecodeWAFCountryDataState(raw)
}

func (a *Server) wafCountryRoutes(m *http.ServeMux) {
	allowed := func(w http.ResponseWriter, r *http.Request, actor identity) bool {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := wafCountryCurrentAccess(ctx, a.Store.DB, actor.ID); err != nil {
			fail(w, 403, "国家数据管理需要当前管理员的软件商店和安全权限")
			return false
		}
		w.Header().Set("Cache-Control", "no-store")
		return true
	}
	const base = "/api/software/nginx-waf/country-data"
	m.HandleFunc("GET "+base, a.authorize(func(w http.ResponseWriter, r *http.Request, actor identity) {
		if !allowed(w, r, actor) {
			return
		}
		if r.URL.RawQuery != "" {
			fail(w, 400, "国家数据状态不接受来源或路径参数")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 22*time.Second)
		defer cancel()
		state, err := a.wafCountryInstalledState(ctx)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		out := struct {
			ActorID     string               `json:"actor_id"`
			State       WAFCountryDataState  `json:"state"`
			Available   *wafCountryAvailable `json:"available"`
			SourceError string               `json:"source_error"`
		}{ActorID: actor.ID, State: state}
		if state.Supported {
			if a.AppCatalog == nil {
				out.SourceError = "签名应用目录不可用，没有替代下载来源"
			} else if _, authority, err := a.AppCatalog.FetchCountryDataEnvelope(ctx, "", time.Now()); err != nil {
				out.SourceError = err.Error()
			} else {
				manifest := authority.Data().Manifest()
				out.Available = &wafCountryAvailable{authority.AppVersion(), authority.AppSHA256(), authority.Data().SHA256(), manifest.Release, manifest.Revision, manifest.License, manifest.AttributionURL, authority.Data().Assets()}
			}
		}
		send(w, 200, out)
	}))
	m.HandleFunc("GET "+base+"/jobs", a.authorize(func(w http.ResponseWriter, r *http.Request, actor identity) {
		if !allowed(w, r, actor) {
			return
		}
		query, queryErr := url.ParseQuery(r.URL.RawQuery)
		if queryErr != nil || len(query) > 1 || len(query) == 1 && (len(query["cursor"]) != 1 || !ValidID(query.Get("cursor"))) {
			fail(w, 400, "国家数据原任务目录游标无效")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		out, err := a.Store.readWAFCountryRequests(ctx, actor.ID, query.Get("cursor"))
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("GET "+base+"/jobs/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, actor identity) {
		if !allowed(w, r, actor) {
			return
		}
		if r.URL.RawQuery != "" || !ValidID(r.PathValue("id")) {
			fail(w, 400, "国家数据原任务编号无效")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		out, err := a.Store.readWAFCountryRequest(ctx, actor.ID, r.PathValue("id"))
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("GET "+base+"/requests/{key}", a.authorize(func(w http.ResponseWriter, r *http.Request, actor identity) {
		if !allowed(w, r, actor) {
			return
		}
		if r.URL.RawQuery != "" || !ValidID(r.PathValue("key")) {
			fail(w, 400, "国家数据原请求编号无效")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		out, err := a.Store.readWAFCountryRequestKey(ctx, actor.ID, r.PathValue("key"))
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("POST "+base, a.authorize(func(w http.ResponseWriter, r *http.Request, actor identity) {
		if !allowed(w, r, actor) {
			return
		}
		keys := r.Header.Values("Idempotency-Key")
		if r.URL.RawQuery != "" || len(keys) != 1 || !ValidID(keys[0]) {
			fail(w, 400, "国家数据必须带唯一32位原请求标识，不接受来源或路径参数")
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		in, decodeErr := decodeWAFCountryActorBody(raw, actor.ID)
		if err != nil || decodeErr != nil {
			fail(w, 400, "国家数据账户或完整选择无效")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 22*time.Second)
		defer cancel()
		prior, err := a.Store.readWAFCountryRequestKey(ctx, actor.ID, keys[0])
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		if prior.StateKnown {
			if prior.Request == nil || !SameWAFCountryDataSelection(prior.Request.Selection, in) {
				fail(w, 409, "原请求标识已绑定不同内容，没有替换或重发")
				return
			}
			send(w, 202, map[string]any{"job_id": prior.Request.Request.ID, "request_id": keys[0], "replayed": true, "data_only": true})
			return
		}
		state, err := a.wafCountryInstalledState(ctx)
		if err != nil || !state.Installed || !state.Supported || state.AppVersion != in.AppVersion || state.InstallationSHA != in.InstallationSHA || a.AppCatalog == nil {
			fail(w, 409, "国家数据需要对应已签名安装实例与完整处理器；请刷新原状态，不自动重试")
			return
		}
		_, authority, err := a.AppCatalog.FetchCountryDataEnvelope(ctx, in.DataManifestSHA, time.Now())
		if err != nil || authority.AppVersion() != in.AppVersion || authority.AppSHA256() != in.AppManifestSHA || authority.Data().Manifest().Release != in.Release || authority.Data().Manifest().Revision != in.Revision {
			fail(w, 409, "签名数据或应用目录已变化，没有创建替代下载")
			return
		}
		if _, err := authority.Data().Select(in.Countries); err != nil {
			fail(w, 409, "国家集合不在完整签名或固定容量内")
			return
		}
		var version, sha, target string
		if a.Store.DB.QueryRowContext(ctx, `SELECT version,sha256,target FROM app_registry_receipts WHERE app_id='nginx-waf' AND scope='nginx-waf'`).Scan(&version, &sha, &target) != nil || version != in.AppVersion || sha != in.AppManifestSHA || target != "nginx-waf" {
			fail(w, 409, "实际签名应用安装回执不同，没有排队")
			return
		}
		id, replayed, err := a.Store.queueWAFCountryData(ctx, in, keys[0], actor.ID)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 202, map[string]any{"job_id": id, "request_id": keys[0], "replayed": replayed, "data_only": true})
	}))
}
