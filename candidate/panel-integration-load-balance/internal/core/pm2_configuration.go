package core

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
)

var pm2ConfigurationProjectID = regexp.MustCompile(`^[a-z][a-z0-9-]{2,31}$`)

const PM2ConfigurationAppVersion = "7.0.4-compat7"

func ParsePM2ConfigurationQuery(raw string) (AppModuleInput, error) {
	if len(raw) > 512 {
		return AppModuleInput{}, errors.New("PM2 配置读取查询过长")
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return AppModuleInput{}, errors.New("PM2 配置读取查询格式无效")
	}
	return PM2ConfigurationReadInput(q)
}

// The recovery reader accepts a fixed, bounded query rather than the full
// mutation DTO. It never imports a legacy report or creates history.
func PM2ConfigurationReadInput(q url.Values) (AppModuleInput, error) {
	var in AppModuleInput
	if len(q) > 4 {
		return in, errors.New("PM2 配置读取参数过多")
	}
	for key, values := range q {
		if len(values) != 1 || len(values[0]) > 128 {
			return in, errors.New("PM2 配置读取参数重复或过长")
		}
		v := values[0]
		switch key {
		case "resource_id":
			if !pm2ConfigurationProjectID.MatchString(v) {
				return in, errors.New("PM2 项目标识无效")
			}
			in.ResourceID = v
		case "pm2_operation_id":
			if !ValidID(v) {
				return in, errors.New("PM2 原操作标识无效")
			}
			in.PM2OperationID = v
		case "limit", "offset":
			n, e := strconv.Atoi(v)
			if e != nil || n < 0 || strconv.Itoa(n) != v || (key == "limit" && n > 128) || (key == "offset" && n > 512) {
				return in, errors.New("PM2 配置事务分页无效")
			}
			if key == "limit" {
				in.Limit = n
			} else {
				in.Offset = n
			}
		default:
			return in, errors.New("PM2 配置读取参数不被支持")
		}
	}
	return in, nil
}
func (a *Server) pm2ConfigurationRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/app-modules/pm2-manager/configuration", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if _, err := ParsePM2ConfigurationQuery(r.URL.RawQuery); err != nil {
			fail(w, 400, err.Error())
			return
		}
		var out any
		if err := a.Executor.Call(r.Context(), "GET", "/v1/app-modules/pm2-manager/configuration?"+r.URL.RawQuery, nil, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 200, out)
	}))
}
