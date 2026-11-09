//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

var errDockerRetainedContainer = errors.New("容器是应用更新的原镜像保留锚点，或其身份不能核对；禁止通用启动、停止、重启和删除，未执行变更")

const dockerRetentionPrefix = "yunzhan-retain-memcached-"
const dockerRetentionReason = "应用更新原镜像保留锚点；必须保持未启动，禁止通用操作或删除"

func dockerContainerRetained(name string, labels map[string]string) bool {
	if strings.HasPrefix(strings.TrimPrefix(name, "/"), dockerRetentionPrefix) || labels["io.yunzhan.owner"] == memcachedRetentionOwner {
		return true
	}
	// Even an empty/damaged retention marker is NOT an ordinary container.
	_, marked := labels["io.yunzhan.retention-sha256"]
	return marked
}

type dockerRequestCall func(context.Context, string, string, any, any, int64) ([]byte, error)

// Must run INSIDE the same Docker mutation lease as the resulting operation.
// A generic UI/HTTP caller cannot manufacture the native worker's retention
// authority. Read the actual daemon object, reject reserved names/markers even
// if incomplete, then bind ordinary operations to the FULL inspected ID.
// The private callback is a test seam, never request/config/CLI supplied.
func dockerOrdinaryRequest(ctx context.Context, method, path string, in, out any, max int64, call dockerRequestCall) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || call == nil {
		return nil, errDockerRetainedContainer
	}
	u, err := url.ParseRequestURI(path)
	if err != nil || u.IsAbs() || u.Host != "" {
		return nil, errDockerRetainedContainer
	}
	if !strings.HasPrefix(u.Path, "/containers/") {
		return call(ctx, method, path, in, out, max)
	}
	if method == http.MethodPost && u.Path == "/containers/create" {
		if dockerContainerRetained(u.Query().Get("name"), nil) {
			return nil, errDockerRetainedContainer
		}
		return call(ctx, method, path, in, out, max)
	}
	parts := strings.Split(u.Path, "/")
	if len(parts) < 3 || !dockerObjectPattern.MatchString(parts[2]) ||
		!(method == http.MethodDelete && len(parts) == 3 || method == http.MethodPost && len(parts) == 4 && (parts[3] == "start" || parts[3] == "stop" || parts[3] == "restart")) {
		return nil, errDockerRetainedContainer
	}
	raw, err := call(ctx, http.MethodGet, "/containers/"+parts[2]+"/json", nil, nil, 256<<10)
	if err != nil || memcachedDaemonJSON(raw) != nil {
		return nil, errDockerRetainedContainer
	}
	fields, fieldErr := dockerPullJSONObject(raw)
	if fieldErr != nil || memcachedDaemonFields(fields, "Id", "Name", "Config") != nil {
		return nil, errDockerRetainedContainer
	}
	config, fieldErr := dockerPullJSONObject(fields["Config"])
	if fieldErr != nil {
		return nil, errDockerRetainedContainer
	}
	// Ordinary Docker containers legitimately use Labels:null. Require the
	// exact field spelling but do not confuse an empty label set with a missing
	// inspection. Native markers, including empty marker values, remain denied.
	if _, present := config["Labels"]; !present {
		return nil, errDockerRetainedContainer
	}
	for name := range config {
		if name != "Labels" && strings.EqualFold(name, "Labels") {
			return nil, errDockerRetainedContainer
		}
	}
	var actual struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Config *struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if json.Unmarshal(raw, &actual) != nil || len(actual.ID) != 64 || !dockerObjectPattern.MatchString(actual.ID) || !strings.HasPrefix(actual.ID, parts[2]) ||
		!strings.HasPrefix(actual.Name, "/") || len(actual.Name) < 2 || actual.Config == nil || dockerContainerRetained(actual.Name, actual.Config.Labels) || ctx.Err() != nil {
		return nil, errDockerRetainedContainer
	}
	parts[2] = actual.ID
	u.Path, u.RawPath = strings.Join(parts, "/"), ""
	return call(ctx, method, u.String(), in, out, max)
}
