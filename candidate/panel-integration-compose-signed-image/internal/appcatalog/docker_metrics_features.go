package appcatalog

import (
	"errors"
	"strings"
)

const DockerMetricsFeature = "docker-container-metrics-v1"
const DockerMetricsVersion = "1-compat2"

func validateDockerMetricsRequirement(m Manifest, available func(string) bool) (bool, error) {
	required := m.ID == "docker-manager" && (m.Version == DockerMetricsVersion ||
		strings.HasPrefix(m.Version, DockerMetricsVersion+"-") || strings.HasPrefix(m.Version, DockerMetricsVersion+"+"))
	for _, feature := range m.RequiredPanelFeatures {
		required = required || feature == DockerMetricsFeature
	}
	if !required {
		return false, nil
	}
	if m.ID != "docker-manager" || m.Version != DockerMetricsVersion || m.Delivery.Provider != "runtime" ||
		m.Delivery.Target != "docker-auto" || m.Delivery.ManageRoute != "docker" || len(m.RequiredPanelFeatures) != 1 ||
		m.RequiredPanelFeatures[0] != DockerMetricsFeature {
		return true, errors.New("Docker 资源监控须绑定对应版本、运行时目标和面板处理器")
	}
	if available == nil || !available(DockerMetricsFeature) {
		return true, errors.New("当前面板缺少 Docker 资源监控处理器，请先升级面板")
	}
	return true, nil
}
