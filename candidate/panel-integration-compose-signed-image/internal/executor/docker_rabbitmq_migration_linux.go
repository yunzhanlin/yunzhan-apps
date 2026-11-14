//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"time"

	"local/panel/internal/core"
)

func rabbitMQMigrationPreflightRoute(m *http.ServeMux) {
	m.HandleFunc("GET /v1/docker/projects/{id}/rabbitmq-migration-preflight", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		w.Header().Set("Cache-Control", "no-store")
		if !core.ValidID(id) || r.URL.RawQuery != "" {
			respond(w, 400, map[string]string{"error": "RabbitMQ 迁移预检项目标识无效"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 36*time.Second)
		defer cancel()
		out, err := readRabbitMQMigrationPreflight(ctx, id)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
}

func readRabbitMQMigrationPreflight(ctx context.Context, id string) (core.RabbitMQMigrationPreflight, error) {
	var report core.RabbitMQMigrationPreflight
	select {
	case rabbitMQReadSlots <- struct{}{}:
		defer func() { <-rabbitMQReadSlots }()
	default:
		return report, errors.New("RabbitMQ 检查繁忙，请稍后重试")
	}
	dir, err := openComposeUpdateDirectory(dockerProjects, id)
	if err != nil {
		return report, errRabbitMQIdentity
	}
	defer dir.Close()
	metadata, metadataInfo, err := dir.read("metadata.json", 16<<10)
	if err != nil {
		return report, errRabbitMQIdentity
	}
	project, err := rabbitMQProject(metadata, id)
	if err != nil || project.TemplateID != core.RabbitMQLegacyTemplate {
		return report, errors.New("迁移预检要求面板原始 RabbitMQ 4.1 项目")
	}
	compose, composeInfo, err := dir.read("compose.yaml", 48<<10)
	if err != nil || !core.IsOriginalRabbitMQCompose(string(compose), project.HostPort) {
		return report, errors.New("原 RabbitMQ 启动配置无法按固定模板核对")
	}
	before, err := inspectRabbitMQ(ctx, project)
	if err != nil {
		return report, err
	}
	volume, err := rabbitMQOriginalVolume(ctx, project, before)
	if err != nil {
		return report, err
	}
	raw, err := rabbitMQRead(ctx, before.ID, "cluster_status")
	if err != nil {
		return report, err
	}
	version, alarms, err := rabbitMQMigrationCluster(raw)
	if err != nil {
		return report, err
	}
	raw, err = rabbitMQRead(ctx, before.ID, "list_feature_flags", "name", "state", "stability")
	if err != nil {
		return report, err
	}
	features, err := rabbitMQMigrationFeatures(raw)
	if err != nil {
		return report, err
	}
	raw, err = rabbitMQRead(ctx, before.ID, "list_connections", "name")
	if err != nil {
		return report, err
	}
	var connections []struct{ Name string }
	if memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &connections) != nil || connections == nil {
		return report, errors.New("RabbitMQ 连接清单无法核对")
	}
	after, err := inspectRabbitMQ(ctx, project)
	endMeta, endMetaInfo, metaErr := dir.read("metadata.json", 16<<10)
	endCompose, endComposeInfo, composeErr := dir.read("compose.yaml", 48<<10)
	if err != nil || metaErr != nil || composeErr != nil || after.ID != before.ID || after.State != before.State ||
		!slices.Equal(before.Mounts, after.Mounts) || !sameComposeUpdateFile(metadataInfo, endMetaInfo) ||
		!sameComposeUpdateFile(composeInfo, endComposeInfo) || !bytes.Equal(metadata, endMeta) || !bytes.Equal(compose, endCompose) {
		return report, errors.New("原 RabbitMQ 运行身份在预检期间发生变化")
	}
	still, err := rabbitMQOriginalVolume(ctx, project, after)
	if err != nil || still != volume {
		return report, errors.New("原 RabbitMQ 数据卷在预检期间发生变化")
	}
	return core.RabbitMQMigrationPreflight{
		ProjectID: id, ObservedAt: core.Now(), BrokerVersion: version, Node: core.RabbitMQNodeName, DataVolume: volume,
		DisabledStableFeatures: features, AlarmCount: alarms, ConnectionCount: len(connections),
	}, nil
}

func rabbitMQOriginalVolume(ctx context.Context, project composeMetadata, broker rabbitMQContainer) (string, error) {
	name := project.Engine + "_data"
	failure := errors.New("无法核对原 RabbitMQ 的单一 Docker 本地数据卷")
	if broker.Config.Hostname != "cloudstack-rabbitmq" || len(broker.Mounts) != 1 {
		return "", failure
	}
	mount := broker.Mounts[0]
	if mount.Name != name || mount.Type != "volume" || mount.Driver != "local" || !mount.RW ||
		mount.Destination != "/var/lib/rabbitmq" {
		return "", failure
	}
	var volume struct {
		Name, Driver, Mountpoint, Scope string
		Labels, Options                 map[string]string
	}
	raw, err := dockerRequest(ctx, http.MethodGet, "/volumes/"+name, nil, nil, 64<<10)
	if err != nil || memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &volume) != nil || volume.Name != name ||
		volume.Driver != "local" || volume.Scope != "local" || len(volume.Options) != 0 ||
		volume.Labels["com.docker.compose.project"] != project.Engine || volume.Labels["com.docker.compose.volume"] != "data" ||
		volume.Mountpoint != mount.Source || !filepath.IsAbs(mount.Source) ||
		filepath.Clean(mount.Source) != mount.Source ||
		filepath.Base(mount.Source) != "_data" || filepath.Base(filepath.Dir(mount.Source)) != name {
		return "", failure
	}
	return name, nil
}

func rabbitMQMigrationCluster(raw []byte) (string, int, error) {
	var status struct {
		DiskNodes    []string                   `json:"disk_nodes"`
		RAMNodes     []string                   `json:"ram_nodes"`
		RunningNodes []string                   `json:"running_nodes"`
		Alarms       []json.RawMessage          `json:"alarms"`
		Partitions   map[string]json.RawMessage `json:"partitions"`
		Versions     map[string]struct {
			RabbitMQ string `json:"rabbitmq_version"`
		} `json:"versions"`
	}
	solo := []string{core.RabbitMQNodeName}
	if memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &status) != nil ||
		!slices.Equal(status.DiskNodes, solo) || !slices.Equal(status.RunningNodes, solo) ||
		status.RAMNodes == nil || len(status.RAMNodes) != 0 || status.Alarms == nil ||
		status.Partitions == nil || len(status.Partitions) != 0 ||
		len(status.Versions) != 1 || status.Versions[core.RabbitMQNodeName].RabbitMQ != "4.1.4" {
		return "", 0, errors.New("预检要求原始、无分区的单节点 RabbitMQ 4.1.4")
	}
	return status.Versions[core.RabbitMQNodeName].RabbitMQ, len(status.Alarms), nil
}

func rabbitMQMigrationFeatures(raw []byte) ([]string, error) {
	var flags []struct{ Name, State, Stability string }
	failure := errors.New("RabbitMQ 功能标志无法核对")
	if memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &flags) != nil || len(flags) == 0 || len(flags) > 256 {
		return nil, failure
	}
	disabled, seen := []string{}, make(map[string]bool, len(flags))
	for _, flag := range flags {
		if !core.ValidRabbitMQName(flag.Name) || seen[flag.Name] {
			return nil, failure
		}
		seen[flag.Name] = true
		switch flag.Stability {
		case "required", "stable":
			switch flag.State {
			case "disabled", "unsupported":
				disabled = append(disabled, flag.Name)
			case "enabled":
			default:
				return nil, failure
			}
		case "experimental":
		default:
			return nil, failure
		}
	}
	slices.Sort(disabled)
	return disabled, nil
}
