//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"time"

	"local/panel/internal/core"
)

const rabbitMQBridgeImage = "rabbitmq:4.2.9-management-alpine@sha256:77ca2ba3621a95208918e6e331199a6c81129690bf7fc570dc61b6e64726840a"
const rabbitMQTargetImage = "rabbitmq:4.4.0-management-alpine@sha256:4841f6384ef8313c3594cd3f2e9f40c10805f8a61c45f08a9a5d9ddea8199267"
const rabbitMQOfflineContainerPrefix = "yunzhan-rabbitmq-offline-"

type rabbitMQOfflineContainerConfig struct {
	Image      string
	Hostname   string
	Env        []string
	Labels     map[string]string
	HostConfig struct {
		Memory      int64
		NetworkMode string
		ExtraHosts  []string
		Mounts      []struct {
			Type, Source, Target string
			VolumeOptions        struct{ NoCopy bool }
		}
	}
}

func rabbitMQOfflineConfig(plan rabbitMQMigrationPlan, image string) rabbitMQOfflineContainerConfig {
	config := rabbitMQOfflineContainerConfig{
		Image: image, Hostname: "cloudstack-rabbitmq", Labels: rabbitMQCandidateVolumeLabels(plan),
		Env: []string{"RABBITMQ_SERVER_ADDITIONAL_ERL_ARGS=+S 2:2 +SDcpu 1 +SDio 1"},
	}
	config.HostConfig.Memory = 512 << 20
	config.HostConfig.NetworkMode = "none"
	config.HostConfig.ExtraHosts = []string{"cloudstack-rabbitmq:127.0.0.1"}
	config.HostConfig.Mounts = append(config.HostConfig.Mounts, struct {
		Type, Source, Target string
		VolumeOptions        struct{ NoCopy bool }
	}{"volume", plan.CandidateVolume, "/var/lib/rabbitmq", struct{ NoCopy bool }{true}})
	return config
}

func rabbitMQOfflineInspect(ctx context.Context, id, name, image string, volume rabbitMQMigrationVolume, plan rabbitMQMigrationPlan, cleanExit bool) (string, error) {
	var got struct {
		ID, Name string
		Mounts   []rabbitMQVolumeMount
		State    struct {
			Status, StartedAt string
			Pid, ExitCode     *int
			OOMKilled         *bool
		}
		Config struct {
			Image, Hostname string
			Labels          map[string]string
		}
		HostConfig struct {
			NetworkMode   string
			Privileged    *bool
			PortBindings  map[string]json.RawMessage
			RestartPolicy struct {
				Name string
			}
		}
	}
	raw, err := dockerRequest(ctx, http.MethodGet, "/containers/"+id+"/json", nil, nil, 256<<10)
	if err != nil || memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &got) != nil ||
		got.ID != id || got.Name != "/"+name || got.Config.Image != image || got.Config.Hostname != "cloudstack-rabbitmq" ||
		got.HostConfig.NetworkMode != "none" || got.HostConfig.Privileged == nil || *got.HostConfig.Privileged ||
		len(got.HostConfig.PortBindings) != 0 || got.HostConfig.RestartPolicy.Name != "no" && got.HostConfig.RestartPolicy.Name != "" ||
		got.Config.Labels[rabbitMQMigrationVolumeJobLabel] != plan.JobID || got.Config.Labels[rabbitMQMigrationVolumeProjectLabel] != plan.ProjectID ||
		len(got.Mounts) != 1 {
		return "", errors.New("RabbitMQ 离线升级容器身份无法核对")
	}
	mount := got.Mounts[0]
	if mount.Type != "volume" || mount.Name != volume.Name || mount.Driver != "local" ||
		mount.Source != volume.Mountpoint || mount.Destination != "/var/lib/rabbitmq" || !mount.RW {
		return "", errors.New("RabbitMQ 离线升级容器没有使用原任务的独立数据卷")
	}
	switch got.State.Status {
	case "created", "running":
		return got.State.Status, nil
	case "exited":
		if got.State.Pid != nil && *got.State.Pid == 0 && got.State.ExitCode != nil && got.State.OOMKilled != nil &&
			(!cleanExit || *got.State.ExitCode == 0 && !*got.State.OOMKilled) {
			return "exited", nil
		}
	}
	return "", errors.New("RabbitMQ 离线升级容器异常退出")
}

func waitRabbitMQOfflineBroker(ctx context.Context, id, version string) error {
	bound, cancel := context.WithTimeout(ctx, 150*time.Second)
	defer cancel()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		raw, err := rabbitMQRead(bound, id, "cluster_status")
		if err == nil {
			if _, alarms, err := rabbitMQClusterVersion(raw, version); err == nil && alarms == 0 {
				return nil
			}
		}
		select {
		case <-bound.Done():
			return errors.New("RabbitMQ 离线升级节点未在期限内返回目标版本和功能标志")
		case <-ticker.C:
		}
	}
}

func upgradeRabbitMQOffline(ctx context.Context, lease *dockerMutationLease, journal *os.Root,
	plan rabbitMQMigrationPlan, phase rabbitMQMigrationEvent) (rabbitMQMigrationEvent, error) {
	var image, version, suffix, finished string
	switch phase.Phase {
	case "bridge-intent":
		image, version, suffix, finished = rabbitMQBridgeImage, "4.2.9", "-bridge", "bridge-stopped"
	case "target-check-intent":
		image, version, suffix, finished = rabbitMQTargetImage, "4.4.0", "-target", "target-verified-offline"
	default:
		return rabbitMQMigrationEvent{}, errors.New("RabbitMQ 原任务未进入离线镜像升级阶段")
	}
	if !plan.valid() || !core.MatchesPanelRabbitMQImage(core.RabbitMQ440Template, rabbitMQTargetImage) {
		return rabbitMQMigrationEvent{}, errors.New("RabbitMQ 离线升级身份无法核对")
	}
	var result rabbitMQMigrationEvent
	err := lease.use(ctx, func(bound context.Context) error {
		retained, err := readRabbitMQMigrationJournal(journal, plan)
		if err != nil || retained != phase {
			return errors.New("RabbitMQ 离线升级前的原记录已发生变化")
		}
		if _, err := stoppedRabbitMQMigrationSource(bound, plan); err != nil {
			return err
		}
		volume, err := namedRabbitMQMigrationVolume(bound, plan.CandidateVolume, rabbitMQCandidateVolumeLabels(plan))
		if err != nil {
			return err
		}
		attachments, err := rabbitMQMigrationVolumeAttachments(bound, volume.Name)
		if err != nil || len(attachments) != 0 {
			return errors.New("RabbitMQ 离线升级发现候选数据卷已有容器引用")
		}
		name := rabbitMQOfflineContainerPrefix + plan.JobID + suffix
		config := rabbitMQOfflineConfig(plan, image)
		var created struct {
			ID string `json:"Id"`
		}
		if _, err := dockerRequestUnlocked(bound, http.MethodPost, "/containers/create?name="+url.QueryEscape(name), config, &created, 64<<10); err != nil {
			return err
		}
		if !core.ValidDockerContainerID(created.ID) {
			return errRabbitMQIdentity
		}
		observed, err := rabbitMQOfflineInspect(bound, created.ID, name, image, volume, plan, true)
		if err != nil || observed != "created" {
			return errRabbitMQIdentity
		}
		endpoint := "/containers/" + created.ID
		if _, err := dockerRequestUnlocked(bound, http.MethodPost, endpoint+"/start", nil, nil, 4096); err != nil {
			return err
		}
		if err := waitRabbitMQOfflineBroker(bound, created.ID, version); err != nil {
			return err
		}
		if err := rabbitMQEnableStableFlags(bound, created.ID); err != nil {
			return err
		}
		if _, err := dockerRequestUnlocked(bound, http.MethodPost, endpoint+"/stop?t=60", nil, nil, 4096); err != nil {
			return err
		}
		observed, err = rabbitMQOfflineInspect(bound, created.ID, name, image, volume, plan, true)
		if err != nil || observed != "exited" {
			return errors.New("RabbitMQ 离线升级后容器没有干净退出")
		}
		if _, err = dockerRequestUnlocked(bound, http.MethodDelete, endpoint+"?v=0", nil, nil, 4096); err != nil {
			return err
		}
		attachments, err = rabbitMQMigrationVolumeAttachments(bound, volume.Name)
		if err != nil || len(attachments) != 0 {
			return errors.New("RabbitMQ 离线升级结束后数据卷仍被引用")
		}
		result, err = appendRabbitMQMigrationEvent(journal, plan, phase, finished, phase.VolumeCopy)
		return err
	})
	return result, err
}

// Only called after the exact offline container and its network policy were
// verified inside the active lease. This fixed CLI never targets the old node.
func rabbitMQEnableStableFlags(ctx context.Context, id string) error {
	if !core.ValidDockerContainerID(id) {
		return errRabbitMQIdentity
	}
	bound, cancel := context.WithTimeout(ctx, 100*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bound, "/usr/bin/docker", "--host", "unix:///run/docker.sock", "exec",
		"--user", "rabbitmq", "--env", "HOME=/var/lib/rabbitmq", id,
		"rabbitmqctl", "--quiet", "--timeout", "90", "enable_feature_flag", "all")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		return errors.New("RabbitMQ 离线节点的稳定功能标志未能启用")
	}
	raw, err := rabbitMQRead(bound, id, "list_feature_flags", "name", "state", "stability")
	if err != nil {
		return err
	}
	disabled, err := rabbitMQMigrationFeatures(raw)
	if err != nil || len(disabled) != 0 {
		return errors.New("RabbitMQ 离线节点仍有未启用的稳定功能标志")
	}
	return nil
}
