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
	"strconv"
	"time"

	"local/panel/internal/core"
)

var errRabbitMQMigrationPending = errors.New("RabbitMQ 迁移原任务还有未核对的状态，请恢复原任务")

// The caller must own the exclusive Docker and runtime leases and authorize
// the actor against this exact job. The signed release verifies the target,
// independently of the caller's permission to take the original offline.
func stageRabbitMQMigration(ctx context.Context, lease *dockerMutationLease, project *composeUpdateDirectory,
	journal *os.Root, plan rabbitMQMigrationPlan, authority rabbitMQMigrationAuthority,
	authorize func(context.Context) error) (rabbitMQMigrationEvent, error) {
	if !plan.valid() || authority.manifestSHA != plan.TargetManifestSHA || authorize == nil {
		return rabbitMQMigrationEvent{}, errRabbitMQIdentity
	}
	var state rabbitMQMigrationEvent
	err := lease.use(ctx, func(bound context.Context) error {
		var err error
		state, err = readRabbitMQMigrationJournal(journal, plan)
		if err != nil || state.Phase != "prepared" {
			return errRabbitMQMigrationPending
		}
		original, err := rabbitMQMigrationOriginalProject(project, plan)
		if err != nil {
			return err
		}
		// Pull both exact images while the original still serves traffic.
		for _, image := range []string{rabbitMQBridgeImage, rabbitMQTargetImage} {
			pull, cancel := context.WithTimeout(bound, 5*time.Minute)
			err := dockerPullUnlocked(pull, image)
			cancel()
			if err != nil {
				return err
			}
		}
		if err := authorize(bound); err != nil {
			return err
		}
		state, err = stopRabbitMQMigrationSource(bound, project, journal, plan, original, state)
		return err
	})
	if err != nil {
		return state, err
	}
	for _, step := range []struct {
		phase string
		run   func(context.Context, *dockerMutationLease, *os.Root, rabbitMQMigrationPlan, rabbitMQMigrationEvent) (rabbitMQMigrationEvent, error)
	}{
		{"copy-intent", prepareRabbitMQMigrationVolume},
		{"bridge-intent", upgradeRabbitMQOffline},
		{"target-check-intent", upgradeRabbitMQOffline},
	} {
		err = lease.use(ctx, func(bound context.Context) error {
			if _, err := rabbitMQMigrationOriginalProject(project, plan); err != nil {
				return err
			}
			var err error
			state, err = appendRabbitMQMigrationEvent(journal, plan, state, step.phase, state.VolumeCopy)
			return err
		})
		if err != nil {
			return state, err
		}
		next, err := step.run(ctx, lease, journal, plan, state)
		if err != nil {
			return state, err
		}
		state = next
	}
	return state, nil
}

func rabbitMQMigrationOriginalProject(dir *composeUpdateDirectory, plan rabbitMQMigrationPlan) (composeMetadata, error) {
	if dir == nil || !plan.valid() {
		return composeMetadata{}, errRabbitMQIdentity
	}
	meta, _, err := dir.read("metadata.json", 16<<10)
	if err != nil || core.Hash(string(meta)) != plan.OriginalMetaSHA {
		return composeMetadata{}, errRabbitMQIdentity
	}
	project, err := rabbitMQProject(meta, plan.ProjectID)
	if err != nil || project.TemplateID != core.RabbitMQLegacyTemplate {
		return composeMetadata{}, errRabbitMQIdentity
	}
	config, _, err := dir.read("compose.yaml", 48<<10)
	if err != nil || core.Hash(string(config)) != plan.OriginalConfigSHA ||
		!core.IsOriginalRabbitMQCompose(string(config), project.HostPort) {
		return composeMetadata{}, errRabbitMQIdentity
	}
	return project, nil
}

func runningRabbitMQMigrationSource(ctx context.Context, project composeMetadata, plan rabbitMQMigrationPlan) (rabbitMQContainer, error) {
	broker, err := inspectRabbitMQ(ctx, project)
	if err != nil || broker.ID != plan.OriginalContainer {
		return rabbitMQContainer{}, errRabbitMQIdentity
	}
	volume, err := rabbitMQOriginalVolume(ctx, project, broker)
	if err != nil || volume != plan.OriginalVolume {
		return rabbitMQContainer{}, errRabbitMQIdentity
	}
	holders, err := rabbitMQMigrationVolumeAttachments(ctx, volume)
	if err != nil || len(holders) != 1 || holders[0] != broker.ID {
		return rabbitMQContainer{}, errRabbitMQIdentity
	}
	if err := rabbitMQVerifyLoopbackBindings(ctx, broker.ID, project); err != nil {
		return rabbitMQContainer{}, err
	}
	return broker, nil
}

func rabbitMQVerifyLoopbackBindings(ctx context.Context, id string, project composeMetadata) error {
	var actual struct {
		HostConfig struct {
			Privileged    *bool
			PortBindings  map[string][]struct{ HostIP, HostPort string }
			RestartPolicy struct{ Name string }
		}
	}
	raw, err := dockerRequest(ctx, http.MethodGet, "/containers/"+id+"/json", nil, nil, 256<<10)
	if err != nil || memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &actual) != nil ||
		actual.HostConfig.Privileged == nil || *actual.HostConfig.Privileged ||
		actual.HostConfig.RestartPolicy.Name != "unless-stopped" || len(actual.HostConfig.PortBindings) != 2 {
		return errRabbitMQIdentity
	}
	for containerPort, port := range map[string]int{"15672/tcp": project.HostPort, "5672/tcp": project.HostPort + 1} {
		binding := actual.HostConfig.PortBindings[containerPort]
		if len(binding) != 1 || binding[0].HostIP != "127.0.0.1" || binding[0].HostPort != strconv.Itoa(port) {
			return errRabbitMQIdentity
		}
	}
	return nil
}

func stopRabbitMQMigrationSource(ctx context.Context, dir *composeUpdateDirectory, journal *os.Root,
	plan rabbitMQMigrationPlan, original composeMetadata, state rabbitMQMigrationEvent) (rabbitMQMigrationEvent, error) {
	broker, err := runningRabbitMQMigrationSource(ctx, original, plan)
	if err != nil {
		return state, err
	}
	source := core.RabbitMQMigrationSource{
		ProjectID: plan.ProjectID, ContainerID: broker.ID, StartedAt: broker.State.StartedAt, Volume: plan.OriginalVolume,
		ConfigSHA: plan.OriginalConfigSHA, MetadataSHA: plan.OriginalMetaSHA,
	}
	if source.SHA256() != plan.SourceSHA {
		return state, errors.New("RabbitMQ 原项目在预检后已变化，请重新确认")
	}
	if err = checkRabbitMQMigrationBroker(ctx, broker.ID); err != nil {
		return state, err
	}
	next, err := appendRabbitMQMigrationEvent(journal, plan, state, "quiesce-intent", state.VolumeCopy)
	if err != nil {
		return state, err
	}
	state = next
	if err = rabbitMQSetListeners(ctx, broker.ID, false); err != nil {
		return state, err
	}
	if err = checkRabbitMQMigrationBroker(ctx, broker.ID); err != nil {
		return state, err
	}
	if _, err = rabbitMQMigrationOriginalProject(dir, plan); err != nil {
		return state, err
	}
	after, err := runningRabbitMQMigrationSource(ctx, original, plan)
	if err != nil || broker.State != after.State {
		return state, errRabbitMQIdentity
	}
	next, err = appendRabbitMQMigrationEvent(journal, plan, state, "stop-original-intent", state.VolumeCopy)
	if err != nil {
		return state, err
	}
	state = next
	if _, err = dockerRequestUnlocked(ctx, http.MethodPost, "/containers/"+broker.ID+"/stop?t=60", nil, nil, 4096); err != nil {
		return state, err
	}
	if _, err = stoppedRabbitMQMigrationSource(ctx, plan); err != nil {
		return state, err
	}
	next, err = appendRabbitMQMigrationEvent(journal, plan, state, "original-stopped", state.VolumeCopy)
	if err != nil {
		return state, err
	}
	return next, nil
}

func checkRabbitMQMigrationBroker(ctx context.Context, id string) error {
	raw, err := rabbitMQRead(ctx, id, "cluster_status")
	if err != nil {
		return err
	}
	if _, alarms, err := rabbitMQMigrationCluster(raw); err != nil || alarms != 0 {
		return errors.New("RabbitMQ 原节点存在告警或集群身份不符")
	}
	raw, err = rabbitMQRead(ctx, id, "list_feature_flags", "name", "state", "stability")
	if err != nil {
		return err
	}
	if disabled, err := rabbitMQMigrationFeatures(raw); err != nil || len(disabled) != 0 {
		return errors.New("RabbitMQ 原节点有未启用的稳定功能标志")
	}
	raw, err = rabbitMQRead(ctx, id, "list_connections", "name")
	if err != nil {
		return err
	}
	var connections []struct{ Name string }
	if memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &connections) != nil || connections == nil {
		return errors.New("无法核对 RabbitMQ 原节点连接")
	}
	if len(connections) != 0 {
		return errors.New("RabbitMQ 仍有客户端连接，请先停止发件和消费任务")
	}
	return nil
}

// Reconcile the original job after a failure or process restart. The caller
// reloads the exact private journal and takes a fresh exclusive lease.
func restoreRabbitMQBeforePublication(ctx context.Context, lease *dockerMutationLease,
	dir *composeUpdateDirectory, journal *os.Root, plan rabbitMQMigrationPlan) (rabbitMQMigrationEvent, error) {
	var state rabbitMQMigrationEvent
	err := lease.use(ctx, func(bound context.Context) error {
		var err error
		state, err = readRabbitMQMigrationJournal(journal, plan)
		if err != nil {
			return errRabbitMQMigrationPending
		}
		original, err := rabbitMQMigrationOriginalProject(dir, plan)
		if err != nil {
			return err
		}
		switch state.Phase {
		case "prepared":
			state, err = appendRabbitMQMigrationEvent(journal, plan, state, "cancelled-before-stop", state.VolumeCopy)
			return err
		case "cancelled-before-stop", "original-restored":
			return nil
		case "quiesce-intent":
			state, err = appendRabbitMQMigrationEvent(journal, plan, state, "resume-listeners-intent", state.VolumeCopy)
		case "resume-listeners-intent", "restore-original-intent", "restart-original-intent":
		case "stop-original-intent", "original-stopped", "copy-intent", "copy-verified",
			"bridge-intent", "bridge-stopped", "target-check-intent", "target-verified-offline":
			state, err = appendRabbitMQMigrationEvent(journal, plan, state, "restore-original-intent", state.VolumeCopy)
		default:
			return errRabbitMQMigrationPending
		}
		if err != nil {
			return err
		}
		if state.Phase == "restore-original-intent" {
			if err := removeRabbitMQOfflineCandidates(bound, plan); err != nil {
				return err
			}
			// A canceled client-side stop can continue in the daemon. Stop
			// the exact old container and wait for its actual exit before
			// starting it again or declaring it available.
			if running, err := runningRabbitMQMigrationSource(bound, original, plan); err == nil {
				if _, err := dockerRequestUnlocked(bound, http.MethodPost, "/containers/"+running.ID+"/stop?t=60", nil, nil, 4096); err != nil {
					return err
				}
			}
			if _, err := rabbitMQVettedMigrationSource(bound, plan, false); err != nil {
				return err
			}
			state, err = appendRabbitMQMigrationEvent(journal, plan, state, "restart-original-intent", state.VolumeCopy)
			if err != nil {
				return err
			}
		}
		if state.Phase == "restart-original-intent" {
			if _, err := rabbitMQMigrationOriginalProject(dir, plan); err != nil {
				return err
			}
			if _, err := runningRabbitMQMigrationSource(bound, original, plan); err != nil {
				if _, err := rabbitMQVettedMigrationSource(bound, plan, false); err != nil {
					return err
				}
				if _, err := dockerRequestUnlocked(bound, http.MethodPost, "/containers/"+plan.OriginalContainer+"/start", nil, nil, 4096); err != nil {
					return err
				}
			}
		}
		if err := waitRabbitMQOfflineBroker(bound, plan.OriginalContainer, "4.1.4"); err != nil {
			return err
		}
		if _, err := runningRabbitMQMigrationSource(bound, original, plan); err != nil {
			return err
		}
		if err := rabbitMQSetListeners(bound, plan.OriginalContainer, true); err != nil {
			return err
		}
		state, err = appendRabbitMQMigrationEvent(journal, plan, state, "original-restored", state.VolumeCopy)
		return err
	})
	return state, err
}

func removeRabbitMQOfflineCandidates(ctx context.Context, plan rabbitMQMigrationPlan) error {
	filter, _ := json.Marshal(map[string][]string{"label": {rabbitMQMigrationVolumeJobLabel + "=" + plan.JobID}})
	var rows []struct {
		ID    string `json:"Id"`
		Names []string
	}
	path := "/containers/json?all=1&filters=" + url.QueryEscape(string(filter))
	raw, err := dockerRequest(ctx, http.MethodGet, path, nil, nil, 256<<10)
	if err != nil || memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &rows) != nil || rows == nil || len(rows) > 2 {
		return errRabbitMQMigrationPending
	}
	for _, row := range rows {
		if !core.ValidDockerContainerID(row.ID) || len(row.Names) != 1 {
			return errRabbitMQIdentity
		}
		name := rabbitMQOfflineContainerPrefix + plan.JobID
		var image string
		switch row.Names[0] {
		case "/" + name + "-bridge":
			name += "-bridge"
			image = rabbitMQBridgeImage
		case "/" + name + "-target":
			name += "-target"
			image = rabbitMQTargetImage
		default:
			return errRabbitMQIdentity
		}
		volume, err := namedRabbitMQMigrationVolume(ctx, plan.CandidateVolume, rabbitMQCandidateVolumeLabels(plan))
		if err != nil {
			return err
		}
		status, err := rabbitMQOfflineInspect(ctx, row.ID, name, image, volume, plan, false)
		if err != nil {
			return err
		}
		endpoint := "/containers/" + row.ID
		if status == "running" {
			if _, err := dockerRequestUnlocked(ctx, http.MethodPost, endpoint+"/stop?t=60", nil, nil, 4096); err != nil {
				return err
			}
			status, err = rabbitMQOfflineInspect(ctx, row.ID, name, image, volume, plan, false)
			if err != nil || status != "exited" {
				return errRabbitMQMigrationPending
			}
		}
		if _, err := dockerRequestUnlocked(ctx, http.MethodDelete, endpoint+"?v=0", nil, nil, 4096); err != nil {
			return err
		}
	}
	return nil
}

func rabbitMQSetListeners(ctx context.Context, id string, resume bool) error {
	if !core.ValidDockerContainerID(id) {
		return errRabbitMQIdentity
	}
	action := "suspend_listeners"
	if resume {
		action = "resume_listeners"
	}
	bound, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bound, "/usr/bin/docker", "--host", "unix:///run/docker.sock", "exec",
		"--user", "rabbitmq", "--env", "HOME=/var/lib/rabbitmq", id,
		"rabbitmqctl", "--quiet", "--timeout", "16", action)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		return errors.New("RabbitMQ 原节点的客户端监听状态无法核对")
	}
	return nil
}
