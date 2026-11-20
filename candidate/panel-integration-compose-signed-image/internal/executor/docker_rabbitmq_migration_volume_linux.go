//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

type rabbitMQMigrationVolume struct {
	Name       string            `json:"Name"`
	Driver     string            `json:"Driver"`
	Scope      string            `json:"Scope"`
	Mountpoint string            `json:"Mountpoint"`
	Labels     map[string]string `json:"Labels"`
	Options    map[string]string `json:"Options"`
}

const rabbitMQMigrationVolumePrefix = "panel_rabbitmq_"

const rabbitMQMigrationVolumeJobLabel = "io.yunzhan.rabbitmq-migration-job"
const rabbitMQMigrationVolumeProjectLabel = "io.yunzhan.rabbitmq-migration-project"

func rabbitMQCandidateVolumeLabels(plan rabbitMQMigrationPlan) map[string]string {
	return map[string]string{
		rabbitMQMigrationVolumeJobLabel:     plan.JobID,
		rabbitMQMigrationVolumeProjectLabel: plan.ProjectID,
	}
}

func namedRabbitMQMigrationVolume(ctx context.Context, name string, labels map[string]string) (rabbitMQMigrationVolume, error) {
	var volume rabbitMQMigrationVolume
	raw, err := dockerRequest(ctx, http.MethodGet, "/volumes/"+name, nil, nil, 64<<10)
	if err != nil || memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &volume) != nil ||
		volume.Name != name || volume.Driver != "local" || volume.Scope != "local" || len(volume.Options) != 0 {
		return rabbitMQMigrationVolume{}, errors.New("无法核对 RabbitMQ 的本地数据卷")
	}
	for key, expected := range labels {
		if volume.Labels[key] != expected {
			return rabbitMQMigrationVolume{}, errors.New("RabbitMQ 数据卷标识与原任务不符")
		}
	}
	return volume, nil
}

func rabbitMQMigrationDockerRoot(ctx context.Context) (string, error) {
	var info struct {
		DataRoot string `json:"DockerRootDir"`
	}
	raw, err := dockerRequest(ctx, http.MethodGet, "/info", nil, nil, 256<<10)
	if err != nil || memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &info) != nil ||
		!filepath.IsAbs(info.DataRoot) || filepath.Clean(info.DataRoot) != info.DataRoot || info.DataRoot == "/" {
		return "", errors.New("无法核对 Docker 的实际数据目录")
	}
	return info.DataRoot, nil
}

func openRabbitMQMigrationVolume(dataRoot string, volume rabbitMQMigrationVolume) (*os.File, error) {
	path := filepath.Join(dataRoot, "volumes", volume.Name, "_data")
	if path != volume.Mountpoint || !dockerResourceNamePattern.MatchString(volume.Name) ||
		!filepath.IsAbs(dataRoot) || filepath.Clean(dataRoot) != dataRoot || dataRoot == "/" {
		return nil, errors.New("RabbitMQ 数据卷路径与 Docker 本地卷不符")
	}
	parent := filepath.Dir(filepath.Dir(path))
	fd, err := unix.Openat2(unix.AT_FDCWD, parent, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	root := os.NewFile(uintptr(fd), parent)
	defer root.Close()
	st, err := rabbitMQCopyStat(root)
	if err != nil || st.Uid != 0 || st.Mode&0022 != 0 {
		return nil, errors.New("Docker 数据卷父目录不由 Root 独占写入")
	}
	dir, err := rabbitMQCopyOpen(root, volume.Name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	st, err = rabbitMQCopyStat(dir)
	if err != nil || st.Uid != 0 || st.Mode&0022 != 0 {
		return nil, errors.New("Docker 命名卷目录不由 Root 独占写入")
	}
	data, err := rabbitMQCopyOpen(dir, "_data", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	volumeStat, err := rabbitMQCopyStat(data)
	if err == nil && rabbitMQLegacyVolumeRootMode(volumeStat, true) {
		err = verifyRabbitMQLegacyVolumeParent(root)
	}
	if err != nil {
		data.Close()
		return nil, err
	}
	return data, nil
}

// Docker's parent directory normally has mode 0710 and is root:root. Require
// that local unprivileged accounts cannot traverse it to the legacy sticky
// data root, even when the Docker data path uses a separate filesystem.
func verifyRabbitMQLegacyVolumeParent(volumes *os.File) error {
	fd, err := unix.Openat(int(volumes.Fd()), "..", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	parent := os.NewFile(uintptr(fd), "Docker data root")
	defer parent.Close()
	info, err := rabbitMQCopyStat(parent)
	if err == nil && info.Uid == 0 && info.Gid == 0 && info.Mode&0027 == 0 {
		// An ACL could grant traversal to a named account despite the
		// directory's Root ownership and ordinary mode bits.
		_, aclErr := unix.Fgetxattr(fd, "system.posix_acl_access", nil)
		if errors.Is(aclErr, unix.ENODATA) || errors.Is(aclErr, unix.ENOTSUP) {
			return nil
		}
	}
	return errors.New("旧 RabbitMQ 数据卷需要 Root 私有的 Docker 数据目录")
}

func rabbitMQMigrationVolumeAttachments(ctx context.Context, volume string) ([]string, error) {
	var rows []struct {
		ID     string                `json:"Id"`
		Mounts []rabbitMQVolumeMount `json:"Mounts"`
	}
	// Docker's volume filter is documented for running containers. A
	// stopped container can still reserve or later start with the volume.
	raw, err := dockerRequest(ctx, http.MethodGet, "/containers/json?all=1", nil, nil, 8<<20)
	if err != nil || strictDockerJSON(raw, 8<<20) != nil || json.Unmarshal(raw, &rows) != nil || rows == nil {
		return nil, errors.New("无法核对 RabbitMQ 数据卷的容器引用")
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		if !core.ValidDockerContainerID(row.ID) {
			return nil, errRabbitMQIdentity
		}
		for _, mount := range row.Mounts {
			if mount.Type == "volume" && mount.Name == volume {
				out = append(out, row.ID)
				break
			}
		}
	}
	return out, nil
}

func stoppedRabbitMQMigrationSource(ctx context.Context, plan rabbitMQMigrationPlan) (rabbitMQMigrationVolume, error) {
	return rabbitMQVettedMigrationSource(ctx, plan, true)
}

// A failed graceful shutdown can still be recovered on the original volume.
// The strict clean-exit check remains mandatory before copying any bytes.
func rabbitMQVettedMigrationSource(ctx context.Context, plan rabbitMQMigrationPlan, cleanExit bool) (rabbitMQMigrationVolume, error) {
	var container struct {
		ID     string                `json:"Id"`
		Mounts []rabbitMQVolumeMount `json:"Mounts"`
		Config struct {
			Image    string            `json:"Image"`
			Hostname string            `json:"Hostname"`
			Labels   map[string]string `json:"Labels"`
		} `json:"Config"`
		State struct {
			Status   string `json:"Status"`
			PID      *int   `json:"Pid"`
			ExitCode *int   `json:"ExitCode"`
			OOM      *bool  `json:"OOMKilled"`
		} `json:"State"`
	}
	engine := "panel_" + plan.ProjectID[:12]
	raw, err := dockerRequest(ctx, http.MethodGet, "/containers/"+plan.OriginalContainer+"/json", nil, nil, 256<<10)
	if err != nil || memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &container) != nil ||
		container.ID != plan.OriginalContainer || !core.MatchesPanelRabbitMQImage(core.RabbitMQLegacyTemplate, container.Config.Image) ||
		container.Config.Hostname != "cloudstack-rabbitmq" || container.Config.Labels["com.docker.compose.project"] != engine ||
		container.Config.Labels["com.docker.compose.service"] != "rabbitmq" ||
		!strings.EqualFold(container.Config.Labels["com.docker.compose.oneoff"], "false") ||
		container.State.Status != "exited" || container.State.PID == nil || *container.State.PID != 0 ||
		container.State.ExitCode == nil || container.State.OOM == nil ||
		cleanExit && (*container.State.ExitCode != 0 || *container.State.OOM) ||
		len(container.Mounts) != 1 {
		return rabbitMQMigrationVolume{}, errors.New("未能确认原 RabbitMQ 容器已干净退出")
	}
	mount := container.Mounts[0]
	volume, err := namedRabbitMQMigrationVolume(ctx, plan.OriginalVolume, map[string]string{
		"com.docker.compose.project": engine, "com.docker.compose.volume": "data",
	})
	if err != nil || mount.Name != volume.Name || mount.Source != volume.Mountpoint || mount.Destination != "/var/lib/rabbitmq" ||
		mount.Type != "volume" || mount.Driver != "local" || !mount.RW {
		return rabbitMQMigrationVolume{}, errors.New("关机后原 RabbitMQ 数据卷身份无法核对")
	}
	attachments, err := rabbitMQMigrationVolumeAttachments(ctx, plan.OriginalVolume)
	if err != nil || len(attachments) != 1 || attachments[0] != plan.OriginalContainer {
		return rabbitMQMigrationVolume{}, errors.New("原 RabbitMQ 数据卷还有其他容器引用")
	}
	return volume, nil
}

func createRabbitMQMigrationVolume(ctx context.Context, plan rabbitMQMigrationPlan) (rabbitMQMigrationVolume, error) {
	if ctx.Err() != nil || !plan.valid() {
		return rabbitMQMigrationVolume{}, errors.New("RabbitMQ 候选数据卷任务标识无效")
	}
	var list struct {
		Volumes []struct{ Name string } `json:"Volumes"`
	}
	filter, _ := json.Marshal(map[string][]string{"name": {plan.CandidateVolume}})
	raw, err := dockerRequest(ctx, http.MethodGet, "/volumes?filters="+url.QueryEscape(string(filter)), nil, nil, 128<<10)
	if err != nil || memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &list) != nil || len(list.Volumes) != 0 {
		return rabbitMQMigrationVolume{}, errors.New("候选数据卷可能已存在，核对原任务而不重新使用或覆盖")
	}
	labels := rabbitMQCandidateVolumeLabels(plan)
	input := struct {
		Name, Driver string
		Labels       map[string]string
	}{plan.CandidateVolume, "local", labels}
	if _, err := dockerRequestUnlocked(ctx, http.MethodPost, "/volumes/create", input, nil, 64<<10); err != nil {
		return rabbitMQMigrationVolume{}, err
	}
	return namedRabbitMQMigrationVolume(ctx, plan.CandidateVolume, labels)
}

// The worker enters only after persisted shutdown and copy-intent. It never
// resumes a partially copied volume. Recovery may restore the original
// container on a separately authorized original task.
func prepareRabbitMQMigrationVolume(ctx context.Context, lease *dockerMutationLease, journal *os.Root,
	plan rabbitMQMigrationPlan, phase rabbitMQMigrationEvent) (rabbitMQMigrationEvent, error) {
	var empty rabbitMQMigrationEvent
	if phase.Phase != "copy-intent" || !plan.valid() {
		return empty, errors.New("RabbitMQ 原任务尚未进入冷备份阶段")
	}
	var result rabbitMQMigrationEvent
	err := lease.use(ctx, func(bound context.Context) error {
		state, err := readRabbitMQMigrationJournal(journal, plan)
		if err != nil || state != phase {
			return errors.New("RabbitMQ 原迁移阶段无法核对")
		}
		source, err := stoppedRabbitMQMigrationSource(bound, plan)
		if err != nil {
			return err
		}
		dataRoot, err := rabbitMQMigrationDockerRoot(bound)
		if err != nil {
			return err
		}
		from, err := openRabbitMQMigrationVolume(dataRoot, source)
		if err != nil {
			return err
		}
		defer from.Close()
		// The active lease is already in use. This typed, fixed candidate
		// creation takes no client-supplied path, driver or options.
		target, err := createRabbitMQMigrationVolume(bound, plan)
		if err != nil {
			return err
		}
		to, err := openRabbitMQMigrationVolume(dataRoot, target)
		if err != nil {
			return err
		}
		defer to.Close()
		attachments, err := rabbitMQMigrationVolumeAttachments(bound, target.Name)
		if err != nil || len(attachments) != 0 {
			return errors.New("RabbitMQ 候选数据卷已被容器引用")
		}
		copy, err := copyRabbitMQColdVolume(bound, from, to)
		if err != nil {
			return err
		}
		original, err := stoppedRabbitMQMigrationSource(bound, plan)
		if err != nil || original.Mountpoint != source.Mountpoint {
			return errors.New("RabbitMQ 冷备份后原卷变化")
		}
		for _, item := range []struct {
			volume rabbitMQMigrationVolume
			fd     *os.File
		}{{source, from}, {target, to}} {
			again, err := openRabbitMQMigrationVolume(dataRoot, item.volume)
			if err != nil {
				return err
			}
			a, aErr := rabbitMQCopyStat(item.fd)
			b, bErr := rabbitMQCopyStat(again)
			again.Close()
			if aErr != nil || bErr != nil || a.Dev != b.Dev || a.Ino != b.Ino {
				return errRabbitMQCopyDrift
			}
		}
		attachments, err = rabbitMQMigrationVolumeAttachments(bound, target.Name)
		if err != nil || len(attachments) != 0 {
			return errors.New("RabbitMQ 冷备份后候选卷引用异常")
		}
		result, err = appendRabbitMQMigrationEvent(journal, plan, phase, "copy-verified", copy)
		return err
	})
	return result, err
}
