//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

type rabbitMQCutoverFile struct {
	name     string
	original []byte
	target   []byte
}

type rabbitMQCutover struct {
	project composeMetadata
	files   []rabbitMQCutoverFile
}

func rabbitMQPrepareCutover(dir *composeUpdateDirectory, plan rabbitMQMigrationPlan) (rabbitMQCutover, error) {
	var empty rabbitMQCutover
	if _, err := rabbitMQMigrationOriginalProject(dir, plan); err != nil {
		return empty, err
	}
	for _, name := range []string{"compose.yaml", "metadata.json"} {
		raw, _, err := dir.read(name, 48<<10)
		if err != nil {
			return empty, err
		}
		path := rabbitMQOriginalCutoverFile(plan.JobID, name)
		if err := rabbitMQKeepCutoverFile(dir.root, path, raw); err != nil {
			return empty, err
		}
	}
	return rabbitMQReadCutover(dir, plan)
}

func rabbitMQOriginalCutoverFile(job, name string) string {
	return "rabbitmq-original-" + job + "-" + name
}

func rabbitMQKeepCutoverFile(root *os.Root, name string, data []byte) error {
	before, err := geoStoreRead(root, name, 48<<10)
	if errors.Is(err, os.ErrNotExist) {
		err = writeRabbitMQMigrationRecord(root, name, data)
		if err != nil {
			return err
		}
		before, err = geoStoreRead(root, name, 48<<10)
	}
	if err != nil || !bytes.Equal(before, data) {
		return errRabbitMQMigrationPending
	}
	return nil
}

func rabbitMQReadCutover(dir *composeUpdateDirectory, plan rabbitMQMigrationPlan) (rabbitMQCutover, error) {
	var empty rabbitMQCutover
	if dir == nil || !dir.current() || !plan.valid() {
		return empty, errRabbitMQIdentity
	}
	config, err := geoStoreRead(dir.root, rabbitMQOriginalCutoverFile(plan.JobID, "compose.yaml"), 48<<10)
	if err != nil || core.Hash(string(config)) != plan.OriginalConfigSHA {
		return empty, errRabbitMQIdentity
	}
	meta, err := geoStoreRead(dir.root, rabbitMQOriginalCutoverFile(plan.JobID, "metadata.json"), 16<<10)
	if err != nil || core.Hash(string(meta)) != plan.OriginalMetaSHA {
		return empty, errRabbitMQIdentity
	}
	project, err := rabbitMQProject(meta, plan.ProjectID)
	if err != nil || project.TemplateID != core.RabbitMQLegacyTemplate {
		return empty, errRabbitMQIdentity
	}
	target, err := core.RabbitMQMigratedCompose(string(config), project.HostPort, plan.JobID)
	if err != nil {
		return empty, err
	}
	project.TemplateID = core.RabbitMQ440Template
	targetMetadata, err := json.Marshal(project)
	if err != nil {
		return empty, err
	}
	return rabbitMQCutover{project: project, files: []rabbitMQCutoverFile{
		{"compose.yaml", config, []byte(target)}, {"metadata.json", meta, targetMetadata},
	}}, nil
}

// Apply a single file transition under durable publish intent. During repair,
// either exact file version is acceptable, including a split config/metadata
// commit across a process or machine restart. Every other edit is refused.
func (c rabbitMQCutover) apply(ctx context.Context, dir *composeUpdateDirectory, plan rabbitMQMigrationPlan) error {
	for _, change := range c.files {
		current, _, err := dir.read(change.name, 48<<10)
		if err != nil || !bytes.Equal(current, change.original) && !bytes.Equal(current, change.target) {
			return errRabbitMQMigrationPending
		}
	}
	for _, change := range c.files {
		if err := change.exchange(ctx, dir, plan); err != nil {
			return err
		}
	}
	return nil
}

func (c rabbitMQCutoverFile) exchange(ctx context.Context, dir *composeUpdateDirectory, plan rabbitMQMigrationPlan) error {
	raw, initial, err := dir.read(c.name, 48<<10)
	if err != nil || ctx.Err() != nil {
		return errRabbitMQMigrationPending
	}
	if bytes.Equal(raw, c.target) {
		return nil
	}
	if !bytes.Equal(raw, c.original) {
		return errRabbitMQMigrationPending
	}
	stage := "rabbitmq-cutover-" + plan.JobID + "-" + c.name
	if err := rabbitMQKeepCutoverFile(dir.root, stage, c.target); err != nil {
		return err
	}
	_, staged, err := geoStoreReadIdentity(dir.root, stage, 48<<10)
	if err != nil {
		return err
	}
	_, visible, err := dir.read(c.name, 48<<10)
	if err != nil || !sameComposeUpdateFile(initial, visible) || !dir.current() || ctx.Err() != nil {
		return errRabbitMQMigrationPending
	}
	fd, err := dir.root.Open(".")
	if err != nil {
		return err
	}
	defer fd.Close()
	if err := unix.Renameat2(int(fd.Fd()), stage, int(fd.Fd()), c.name, unix.RENAME_EXCHANGE); err != nil {
		return err
	}
	if err := fd.Sync(); err != nil {
		return err
	}
	got, after, err := dir.read(c.name, 48<<10)
	retainedRaw, retained, retainedErr := geoStoreReadIdentity(dir.root, stage, 48<<10)
	if err != nil || retainedErr != nil || !os.SameFile(after, staged) || !os.SameFile(retained, initial) ||
		!bytes.Equal(got, c.target) || !bytes.Equal(retainedRaw, c.original) {
		return errRabbitMQMigrationPending
	}
	return nil
}

// The caller rechecks the original administrator reservation before entering
// with a fresh signed release and exclusive lease. After publish intent, only
// the same candidate volume can be reconciled, including after a lost reply.
func publishRabbitMQMigration(ctx context.Context, lease *dockerMutationLease, dir *composeUpdateDirectory,
	journal *os.Root, plan rabbitMQMigrationPlan, authority rabbitMQMigrationAuthority) (rabbitMQMigrationEvent, error) {
	if !plan.valid() || authority.manifestSHA != plan.TargetManifestSHA {
		return rabbitMQMigrationEvent{}, errRabbitMQIdentity
	}
	var state rabbitMQMigrationEvent
	err := lease.use(ctx, func(bound context.Context) error {
		var err error
		state, err = readRabbitMQMigrationJournal(journal, plan)
		if err != nil {
			return errRabbitMQMigrationPending
		}
		if state.Phase == "target-published" {
			return nil
		}
		volume, err := namedRabbitMQMigrationVolume(bound, plan.CandidateVolume, rabbitMQCandidateVolumeLabels(plan))
		if err != nil {
			return err
		}
		var cutover rabbitMQCutover
		switch state.Phase {
		case "target-verified-offline":
			if _, err := stoppedRabbitMQMigrationSource(bound, plan); err != nil {
				return err
			}
			references, err := rabbitMQMigrationVolumeAttachments(bound, volume.Name)
			if err != nil || len(references) != 0 {
				return errRabbitMQMigrationPending
			}
			cutover, err = rabbitMQPrepareCutover(dir, plan)
			if err != nil {
				return err
			}
			state, err = appendRabbitMQMigrationEvent(journal, plan, state, "publish-endpoint-intent", state.VolumeCopy)
		case "publish-endpoint-intent":
			cutover, err = rabbitMQReadCutover(dir, plan)
		default:
			return errRabbitMQMigrationPending
		}
		if err != nil {
			return err
		}
		if err = cutover.apply(bound, dir, plan); err != nil {
			return err
		}
		id, err := rabbitMQCutoverContainer(bound, dir, cutover.project, plan, volume)
		if err != nil {
			return err
		}
		if err = waitRabbitMQOfflineBroker(bound, id, "4.4.0"); err != nil {
			return err
		}
		if err = rabbitMQCheckAMQPEndpoint(bound, cutover.project.HostPort+1); err != nil {
			return err
		}
		if err = rabbitMQObserveCutoverTarget(bound, cutover.project, plan, volume, id); err != nil {
			return err
		}
		state, err = appendRabbitMQMigrationEvent(journal, plan, state, "target-published", state.VolumeCopy)
		return err
	})
	return state, err
}

func rabbitMQCutoverContainer(ctx context.Context, dir *composeUpdateDirectory, project composeMetadata,
	plan rabbitMQMigrationPlan, volume rabbitMQMigrationVolume) (string, error) {
	if !dir.current() {
		return "", errRabbitMQMigrationPending
	}
	id, err := rabbitMQCutoverProjectContainer(ctx, project)
	if err != nil {
		return "", err
	}
	oldVolume, err := namedRabbitMQMigrationVolume(ctx, plan.OriginalVolume, map[string]string{
		"com.docker.compose.project": project.Engine, "com.docker.compose.volume": "data",
	})
	if err != nil {
		return "", err
	}
	refs, err := rabbitMQMigrationVolumeAttachments(ctx, oldVolume.Name)
	if err != nil {
		return "", err
	}
	if id == plan.OriginalContainer {
		if _, err := stoppedRabbitMQMigrationSource(ctx, plan); err != nil {
			return "", err
		}
		candidateRefs, err := rabbitMQMigrationVolumeAttachments(ctx, volume.Name)
		if err != nil || len(candidateRefs) != 0 {
			return "", errRabbitMQMigrationPending
		}
		// Leave the old named volume and image intact. A stopped old
		// container may not remain eligible to restart against stale data.
		if _, err := dockerRequestUnlocked(ctx, http.MethodDelete, "/containers/"+id+"?v=0", nil, nil, 4096); err != nil {
			return "", err
		}
		id = ""
		refs, err = rabbitMQMigrationVolumeAttachments(ctx, oldVolume.Name)
	}
	if err != nil || len(refs) != 0 || !dir.current() {
		return "", errRabbitMQMigrationPending
	}
	if id != "" {
		// A retried cutover uses the existing candidate even if it already
		// accepted new messages before an interruption.
		if err := rabbitMQObserveCutoverTarget(ctx, project, plan, volume, id); err == nil {
			return id, nil
		}
		if err := rabbitMQCheckCutoverTarget(ctx, project, plan, volume, id); err != nil {
			return "", err
		}
	} else if holders, err := rabbitMQMigrationVolumeAttachments(ctx, volume.Name); err != nil || len(holders) != 0 {
		return "", errRabbitMQMigrationPending
	}
	if _, err := composeCommandUnlocked(ctx, composeArgs(project, dir.root.Name(), "up", "-d", "--no-recreate", "--no-deps",
		"--pull", "never", "rabbitmq")...); err != nil {
		return "", errors.New("RabbitMQ 新实例启动未确认，保留原卷和已经升级的数据卷")
	}
	id, err = rabbitMQCutoverProjectContainer(ctx, project)
	if err != nil || id == "" || id == plan.OriginalContainer {
		return "", errRabbitMQMigrationPending
	}
	if err := rabbitMQObserveCutoverTarget(ctx, project, plan, volume, id); err != nil {
		return "", err
	}
	return id, nil
}

func rabbitMQCutoverProjectContainer(ctx context.Context, project composeMetadata) (string, error) {
	filter, _ := json.Marshal(map[string][]string{"label": {"com.docker.compose.project=" + project.Engine}})
	raw, err := dockerRequest(ctx, http.MethodGet, "/containers/json?all=1&filters="+url.QueryEscape(string(filter)), nil, nil, 256<<10)
	var rows []struct {
		ID string `json:"Id"`
	}
	if err != nil || memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &rows) != nil || rows == nil || len(rows) > 1 {
		return "", errRabbitMQIdentity
	}
	if len(rows) == 0 {
		return "", nil
	}
	if !core.ValidDockerContainerID(rows[0].ID) {
		return "", errRabbitMQIdentity
	}
	return rows[0].ID, nil
}

func rabbitMQCheckCutoverTarget(ctx context.Context, project composeMetadata, plan rabbitMQMigrationPlan,
	volume rabbitMQMigrationVolume, id string) error {
	var broker rabbitMQContainer
	raw, err := dockerRequest(ctx, http.MethodGet, "/containers/"+id+"/json", nil, nil, 256<<10)
	if err != nil || memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &broker) != nil || broker.ID != id ||
		broker.Config.Hostname != "cloudstack-rabbitmq" || broker.Config.Image != rabbitMQTargetImage ||
		broker.Config.Labels["com.docker.compose.project"] != project.Engine ||
		broker.Config.Labels["com.docker.compose.service"] != "rabbitmq" ||
		!strings.EqualFold(broker.Config.Labels["com.docker.compose.oneoff"], "false") ||
		len(broker.Mounts) != 1 {
		return errRabbitMQIdentity
	}
	mount := broker.Mounts[0]
	if mount.Type != "volume" || mount.Name != plan.CandidateVolume || mount.Driver != "local" ||
		mount.Source != volume.Mountpoint || mount.Destination != "/var/lib/rabbitmq" || !mount.RW {
		return errRabbitMQIdentity
	}
	refs, err := rabbitMQMigrationVolumeAttachments(ctx, volume.Name)
	if err != nil || len(refs) != 1 || refs[0] != id {
		return errRabbitMQIdentity
	}
	return rabbitMQVerifyLoopbackBindings(ctx, id, project)
}

func rabbitMQObserveCutoverTarget(ctx context.Context, project composeMetadata, plan rabbitMQMigrationPlan,
	volume rabbitMQMigrationVolume, id string) error {
	broker, err := inspectRabbitMQ(ctx, project)
	if err != nil || broker.ID != id {
		return errRabbitMQIdentity
	}
	return rabbitMQCheckCutoverTarget(ctx, project, plan, volume, id)
}

// Observe a Connection.Start method frame from the published AMQP port. It
// requires no broker password, creates no queue and cannot acknowledge or
// publish a message. This independently tests the host port mapping.
func rabbitMQCheckAMQPEndpoint(ctx context.Context, port int) error {
	bound, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(bound, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	failure := errors.New("RabbitMQ 的 AMQP 端口尚未通过协议检查")
	if err != nil {
		return failure
	}
	defer conn.Close()
	deadline, _ := bound.Deadline()
	header := []byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1}
	if err := conn.SetDeadline(deadline); err != nil {
		return failure
	}
	if n, err := conn.Write(header); err != nil || n != len(header) {
		return failure
	}
	var buf [11]byte
	if _, err := io.ReadFull(conn, buf[:]); err != nil || buf[0] != 1 ||
		binary.BigEndian.Uint16(buf[1:3]) != 0 || binary.BigEndian.Uint32(buf[3:7]) < 4 ||
		binary.BigEndian.Uint16(buf[7:9]) != 10 || binary.BigEndian.Uint16(buf[9:11]) != 10 {
		return failure
	}
	return nil
}
