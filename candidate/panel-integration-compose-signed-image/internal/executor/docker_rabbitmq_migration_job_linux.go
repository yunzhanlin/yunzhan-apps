//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"time"

	"local/panel/internal/core"
)

func rabbitMQMigrationPlanForDispatch(ctx context.Context, dir *composeUpdateDirectory, dispatch core.RabbitMQMigrationDispatch) (rabbitMQMigrationPlan, error) {
	var empty rabbitMQMigrationPlan
	meta, _, err := dir.read("metadata.json", 16<<10)
	if err != nil {
		return empty, errRabbitMQIdentity
	}
	project, err := rabbitMQProject(meta, dispatch.ProjectID)
	if err != nil || project.TemplateID != core.RabbitMQLegacyTemplate {
		return empty, errRabbitMQIdentity
	}
	config, _, err := dir.read("compose.yaml", 48<<10)
	if err != nil || !core.IsOriginalRabbitMQCompose(string(config), project.HostPort) {
		return empty, errRabbitMQIdentity
	}
	broker, err := inspectRabbitMQ(ctx, project)
	if err != nil {
		return empty, err
	}
	volume, err := rabbitMQOriginalVolume(ctx, project, broker)
	if err != nil {
		return empty, err
	}
	source := core.RabbitMQMigrationSource{
		ProjectID: dispatch.ProjectID, ContainerID: broker.ID, StartedAt: broker.State.StartedAt, Volume: volume,
		ConfigSHA: core.Hash(string(config)), MetadataSHA: core.Hash(string(meta)),
	}
	if source.SHA256() != dispatch.Input.SourceSHA256 {
		return empty, errRabbitMQIdentity
	}
	plan := rabbitMQMigrationPlan{
		JobID: dispatch.JobID, RequestID: dispatch.RequestID, ActorID: dispatch.ActorID, ProjectID: dispatch.ProjectID,
		OriginalContainer: source.ContainerID, SourceSHA: dispatch.Input.SourceSHA256,
		OriginalConfigSHA: source.ConfigSHA, OriginalMetaSHA: source.MetadataSHA,
		TargetManifestSHA: dispatch.Input.TargetManifestSHA256,
		OriginalVolume:    volume, CandidateVolume: rabbitMQMigrationVolumePrefix + dispatch.JobID,
	}
	if !plan.valid() {
		return empty, errRabbitMQIdentity
	}
	return plan, nil
}

func verifyRabbitMQOriginalDispatch(ctx context.Context, reader *diskHostCoreReader, dispatch core.RabbitMQMigrationDispatch) error {
	if !reader.current() {
		return errRabbitMQIdentity
	}
	if err := (&core.Store{DB: reader.db}).VerifyRabbitMQMigrationDispatch(ctx, dispatch); err != nil {
		return err
	}
	if !reader.current() {
		return errRabbitMQIdentity
	}
	return ctx.Err()
}

// Root entrypoint for the exact durable job. It is never dispatched by a
// generic Compose project operation or a caller-provided command.
func RunRabbitMQMigration(job string) error {
	if os.Geteuid() != 0 || !core.ValidID(job) {
		return errRabbitMQIdentity
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	reader, err := openDiskHostCoreReader()
	if err != nil {
		return err
	}
	defer reader.db.Close()
	dispatch, err := (&core.Store{DB: reader.db}).ReadRabbitMQMigrationDispatch(ctx, job)
	if err != nil {
		return err
	}
	if err := verifyRabbitMQOriginalDispatch(ctx, reader, dispatch); err != nil {
		return err
	}
	project, err := openComposeUpdateDirectory(dockerProjects, dispatch.ProjectID)
	if err != nil {
		return err
	}
	defer project.Close()
	lease, err := productionDockerMutationStore().begin(ctx)
	if err != nil {
		return err
	}
	defer lease.Close()
	if err := checkRabbitMQDispatchClaim(lease, dispatch); err != nil {
		return err
	}
	jobs := productionRabbitMQMigrationStore()
	plan, err := rabbitMQMigrationPlanForDispatch(ctx, project, dispatch)
	if err != nil {
		return err
	}
	official, err := verifyRabbitMQMigrationRelease(ctx, plan)
	if err != nil {
		return err
	}
	if err := verifyRabbitMQOriginalDispatch(ctx, reader, dispatch); err != nil {
		return err
	}
	if err := jobs.prepare(ctx, lease, plan); err != nil {
		return err
	}
	journal, actual, _, err := jobs.read(job)
	if err != nil {
		return err
	}
	defer journal.Close()
	if actual != plan {
		return errRabbitMQIdentity
	}
	if err := verifyRabbitMQOriginalDispatch(ctx, reader, dispatch); err != nil {
		return err
	}
	stage, err := stageRabbitMQMigration(ctx, lease, project, journal.root, plan, official, func(bound context.Context) error {
		return verifyRabbitMQOriginalDispatch(bound, reader, dispatch)
	})
	if err == nil {
		err = verifyRabbitMQOriginalDispatch(ctx, reader, dispatch)
	}
	if err == nil {
		if stage.Phase != "target-verified-offline" {
			err = errRabbitMQMigrationPending
		} else {
			_, err = publishRabbitMQMigration(ctx, lease, project, journal.root, plan, official)
		}
	}
	if err == nil {
		return nil
	}
	// A stopped source can be restored under the original task even when
	// its actor has since lost access. The journal prohibits it once new
	// messages may have reached the published endpoint.
	recovery, finish := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
	defer finish()
	current, readErr := readRabbitMQMigrationJournal(journal.root, plan)
	if readErr != nil || current.Phase == "publish-endpoint-intent" || current.Phase == "target-published" {
		return errors.Join(err, errRabbitMQMigrationPending)
	}
	_, recoveryErr := restoreRabbitMQBeforePublication(recovery, lease, project, journal.root, plan)
	return errors.Join(err, recoveryErr)
}

func ResumeRabbitMQMigration(job string) error {
	if os.Geteuid() != 0 || !core.ValidID(job) {
		return errRabbitMQIdentity
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	reader, err := openDiskHostCoreReader()
	if err != nil {
		return err
	}
	defer reader.db.Close()
	dispatch, err := (&core.Store{DB: reader.db}).ReadRabbitMQMigrationDispatch(ctx, job)
	if err != nil || !reader.current() {
		return errRabbitMQIdentity
	}
	lease, err := productionDockerMutationStore().lock(ctx)
	if err != nil {
		return err
	}
	defer lease.Close()
	if err := checkMemcachedDockerTransactions(ctx); err != nil {
		return err
	}
	journal, plan, state, err := productionRabbitMQMigrationStore().read(job)
	if errors.Is(err, os.ErrNotExist) {
		return lease.use(ctx, func(bound context.Context) error {
			if _, err := (&core.Store{DB: reader.db}).ReadRabbitMQMigrationDispatch(bound, job); err != nil || !reader.current() {
				return errRabbitMQIdentity
			}
			anchor := lease.tree.roots[len(lease.tree.roots)-1]
			return rabbitMQKeepCutoverFile(anchor, dispatch.JobID+".rabbitmq-cancelled", []byte(dispatch.RequestID))
		})
	}
	if err != nil {
		return err
	}
	defer journal.Close()
	if plan.ProjectID != dispatch.ProjectID || plan.ActorID != dispatch.ActorID || plan.RequestID != dispatch.RequestID ||
		plan.SourceSHA != dispatch.Input.SourceSHA256 || plan.TargetManifestSHA != dispatch.Input.TargetManifestSHA256 {
		return errRabbitMQIdentity
	}
	if !rabbitMQMigrationMayChangeDocker(state.Phase) && state.Phase != "prepared" {
		return nil
	}
	project, err := openComposeUpdateDirectory(dockerProjects, plan.ProjectID)
	if err != nil {
		return err
	}
	defer project.Close()
	if state.Phase == "publish-endpoint-intent" {
		// The original job already crossed the irreversibility boundary
		// under valid authorization. It may have accepted new writes.
		a := rabbitMQMigrationAuthority{manifestSHA: plan.TargetManifestSHA}
		_, err := publishRabbitMQMigration(ctx, lease, project, journal.root, plan, a)
		return err
	}
	_, err = restoreRabbitMQBeforePublication(ctx, lease, project, journal.root, plan)
	return err
}
