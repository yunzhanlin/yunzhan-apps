//go:build linux

package executor

import (
	"context"
	"errors"
	"runtime"
	"slices"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
)

const rabbitMQMigrationRelease = "4.4.0-compat1"

type rabbitMQMigrationAuthority struct {
	manifestSHA string
}

// Read the exact signed catalog entry through the executor's compiled
// repository. No browser-supplied URL, key, version, image, or cache qualifies.
func verifyRabbitMQMigrationRelease(ctx context.Context, plan rabbitMQMigrationPlan) (rabbitMQMigrationAuthority, error) {
	var empty rabbitMQMigrationAuthority
	if !plan.valid() {
		return empty, errRabbitMQIdentity
	}
	client := appcatalog.Default()
	manifest, err := client.FetchRabbitMQMigrationManifest(ctx, rabbitMQMigrationRelease, plan.TargetManifestSHA)
	if err != nil {
		return empty, err
	}
	delivery := manifest.Delivery
	if manifest.ID != "rabbitmq" || manifest.Version != rabbitMQMigrationRelease ||
		manifest.Risk != "maintained" || delivery.Provider != "compose" ||
		delivery.Target != core.RabbitMQ440Template || delivery.ManageRoute != "docker" ||
		delivery.Isolation != "" || delivery.Image != rabbitMQTargetImage ||
		!core.MatchesPanelRabbitMQImage(core.RabbitMQ440Template, delivery.Image) ||
		!manifest.Uninstall.PreserveData || !manifest.Uninstall.ReferenceCheck ||
		!slices.Contains(manifest.Compatibility.Architectures, runtime.GOARCH) ||
		!slices.Contains(manifest.Compatibility.OS, runtimecatalog.HostPlatform()) {
		return empty, errors.New("RabbitMQ 签名应用的迁移目标和本机环境无法核对")
	}
	return rabbitMQMigrationAuthority{manifestSHA: plan.TargetManifestSHA}, nil
}
