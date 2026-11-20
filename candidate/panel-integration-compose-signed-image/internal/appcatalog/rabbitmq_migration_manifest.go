package appcatalog

import (
	"context"
	"errors"
)

// The Root migration executor supplies its compiled official client. The
// catalog must authorize both the object and its exact bytes before shutdown.
func (c *Client) FetchRabbitMQMigrationManifest(ctx context.Context, version, manifestSHA string) (Manifest, error) {
	var empty Manifest
	if !ruleFeedSHAPattern.MatchString(manifestSHA) || ctx == nil {
		return empty, errors.New("RabbitMQ 迁移包摘要无效")
	}
	catalog, _, _, err := c.FetchCatalog(ctx)
	if err != nil {
		return empty, err
	}
	item, found := Find(catalog, "rabbitmq")
	if !found || item.Version != version || item.SHA256 != manifestSHA {
		return empty, errors.New("RabbitMQ 迁移签名目录已变化，请刷新预检")
	}
	raw, err := c.get(ctx, item.PackageURL, maxManifestBytes)
	if err != nil {
		return empty, err
	}
	return c.verifyManifestData(item, raw)
}
