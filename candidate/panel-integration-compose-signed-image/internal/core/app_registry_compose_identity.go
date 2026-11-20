package core

import (
	"errors"
	"strings"

	"local/panel/internal/appcatalog"
)

const (
	dockerRabbitMQImage         = "rabbitmq:4.1.4-management-alpine@sha256:5cbd7145b0306399ad68422c3350b6cbd1bb95704b39f5896480e5b6d4238a04"
	dockerRabbitMQ440Image      = "rabbitmq:4.4.0-management-alpine@sha256:4841f6384ef8313c3594cd3f2e9f40c10805f8a61c45f08a9a5d9ddea8199267"
	dockerOpenLiteSpeedImage    = "litespeedtech/openlitespeed:1.8.4-lsphp83@sha256:6f50ba204e66f1c746dd183f3022340ca912124c414669755db7f4701167f268"
	dockerOpenLiteSpeed194Image = "ghcr.io/yunzhanlin/yunzhan-apps-openlitespeed:1.9.4-lsphp83-compat2@sha256:a3f4cdafd5581e83d3deb4d50ef1b003a1164142f545652f7ae540bf18c2fd82"
	dockerPhpMyAdminImage       = "phpmyadmin:5.2.2-apache@sha256:6b5ab5f9ebfe3dbb38388b5695c2ff5ba3e26cdc2c4ce0bd97092eefc6a20bfd"
	dockerPhpMyAdmin523Image    = "phpmyadmin:5.2.3-apache@sha256:f54a37b908b26caa7032c4eb0c7f3495fdd90208a06eed9c4b2c8e691dd1662c"
	dockerMongoDBImage          = "mongo:8.0@sha256:d0d926f94df099bff534b7ee5b5986458131a22489dfff8664509af0c1e2ca9c"
	dockerMongoDB8038Image      = "mongo:8.0.38-noble@sha256:76a93cc399d05709baeea4e55385749657aa0085ad5b497c851380778eccea2c"
	dockerElasticsearchImage    = "docker.elastic.co/elasticsearch/elasticsearch:9.1.4@sha256:62a245d92e8d14440e1e43a1b4f08d37aef316d82f198b4f878985948aa2d1d8"
)

type registryComposeIdentity struct {
	id, image, route, isolation string
}

// The store admits only its fixed deployment recipes. Direct Docker templates
// such as WordPress and Node are managed separately and do not receive a
// signed store installation receipt.
func registryComposeTemplateIdentity(target string) (registryComposeIdentity, bool) {
	switch target {
	case RabbitMQLegacyTemplate, RabbitMQ440Template:
		return registryComposeIdentity{"rabbitmq", rabbitMQTemplateImage(target), "docker", ""}, true
	case OpenLiteSpeedLegacyTemplate:
		return registryComposeIdentity{"openlitespeed", dockerOpenLiteSpeedImage, "docker", ""}, true
	case OpenLiteSpeed194Template:
		return registryComposeIdentity{"openlitespeed", dockerOpenLiteSpeed194Image, "docker", ""}, true
	case PhpMyAdminLegacyTemplate:
		return registryComposeIdentity{"phpmyadmin", dockerPhpMyAdminImage, "databases", ""}, true
	case PhpMyAdmin523Template:
		return registryComposeIdentity{"phpmyadmin", dockerPhpMyAdmin523Image, "databases", ""}, true
	case MongoDBLegacyTemplate, MongoDB8038Template:
		return registryComposeIdentity{"mongodb", mongoDBTemplateImage(target), "docker", ""}, true
	case ElasticsearchLegacyTemplate, ElasticsearchSnapshotTemplate:
		return registryComposeIdentity{"elasticsearch", dockerElasticsearchImage, "docker", ""}, true
	case "memcached-cache":
		return registryComposeIdentity{"memcached", appcatalog.MemcachedDigestImage, "docker", ""}, true
	}
	if release, ok := findFinalLegacyPHPRelease(target); ok {
		return registryComposeIdentity{release.appID, release.image, "docker", "legacy-container"}, true
	}
	if image, ok := LegacyPHPImages[target]; ok {
		id := "php-" + strings.TrimPrefix(target, "php-legacy-")
		return registryComposeIdentity{id, image, "docker", "legacy-container"}, true
	}
	return registryComposeIdentity{}, false
}

func validateRegistryComposeDelivery(manifest appcatalog.Manifest) error {
	d := manifest.Delivery
	bound, ok := registryComposeTemplateIdentity(d.Target)
	if d.Provider != "compose" || !ok || manifest.ID != bound.id || d.ManageRoute != bound.route || d.Isolation != bound.isolation ||
		(bound.isolation == "legacy-container") != (manifest.Risk == "eol") {
		return errors.New("签名应用包与当前面板的容器模板身份不一致，未提交安装")
	}
	if release, ok := findFinalLegacyPHPRelease(d.Target); ok && manifest.Version != release.appVersion {
		return errors.New("PHP 隔离模板需要对应的签名应用版本")
	}
	if d.Target == PhpMyAdmin523Template && manifest.Version != phpMyAdmin523AppVersion {
		return errors.New("phpMyAdmin 5.2.3 模板需要对应的签名应用版本")
	}
	if d.Target == OpenLiteSpeed194Template && manifest.Version != openLiteSpeed194AppVersion {
		return errors.New("OpenLiteSpeed 1.9.4 模板需要对应的签名应用版本")
	}
	if d.Target == RabbitMQ440Template && manifest.Version != rabbitMQ440AppVersion {
		return errors.New("RabbitMQ 4.4 模板需要对应的签名应用版本")
	}
	if d.Target == MongoDB8038Template && manifest.Version != mongoDB8038AppVersion {
		return errors.New("MongoDB 8.0.38 模板需要对应的签名应用版本")
	}
	if d.Target == ElasticsearchSnapshotTemplate && manifest.Version != elasticsearchSnapshotAppVersion {
		return errors.New("Elasticsearch 快照模板需要对应的签名应用版本")
	}
	if d.Image != bound.image {
		return errors.New("签名应用包的镜像或摘要与当前面板模板不一致；请先升级面板，未提交安装或拉取镜像")
	}
	return nil
}
