package core

import (
	"errors"
	"strings"

	"local/panel/internal/appcatalog"
)

const (
	dockerRabbitMQImage      = "rabbitmq:4.1.4-management-alpine@sha256:5cbd7145b0306399ad68422c3350b6cbd1bb95704b39f5896480e5b6d4238a04"
	dockerOpenLiteSpeedImage = "litespeedtech/openlitespeed:1.8.4-lsphp83@sha256:6f50ba204e66f1c746dd183f3022340ca912124c414669755db7f4701167f268"
	dockerPhpMyAdminImage    = "phpmyadmin:5.2.2-apache@sha256:6b5ab5f9ebfe3dbb38388b5695c2ff5ba3e26cdc2c4ce0bd97092eefc6a20bfd"
	dockerPhpMyAdmin523Image = "phpmyadmin:5.2.3-apache@sha256:f54a37b908b26caa7032c4eb0c7f3495fdd90208a06eed9c4b2c8e691dd1662c"
	dockerMongoDBImage       = "mongo:8.0@sha256:d0d926f94df099bff534b7ee5b5986458131a22489dfff8664509af0c1e2ca9c"
	dockerElasticsearchImage = "docker.elastic.co/elasticsearch/elasticsearch:9.1.4@sha256:62a245d92e8d14440e1e43a1b4f08d37aef316d82f198b4f878985948aa2d1d8"
)

type registryComposeIdentity struct {
	id, image, route, isolation string
}

// The store admits only its fixed deployment recipes. Direct Docker templates
// such as WordPress and Node are managed separately and do not receive a
// signed store installation receipt.
func registryComposeTemplateIdentity(target string) (registryComposeIdentity, bool) {
	switch target {
	case "rabbitmq":
		return registryComposeIdentity{"rabbitmq", dockerRabbitMQImage, "docker", ""}, true
	case "openlitespeed":
		return registryComposeIdentity{"openlitespeed", dockerOpenLiteSpeedImage, "docker", ""}, true
	case PhpMyAdminLegacyTemplate:
		return registryComposeIdentity{"phpmyadmin", dockerPhpMyAdminImage, "databases", ""}, true
	case PhpMyAdmin523Template:
		return registryComposeIdentity{"phpmyadmin", dockerPhpMyAdmin523Image, "databases", ""}, true
	case "mongodb":
		return registryComposeIdentity{"mongodb", dockerMongoDBImage, "docker", ""}, true
	case "elasticsearch":
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
	if d.Image != bound.image {
		return errors.New("签名应用包的镜像或摘要与当前面板模板不一致；请先升级面板，未提交安装或拉取镜像")
	}
	return nil
}
