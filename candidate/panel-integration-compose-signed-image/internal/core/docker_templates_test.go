package core

import (
	"regexp"
	"strings"
	"testing"

	"local/panel/internal/appcatalog"
)

func TestWordPressTemplateKeepsDatabasePrivate(t *testing.T) {
	one, e := dockerTemplate("wordpress-blog", 18480)
	if e != nil {
		t.Fatal(e)
	}
	two, e := dockerTemplate("wordpress-blog", 18480)
	if e != nil || one == two {
		t.Fatal("WordPress template reused database credentials", e)
	}
	dbPassword := regexp.MustCompile(`(?m)^      MARIADB_PASSWORD: "([a-f0-9]{64})"$`).FindStringSubmatch(one)
	wpPassword := regexp.MustCompile(`(?m)^      WORDPRESS_DB_PASSWORD: "([a-f0-9]{64})"$`).FindStringSubmatch(one)
	rootPassword := regexp.MustCompile(`(?m)^      MARIADB_ROOT_PASSWORD: "([a-f0-9]{64})"$`).FindStringSubmatch(one)
	if len(dbPassword) != 2 || len(wpPassword) != 2 || len(rootPassword) != 2 || dbPassword[1] != wpPassword[1] || dbPassword[1] == rootPassword[1] {
		t.Fatal("WordPress and MariaDB credentials did not match securely")
	}
	for _, text := range []string{
		"image: wordpress:7.1.2-php8.3-apache",
		"image: mariadb:11.8.9",
		`127.0.0.1:18480:80`,
		"condition: service_healthy",
		"wordpress-data:/var/www/html",
		"db-data:/var/lib/mysql",
	} {
		if !strings.Contains(one, text) {
			t.Fatalf("WordPress template missing %q", text)
		}
	}
	if strings.Contains(one, "3306:3306") {
		t.Fatal("database port was published")
	}
	if _, e := dockerTemplate("wordpress-blog", 80); e == nil {
		t.Fatal("privileged host port accepted")
	}
}

func TestMemcachedTemplateIsPinnedAndLoopbackOnly(t *testing.T) {
	compose, e := dockerTemplate("memcached-cache", 21211)
	if e != nil {
		t.Fatal(e)
	}
	for _, expected := range []string{
		"image: " + appcatalog.MemcachedDigestImage,
		`127.0.0.1:21211:11211`,
		`command: ["memcached", "-m", "128", "-I", "4m"]`,
		"healthcheck:",
		"restart: unless-stopped",
	} {
		if !strings.Contains(compose, expected) {
			t.Fatalf("Memcached template missing %q", expected)
		}
	}
	if strings.Contains(compose, "0.0.0.0") || strings.Contains(compose, "latest") {
		t.Fatal("Memcached template exposed a public port or mutable tag")
	}
	images := regexp.MustCompile(`(?m)^    image: (.+)$`).FindAllStringSubmatch(compose, -1)
	if len(images) != 1 || images[0][1] != appcatalog.MemcachedDigestImage || !regexp.MustCompile(`^memcached:1\.6\.45-alpine@sha256:[a-f0-9]{64}$`).MatchString(images[0][1]) {
		t.Fatal("Memcached template did not use one exact content-addressed image")
	}
}

func TestPhpMyAdminTemplateIsPinnedAndLoopbackOnly(t *testing.T) {
	compose, err := dockerTemplate("phpmyadmin", 18080)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"phpmyadmin:5.2.2-apache@sha256:6b5ab5f9ebfe3dbb38388b5695c2ff5ba3e26cdc2c4ce0bd97092eefc6a20bfd",
		`127.0.0.1:18080:80`,
		`PMA_ARBITRARY: "1"`,
		`UPLOAD_LIMIT: "256M"`,
		"healthcheck:",
	} {
		if !strings.Contains(compose, expected) {
			t.Fatalf("phpMyAdmin template missing %q", expected)
		}
	}
	if strings.Contains(compose, "0.0.0.0") || strings.Contains(compose, ":latest") {
		t.Fatal("phpMyAdmin template exposed a public port or mutable tag")
	}

	project, server := strings.Repeat("1", 32), strings.Repeat("2", 32)
	local, err := PhpMyAdminCompose(PhpMyAdminLegacyTemplate, 18080, project, server)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		dockerPhpMyAdminImage,
		"127.0.0.1:18080:80",
		"PMA_HOST: localhost",
		"PMA_SOCKET: /run/panel-db/mysql.sock",
		"source: " + PhpMyAdminSocketDirectory(project, server),
		"read_only: true",
		"create_host_path: false",
	} {
		if !strings.Contains(local, expected) {
			t.Fatalf("local phpMyAdmin template missing %q", expected)
		}
	}
	if strings.Contains(local, "PMA_ARBITRARY") || strings.Contains(compose, PhpMyAdminSocketTarget) {
		t.Fatal("phpMyAdmin mixed the external and selected local profiles")
	}
	for _, arch := range []string{"amd64", "arm64"} {
		updated, err := dockerTemplateOnArchitecture(PhpMyAdmin523Template, 18081, arch)
		if err != nil || !strings.Contains(updated, "    image: "+dockerPhpMyAdmin523Image+"\n") ||
			!strings.Contains(updated, `"127.0.0.1:18081:80"`) ||
			!strings.Contains(updated, `PMA_ARBITRARY: "1"`) {
			t.Fatalf("updated %s image and external-server settings were not applied: %v", arch, err)
		}
	}
	updatedLocal, err := PhpMyAdminCompose(PhpMyAdmin523Template, 18081, project, server)
	if err != nil || updatedLocal != strings.NewReplacer(dockerPhpMyAdminImage, dockerPhpMyAdmin523Image, "18080:80", "18081:80").Replace(local) {
		t.Fatal("phpMyAdmin update changed the selected MySQL relay settings", err)
	}
}

func TestRegistryDatabaseTemplatesAreDigestPinnedAndPrivate(t *testing.T) {
	mongoOne, err := dockerTemplate("mongodb", 27017)
	if err != nil {
		t.Fatal(err)
	}
	mongoTwo, err := dockerTemplate("mongodb", 27017)
	if err != nil || mongoOne == mongoTwo {
		t.Fatal("MongoDB template reused its root credential", err)
	}
	for _, expected := range []string{
		"mongo:8.0@sha256:d0d926f94df099bff534b7ee5b5986458131a22489dfff8664509af0c1e2ca9c",
		`127.0.0.1:27017:27017`,
		"MONGO_INITDB_ROOT_PASSWORD",
		"healthcheck:",
		"data:/data/db",
	} {
		if !strings.Contains(mongoOne, expected) {
			t.Fatalf("MongoDB template missing %q", expected)
		}
	}
	elastic, err := dockerTemplate("elasticsearch", 19200)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"elasticsearch:9.1.4@sha256:62a245d92e8d14440e1e43a1b4f08d37aef316d82f198b4f878985948aa2d1d8",
		`127.0.0.1:19200:9200`,
		"mem_limit: 1g",
		`ES_JAVA_OPTS: "-Xms512m -Xmx512m"`,
		"node.store.allow_mmap",
		`xpack.security.enabled: "true"`,
		`transport.host: "127.0.0.1"`,
		" = 401",
		"/_cluster/health",
	} {
		if !strings.Contains(elastic, expected) {
			t.Fatalf("Elasticsearch template missing %q", expected)
		}
	}
	otherElastic, err := dockerTemplate("elasticsearch", 19200)
	passwordLine := regexp.MustCompile(`ELASTIC_PASSWORD: "[0-9a-f]{32,}"`)
	first, second := passwordLine.FindString(elastic), passwordLine.FindString(otherElastic)
	if err != nil || first == "" || second == "" || first == second {
		t.Fatal("each Elasticsearch installation must generate its own initial password")
	}
	if strings.Contains(mongoOne, "0.0.0.0") || strings.Contains(elastic, "0.0.0.0") || strings.Contains(mongoOne, ":latest") || strings.Contains(elastic, ":latest") {
		t.Fatal("registry template exposed a public port or mutable tag")
	}
}
