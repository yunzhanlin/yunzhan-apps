package core

import (
	"errors"
	"fmt"
)

const (
	PhpMyAdminLegacyTemplate = "phpmyadmin"
	PhpMyAdmin523Template    = "phpmyadmin-523"
	PhpMyAdminSocketTarget   = "/run/panel-db"
	phpMyAdmin523AppVersion  = "5.2.3-compat2"
)

func IsPhpMyAdminTemplate(template string) bool {
	return template == PhpMyAdminLegacyTemplate || template == PhpMyAdmin523Template
}

func PhpMyAdminSocketDirectory(projectID, serverID string) string {
	return "/run/panel-phpmyadmin-db-" + projectID + "-" + serverID
}

// PhpMyAdminCompose retains the original external-server template. Only the
// Linux executor renders the mount for a verified local instance.
func PhpMyAdminCompose(template string, port int, projectID, serverID string) (string, error) {
	if !IsPhpMyAdminTemplate(template) || port < 1024 || port > 65535 || (projectID != "" || serverID != "") && (!ValidID(projectID) || !ValidID(serverID)) {
		return "", errors.New("phpMyAdmin 项目或端口无效")
	}
	image := dockerPhpMyAdminImage
	if template == PhpMyAdmin523Template {
		image = dockerPhpMyAdmin523Image
	}
	environment := "      PMA_ARBITRARY: \"1\"\n"
	mount := ""
	if projectID != "" {
		environment = "      PMA_HOST: localhost\n      PMA_SOCKET: " + PhpMyAdminSocketTarget + "/mysql.sock\n"
		mount = fmt.Sprintf(`    volumes:
      - type: bind
        source: %s
        target: %s
        read_only: true
        bind:
          create_host_path: false
`, PhpMyAdminSocketDirectory(projectID, serverID), PhpMyAdminSocketTarget)
	}
	return fmt.Sprintf(`services:
  phpmyadmin:
    image: %s
    restart: unless-stopped
    environment:
%s      UPLOAD_LIMIT: "256M"
    ports:
      - "127.0.0.1:%d:80"
%s    healthcheck:
      test: ["CMD-SHELL", "php -r '$$s=@fsockopen(\"127.0.0.1\",80); exit($$s?0:1);'"]
      interval: 10s
      timeout: 5s
      retries: 18
      start_period: 30s
`, image, environment, port, mount), nil
}
