package core

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	MongoDBLegacyTemplate = "mongodb"
	MongoDB8038Template   = "mongodb-8038"
	mongoDB8038AppVersion = "8.0.38-compat1"
)

func IsMongoDBTemplate(template string) bool {
	return template == MongoDBLegacyTemplate || template == MongoDB8038Template
}

func mongoDBTemplateImage(template string) string {
	if template == MongoDB8038Template {
		return dockerMongoDB8038Image
	}
	return dockerMongoDBImage
}

// MongoDBKernelCompatibility checks the kernel for the requested pinned recipe.
func MongoDBKernelCompatibility(template string) error {
	release, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return errors.New("无法读取当前 Linux 内核版本，不能确认 MongoDB 8.0 兼容性")
	}
	var signature []byte
	if template == MongoDB8038Template && strings.HasPrefix(string(release), "7.0.") {
		kernelBuild, _ := os.ReadFile("/proc/sys/kernel/version")
		if strings.Contains(string(kernelBuild), "Ubuntu") {
			signature, _ = os.ReadFile("/proc/version_signature")
		}
	}
	return mongoDBKernelCompatibilityOn(template, string(release), string(signature))
}

func mongoDBKernelCompatibilityOn(template, release, ubuntuSignature string) error {
	release = strings.TrimSpace(release)
	number := release
	// MongoDB 8.0.37+ reads the upstream patch level from the Ubuntu kernel
	// signature. Only accept the 7.0 branch named by the running kernel.
	if template == MongoDB8038Template && strings.HasPrefix(release, "7.0.") {
		fields := strings.Fields(ubuntuSignature)
		if len(fields) == 3 && fields[0] == "Ubuntu" && strings.HasPrefix(fields[2], "7.0.") {
			number = fields[2]
		}
	}
	if end := strings.IndexAny(number, "-+"); end >= 0 {
		number = number[:end]
	}
	parts := strings.Split(number, ".")
	var version [3]int
	for i := range version {
		if i >= len(parts) {
			return errors.New("无法识别当前 Linux 内核版本，不能确认 MongoDB 8.0 兼容性")
		}
		value, err := strconv.Atoi(parts[i])
		if err != nil || value < 0 {
			return errors.New("无法识别当前 Linux 内核版本，不能确认 MongoDB 8.0 兼容性")
		}
		version[i] = value
	}
	major, minor, patch := version[0], version[1], version[2]
	// The affected range is 6.19 through 7.0.13 inclusive.
	if (major == 6 && minor >= 19) || (major == 7 && minor == 0 && patch < 14) {
		return fmt.Errorf("此 MongoDB 镜像与 Linux 内核 %s 不兼容。需要 Linux 6.19 以前或上游 7.0.14 及以上的内核", release)
	}
	return nil
}

func mongoDBCompose(template string, port int, password string) string {
	health := fmt.Sprintf(`["CMD-SHELL", "mongosh --username paneladmin --password '%s' --authenticationDatabase admin --quiet --eval 'quit(db.adminCommand({ping:1}).ok ? 0 : 2)'"]`, password)
	if template == MongoDB8038Template {
		health = `["CMD", "mongosh", "--quiet", "--eval", "const admin = db.getSiblingDB('admin'); const auth = admin.auth(process.env.MONGO_INITDB_ROOT_USERNAME, process.env.MONGO_INITDB_ROOT_PASSWORD); quit(auth.ok === 1 && admin.runCommand({ping:1}).ok === 1 ? 0 : 2)"]`
	}
	return fmt.Sprintf(`services:
  mongodb:
    image: %s
    restart: unless-stopped
    environment:
      MONGO_INITDB_ROOT_USERNAME: paneladmin
      MONGO_INITDB_ROOT_PASSWORD: "%s"
    ports:
      - "127.0.0.1:%d:27017"
    volumes:
      - data:/data/db
    healthcheck:
      test: %s
      interval: 15s
      timeout: 20s
      retries: 18
      start_period: 60s
volumes:
  data: {}
`, mongoDBTemplateImage(template), password, port, health)
}

func MongoDB8038ComposeMatches(source string, port int, password string) bool {
	return len(password) == 64 && ValidID(password[:32]) && ValidID(password[32:]) &&
		source == mongoDBCompose(MongoDB8038Template, port, password)
}
