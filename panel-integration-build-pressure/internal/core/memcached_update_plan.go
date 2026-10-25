package core

import (
	"encoding/json"
	"errors"
	"strings"

	"local/panel/internal/appcatalog"
)

// Compose decodes the reviewed YAML escapes into actual CR/LF before running
// the shell. This constant is the runtime command, not its escaped YAML spelling.
const MemcachedHealthCommand = "printf 'version\r\n' | nc -w 2 127.0.0.1 11211 | grep -q '^VERSION'"

// This is a read-only project precondition, not signing authority, an update
// acknowledgement or permission to recreate a container. The native receiver
// must reconstruct it from held private files and actual Docker observations.
type MemcachedUpdatePlan struct {
	Format                int    `json:"format"`
	AppID                 string `json:"app_id"`
	ProjectID             string `json:"project_id"`
	ProjectSHA256         string `json:"project_sha256"`
	MetadataSHA256        string `json:"metadata_sha256"`
	ComposeSHA256         string `json:"compose_sha256"`
	RollbackComposeSHA256 string `json:"rollback_compose_sha256"`
	ContainerID           string `json:"container_id"`
	RuntimeImageID        string `json:"runtime_image_id"`
	RuntimeConfigSHA256   string `json:"runtime_config_sha256"`
	CurrentImage          string `json:"current_image"`
	TargetImage           string `json:"target_image"`
	HostPort              int    `json:"host_port"`
	AlreadyPinned         bool   `json:"already_pinned"`
	CacheMayBeCleared     bool   `json:"cache_may_be_cleared"`
}

// MemcachedComposeUpdatePlan accepts only the reviewed template
// shapes. It never normalizes or rewrites a user's changed YAML, environment,
// command, port, volume or security policy into something that merely matches.
func MemcachedComposeUpdatePlan(project, metadataSHA string, source []byte, port int, container, imageID, runtimeSHA string) (MemcachedUpdatePlan, error) {
	var empty MemcachedUpdatePlan
	if !ValidID(project) || !registryDigestValid(metadataSHA) || !registryDigestValid(runtimeSHA) || !registryDigestValid(container) ||
		!strings.HasPrefix(imageID, "sha256:") || !registryDigestValid(strings.TrimPrefix(imageID, "sha256:")) || len(source) == 0 || len(source) > 48*1024 {
		return empty, errors.New("Memcached 原项目身份、配置摘要或容器镜像身份无效")
	}
	target, err := dockerTemplate("memcached-cache", port)
	if err != nil {
		return empty, err
	}
	legacy := strings.Replace(target, "image: "+appcatalog.MemcachedDigestImage+"\n", "image: memcached:1.6.45-alpine\n", 1)
	rollback := strings.Replace(target, "image: "+appcatalog.MemcachedDigestImage+"\n", "image: "+imageID+"\n", 1)
	currentImage := "memcached:1.6.45-alpine"
	switch string(source) {
	case target:
		currentImage = appcatalog.MemcachedDigestImage
	case legacy:
	case rollback:
		// A previous bounded rollback may have pinned the exact original local
		// image. No tag substitution, arbitrary YAML or different image is allowed.
		currentImage = imageID
	default:
		return empty, errors.New("原 Memcached 配置不是已审核模板；保留原配置，不能自动覆盖手工修改")
	}
	out := MemcachedUpdatePlan{Format: 1, AppID: "memcached", ProjectID: project, MetadataSHA256: metadataSHA, ComposeSHA256: Hash(string(source)), ContainerID: container, RuntimeImageID: imageID, RuntimeConfigSHA256: runtimeSHA, CurrentImage: currentImage, TargetImage: appcatalog.MemcachedDigestImage, HostPort: port, AlreadyPinned: currentImage == appcatalog.MemcachedDigestImage, CacheMayBeCleared: true}
	out.RollbackComposeSHA256 = Hash(rollback)
	out.ProjectSHA256, err = memcachedPlanIdentity(out)
	return out, err
}

func memcachedPlanIdentity(plan MemcachedUpdatePlan) (string, error) {
	plan.ProjectSHA256 = ""
	identity, err := json.Marshal(struct {
		Domain string              `json:"domain"`
		Plan   MemcachedUpdatePlan `json:"plan"`
	}{"yunzhan.memcached-project-precondition.v1", plan})
	if err != nil {
		return "", err
	}
	return Hash(string(identity)), nil
}

// ValidateMemcachedUpdatePlan checks a transport reply's complete closed shape
// and self-binding only. It deliberately cannot authorize a native mutation.
func ValidateMemcachedUpdatePlan(plan MemcachedUpdatePlan, project string) error {
	if plan.Format != 1 || plan.AppID != "memcached" || plan.ProjectID != project || !ValidID(project) ||
		!registryDigestValid(plan.MetadataSHA256) || !registryDigestValid(plan.ComposeSHA256) || !registryDigestValid(plan.RuntimeConfigSHA256) ||
		!registryDigestValid(plan.ContainerID) || !strings.HasPrefix(plan.RuntimeImageID, "sha256:") || !registryDigestValid(strings.TrimPrefix(plan.RuntimeImageID, "sha256:")) ||
		plan.TargetImage != appcatalog.MemcachedDigestImage || (plan.CurrentImage != "memcached:1.6.45-alpine" && plan.CurrentImage != plan.TargetImage && plan.CurrentImage != plan.RuntimeImageID) ||
		plan.AlreadyPinned != (plan.CurrentImage == plan.TargetImage) || !plan.CacheMayBeCleared || plan.HostPort < 1024 || plan.HostPort > 65535 {
		return errors.New("Memcached 预检回复结构或原项目身份无法核对")
	}
	template, err := dockerTemplate("memcached-cache", plan.HostPort)
	if err != nil || plan.ComposeSHA256 != Hash(strings.Replace(template, "image: "+plan.TargetImage+"\n", "image: "+plan.CurrentImage+"\n", 1)) ||
		plan.RollbackComposeSHA256 != Hash(strings.Replace(template, "image: "+plan.TargetImage+"\n", "image: "+plan.RuntimeImageID+"\n", 1)) {
		return errors.New("Memcached 原配置或固定镜像回滚配置摘要不一致")
	}
	identity, err := memcachedPlanIdentity(plan)
	if err != nil || plan.ProjectSHA256 != identity {
		return errors.New("Memcached 预检回复摘要不一致")
	}
	return nil
}

// Preserve every original reviewed setting, but bind a recreated rollback to
// its retained opaque local image, never a mutable tag that a pull may move.
func MemcachedComposeRollback(plan MemcachedUpdatePlan) ([]byte, error) {
	if err := ValidateMemcachedUpdatePlan(plan, plan.ProjectID); err != nil {
		return nil, err
	}
	target, err := dockerTemplate("memcached-cache", plan.HostPort)
	if err != nil {
		return nil, err
	}
	return []byte(strings.Replace(target, "image: "+plan.TargetImage+"\n", "image: "+plan.RuntimeImageID+"\n", 1)), nil
}

// Only the fixed audited template can be materialized from a validated old
// inspection. This does not authorize a mutation or accept caller-supplied YAML.
func MemcachedComposeUpdateTarget(plan MemcachedUpdatePlan) ([]byte, error) {
	if err := ValidateMemcachedUpdatePlan(plan, plan.ProjectID); err != nil {
		return nil, err
	}
	target, err := dockerTemplate("memcached-cache", plan.HostPort)
	return []byte(target), err
}
