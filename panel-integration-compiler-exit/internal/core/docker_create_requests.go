package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
)

var dockerRequestDigestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Existing panel clients use randomId()'s canonical UUIDv4. Keep the earlier
// opaque32-hex API form too; actor/job/project IDs remain strictly32-hex.
var dockerCreateRequestKeyPattern = regexp.MustCompile(`^(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})$`)

func rejectDockerCreateBeforeDispatch(w http.ResponseWriter, message string) {
	send(w, 400, map[string]any{"error": message, "request_not_accepted": true})
}

// A request key is not an authorization token. The stable server secret and
// authenticated actor bind it to one job/project without persisting the key,
// a password or the potentially private custom Compose input in a new index.
func (a *Server) dockerCreateIdentity(actor, key string, payload any) (job, project, digest string, err error) {
	if !ValidID(actor) || !dockerCreateRequestKeyPattern.MatchString(key) || len(a.accountSecretKey) < 32 {
		return "", "", "", errors.New("创建项目需要有效的原请求标识")
	}
	mac := func(scope string, value []byte) []byte {
		h := hmac.New(sha256.New, a.accountSecretKey)
		h.Write([]byte("yunzhan.docker-create.v1\x00" + scope + "\x00" + actor + "\x00" + key + "\x00"))
		h.Write(value)
		return h.Sum(nil)
	}
	ids := hex.EncodeToString(mac("identity", nil))
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", "", "", err
	}
	return ids[:32], ids[32:], hex.EncodeToString(mac("payload", raw)), nil
}

type DockerCreateRequestStatus struct {
	Found     bool             `json:"found"`
	JobID     string           `json:"job_id,omitempty"`
	ProjectID string           `json:"project_id,omitempty"`
	Job       *DockerJobResult `json:"job,omitempty"`
	Pending   bool             `json:"pending,omitempty"`
	Error     string           `json:"error,omitempty"`
}

func validComposeCreateResult(value DockerJobResult, job, project string) bool {
	if value.JobID != job || value.ProjectID != project || value.Kind != "compose" || value.Image != "" || value.ContainerID != "" || len(value.Error) > 4096 || len(value.Message) > 4096 {
		return false
	}
	switch value.State {
	case "queued", "running", "succeeded":
		return value.Error == ""
	case "failed":
		return true
	default:
		return false
	}
}
func validComposeCreateStatus(value DockerCreateRequestStatus, job string) bool {
	if !value.Found {
		return value.JobID == "" && value.ProjectID == "" && value.Job == nil && !value.Pending && value.Error == ""
	}
	if value.JobID != job || !ValidID(value.ProjectID) || len(value.Error) > 4096 {
		return false
	}
	if value.Pending {
		return value.Job == nil && value.Error != ""
	}
	return value.Error == "" && value.Job != nil && validComposeCreateResult(*value.Job, job, value.ProjectID)
}
