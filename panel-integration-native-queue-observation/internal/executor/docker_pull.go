package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"local/panel/internal/core"
)

const dockerPullStreamLimit = 64 << 20
const dockerPullEventLimit = 1 << 20

var errDockerPullIncomplete = errors.New("Docker 镜像拉取未获得完整、匹配的成功回执；未视为更新完成或继续创建容器")
var errDockerPullIdentity = errors.New("Docker 拉取后的本地镜像身份或仓库摘要无法核对；未继续创建容器")
var dockerPullDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// A daemon stream receipt is not an application signature, actor grant,
// installation receipt or proof of container health. Its digest is a registry
// manifest/index identity, NOT an assumed Docker-local image ID.
type dockerPullReceipt struct {
	Image, Digest string
}

// The production caller holds the original Docker mutation lease for this
// whole transfer and both inspections. The internal client seam is only for
// protocol tests; it is never supplied by a request or runtime configuration.
func dockerPullFromDaemon(ctx context.Context, image string, client *http.Client, read dockerPulledImageRead) error {
	image, err := dockerPullRequestReference(image)
	if ctx == nil || client == nil || read == nil || err != nil || ctx.Err() != nil {
		return errDockerPullIncomplete
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker/images/create?fromImage="+url.QueryEscape(image), nil)
	if err != nil {
		return errDockerPullIncomplete
	}
	guarded := *client
	guarded.Jar = nil
	// Do not redirect/replay a daemon POST, including after a 307/308 response.
	guarded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := guarded.Do(req)
	if err != nil {
		return errDockerPullIncomplete
	}
	defer response.Body.Close()
	receipt, err := readDockerPullResponse(ctx, image, response.StatusCode, response.Body)
	if err != nil {
		return err
	}
	_, err = verifyDockerPulledImage(ctx, receipt, read)
	return err
}

func dockerPullRequestReference(image string) (string, error) {
	// Format checking only; this constant does not authorize a job or effect.
	if core.ValidateDockerJob(core.DockerJobRequest{JobID: "00000000000000000000000000000000", Action: "pull", Image: image}) != nil {
		return "", errDockerPullIncomplete
	}
	if !strings.Contains(image, "@") && !strings.Contains(image[strings.LastIndex(image, "/")+1:], ":") {
		// Engine's bare-name API request means ALL tags, unlike docker CLI's
		// familiar single-image default. Never turn a UI pull into pull --all.
		image += ":latest"
	}
	return image, nil
}

func dockerFamiliarPullReference(image string) string {
	if strings.HasPrefix(image, "index.docker.io/") {
		image = strings.TrimPrefix(image, "index.docker.io/")
	} else {
		image = strings.TrimPrefix(image, "docker.io/")
	}
	// Only Docker Hub's official library namespace is familiarized. An
	// explicit other registry's library path must retain its identity.
	first := strings.SplitN(image, "/", 2)[0]
	if !strings.Contains(first, ".") && first != "localhost" {
		image = strings.TrimPrefix(image, "library/")
	}
	return image
}

func dockerPullDigestReference(image string) string {
	name, digest, ok := strings.Cut(dockerFamiliarPullReference(image), "@")
	if !ok {
		return ""
	}
	if colon := strings.LastIndex(name, ":"); colon > strings.LastIndex(name, "/") {
		name = name[:colon]
	}
	return name + "@" + digest
}

// Docker may add progress fields. Allow those without letting duplicate/case
// aliases hide errors or replace identity fields through encoding/json's
// case-insensitive last-key-wins decoding. No daemon error text is reflected.
func dockerPullJSONObject(raw []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) {
		return nil, errDockerPullIncomplete
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errDockerPullIncomplete
	}
	fields, seen := map[string]json.RawMessage{}, map[string]bool{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		folded := strings.ToLower(name)
		if err != nil || !ok || name == "" || seen[folded] {
			return nil, errDockerPullIncomplete
		}
		seen[folded] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, errDockerPullIncomplete
		}
		fields[name] = value
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(fields) == 0 {
		return nil, errDockerPullIncomplete
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errDockerPullIncomplete
	}
	return fields, nil
}

func dockerPullJSONString(raw json.RawMessage) (string, bool) {
	var value string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
}

func readDockerPullResponse(ctx context.Context, image string, statusCode int, body io.Reader) (dockerPullReceipt, error) {
	var empty dockerPullReceipt
	requested, err := dockerPullRequestReference(image)
	if ctx == nil || body == nil || statusCode != 200 || err != nil || ctx.Err() != nil {
		return empty, errDockerPullIncomplete
	}
	limited := &io.LimitedReader{R: body, N: dockerPullStreamLimit + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 64<<10), dockerPullEventLimit)
	var digest string
	complete := false
	for scanner.Scan() {
		if ctx.Err() != nil || limited.N == 0 {
			return empty, errDockerPullIncomplete
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		fields, err := dockerPullJSONObject(line)
		if err != nil {
			return empty, errDockerPullIncomplete
		}
		for name := range fields {
			switch strings.ToLower(name) {
			case "error", "errordetail":
				// Even an empty/null or unfamiliar shaped error is not success.
				return empty, errDockerPullIncomplete
			case "status", "id":
				if name != strings.ToLower(name) {
					return empty, errDockerPullIncomplete
				}
			}
		}
		status, ok := dockerPullJSONString(fields["status"])
		if !ok || status == "" {
			return empty, errDockerPullIncomplete
		}
		id := ""
		if raw, exists := fields["id"]; exists {
			var ok bool
			id, ok = dockerPullJSONString(raw)
			if !ok {
				return empty, errDockerPullIncomplete
			}
		}
		if id != "" {
			continue
		}
		if strings.HasPrefix(status, "Digest:") {
			candidate := strings.TrimPrefix(status, "Digest: ")
			if digest != "" || complete || !dockerPullDigestPattern.MatchString(candidate) {
				return empty, errDockerPullIncomplete
			}
			if _, expected, pinned := strings.Cut(requested, "@"); pinned && candidate != expected {
				return empty, errDockerPullIncomplete
			}
			digest = candidate
		}
		if strings.HasPrefix(status, "Status:") {
			ref := strings.TrimPrefix(status, "Status: Downloaded newer image for ")
			if ref == status {
				ref = strings.TrimPrefix(status, "Status: Image is up to date for ")
			}
			familiar := dockerFamiliarPullReference(requested)
			// Engine backends can discard the redundant tag on tag@digest.
			if complete || digest == "" || ref == status || ref != familiar && (dockerPullDigestReference(requested) == "" || ref != dockerPullDigestReference(requested)) {
				return empty, errDockerPullIncomplete
			}
			complete = true
		}
	}
	// A LimitReader's artificial EOF, malformed event or transport error is not
	// a successful pull. Consume through actual EOF, including any late error.
	if scanner.Err() != nil || limited.N == 0 || !complete || ctx.Err() != nil {
		return empty, errDockerPullIncomplete
	}
	return dockerPullReceipt{Image: requested, Digest: digest}, nil
}

type dockerPulledImageRead func(context.Context, string) ([]byte, error)

// Re-resolve the requested reference and then its opaque local ID. Never use
// the OCI index digest as a guessed local image ID, or return an old tagged
// image after an incomplete pull. This is read-only; it does not retain an
// image, run a container, authorize a worker or advance an app version.
func verifyDockerPulledImage(ctx context.Context, receipt dockerPullReceipt, read dockerPulledImageRead) (string, error) {
	requested, err := dockerPullRequestReference(receipt.Image)
	if ctx == nil || read == nil || err != nil || requested != receipt.Image || !dockerPullDigestPattern.MatchString(receipt.Digest) || ctx.Err() != nil {
		return "", errDockerPullIdentity
	}
	if _, digest, pinned := strings.Cut(requested, "@"); pinned && digest != receipt.Digest {
		return "", errDockerPullIdentity
	}
	name := strings.SplitN(dockerFamiliarPullReference(requested), "@", 2)[0]
	if colon := strings.LastIndex(name, ":"); colon > strings.LastIndex(name, "/") {
		name = name[:colon]
	}
	expected := name + "@" + receipt.Digest
	imageID := ""
	for _, ref := range []string{requested, ""} {
		if ctx.Err() != nil {
			return "", errDockerPullIdentity
		}
		if ref == "" {
			ref = imageID
		}
		raw, err := read(ctx, ref)
		if err != nil || len(raw) == 0 || len(raw) > 1<<20 {
			return "", errDockerPullIdentity
		}
		fields, err := dockerPullJSONObject(raw)
		if err != nil {
			return "", errDockerPullIdentity
		}
		id, ok := dockerPullJSONString(fields["Id"])
		var digests []string
		if !ok || !dockerPullDigestPattern.MatchString(id) || imageID != "" && id != imageID || json.Unmarshal(fields["RepoDigests"], &digests) != nil || len(digests) == 0 || len(digests) > 256 {
			return "", errDockerPullIdentity
		}
		matched := false
		for _, digest := range digests {
			matched = matched || dockerFamiliarPullReference(digest) == expected
		}
		if !matched {
			return "", errDockerPullIdentity
		}
		imageID = id
	}
	if ctx.Err() != nil {
		return "", errDockerPullIdentity
	}
	return imageID, nil
}
