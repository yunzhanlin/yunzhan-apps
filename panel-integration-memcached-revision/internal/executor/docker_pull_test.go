package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"
)

const dockerPullFixtureDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const dockerPullFixtureID = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func dockerPullFixtureStream(image string) string {
	return "{\"status\":\"Pulling from library/memcached\",\"id\":\"1.6.45-alpine\"}\n" +
		"{\"status\":\"Already exists\",\"progressDetail\":{},\"id\":\"abc123\"}\n" +
		"{\"status\":\"Digest: " + dockerPullFixtureDigest + "\"}\n" +
		"{\"status\":\"Status: Image is up to date for " + image + "\"}\n"
}

func TestDockerPullReferenceDefaultsToOneLatestNotAllTags(t *testing.T) {
	for input, expected := range map[string]string{"redis": "redis:latest", "library/redis": "library/redis:latest", "docker.io/library/redis": "docker.io/library/redis:latest", "example.com/team/app": "example.com/team/app:latest", "localhost/team/app": "localhost/team/app:latest", "redis:8.2": "redis:8.2", "redis@" + dockerPullFixtureDigest: "redis@" + dockerPullFixtureDigest, "redis:8.2@" + dockerPullFixtureDigest: "redis:8.2@" + dockerPullFixtureDigest} {
		t.Run(input, func(t *testing.T) {
			actual, err := dockerPullRequestReference(input)
			if err != nil || actual != expected {
				t.Fatal(actual, err)
			}
		})
	}
	for _, input := range []string{"", " redis", "redis ", "https://example.com/redis", "redis?tag=x", "redis\n", "redis:latest@sha256:bad", strings.Repeat("a", 201)} {
		if value, err := dockerPullRequestReference(input); err == nil || value != "" {
			t.Fatal("invalid image admitted", input)
		}
	}
}

func TestDockerPullCompleteDaemonReceiptAcceptsCurrentAndClassicEngineFraming(t *testing.T) {
	for _, scenario := range []string{"uptodate", "downloaded", "one-byte-chunks", "crlf-blank", "no-final-newline", "late-warning", "hub-alias", "digest-tag", "digest-tag-removed", "digest-no-tag"} {
		t.Run(scenario, func(t *testing.T) {
			image, familiar := "memcached:1.6.45-alpine", "memcached:1.6.45-alpine"
			switch scenario {
			case "hub-alias":
				image = "docker.io/library/" + image
			case "digest-tag", "digest-tag-removed":
				image += "@" + dockerPullFixtureDigest
				familiar = image
				if scenario == "digest-tag-removed" {
					familiar = "memcached@" + dockerPullFixtureDigest
				}
			case "digest-no-tag":
				image = "memcached@" + dockerPullFixtureDigest
				familiar = image
			}
			body := dockerPullFixtureStream(familiar)
			switch scenario {
			case "downloaded":
				body = strings.Replace(body, "Image is up to date", "Downloaded newer image", 1)
			case "crlf-blank":
				body = "\r\n" + strings.ReplaceAll(body, "\n", "\r\n\r\n")
			case "no-final-newline":
				body = strings.TrimSuffix(body, "\n")
			case "late-warning":
				body += "{\"status\":\"WARNING: platform observation\"}\n"
			}
			var reader io.Reader = strings.NewReader(body)
			if scenario == "one-byte-chunks" {
				reader = iotest.OneByteReader(reader)
			}
			receipt, err := readDockerPullResponse(context.Background(), image, 200, reader)
			if err != nil || receipt.Image != image || receipt.Digest != dockerPullFixtureDigest {
				t.Fatal("complete matching stream rejected", receipt, err)
			}
		})
	}
}

func TestDockerPullIncompleteOrAmbiguousStreamNeverReportsSuccess(t *testing.T) {
	good := dockerPullFixtureStream("memcached:1.6.45-alpine")
	digestEvent := "{\"status\":\"Digest: " + dockerPullFixtureDigest + "\"}\n"
	statusEvent := "{\"status\":\"Status: Image is up to date for memcached:1.6.45-alpine\"}\n"
	for name, body := range map[string]string{
		"empty": "", "whitespace": " \n\r\n", "object": "{}", "null": "null", "array": "[]", "malformed": "{\"status\":", "unknown-event": "{\"progress\":\"anything\"}\n",
		"no-completion": digestEvent, "no-digest": statusEvent, "completion-before-digest": statusEvent + digestEvent,
		"duplicate-completion": good + statusEvent, "duplicate-digest": digestEvent + good, "bad-digest": strings.Replace(good, dockerPullFixtureDigest, "sha256:bad", 1),
		"different-reference": strings.Replace(good, "for memcached:", "for redis:", 1), "malformed-completion": strings.Replace(good, "Status: Image is up to date", "Status: success", 1),
		"error": "{\"error\":\"private-do-not-reflect\"}\n", "detail-only": "{\"errorDetail\":{\"message\":\"private-do-not-reflect\"}}\n",
		"late-error": good + "{\"error\":\"private-do-not-reflect\"}\n", "empty-error": good + "{\"error\":\"\"}\n", "null-error": good + "{\"error\":null}\n", "error-case": good + "{\"Error\":\"private-do-not-reflect\"}\n",
		"escaped-error": good + "{\"\\u0065rror\":\"private-do-not-reflect\"}\n", "null-detail": good + "{\"errorDetail\":null}\n",
		"duplicate-status": "{\"status\":\"invalid\",\"status\":\"valid\"}\n" + good, "case-status": "{\"Status\":\"anything\"}\n" + good,
		"case-collision": "{\"status\":\"first\",\"Status\":\"second\"}\n" + good, "escaped-duplicate": "{\"status\":\"first\",\"\\u0073tatus\":\"second\"}\n" + good,
		"null-status": "{\"status\":null}\n" + good, "numeric-status": "{\"status\":1}\n" + good, "null-id": "{\"status\":\"progress\",\"id\":null}\n" + good,
		"trailing-json": good + "{\"status\":\"progress\"} {}\n", "invalid-utf8": good + "{\"status\":\"\xff\"}\n", "overlong-event": "{\"status\":\"" + strings.Repeat("a", dockerPullEventLimit) + "\"}\n" + good,
	} {
		t.Run(name, func(t *testing.T) {
			receipt, err := readDockerPullResponse(context.Background(), "memcached:1.6.45-alpine", 200, strings.NewReader(body))
			if err == nil || receipt != (dockerPullReceipt{}) || strings.Contains(err.Error(), "private-do-not-reflect") {
				t.Fatal("incomplete/ambiguous stream or private error admitted", receipt, err)
			}
		})
	}
	if receipt, err := readDockerPullResponse(context.Background(), "memcached@sha256:"+strings.Repeat("c", 64), 200, strings.NewReader(good)); err == nil || receipt != (dockerPullReceipt{}) {
		t.Fatal("different pinned digest admitted", receipt, err)
	}
	for _, status := range []int{0, 201, 204, 206, 301, 307, 400, 401, 429, 500} {
		if receipt, err := readDockerPullResponse(context.Background(), "memcached:1.6.45-alpine", status, strings.NewReader(good)); err == nil || receipt != (dockerPullReceipt{}) {
			t.Fatal("non-pull response admitted", status, receipt, err)
		}
	}
}

type dockerPullEndingReader struct {
	raw    *strings.Reader
	err    error
	onDone func()
}

func (r *dockerPullEndingReader) Read(p []byte) (int, error) {
	n, err := r.raw.Read(p)
	if err == io.EOF {
		if r.onDone != nil {
			r.onDone()
		}
		return n, r.err
	}
	return n, err
}

func TestDockerPullRealEOFAndCancellationAreRequiredEvenAfterTerminalStatus(t *testing.T) {
	for _, scenario := range []string{"unexpected-eof", "late-private-transport-error", "cancel-at-eof", "already-canceled", "nil-context", "nil-reader"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := &dockerPullEndingReader{raw: strings.NewReader(dockerPullFixtureStream("memcached:1.6.45-alpine")), err: io.EOF}
			var reader io.Reader = r
			switch scenario {
			case "unexpected-eof":
				r.err = io.ErrUnexpectedEOF
			case "late-private-transport-error":
				r.err = errors.New("private-do-not-reflect")
			case "cancel-at-eof":
				r.onDone = cancel
			case "already-canceled":
				cancel()
			case "nil-context":
				ctx = nil
			case "nil-reader":
				reader = nil
			}
			if receipt, err := readDockerPullResponse(ctx, "memcached:1.6.45-alpine", 200, reader); err == nil || receipt != (dockerPullReceipt{}) || strings.Contains(err.Error(), "private-do-not-reflect") {
				t.Fatal("unknown transport result admitted", receipt, err)
			}
		})
	}
}

type dockerPullRepeatedReader struct {
	line string
	n    int64
}

func (r *dockerPullRepeatedReader) Read(p []byte) (int, error) {
	if r.n == 0 {
		return 0, io.EOF
	}
	count := min(len(p), int(r.n), len(r.line))
	copy(p[:count], r.line[:count])
	r.n -= int64(count)
	return count, nil
}

func TestDockerPullTotalCapacityCannotTurnArtificialEOFIntoSuccess(t *testing.T) {
	good := dockerPullFixtureStream("memcached:1.6.45-alpine")
	// Blank lines cost no JSON allocations; they still count towards the
	// ORIGINAL 64 MiB total bound. An error beyond it must never be hidden.
	for _, extra := range []int64{0, 1} {
		padding := &dockerPullRepeatedReader{line: strings.Repeat("\n", 32<<10), n: dockerPullStreamLimit - int64(len(good)) + extra}
		reader := io.MultiReader(strings.NewReader(good), padding)
		if extra == 1 {
			reader = io.MultiReader(reader, strings.NewReader("{\"error\":\"hidden\"}\n"))
		}
		receipt, err := readDockerPullResponse(context.Background(), "memcached:1.6.45-alpine", 200, reader)
		if extra == 0 && (err != nil || receipt.Digest != dockerPullFixtureDigest) || extra == 1 && (err == nil || receipt != (dockerPullReceipt{})) {
			t.Fatal("total capacity boundary", extra, receipt, err)
		}
	}
}

func dockerPullFixtureInspection(id string) []byte {
	raw, _ := json.Marshal(map[string]any{"Id": id, "RepoDigests": []string{"docker.io/library/memcached@" + dockerPullFixtureDigest}, "Config": map[string]string{"Env": "private-do-not-reflect"}})
	return raw
}

func TestDockerPulledImageUsesOpaqueLocalIDAndMatchingRegistryIdentity(t *testing.T) {
	receipt := dockerPullReceipt{Image: "memcached:1.6.45-alpine", Digest: dockerPullFixtureDigest}
	calls := []string{}
	id, err := verifyDockerPulledImage(context.Background(), receipt, func(_ context.Context, ref string) ([]byte, error) {
		calls = append(calls, ref)
		return dockerPullFixtureInspection(dockerPullFixtureID), nil
	})
	if err != nil || id != dockerPullFixtureID || id == receipt.Digest || len(calls) != 2 || calls[0] != receipt.Image || calls[1] != id {
		t.Fatal("registry digest confused with actual local image ID", id, calls, err)
	}
}

func TestDockerPulledImageRejectsUnboundOrChangedIdentityWithoutMutation(t *testing.T) {
	for _, scenario := range []string{"read-error", "missing", "malformed", "duplicate-id", "case-id", "duplicate-digests", "wrong-digest", "wrong-repository", "missing-digests", "empty-digests", "null-digests", "oversized-digests", "oversized-body", "tag-instead-of-id", "missing-id", "second-id-changed", "second-repo-changed", "second-read-error", "canceled-after-first", "canceled-after-second", "invalid-receipt", "noncanonical-bare-receipt", "pinned-digest-mismatch", "nil-reader", "nil-context"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			receipt := dockerPullReceipt{Image: "memcached:1.6.45-alpine", Digest: dockerPullFixtureDigest}
			calls := 0
			var read dockerPulledImageRead = func(_ context.Context, ref string) ([]byte, error) {
				calls++
				raw := dockerPullFixtureInspection(dockerPullFixtureID)
				switch scenario {
				case "read-error":
					return nil, errors.New("private-do-not-reflect")
				case "missing":
					return nil, nil
				case "malformed":
					return []byte("{not-json"), nil
				case "duplicate-id":
					raw = []byte(strings.Replace(string(raw), "{", "{\"Id\":\""+dockerPullFixtureID+"\",", 1))
				case "case-id":
					raw = []byte(strings.Replace(string(raw), "\"Id\"", "\"ID\"", 1))
				case "duplicate-digests":
					raw = []byte(strings.Replace(string(raw), "{", "{\"repodigests\":[],", 1))
				case "wrong-digest":
					raw = []byte(strings.ReplaceAll(string(raw), dockerPullFixtureDigest, "sha256:"+strings.Repeat("c", 64)))
				case "wrong-repository":
					raw = []byte(strings.ReplaceAll(string(raw), "library/memcached", "library/redis"))
				case "missing-digests":
					raw = []byte("{\"Id\":\"" + dockerPullFixtureID + "\"}")
				case "empty-digests", "null-digests", "oversized-digests":
					var values []string
					if scenario == "empty-digests" {
						values = []string{}
					} else if scenario == "oversized-digests" {
						values = make([]string, 257)
					}
					raw, _ = json.Marshal(map[string]any{"Id": dockerPullFixtureID, "RepoDigests": values})
				case "oversized-body":
					raw = make([]byte, (1<<20)+1)
				case "tag-instead-of-id":
					raw = []byte(strings.ReplaceAll(string(raw), dockerPullFixtureID, receipt.Image))
				case "missing-id":
					raw = []byte(strings.ReplaceAll(string(raw), "\"Id\"", "\"not-id\""))
				case "second-id-changed":
					if calls == 2 {
						raw = dockerPullFixtureInspection("sha256:" + strings.Repeat("c", 64))
					}
				case "second-repo-changed":
					if calls == 2 {
						raw = []byte(strings.ReplaceAll(string(raw), "memcached", "redis"))
					}
				case "second-read-error":
					if calls == 2 {
						return nil, errors.New("private-do-not-reflect")
					}
				case "canceled-after-first":
					cancel()
				case "canceled-after-second":
					if calls == 2 {
						cancel()
					}
				}
				return raw, nil
			}
			switch scenario {
			case "invalid-receipt":
				receipt.Digest = "sha256:bad"
			case "noncanonical-bare-receipt":
				receipt.Image = "memcached"
			case "pinned-digest-mismatch":
				receipt.Image = "memcached@sha256:" + strings.Repeat("c", 64)
			case "nil-reader":
				read = nil
			case "nil-context":
				ctx = nil
			}
			id, err := verifyDockerPulledImage(ctx, receipt, read)
			if err == nil || id != "" || strings.Contains(err.Error(), "private-do-not-reflect") || calls > 2 {
				t.Fatal("unbound image identity admitted", id, calls, err)
			}
		})
	}
}

func TestDockerPullDaemonHTTPProtocolDoesNotReplayOrInspectIncompletePulls(t *testing.T) {
	for _, scenario := range []string{"complete", "bare-default-latest", "pinned", "empty-stream", "truncated-stream", "late-error", "transport-interrupted", "redirect301", "redirect307", "redirect308", "http500", "image-identity-mismatch", "second-inspect-mismatch", "canceled-before-request"} {
		t.Run(scenario, func(t *testing.T) {
			image := "memcached:1.6.45-alpine"
			if scenario == "bare-default-latest" {
				image = "memcached"
			} else if scenario == "pinned" {
				image += "@" + dockerPullFixtureDigest
			}
			requested, _ := dockerPullRequestReference(image)
			var mu sync.Mutex
			var requests []string
			postCount, inspectCount := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				requests = append(requests, r.Method+" "+r.URL.RequestURI())
				if r.Host != "docker" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
					t.Error("daemon request identity/cookie changed")
				}
				switch {
				case r.Method == http.MethodPost && r.URL.Path == "/images/create":
					postCount++
					if r.URL.Query().Get("fromImage") != requested || len(r.URL.Query()) != 1 {
						t.Error("wrong image, all-tags request or extra instructions")
					}
					body := dockerPullFixtureStream(requested)
					switch scenario {
					case "empty-stream":
						body = ""
					case "truncated-stream":
						body = "{\"status\":\"Pulling from library/memcached\"}\n"
					case "late-error":
						body += "{\"errorDetail\":{\"message\":\"private-do-not-reflect\"}}\n"
					case "transport-interrupted":
						w.Header().Set("Content-Length", "999999")
					case "redirect301", "redirect307", "redirect308":
						status := map[string]int{"redirect301": 301, "redirect307": 307, "redirect308": 308}[scenario]
						w.Header().Set("Location", "http://docker/never-replay")
						w.WriteHeader(status)
					case "http500":
						w.WriteHeader(500)
					}
					_, _ = io.WriteString(w, body)
				case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/images/") && strings.HasSuffix(r.URL.Path, "/json"):
					inspectCount++
					ref := requested
					if inspectCount == 2 {
						ref = dockerPullFixtureID
					}
					if r.URL.EscapedPath() != "/images/"+url.PathEscape(ref)+"/json" || r.URL.RawQuery != "" {
						t.Error("inspection not bound to requested ref then opaque local ID")
					}
					body := dockerPullFixtureInspection(dockerPullFixtureID)
					if scenario == "image-identity-mismatch" || scenario == "second-inspect-mismatch" && inspectCount == 2 {
						body = []byte(strings.ReplaceAll(string(body), "library/memcached", "library/redis"))
					}
					_, _ = w.Write(body)
				default:
					t.Error("unexpected mutation/replay", r.Method, r.URL.Path)
					w.WriteHeader(500)
				}
			}))
			defer server.Close()
			address := server.Listener.Addr().String()
			transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", address)
			}}
			defer transport.CloseIdleConnections()
			jar, _ := cookiejar.New(nil)
			base, _ := url.Parse("http://docker")
			jar.SetCookies(base, []*http.Cookie{{Name: "unrelated", Value: "never-send"}})
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second, Jar: jar}
			read := func(ctx context.Context, ref string) ([]byte, error) {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/images/"+url.PathEscape(ref)+"/json", nil)
				if err != nil {
					return nil, err
				}
				clean := *client
				clean.Jar = nil
				response, err := clean.Do(req)
				if err != nil {
					return nil, err
				}
				defer response.Body.Close()
				return io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "canceled-before-request" {
				cancel()
			}
			err := dockerPullFromDaemon(ctx, image, client, read)
			mu.Lock()
			defer mu.Unlock()
			complete := scenario == "complete" || scenario == "bare-default-latest" || scenario == "pinned"
			if complete != (err == nil) || err != nil && strings.Contains(err.Error(), "private-do-not-reflect") || postCount > 1 {
				t.Fatal("incorrect pull/replay result", requests, err)
			}
			expectedInspects := 0
			if complete || scenario == "second-inspect-mismatch" {
				expectedInspects = 2
			} else if scenario == "image-identity-mismatch" {
				expectedInspects = 1
			}
			if inspectCount != expectedInspects || scenario == "canceled-before-request" && len(requests) != 0 || scenario != "canceled-before-request" && postCount != 1 {
				t.Fatal("incomplete pull inspected/replayed or skipped a binding", requests)
			}
		})
	}
}
