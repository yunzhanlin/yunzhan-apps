package core

import (
	"encoding/json"
	"local/panel/internal/appcatalog"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRegistryComposeDeliveryMatchesPublishedRecipes(t *testing.T) {
	raw, err := os.ReadFile("../appcatalog/testdata/published-catalog-20261015.json")
	if err != nil {
		t.Fatal(err)
	}
	var original struct {
		Manifests map[string]string `json:"manifests"`
	}
	if err := json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	ids := []string{"rabbitmq", "mongodb", "elasticsearch", "openlitespeed", "phpmyadmin"}
	for target := range LegacyPHPImages {
		ids = append(ids, "php-"+strings.TrimPrefix(target, "php-legacy-"))
	}
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			var manifest appcatalog.Manifest
			if err := json.Unmarshal([]byte(original.Manifests[id]), &manifest); err != nil {
				t.Fatal(err)
			}
			if err := validateRegistryComposeDelivery(manifest); err != nil {
				t.Fatal("unchanged published package refused:", err)
			}
			compose, err := dockerTemplateOnArchitecture(manifest.Delivery.Target, 26571, "amd64")
			if err != nil || strings.Count(compose, "    image: "+manifest.Delivery.Image+"\n") != 1 {
				t.Fatal("rendered primary image differs from the original published recipe")
			}
		})
	}
}

func TestRegistryPhpMyAdmin523RequiresItsSignedImageAndVersion(t *testing.T) {
	manifest := appcatalog.Manifest{
		ID: "phpmyadmin", Version: phpMyAdmin523AppVersion, Risk: "maintained",
		Delivery: appcatalog.Delivery{Provider: "compose", Target: PhpMyAdmin523Template,
			ManageRoute: "databases", Image: dockerPhpMyAdmin523Image},
	}
	if err := validateRegistryComposeDelivery(manifest); err != nil {
		t.Fatal(err)
	}
	oldImage := manifest
	oldImage.Delivery.Image = dockerPhpMyAdminImage
	oldVersion := manifest
	oldVersion.Version = "5.2.2-compat1"
	if validateRegistryComposeDelivery(oldImage) == nil || validateRegistryComposeDelivery(oldVersion) == nil {
		t.Fatal("phpMyAdmin 5.2.3 accepted an earlier signed image or application version")
	}
}

func TestRegistryInstallSignedRabbitMQImageBindsActualSubmission(t *testing.T) {
	baseline := appcatalog.Manifest{
		SchemaVersion: 1, ID: "rabbitmq", Name: "RabbitMQ", Category: "deployment", Version: "4.1-compat1",
		Summary: "Bounded signed RabbitMQ recipe for actual Core install tests", Stage: "ready", Risk: "maintained",
		Delivery:      appcatalog.Delivery{Provider: "compose", Target: "rabbitmq", ManageRoute: "docker", Image: dockerRabbitMQImage},
		Compatibility: appcatalog.Compatibility{OS: []string{runtimecatalog.HostPlatform()}, Architectures: []string{runtime.GOARCH}},
		Capabilities:  []string{"install"},
	}
	tests := []struct {
		name string
		edit func(*appcatalog.Manifest)
		want int
	}{
		{"same verified image", func(*appcatalog.Manifest) {}, 202},
		{"signed different digest", func(m *appcatalog.Manifest) {
			m.Delivery.Image = strings.SplitN(dockerRabbitMQImage, "@", 2)[0] + "@sha256:" + strings.Repeat("7", 64)
		}, 409},
		{"signed tag without digest", func(m *appcatalog.Manifest) {
			m.Delivery.Image = strings.SplitN(dockerRabbitMQImage, "@", 2)[0]
		}, 409},
		{"signed absent image", func(m *appcatalog.Manifest) { m.Delivery.Image = "" }, 409},
		{"signed image but different template", func(m *appcatalog.Manifest) { m.Delivery.Target = "mongodb" }, 409},
		{"signed manual template", func(m *appcatalog.Manifest) { m.Delivery.Target = "wordpress-blog" }, 409},
		{"signed conflicting route", func(m *appcatalog.Manifest) { m.Delivery.ManageRoute = "databases" }, 409},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest := baseline
			tc.edit(&manifest)
			store := testStore(t)
			before := installReplayCounts(t, store)
			catalog, item := installSignedCatalogForManifest(t, manifest)
			var calls atomic.Int32
			submitted := make(chan DockerProjectRequest, 1)
			executor := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				var op DockerProjectRequest
				if r.URL.Path != "/v1/docker/projects/jobs" || r.Method != "POST" || json.NewDecoder(r.Body).Decode(&op) != nil {
					t.Error("unexpected executor request", r.Method, r.URL.Path)
					w.WriteHeader(500)
					return
				}
				select {
				case submitted <- op:
				default:
					t.Error("duplicate executor submission")
				}
				_ = json.NewEncoder(w).Encode(DockerJobResult{JobID: op.JobID, ProjectID: op.ProjectID, Kind: "compose", State: "queued"})
			})
			server := &Server{Store: store, AppCatalog: catalog, Executor: executor, Config: Config{DataDir: t.TempDir()}}
			actor := identity{ID: ID(), Username: "admin"}
			key := ID()
			request := registryInstallInput{ExpectedVersion: item.Version, ExpectedSHA256: item.SHA256, Name: "owned-rabbitmq-qa", HostPort: 26571}
			response := installReplayHTTP(server, item.ID, key, actor, request)
			if response.Code != tc.want {
				t.Fatalf("install response = %d, wanted %d: %s", response.Code, tc.want, response.Body.String())
			}
			if tc.want == 409 {
				if calls.Load() != 0 || !reflect.DeepEqual(before, installReplayCounts(t, store)) ||
					!strings.Contains(response.Body.String(), "未提交安装") {
					t.Fatal("incompatible signed recipe reserved, audited or submitted an installation")
				}
				return
			}
			if calls.Load() != 1 {
				t.Fatal("exact signed recipe did not submit once")
			}
			op := <-submitted
			if op.TemplateID != "rabbitmq" || op.Action != "create" || op.Name != request.Name ||
				strings.Count(op.Compose, "    image: "+manifest.Delivery.Image+"\n") != 1 ||
				!strings.Contains(op.Compose, "127.0.0.1:26571:15672") || !strings.Contains(op.Compose, "127.0.0.1:26572:5672") {
				t.Fatal("signed identity or loopback bindings were not carried to Compose")
			}
			var scope, target, sha, version, job string
			if err := store.DB.QueryRow(`SELECT scope,target,sha256,version,job_id FROM app_registry_install_requests WHERE idempotency_key=?`, key).
				Scan(&scope, &target, &sha, &version, &job); err != nil {
				t.Fatal(err)
			}
			if scope != op.ProjectID || target != op.TemplateID || sha != item.SHA256 || version != item.Version || job != op.JobID {
				t.Fatal("install receipt is not bound to the exact accepted request")
			}
		})
	}
}

func TestRegistryMongoDB8038RequiresItsSignedImageAndVersion(t *testing.T) {
	manifest := appcatalog.Manifest{
		ID: "mongodb", Version: mongoDB8038AppVersion, Risk: "maintained",
		Delivery: appcatalog.Delivery{Provider: "compose", Target: MongoDB8038Template, ManageRoute: "docker", Image: dockerMongoDB8038Image},
	}
	if err := validateRegistryComposeDelivery(manifest); err != nil {
		t.Fatal(err)
	}
	for _, architecture := range []string{"arm64", "amd64"} {
		compose, err := dockerTemplateOnArchitecture(MongoDB8038Template, 27018, architecture)
		if err != nil || strings.Count(compose, "image: "+manifest.Delivery.Image+"\n") != 1 {
			t.Fatalf("%s did not render the exact signed image: %v", architecture, err)
		}
	}
	oldImage := manifest
	oldImage.Delivery.Image = dockerMongoDBImage
	oldVersion := manifest
	oldVersion.Version = "8.0-compat1"
	oldTemplate := manifest
	oldTemplate.Delivery.Target = MongoDBLegacyTemplate
	if validateRegistryComposeDelivery(oldImage) == nil || validateRegistryComposeDelivery(oldVersion) == nil ||
		validateRegistryComposeDelivery(oldTemplate) == nil {
		t.Fatal("MongoDB 8.0.38 accepted an old image, version or template")
	}
}
