package core

import (
	"net/http"
	"testing"
)

func TestRetiredPHPNewDeploymentsRefusedBeforeExecutor(t *testing.T) {
	s := testStore(t)
	owner := accessUser(t, s, "php-retirement-owner", "admin", nil)
	a, request, login := diskHostHTTPServer(t, s)
	cookie, csrf := login(owner.Username)
	calls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		t.Fatal("retired create reached executor")
		return nil, nil
	})}}
	for _, release := range finalLegacyPHPReleases {
		retired := release.appID != "php-80" && release.appID != "php-81"
		for _, id := range append(previousLegacyPHPTemplates(release), release.template) {
			if RetiredLegacyPHPTemplate(id) != retired {
				t.Fatal("incorrect retirement", id)
			}
			if !retired {
				continue
			}
			if _, ok := LegacyPHPImage(id); !ok {
				t.Fatal("existing identity removed", id)
			}
			v := DockerProjectRequest{JobID: ID(), ProjectID: ID(), Action: "create", Name: "retired-php", TemplateID: id, Compose: "services:\n  app:\n    image: retained\n"}
			if ValidateDockerProject(v) == nil {
				t.Fatal("retired create accepted", id)
			}
			w := request("POST", "/api/docker/projects", `{"name":"retired-php","template_id":"`+id+`","host_port":23000}`, cookie, csrf)
			if w.Code != 400 || calls != 0 {
				t.Fatal("retired HTTP create dispatched", id, w.Code, calls)
			}
		}
	}
	for _, action := range []string{"start", "stop", "restart", "update"} {
		if err := ValidateDockerProject(DockerProjectRequest{JobID: ID(), ProjectID: ID(), Action: action}); err != nil {
			t.Fatal("existing lifecycle rejected", action, err)
		}
	}
}
