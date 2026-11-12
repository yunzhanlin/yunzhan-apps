package appcatalog

import "testing"

func TestDockerMetricsPackageRequiresItsReviewedRuntimeTarget(t *testing.T) {
	m := panelRequirementFixture()
	m.ID, m.Version = "docker-manager", DockerMetricsVersion
	m.Delivery = Delivery{Provider: "runtime", Target: "docker-auto", ManageRoute: "docker"}
	available := func(feature string) bool { return feature == DockerMetricsFeature }
	if validatePanelRequirements(m, available) == nil {
		t.Fatal("missing resource monitoring handler was accepted")
	}
	m.RequiredPanelFeatures = []string{DockerMetricsFeature}
	if err := validatePanelRequirements(m, available); err != nil {
		t.Fatal(err)
	}
	if validatePanelRequirements(m, func(string) bool { return false }) == nil {
		t.Fatal("older panel admitted the resource monitoring package")
	}
	foreign := m
	foreign.Delivery.Target = "apache-2.4.68"
	if validatePanelRequirements(foreign, available) == nil {
		t.Fatal("a different runtime target borrowed Docker monitoring")
	}
	old := m
	old.Version = "1-compat1"
	old.RequiredPanelFeatures = nil
	if err := validatePanelRequirements(old, nil); err != nil {
		t.Fatal("original Docker install was refused", err)
	}
}
