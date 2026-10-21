package core

import "testing"

func TestValidateNodeApplicationBoundaries(t *testing.T) {
	valid := NodeApplication{ID: ID(), Name: "api-service", ReleaseID: "node-24.21.0", SiteID: ID(), Entry: "server.js", Port: 17000, CreatedAt: Now()}
	if e := ValidateNodeApplication(valid); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*NodeApplication){func(v *NodeApplication) { v.Entry = "../server.js" }, func(v *NodeApplication) { v.Entry = "server.php" }, func(v *NodeApplication) { v.ReleaseID = "node-99.0.0" }, func(v *NodeApplication) { v.ReleaseID = "redis-8.2.10" }, func(v *NodeApplication) { v.Port = 3000 }, func(v *NodeApplication) { v.Name = "../api" }} {
		candidate := valid
		change(&candidate)
		if e := ValidateNodeApplication(candidate); e == nil {
			t.Fatalf("accepted invalid app: %+v", candidate)
		}
	}
}
