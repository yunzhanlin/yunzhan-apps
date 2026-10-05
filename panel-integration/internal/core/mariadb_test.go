package core

import (
	"local/panel/internal/runtimecatalog"
	"testing"
)

func TestValidateMariaDBInstanceBoundaries(t *testing.T) {
	if len(runtimecatalog.MariaDB()) == 0 {
		t.Skip("official MariaDB binary catalog is x86_64-only")
	}
	valid := MariaDBInstance{ID: ID(), Name: "mariadb-main", ReleaseID: "mariadb-11.8.9", Port: 13000, MemoryMB: 256, CreatedAt: Now()}
	if e := ValidateMariaDBInstance(valid); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*MariaDBInstance){
		func(v *MariaDBInstance) { v.Name = "../cache" },
		func(v *MariaDBInstance) { v.ReleaseID = "mariadb-9.9.9" },
		func(v *MariaDBInstance) { v.ReleaseID = "redis-8.2.10" },
		func(v *MariaDBInstance) { v.Port = 3306 },
		func(v *MariaDBInstance) { v.MemoryMB = 64 },
	} {
		candidate := valid
		change(&candidate)
		if e := ValidateMariaDBInstance(candidate); e == nil {
			t.Fatalf("accepted invalid instance: %+v", candidate)
		}
	}
}

func TestValidateMariaDBDatabase(t *testing.T) {
	database := MariaDBDatabase{ID: ID(), InstanceID: ID(), Name: "website_db", Username: "mdb_0123456789abcdef0123", CreatedAt: Now()}
	if e := ValidateMariaDBDatabase(database); e != nil {
		t.Fatal(e)
	}
	for _, invalid := range []MariaDBDatabase{
		{ID: ID(), InstanceID: database.InstanceID, Name: "DROP DATABASE", Username: database.Username, CreatedAt: Now()},
		{ID: ID(), InstanceID: database.InstanceID, Name: database.Name, Username: "root", CreatedAt: Now()},
		{ID: ID(), InstanceID: "../escape", Name: database.Name, Username: database.Username, CreatedAt: Now()},
	} {
		if ValidateMariaDBDatabase(invalid) == nil {
			t.Fatalf("invalid MariaDB database accepted: %+v", invalid)
		}
	}
}
