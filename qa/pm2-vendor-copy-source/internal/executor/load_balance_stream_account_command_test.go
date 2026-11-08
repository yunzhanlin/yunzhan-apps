package executor

import (
	"reflect"
	"testing"
)

func TestLoadBalanceStreamAccountCreationCommandIsClosedAndFresh(t *testing.T) {
	want := []string{"--system", "--user-group", "--no-create-home", "--no-log-init",
		"--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "--comment", "panel-lbstream", "--groups", "",
		"--key", "SYS_UID_MIN=100", "--key", "SYS_UID_MAX=999", "--key", "SYS_GID_MIN=100", "--key", "SYS_GID_MAX=999", "--", "panel-lbstream"}
	got := loadBalanceStreamAccountCreationArgs()
	if !reflect.DeepEqual(got, want) {
		t.Fatal("fixed account command widened")
	}
	got[0], got[len(got)-1] = "--non-unique", "root"
	if !reflect.DeepEqual(loadBalanceStreamAccountCreationArgs(), want) {
		t.Fatal("caller mutation changed a later fixed command")
	}
}
