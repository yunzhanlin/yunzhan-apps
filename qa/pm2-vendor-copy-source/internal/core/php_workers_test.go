package core

import (
	"reflect"
	"strings"
	"testing"
)

func TestPHPWorkerSupportsFrameworkCLIAndLiteralArguments(t *testing.T) {
	v := DefaultPHPWorkerSpec(ID())
	v.Name = "订单队列"
	v.Arguments = []string{"queue:work", "--queue=orders,default", "--tries=3", `literal $(touch /tmp/no) ; % $ "`, ""}
	for _, entry := range []string{"artisan", "bin/console", "workers/order.php", "worker scripts/orders.php"} {
		v.Entry = entry
		if e := ValidatePHPWorkerSpec(v); e != nil {
			t.Fatal(entry, e)
		}
	}
	args := PHPWorkerScriptArguments("/srv/site/artisan", v.Arguments)
	if !reflect.DeepEqual(args[:3], []string{"-f", "/srv/site/artisan", "--"}) || !reflect.DeepEqual(args[3:], v.Arguments) {
		t.Fatal("application arguments were changed or parsed as runtime options", args)
	}
	v.Arguments[0] = "changed"
	if args[3] != "queue:work" {
		t.Fatal("launch arguments alias mutable caller storage")
	}
}

func TestPHPWorkerRejectsTraversalControlAndUnboundedResources(t *testing.T) {
	base := DefaultPHPWorkerSpec(ID())
	base.Name, base.Entry = "queue", "artisan"
	for _, entry := range []string{"../artisan", "/etc/console", "nested/../artisan", "./artisan", `.\artisan`, ".secret.php", "nested/.secret/console", "artisan\n", "run.sh", "", "a//artisan"} {
		v := base
		v.Entry = entry
		if ValidatePHPWorkerSpec(v) == nil {
			t.Fatal("unsafe entry accepted", entry)
		}
	}
	for _, mutate := range []func(*PHPWorkerSpec){
		func(v *PHPWorkerSpec) { v.SiteID = "root" },
		func(v *PHPWorkerSpec) { v.MemoryMB = 0 },
		func(v *PHPWorkerSpec) { v.MemoryMB = 2049 },
		func(v *PHPWorkerSpec) { v.TasksMax = 10000 },
		func(v *PHPWorkerSpec) { v.StopSeconds = 121 },
		func(v *PHPWorkerSpec) { v.RestartPolicy = "shell" },
		func(v *PHPWorkerSpec) { v.Arguments = []string{"bad\x00value"} },
		func(v *PHPWorkerSpec) { v.Arguments = []string{"bad\nvalue"} },
		func(v *PHPWorkerSpec) { v.Arguments = []string{string([]byte{0xff})} },
		func(v *PHPWorkerSpec) { v.Arguments = make([]string, 33) },
		func(v *PHPWorkerSpec) { v.Arguments = []string{strings.Repeat("x", 513)} },
		func(v *PHPWorkerSpec) {
			v.Arguments = make([]string, 9)
			for i := range v.Arguments {
				v.Arguments[i] = strings.Repeat("x", 512)
			}
		},
	} {
		v := base
		mutate(&v)
		if ValidatePHPWorkerSpec(v) == nil {
			t.Fatal("invalid process configuration accepted", v)
		}
	}
}
