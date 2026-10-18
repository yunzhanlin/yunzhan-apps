package core

import "testing"

func TestValidateRedisInstanceBoundaries(t *testing.T) {
	valid := RedisInstance{ID: ID(), Name: "session-cache", ReleaseID: "redis-8.2.10", Port: 16379, MaxMemoryMB: 128, CreatedAt: Now()}
	if e := ValidateRedisInstance(valid); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*RedisInstance){
		func(v *RedisInstance) { v.Name = "../cache" },
		func(v *RedisInstance) { v.ReleaseID = "redis-9.9.9" },
		func(v *RedisInstance) { v.ReleaseID = "node-24.21.0" },
		func(v *RedisInstance) { v.Port = 6379 },
		func(v *RedisInstance) { v.MaxMemoryMB = 16 },
	} {
		candidate := valid
		change(&candidate)
		if e := ValidateRedisInstance(candidate); e == nil {
			t.Fatalf("accepted invalid instance: %+v", candidate)
		}
	}
}
