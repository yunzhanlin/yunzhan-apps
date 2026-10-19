package core

import "errors"

// Only the hardening executor understands the original-job durable protocol.
// Keep every other existing software request byte shape unchanged.
func softwareExecutorPayload(target, job string, settings map[string]any, version string) (map[string]any, error) {
	out := map[string]any{"settings": settings, "version": version}
	if target == "system-hardening" {
		if !ValidID(job) {
			return nil, errors.New("加固原队列任务身份无效，未调用执行器")
		}
		out["job_id"] = job
	}
	return out, nil
}
