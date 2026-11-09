package core

import "errors"

// These two executors require the actual original queue identity. Keep every
// other existing software request byte shape unchanged.
func softwareExecutorPayload(target, job string, settings map[string]any, version string) (map[string]any, error) {
	out := map[string]any{"settings": settings, "version": version}
	if target == "system-hardening" || target == "intrusion-prevention" {
		if !ValidID(job) {
			return nil, errors.New("安全应用原队列任务身份无效，未调用执行器")
		}
		out["job_id"] = job
	}
	return out, nil
}
