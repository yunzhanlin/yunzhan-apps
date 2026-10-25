package core

import "net/http"

// A job observation never reconciles, restarts, rewrites or infers success from
// systemd. It returns only the original worker's atomically published result.
func ValidDockerJobObservation(value DockerJobResult, id string) bool {
	if !ValidID(id) || value.JobID != id || len(value.Error) > 4096 || len(value.Message) > 4096 || len(value.Image) > 1024 {
		return false
	}
	switch value.State {
	case "queued", "running", "succeeded":
		if value.Error != "" {
			return false
		}
	case "failed":
	default:
		return false
	}
	if value.Kind == "compose" {
		return ValidID(value.ProjectID) && value.ContainerID == "" && value.Image == ""
	}
	return value.Kind == "" && value.ProjectID == "" && (value.ContainerID == "" || validDockerObjectID(value.ContainerID))
}

func (a *Server) dockerJobObservationRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/docker/job-observations/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		w.Header().Set("Cache-Control", "no-store")
		id := r.PathValue("id")
		if !ValidID(id) {
			fail(w, 400, "Docker 作业标识无效")
			return
		}
		var out DockerJobResult
		if err := a.Executor.Call(r.Context(), http.MethodGet, "/v1/docker/job-observations/"+id, nil, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		if !ValidDockerJobObservation(out, id) {
			fail(w, 409, "Docker 原始任务状态无法核对；未修改或重新提交原任务")
			return
		}
		send(w, 200, out)
	}))
}
