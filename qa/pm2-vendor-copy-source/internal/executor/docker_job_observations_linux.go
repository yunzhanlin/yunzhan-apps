//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

var errDockerObservation = errors.New("Docker 原始任务状态无法核对；未修改、修复或重新提交原任务")

// Open the SAME trusted ancestry without acquiring or creating either mutation
// lock. Reading an original result is not authority to mutate an executing job.
func readDockerJobObservation(state, id string) (core.DockerJobResult, error) {
	var result core.DockerJobResult
	if !core.ValidID(id) {
		return result, errDockerObservation
	}
	tree, err := openDockerMutationTree(state)
	if err != nil {
		return result, errDockerObservation
	}
	defer tree.close()
	root := tree.roots[len(tree.roots)-1]
	name := id + ".result.json"
	f, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return result, errDockerObservation
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !moduleRecordInfo(info, false, false) || info.Size() < 2 || info.Size() > 32768 {
		return result, errDockerObservation
	}
	raw, err := io.ReadAll(io.LimitReader(f, 32769))
	if err != nil || len(raw) > 32768 || json.Unmarshal(raw, &result) != nil || !core.ValidDockerJobObservation(result, id) {
		return core.DockerJobResult{}, errDockerObservation
	}
	canonical, err := json.Marshal(result)
	visible, namedErr := root.Lstat(name)
	opened, statErr := f.Stat()
	if err != nil || !bytes.Equal(raw, canonical) || namedErr != nil || statErr != nil || !geoStoreStableInfo(info, opened) || !geoStoreStableInfo(opened, visible) || !tree.current() {
		return core.DockerJobResult{}, errDockerObservation
	}
	return result, nil
}

func (s *Service) dockerJobObservationRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/docker/job-observations/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		out, err := readDockerJobObservation(filepath.Dir(dockerJobs), r.PathValue("id"))
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
}
