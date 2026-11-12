//go:build linux

package executor

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strings"
	"time"

	"local/panel/internal/core"
)

type dockerCPUStats struct {
	Usage struct {
		Total  *uint64  `json:"total_usage"`
		PerCPU []uint64 `json:"percpu_usage"`
	} `json:"cpu_usage"`
	System *uint64 `json:"system_cpu_usage"`
	Online int     `json:"online_cpus"`
}

type dockerStatsResponse struct {
	ID       string         `json:"id"`
	Read     time.Time      `json:"read"`
	CPU      dockerCPUStats `json:"cpu_stats"`
	Previous dockerCPUStats `json:"precpu_stats"`
	Memory   struct {
		Usage *uint64           `json:"usage"`
		Limit *uint64           `json:"limit"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
	PIDs struct {
		Current *uint64 `json:"current"`
	} `json:"pids_stats"`
	Networks map[string]struct {
		RX uint64 `json:"rx_bytes"`
		TX uint64 `json:"tx_bytes"`
	} `json:"networks"`
	BlockIO struct {
		Entries []struct {
			Operation string `json:"op"`
			Bytes     uint64 `json:"value"`
		} `json:"io_service_bytes_recursive"`
	} `json:"blkio_stats"`
}

type dockerStatsSample struct {
	ID           string    `json:"id"`
	ObservedAt   time.Time `json:"observed_at"`
	CPUPercent   *float64  `json:"cpu_percent"`
	MemoryBytes  *uint64   `json:"memory_bytes"`
	MemoryLimit  *uint64   `json:"memory_limit_bytes"`
	NetworkRX    *uint64   `json:"network_rx_bytes"`
	NetworkTX    *uint64   `json:"network_tx_bytes"`
	BlockRead    *uint64   `json:"block_read_bytes"`
	BlockWritten *uint64   `json:"block_written_bytes"`
	PIDs         *uint64   `json:"pids"`
}

func dockerCPUPercent(current, previous dockerCPUStats) *float64 {
	if current.Usage.Total == nil || previous.Usage.Total == nil || current.System == nil || previous.System == nil ||
		*current.Usage.Total < *previous.Usage.Total || *current.System <= *previous.System {
		return nil
	}
	cpus := current.Online
	if cpus == 0 {
		cpus = len(current.Usage.PerCPU)
	}
	if cpus <= 0 {
		return nil
	}
	percent := float64(*current.Usage.Total-*previous.Usage.Total) / float64(*current.System-*previous.System) * float64(cpus) * 100
	return &percent
}

func dockerStatsMetrics(raw dockerStatsResponse, id string) (dockerStatsSample, error) {
	if raw.ID != id || raw.Read.IsZero() {
		return dockerStatsSample{}, errors.New("Docker 未返回此容器的有效运行采样")
	}
	out := dockerStatsSample{ID: id, ObservedAt: raw.Read, CPUPercent: dockerCPUPercent(raw.CPU, raw.Previous), PIDs: raw.PIDs.Current}
	if raw.Memory.Usage != nil {
		usage := *raw.Memory.Usage
		for _, key := range []string{"total_inactive_file", "inactive_file", "cache"} {
			if cache, present := raw.Memory.Stats[key]; present {
				if cache < usage {
					usage -= cache
				}
				break
			}
		}
		out.MemoryBytes = &usage
	}
	if raw.Memory.Limit != nil && *raw.Memory.Limit > 0 {
		out.MemoryLimit = raw.Memory.Limit
	}
	if len(raw.Networks) > 0 {
		var received, transmitted uint64
		networkOK := true
		for _, counts := range raw.Networks {
			if math.MaxUint64-received < counts.RX || math.MaxUint64-transmitted < counts.TX {
				networkOK = false
				break
			}
			received += counts.RX
			transmitted += counts.TX
		}
		if networkOK {
			out.NetworkRX, out.NetworkTX = &received, &transmitted
		}
	}
	var read, written uint64
	readKnown, writeKnown := false, false
	for _, entry := range raw.BlockIO.Entries {
		switch strings.ToLower(entry.Operation) {
		case "read":
			if math.MaxUint64-read < entry.Bytes {
				return dockerStatsSample{}, errors.New("Docker 返回的磁盘读取计数无法核对")
			}
			read += entry.Bytes
			readKnown = true
		case "write":
			if math.MaxUint64-written < entry.Bytes {
				return dockerStatsSample{}, errors.New("Docker 返回的磁盘写入计数无法核对")
			}
			written += entry.Bytes
			writeKnown = true
		}
	}
	if readKnown {
		out.BlockRead = &read
	}
	if writeKnown {
		out.BlockWritten = &written
	}
	return out, nil
}

func dockerContainerStats(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !core.ValidDockerContainerID(id) {
		respond(w, http.StatusBadRequest, map[string]string{"error": "容器标识无效"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	var raw dockerStatsResponse
	if _, err := dockerRequest(ctx, http.MethodGet, "/containers/"+id+"/stats?stream=false", nil, &raw, 512<<10); err != nil {
		respond(w, http.StatusConflict, map[string]string{"error": "无法取得容器资源采样，请核对容器运行状态"})
		return
	}
	stats, err := dockerStatsMetrics(raw, id)
	if err != nil {
		respond(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	respond(w, http.StatusOK, stats)
}
