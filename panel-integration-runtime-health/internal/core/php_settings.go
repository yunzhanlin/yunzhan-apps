package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/runtimecatalog"
	"regexp"
	"strings"
	"time"
)

type PHPSettings struct {
	Extensions          []string `json:"extensions,omitempty"`
	MemoryMB            int      `json:"memory_mb"`
	MaxExecutionSeconds int      `json:"max_execution_seconds"`
	UploadMB            int      `json:"upload_mb"`
	PostMB              int      `json:"post_mb"`
	Timezone            string   `json:"timezone"`
	DisplayErrors       bool     `json:"display_errors"`
	MaxChildren         int      `json:"max_children"`
	MaxRequests         int      `json:"max_requests"`
}

func DefaultPHPSettings() PHPSettings {
	return PHPSettings{MemoryMB: 128, MaxExecutionSeconds: 60, UploadMB: 2, PostMB: 8, Timezone: "UTC", MaxChildren: 3, MaxRequests: 500}
}

var phpTimezone = regexp.MustCompile(`^[A-Za-z0-9_+\-/]{1,64}$`)

func ValidatePHPSettings(in *PHPSettings) error {
	if in == nil {
		return nil
	}
	seen := map[string]bool{}
	if len(in.Extensions) > 8 {
		return errors.New("每个站点最多选择 8 个独立扩展")
	}
	for _, id := range in.Extensions {
		if _, ok := runtimecatalog.FindExtension(id); !ok || seen[id] {
			return errors.New("请选择不重复且在固定目录中的 PHP 扩展")
		}
		seen[id] = true
	}
	if in.MemoryMB < 32 || in.MemoryMB > 2048 {
		return errors.New("PHP 内存限制需为 32–2048 MiB")
	}
	if in.MaxExecutionSeconds < 0 || in.MaxExecutionSeconds > 3600 {
		return errors.New("PHP 执行时间需为 0–3600 秒，0 表示不限")
	}
	if in.UploadMB < 1 || in.UploadMB > 512 || in.PostMB < in.UploadMB || in.PostMB > 512 || in.PostMB > in.MemoryMB {
		return errors.New("上传需为 1–512 MiB，POST 上限不得小于上传或超过内存限制")
	}
	if in.MaxChildren < 1 || in.MaxChildren > 32 || in.MaxRequests < 1 || in.MaxRequests > 10000 {
		return errors.New("FPM 子进程需为 1–32 个，回收请求数需为 1–10000")
	}
	if !phpTimezone.MatchString(in.Timezone) || (in.Timezone != "UTC" && !strings.Contains(in.Timezone, "/")) {
		return errors.New("请选择有效的 IANA 时区")
	}
	if _, e := time.LoadLocation(in.Timezone); e != nil {
		return errors.New("时区不存在")
	}
	return nil
}
func PHPInstanceID(site Site) string {
	if site.PHPVersionID == "" {
		return "static"
	}
	id := site.ID + "-" + site.PHPVersionID
	if site.Settings.PHP != nil {
		b, _ := json.Marshal(site.Settings.PHP)
		id += "-cfg-" + Hash(string(b))[:24]
	}
	return id
}
func PHPIniValues(in *PHPSettings) [][2]string {
	if in == nil {
		return nil
	}
	show := "0"
	if in.DisplayErrors {
		show = "1"
	}
	return [][2]string{{"memory_limit", fmt.Sprintf("%dM", in.MemoryMB)}, {"max_execution_time", fmt.Sprint(in.MaxExecutionSeconds)}, {"upload_max_filesize", fmt.Sprintf("%dM", in.UploadMB)}, {"post_max_size", fmt.Sprintf("%dM", in.PostMB)}, {"date.timezone", in.Timezone}, {"display_errors", show}}
}
