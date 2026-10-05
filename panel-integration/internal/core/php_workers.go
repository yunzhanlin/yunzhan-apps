package core

import (
	"errors"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A worker chooses a website, never a caller-supplied PHP binary or user.
// Linux execution must resolve the current committed website binding.
type PHPWorkerSpec struct {
	SiteID        string   `json:"site_id"`
	Name          string   `json:"name"`
	Entry         string   `json:"entry"`
	Arguments     []string `json:"arguments"`
	RestartPolicy string   `json:"restart_policy"`
	MemoryMB      int      `json:"memory_mb"`
	TasksMax      int      `json:"tasks_max"`
	StopSeconds   int      `json:"stop_seconds"`
}

type PHPWorker struct {
	PHPWorkerSpec
	ID                string `json:"id"`
	Enabled           bool   `json:"enabled"`
	Status            string `json:"status"`
	ObservedReleaseID string `json:"observed_release_id,omitempty"`
	PID               int    `json:"pid,omitempty"`
	InvocationID      string `json:"invocation_id,omitempty"`
	LastError         string `json:"last_error,omitempty"`
	UpdatedAt         string `json:"updated_at"`
}

func DefaultPHPWorkerSpec(siteID string) PHPWorkerSpec {
	return PHPWorkerSpec{SiteID: siteID, RestartPolicy: "always", MemoryMB: 256, TasksMax: 64, StopSeconds: 30}
}

func ValidPHPWorkerEntry(entry string) bool {
	if len(entry) == 0 || len(entry) > 256 || !utf8.ValidString(entry) || !filepath.IsLocal(entry) || filepath.Clean(entry) != entry || strings.Contains(entry, `\`) {
		return false
	}
	for _, part := range strings.Split(entry, "/") {
		if strings.HasPrefix(part, ".") {
			return false
		}
	}
	for _, char := range entry {
		if unicode.IsControl(char) {
			return false
		}
	}
	// Framework CLI entrypoints are PHP scripts without a .php suffix.
	base := filepath.Base(entry)
	return strings.EqualFold(filepath.Ext(entry), ".php") || base == "artisan" || base == "console"
}

func ValidatePHPWorkerSpec(v PHPWorkerSpec) error {
	if !ValidID(v.SiteID) || !nodeAppName.MatchString(v.Name) || !ValidPHPWorkerEntry(v.Entry) {
		return errors.New("PHP 进程的网站、名称或入口无效；入口须为网站内 PHP 文件、artisan 或 console")
	}
	if v.RestartPolicy != "always" && v.RestartPolicy != "on-failure" {
		return errors.New("PHP 进程重启策略必须为 always 或 on-failure")
	}
	if v.MemoryMB < 64 || v.MemoryMB > 2048 || v.TasksMax < 16 || v.TasksMax > 256 || v.StopSeconds < 5 || v.StopSeconds > 120 {
		return errors.New("PHP 进程内存、子进程数或停止等待时间超出允许范围")
	}
	if len(v.Arguments) > 32 {
		return errors.New("PHP 进程最多允许 32 个独立参数")
	}
	total := 0
	for _, argument := range v.Arguments {
		total += len(argument)
		if !utf8.ValidString(argument) || len(argument) > 512 || total > 4096 {
			return errors.New("PHP 进程参数过长或编码无效")
		}
		for _, char := range argument {
			if unicode.IsControl(char) {
				return errors.New("PHP 进程参数不能包含控制字符")
			}
		}
	}
	return nil
}

// Application options stay after PHP's -- separator. They are never shell code
// and cannot be interpreted as PHP's -d, -r or -c runtime options.
func PHPWorkerScriptArguments(script string, arguments []string) []string {
	result := []string{"-f", script, "--"}
	return append(result, arguments...)
}
