//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"local/panel/internal/core"
)

const openLiteSpeedPreviousCompose = "compose.before-webadmin-init.yaml"

// The Compose job's existing mutation lock covers the retained source,
// replacement and subsequent Docker operation.
func reconcileOpenLiteSpeedAdmin(ctx context.Context, metadata composeMetadata, dir string) (bool, error) {
	d, err := openComposeUpdateDirectory(dockerProjects, metadata.ID)
	if err != nil {
		return false, err
	}
	defer d.Close()
	source, sourceInfo, err := d.read("compose.yaml", 48*1024)
	if err != nil {
		return false, err
	}
	next, legacy := core.UpgradeOpenLiteSpeedAdminCompose(string(source))
	_, backupErr := d.root.Lstat(openLiteSpeedPreviousCompose)
	if !legacy && errors.Is(backupErr, os.ErrNotExist) {
		return false, nil
	}
	if backupErr == nil {
		backup, _, err := d.read(openLiteSpeedPreviousCompose, 48*1024)
		if err != nil {
			return false, err
		}
		expected, known := core.UpgradeOpenLiteSpeedAdminCompose(string(backup))
		if !known || (legacy && !bytes.Equal(backup, source)) || (!legacy && expected != string(source)) {
			return false, errors.New("OpenLiteSpeed 的原 Compose 配置与当前迁移状态不一致")
		}
	} else if !errors.Is(backupErr, os.ErrNotExist) {
		return false, backupErr
	}

	recreate, err := openLiteSpeedAdminNeedsRecreate(ctx, metadata)
	if err != nil || !legacy {
		return recreate, err
	}
	staging, err := os.MkdirTemp(dir, ".webadmin-init-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(staging)
	if err := atomicWrite(filepath.Join(staging, "compose.yaml"), []byte(next), 0o600); err != nil {
		return false, err
	}
	config, err := validateComposeFile(ctx, metadata, staging, next)
	if err != nil {
		return false, err
	}
	port, err := dualTemplatePort(config, "openlitespeed")
	if err != nil || port != metadata.HostPort || len(config.Services) != 1 {
		return false, errors.New("OpenLiteSpeed 迁移改变了原服务或监听端口")
	}
	actual, actualInfo, err := d.read("compose.yaml", 48*1024)
	if err != nil || !sameComposeUpdateFile(sourceInfo, actualInfo) || !bytes.Equal(source, actual) {
		return false, errors.New("OpenLiteSpeed 原 Compose 配置在迁移期间发生变化")
	}
	if errors.Is(backupErr, os.ErrNotExist) {
		if err := atomicWrite(filepath.Join(dir, openLiteSpeedPreviousCompose), source, 0o600); err != nil {
			return false, err
		}
	}
	if err := atomicWrite(filepath.Join(dir, "compose.yaml"), []byte(next), 0o600); err != nil {
		return false, err
	}
	return recreate, nil
}

func openLiteSpeedAdminNeedsRecreate(ctx context.Context, metadata composeMetadata) (bool, error) {
	filters, _ := json.Marshal(map[string][]string{"label": {
		"com.docker.compose.project=" + metadata.Engine,
		"com.docker.compose.service=openlitespeed",
	}})
	var containers []struct {
		ID string `json:"Id"`
	}
	if _, err := dockerRequest(ctx, http.MethodGet, "/containers/json?all=1&filters="+url.QueryEscape(string(filters)), nil, &containers, 256*1024); err != nil {
		return false, err
	}
	if len(containers) == 0 {
		return true, nil
	}
	if len(containers) != 1 || len(containers[0].ID) != 64 || !dockerObjectPattern.MatchString(containers[0].ID) {
		return false, errors.New("无法唯一核对原 OpenLiteSpeed 容器")
	}
	var existing struct {
		ID     string `json:"Id"`
		Config struct {
			Image  string            `json:"Image"`
			Cmd    []string          `json:"Cmd"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	id := containers[0].ID
	if _, err := dockerRequest(ctx, http.MethodGet, "/containers/"+id+"/json", nil, &existing, 512*1024); err != nil {
		return false, err
	}
	if existing.ID != id || existing.Config.Labels["com.docker.compose.project"] != metadata.Engine ||
		existing.Config.Labels["com.docker.compose.service"] != "openlitespeed" {
		return false, errors.New("原 OpenLiteSpeed 容器身份发生变化")
	}
	switch core.OpenLiteSpeedAdminCommandVersion(existing.Config.Image, existing.Config.Cmd) {
	case 1:
		return true, nil
	case 2:
		return false, nil
	default:
		return false, errors.New("无法核对原 OpenLiteSpeed WebAdmin 启动命令")
	}
}
