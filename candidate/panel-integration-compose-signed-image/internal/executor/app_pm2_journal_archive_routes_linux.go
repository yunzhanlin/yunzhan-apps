//go:build linux

package executor

import (
	"errors"
	"local/panel/internal/core"
	"net/http"
)

func (s *Service) pm2ConfigurationArchiveVersion(instance string) error {
	record, err := s.moduleInstalledRecord("pm2-manager")
	if err != nil || record["version"] != core.PM2ConfigurationArchiveAppVersion || !core.ValidID(instance) || record["installation_id"] != instance {
		return errors.New("配置封存及恢复须先签名更新至固定 compat12；旧安装不借用新归档能力")
	}
	return nil
}
func (s *Service) pm2ConfigurationArchiveReadRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/app-modules/pm2-manager/configuration-archives/{id}/records", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !core.ValidID(id) {
			respond(w, 400, map[string]string{"error": "原配置归档标识无效"})
			return
		}
		in, err := core.ParsePM2ConfigurationArchiveRecordsQuery(r.URL.RawQuery)
		if err != nil {
			respond(w, 400, map[string]string{"error": err.Error()})
			return
		}
		guard, installed, err := s.beginModuleAlertRead("pm2-manager")
		if err != nil || !installed {
			respond(w, 409, map[string]string{"error": "PM2 原安装身份无法核对"})
			return
		}
		defer guard.dir.Close()
		if err = s.pm2ConfigurationArchiveVersion(in.PM2InstallationID); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		lease, err := s.readPM2ConfigurationJournalLease()
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		defer lease.Close()
		out, err := s.pm2ConfigurationArchiveRecords(id, in)
		if err == nil && !lease.current() {
			err = errors.New("原封存读取锁已变化")
		}
		if err == nil {
			err = guard.check(r.Context())
		}
		if err == nil {
			err = lease.Close()
		}
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})

	m.HandleFunc("GET /v1/app-modules/pm2-manager/configuration-archives", func(w http.ResponseWriter, r *http.Request) {
		in, err := core.ParsePM2ConfigurationArchiveQuery(r.URL.RawQuery)
		if err != nil {
			respond(w, 400, map[string]string{"error": err.Error()})
			return
		}
		guard, installed, err := s.beginModuleAlertRead("pm2-manager")
		if err != nil || !installed {
			respond(w, 409, map[string]string{"error": "PM2 原安装身份无法核对，未读取配置归档"})
			return
		}
		defer guard.dir.Close()
		if err = s.pm2ConfigurationArchiveVersion(in.PM2InstallationID); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		lease, err := s.readPM2ConfigurationJournalLease()
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		defer lease.Close()
		out, err := s.pm2ConfigurationArchiveReport(in)
		if err == nil && !lease.current() {
			err = errors.New("配置日志读取锁已变化，请重新只读核对")
		}
		if err == nil {
			err = guard.check(r.Context())
		}
		if err == nil {
			err = lease.Close()
		}
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
}
