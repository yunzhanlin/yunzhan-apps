package core

import (
	"testing"
	"time"
)

func TestNotificationsPersistReadStateAndDeduplicate(t *testing.T) {
	s := testStore(t)
	now := time.Now().Unix()
	scheduleID, runID := ID(), ID()
	if _, e := s.DB.Exec(`INSERT INTO schedules(id,name,kind,target_id,schedule_type,timezone,minute,hour,weekday,retention_count,enabled,revision,next_run_at,created_at,updated_at) VALUES(?,?,'admin_script',?,'daily','UTC',0,3,1,1,1,1,?,?,?)`, scheduleID, "night audit", ID(), now+3600, Now(), Now()); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec(`INSERT INTO schedule_runs(id,schedule_id,schedule_name,trigger,state,scheduled_for,started_at,finished_at,error,created_at) VALUES(?,?,?,'manual','failed',?,?,?,'exit status 7',?)`, runID, scheduleID, "night audit", now, now, now, Now()); e != nil {
		t.Fatal(e)
	}
	items, unread, e := s.Notifications(20)
	if e != nil || len(items) != 1 || unread != 1 || items[0].SourceID != runID || items[0].Severity != "critical" {
		t.Fatal(items, unread, e)
	}
	if e = s.ReadNotification(items[0].ID); e != nil {
		t.Fatal(e)
	}
	items, unread, e = s.Notifications(20)
	if e != nil || len(items) != 1 || unread != 0 || items[0].ReadAt == 0 {
		t.Fatal("read state was not persistent or event duplicated", items, unread, e)
	}
	if e = s.ReadAllNotifications(); e != nil {
		t.Fatal(e)
	}
	settings, e := s.NotificationSettings()
	if e != nil {
		t.Fatal(e)
	}
	settings.ScheduleFailures = false
	settings.RetentionDays = 30
	if settings, e = s.SaveNotificationSettings(settings, settings.Revision); e != nil || settings.Revision != 2 {
		t.Fatal(settings, e)
	}
	if _, e = s.DB.Exec(`INSERT INTO schedule_runs(id,schedule_id,schedule_name,trigger,state,scheduled_for,started_at,finished_at,error,created_at) VALUES(?,?,?,'manual','failed',?,?,?,'disabled source',?)`, ID(), scheduleID, "night audit", now+1, now+1, now+1, Now()); e != nil {
		t.Fatal(e)
	}
	items, _, e = s.Notifications(20)
	if e != nil || len(items) != 1 {
		t.Fatal("disabled source still created a notification", items, e)
	}
	settings.ScheduleFailures = true
	if settings, e = s.SaveNotificationSettings(settings, settings.Revision); e != nil {
		t.Fatal(e)
	}
	items, _, e = s.Notifications(20)
	if e != nil || len(items) != 1 {
		t.Fatal("re-enabling replayed a failure from the disabled interval", items, e)
	}
	newRunID := ID()
	if _, e = s.DB.Exec(`INSERT INTO schedule_runs(id,schedule_id,schedule_name,trigger,state,scheduled_for,started_at,finished_at,error,created_at) VALUES(?,?,?,'manual','failed',?,?,?,'new failure',?)`, newRunID, scheduleID, "night audit", now+2, now+2, now+2, Now()); e != nil {
		t.Fatal(e)
	}
	items, _, e = s.Notifications(20)
	if e != nil || len(items) != 2 || items[0].SourceID != newRunID {
		t.Fatal("new failure after re-enabling was not recorded", items, e)
	}
}

func TestNotificationsIncludeResolvedMonitorAlert(t *testing.T) {
	s := testStore(t)
	alertID := ID()
	now := time.Now().Unix()
	if _, e := s.DB.Exec(`INSERT INTO monitor_alerts(id,metric,state,started_at,last_observed_at,resolved_at,peak,threshold) VALUES(?,'cpu','resolved',?,?,?,?,80)`, alertID, now-60, now, now, 92); e != nil {
		t.Fatal(e)
	}
	items, unread, e := s.Notifications(20)
	if e != nil || len(items) != 1 || unread != 1 || items[0].SourceID != alertID {
		t.Fatal("resolved alert was lost before the first notification read", items, unread, e)
	}
	if e = s.ReadNotification(items[0].ID); e != nil {
		t.Fatal(e)
	}
	items, unread, e = s.Notifications(20)
	if e != nil || len(items) != 1 || unread != 0 {
		t.Fatal("resolved alert notification was duplicated", items, unread, e)
	}
}

func TestReadAllNotificationsIncludesUnseenEvents(t *testing.T) {
	s := testStore(t)
	alertID := ID()
	now := time.Now().Unix()
	if _, e := s.DB.Exec(`INSERT INTO monitor_alerts(id,metric,state,started_at,last_observed_at,peak,threshold) VALUES(?,'memory','active',?,?,91,80)`, alertID, now, now); e != nil {
		t.Fatal(e)
	}
	if e := s.ReadAllNotifications(); e != nil {
		t.Fatal(e)
	}
	items, unread, e := s.Notifications(20)
	if e != nil || len(items) != 1 || unread != 0 || items[0].ReadAt == 0 {
		t.Fatal("mark all read missed an event that had not yet been listed", items, unread, e)
	}
}

func TestNotificationMonitorPolicyDoesNotReplayDisabledAlerts(t *testing.T) {
	s := testStore(t)
	settings, e := s.NotificationSettings()
	if e != nil {
		t.Fatal(e)
	}
	settings.MonitorAlerts = false
	settings, e = s.SaveNotificationSettings(settings, settings.Revision)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().Unix()
	oldID := ID()
	if _, e = s.DB.Exec(`INSERT INTO monitor_alerts(id,metric,state,started_at,last_observed_at,resolved_at,peak,threshold) VALUES(?,'cpu','resolved',?,?,?,?,80)`, oldID, now-60, now, now, 92); e != nil {
		t.Fatal(e)
	}
	settings.MonitorAlerts = true
	settings, e = s.SaveNotificationSettings(settings, settings.Revision)
	if e != nil {
		t.Fatal(e)
	}
	items, _, e := s.Notifications(20)
	if e != nil || len(items) != 0 {
		t.Fatal("old disabled alert was replayed", items, e)
	}
	newID := ID()
	if _, e = s.DB.Exec(`INSERT INTO monitor_alerts(id,metric,state,started_at,last_observed_at,peak,threshold) VALUES(?,'memory','active',?,?,90,80)`, newID, now, now); e != nil {
		t.Fatal(e)
	}
	items, _, e = s.Notifications(20)
	if e != nil || len(items) != 1 || items[0].SourceID != newID {
		t.Fatal("new enabled alert was not recorded", items, e)
	}
}
