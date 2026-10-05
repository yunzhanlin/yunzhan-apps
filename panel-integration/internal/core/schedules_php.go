package core

import "database/sql"

func saveSchedulePHPScript(tx *sql.Tx, scheduleID, siteID string) error {
	if siteID == "" {
		_, e := tx.Exec(`DELETE FROM schedule_php_scripts WHERE schedule_id=?`, scheduleID)
		return e
	}
	_, e := tx.Exec(`INSERT INTO schedule_php_scripts(schedule_id,site_id) VALUES(?,?) ON CONFLICT(schedule_id) DO UPDATE SET site_id=excluded.site_id`, scheduleID, siteID)
	return e
}
