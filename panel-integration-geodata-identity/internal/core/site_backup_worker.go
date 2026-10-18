package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"
)

// Site backups have their own worker so large archives do not hold up site
// configuration jobs. They reuse the same artifact ID across retries/restarts.
func RunSiteBackupWorker(ctx context.Context, store *Store, executor *ExecutorClient) {
	if executor == nil {
		return
	}
	client := *executor.Client
	client.Timeout = 30 * time.Minute
	longExecutor := &ExecutorClient{Client: &client}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			job, err := store.NextSiteBackupJob()
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				log.Printf("claim site backup job: %v", err)
				continue
			}
			var payload JobPayload
			if json.Unmarshal([]byte(job.Payload), &payload) != nil || payload.SiteBackup == nil || payload.SiteBackup.SiteID != job.SiteID || !ValidID(payload.SiteBackup.ID) {
				_, _ = store.DB.Exec(`UPDATE jobs SET state='failed',error='网站备份任务身份无效',updated_at=? WHERE id=? AND state='running'`, Now(), job.ID)
				continue
			}
			backup := *payload.SiteBackup
			err = longExecutor.Call(ctx, http.MethodPost, "/v1/sites/"+job.SiteID+"/backups", backup, &backup)
			if ctx.Err() != nil {
				return
			}
			if finishErr := store.FinishSiteBackupJob(job, backup, err); finishErr != nil {
				log.Printf("persist site backup job %s: %v", job.ID, finishErr)
			}
		}
	}
}
