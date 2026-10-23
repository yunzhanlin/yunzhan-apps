package core

func (s *Store) migrateMonitorDiskIO() error {
	var applied int
	if err := s.DB.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version=30`).Scan(&applied); err != nil {
		return err
	}
	if applied > 0 {
		return nil
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`ALTER TABLE monitor_samples ADD COLUMN disk_read INTEGER;
 ALTER TABLE monitor_samples ADD COLUMN disk_write INTEGER;
 ALTER TABLE monitor_samples ADD COLUMN disk_read_rate REAL;
 ALTER TABLE monitor_samples ADD COLUMN disk_write_rate REAL;
 INSERT INTO schema_migrations VALUES(30,strftime('%Y-%m-%dT%H:%M:%SZ','now'));`)
	if err != nil {
		return err
	}
	return tx.Commit()
}
