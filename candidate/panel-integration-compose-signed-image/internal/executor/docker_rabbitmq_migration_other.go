//go:build !linux

package executor

import "errors"

func RunRabbitMQMigration(string) error    { return errors.New("RabbitMQ 迁移仅支持 Linux") }
func ResumeRabbitMQMigration(string) error { return errors.New("RabbitMQ 迁移仅支持 Linux") }
