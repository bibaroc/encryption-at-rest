package db

import (
	"github.com/bibaroc/encryption-at-rest/pkg/env"
)

func DBConfigurationFromEnv() DBConfiguration {
	return DBConfiguration{
		Host:     env.String("DB_HOST", "postgres"),
		Port:     env.Int("DB_PORT", 5432),
		User:     env.String("DB_USER", "postgres"),
		Password: env.String("DB_PASSWORD", "postgres"),
		DbName:   env.String("DB_NAME", "postgres"),
	}
}
