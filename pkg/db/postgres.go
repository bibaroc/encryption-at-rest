package db

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

// DBConfiguration ...
type DBConfiguration struct {
	Host     string
	Port     int
	User     string
	Password string
	DbName   string
}

// PGConnect will connect to the database and ping it to insure connectivity.
func PGConnect(config DBConfiguration) (*sql.DB, error) {
	dataSource := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=disable",
		config.User,
		config.Password,
		config.Host,
		config.Port,
		config.DbName,
	)

	database, err := sql.Open("postgres", dataSource)
	if err != nil {
		return nil, err
	}

	err = database.Ping()
	if err != nil {
		return nil, err
	}

	return database, nil
}
