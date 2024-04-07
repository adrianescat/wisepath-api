package main

import (
	"context"
	"database/sql"
	_ "github.com/lib/pq"
	"github.com/sakirsensoy/genv"
	_ "github.com/sakirsensoy/genv/dotenv/autoload"
	"os"
	"sync"
	"time"
	"wisepath.adrianescat.com/graph/model"
	"wisepath.adrianescat.com/internal/jsonlog"
	"wisepath.adrianescat.com/internal/vcs"
)

var (
	version = vcs.Version()
)

type dbConfig struct {
	dsn          string
	maxOpenConns int
	maxIdleConns int
	maxIdleTime  string
}

type config struct {
	port int
	env  string
	db   dbConfig
	cors struct {
		trustedOrigins []string
	}
}

type app struct {
	config *config
	logger *jsonlog.Logger
	models model.Models
	wg     sync.WaitGroup
}

func main() {
	var cfg = &config{
		port: genv.Key("PORT").Int(),
		env:  genv.Key("ENV").Default("development").String(),
	}

	cfg.db.dsn = genv.Key("DB-DSN").String()
	cfg.db.maxOpenConns = genv.Key("DB-MAX-OPEN-CONNS").Default(25).Int()
	cfg.db.maxIdleConns = genv.Key("DB-MAX-IDLE-CONNS").Default(25).Int()
	cfg.db.maxIdleTime = genv.Key("DB-MAX-IDLE-TIME").Default("15m").String()

	trustedDomains := []string{"http://localhost:3000"}
	cfg.cors.trustedOrigins = trustedDomains

	logger := jsonlog.New(os.Stdout, jsonlog.LevelInfo)

	db, err := openDB(cfg)
	if err != nil {
		logger.PrintFatal(err, nil)
	}

	defer db.Close()

	logger.PrintInfo("database connection pool established", nil)

	app := &app{
		config: cfg,
		logger: logger,
		models: model.NewModels(db),
	}

	app.serve(db)
}

func openDB(cfg *config) (*sql.DB, error) {
	db, err := sql.Open("postgres", cfg.db.dsn)

	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(cfg.db.maxOpenConns)

	db.SetMaxIdleConns(cfg.db.maxIdleConns)

	duration, err := time.ParseDuration(cfg.db.maxIdleTime)

	if err != nil {
		return nil, err
	}

	db.SetConnMaxIdleTime(duration)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	defer cancel()

	err = db.PingContext(ctx)

	if err != nil {
		return nil, err
	}

	return db, nil
}
