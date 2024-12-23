package manager

import (
	"context"
	"github.com/Erlendum/rsoi-lab-02/internal/library-system/config"
	"github.com/Erlendum/rsoi-lab-02/internal/library-system/http"
	"github.com/Erlendum/rsoi-lab-02/internal/library-system/library"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"os"
)

type server interface {
	Init() error
	Run() error
	Stop(ctx context.Context) error
}

type root struct {
	errorChan chan error
	server    server
	cfg       *config.Config
}

func NewRoot() *root {
	return &root{}
}

func (r *root) Register(ctx context.Context) error {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.With().Caller().Logger()

	var err error
	r.cfg, err = config.New()
	if err != nil {
		log.Error().Err(err).Msg("config load error")
		return err
	}

	psqldb, err := sqlx.Connect("postgres", r.cfg.PostgreSQL.DSN)
	if err != nil {
		log.Error().Err(err).Msg("postgresql connection error")
		return err
	}

	libraryRepo := library.NewRepository(psqldb)

	libraryHandler := library.NewHandler(libraryRepo, r.cfg)

	r.server = http.NewServer(&r.cfg.Server, libraryHandler)

	err = r.server.Init()
	if err != nil {
		log.Error().Err(err).Msg("server init error")
		return err
	}

	return nil
}

func (r *root) Resolve(ctx context.Context, shutdown chan os.Signal) os.Signal {
	go func() {
		log.Info().Msg("server started")
		r.errorChan <- r.server.Run()
	}()
	for {
		select {
		case err := <-r.errorChan:
			log.Err(err).Msg("error occurred")
		case sig := <-shutdown:
			return sig
		}
	}
}

func (r *root) Release(ctx context.Context, signal os.Signal) {
	log.Info().Msgf("shutdown started with signal : [%d]", signal)
	defer log.Info().Msg("shutdown completed")
	if err := r.server.Stop(ctx); err != nil {
		log.Err(err).Msg("could not stop server")
	}
}
