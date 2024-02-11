package main

import (
	"net/http"
	"os"

	"log/slog"

	"github.com/l3montree-dev/traefik-crowdsec-bouncer/config"
	"github.com/l3montree-dev/traefik-crowdsec-bouncer/controller"
	"github.com/lmittmann/tint"
)

func getLogLevel() slog.Level {
	envVar := os.Getenv("LOG_LEVEL")
	if envVar == "" {
		return slog.LevelDebug
	}
	switch envVar {
	case "DEBUG":
		return slog.LevelDebug
	case "INFO":
		return slog.LevelInfo
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelDebug
	}
}
func initLogger() {
	loggingHandler := tint.NewHandler(os.Stdout, &tint.Options{
		AddSource: true,
		Level:     getLogLevel(),
	})
	logger := slog.New(loggingHandler)
	slog.SetDefault(logger)
}

func main() {
	initLogger()
	config.ValidateEnv()

	router, err := setupRouter()
	if err != nil {
		slog.Error("An error occurred while starting webserver", "err", err)
		return
	}
	controller.StartStreaming()

	slog.Info("starting server on port :8080")
	err = http.ListenAndServe(":8080", router)
	if err != nil {
		slog.Error("An error occurred while starting bouncer", "err", err)
		return
	}
}

func setupRouter() (*http.ServeMux, error) {
	// Web framework
	router := http.NewServeMux()

	router.HandleFunc("GET /api/v1/ping", controller.Ping)
	router.HandleFunc("GET /api/v1/healthz", controller.Healthz)
	router.HandleFunc("GET /api/v1/forwardAuth", controller.ForwardAuth)
	router.HandleFunc("GET /api/v1/metrics", controller.Metrics)

	return router, nil
}
