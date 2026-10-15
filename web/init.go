package web

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"

	"rulehound/core"
	"rulehound/web/api"
)

//go:embed static
var staticFiles embed.FS

func InitWebServer(cfg *core.Config, database *core.Database) error {
	mux := http.NewServeMux()

	api.InitAPI(mux, database)

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("failed to load embedded static files: %w", err)
	}

	index, err := fs.ReadFile(staticFS, "index.html")
	if err != nil {
		return fmt.Errorf("failed to load embedded index.html: %w", err)
	}

	mux.Handle(
		"/static/",
		http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))),
	)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(index)
	})

	address := fmt.Sprintf(
		"%s:%d",
		cfg.Server.Host,
		cfg.Server.Port,
	)

	core.Success(fmt.Sprintf(
		"Web server listening on http://%s",
		address,
	))

	if err := http.ListenAndServe(address, mux); err != nil {
		core.Error(fmt.Sprintf(
			"Web server stopped: %v",
			err,
		))

		return err
	}

	return nil
}
