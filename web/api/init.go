package api

import (
	"net/http"

	"rulehound/core"
)

func InitAPI(mux *http.ServeMux, database *core.Database) {
	mux.HandleFunc(
		"/api/ingest/yaml",
		IngestYAML(database),
	)
	mux.HandleFunc(
		"/api/query",
		Query(database),
	)
	mux.HandleFunc(
		"/api/query/json",
		QueryJSON(database),
	)
	mux.HandleFunc(
		"/api/clear",
		ClearDB(database),
	)
}
