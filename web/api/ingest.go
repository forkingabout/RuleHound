package api

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"rulehound/core"
	"rulehound/db"
)

func IngestYAML(database *core.Database) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(
				w,
				"Method not allowed",
				http.StatusMethodNotAllowed,
			)
			return
		}

		contentType := r.Header.Get("Content-Type")

		if !strings.EqualFold(contentType, "application/yaml; charset=utf-8") {
			http.Error(
				w,
				"Content-Type must be application/yaml; charset=utf-8",
				http.StatusBadRequest,
			)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("Failed to read request body: %v", err),
				http.StatusBadRequest,
			)
			return
		}

		defer r.Body.Close()

		if err := db.WriteObjects(database, body); err != nil {
			http.Error(
				w,
				err.Error(),
				http.StatusBadRequest,
			)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Ingestion successful!"))
	}
}
