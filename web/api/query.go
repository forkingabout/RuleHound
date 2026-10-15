package api

import (
	"io"
	"net/http"
	"strings"

	"rulehound/core"
	"rulehound/db"
)

func Query(database *core.Database) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(
				w,
				"Method not allowed",
				http.StatusMethodNotAllowed,
			)
			return
		}

		defer r.Body.Close()

		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxQueryBytes))
		if err != nil {
			http.Error(
				w,
				"Failed to read request body",
				http.StatusBadRequest,
			)
			return
		}

		cypher := strings.TrimSpace(string(data))
		if cypher == "" {
			http.Error(
				w,
				"Query is empty",
				http.StatusBadRequest,
			)
			return
		}

		core.Debug("Request made to /api/query")

		yamlData, err := db.ReadDB(r.Context(), database, cypher)
		if err != nil {
			if queryCancelled(r) {
				return
			}

			core.Error(err.Error())

			http.Error(
				w,
				err.Error(),
				http.StatusBadRequest,
			)
			return
		}

		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		_, _ = w.Write(yamlData)
	}
}

// queryCancelled reports whether the client went away mid-query, in which
// case the error is expected and there is nobody left to send a response to.
func queryCancelled(r *http.Request) bool {
	if r.Context().Err() == nil {
		return false
	}

	core.Warn("Query cancelled by client")

	return true
}
