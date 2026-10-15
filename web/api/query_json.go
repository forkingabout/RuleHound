package api

import (
	"io"
	"net/http"
	"strings"

	"rulehound/core"
	"rulehound/db"
)

const maxQueryBytes = 1 << 20

func QueryJSON(database *core.Database) http.HandlerFunc {
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

		core.Debug("Request made to /api/query/json")

		jsonData, err := db.ReadDBJSON(r.Context(), database, cypher)
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

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		_, _ = w.Write(jsonData)
	}
}
