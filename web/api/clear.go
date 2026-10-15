package api

import (
	"net/http"

	"rulehound/core"
	"rulehound/db"
)

func ClearDB(database *core.Database) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(
				w,
				"Method not allowed",
				http.StatusMethodNotAllowed,
			)
			return
		}

		if err := db.ClearDB(database); err != nil {
			core.Error(err.Error())

			http.Error(
				w,
				err.Error(),
				http.StatusBadRequest,
			)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Database cleared successfully!"))
	}
}
