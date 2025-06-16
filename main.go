package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync/atomic"
)

type apiConfig struct {
	fileServerHits atomic.Int32
}

func (c *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.fileServerHits.Add(1)
		fmt.Println("File server hit count incremented:", c.fileServerHits.Load())
		next.ServeHTTP(w, r)
	})
}

func healthCheckHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("OK"))
	}
}

func (c *apiConfig) getFileServerHitsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hits := c.fileServerHits.Load()
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/html")

		data, _ := os.ReadFile("./admin/metrics/index.html")

		w.Write(fmt.Appendf(nil, string(data), hits))
	}
}

func (c *apiConfig) resetHitsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c.fileServerHits.Swap(0)
		w.WriteHeader(http.StatusOK)
	}
}

func validateChirpHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		type req struct {
			Body string `json:"body" validate:"required"`
		}

		type errorResponse struct {
			Error string `json:"error"`
		}

		type successResponse struct {
			Valid bool `json:"valid"`
		}

		// Set content-type early
		w.Header().Set("Content-Type", "application/json")

		// Decode request
		var request req
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&request)
		if err != nil || request.Body == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(errorResponse{Error: "Something went wrong"})
			return
		}
		// Validate chirp length
		if len(request.Body) > 140 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(errorResponse{Error: "Chirp is too long"})
			return
		}

		// Valid chirp
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(successResponse{Valid: true})
	}
}

func main() {
	ServeMux := http.NewServeMux()

	port := ":8080"
	server := http.Server{
		Handler: ServeMux,
		Addr:    port,
	}
	api := &apiConfig{}

	fileHandler := http.FileServer(
		http.Dir("./"),
	)
	ServeMux.Handle("/app/", http.StripPrefix("/app/", api.middlewareMetricsInc(fileHandler)))

	ServeMux.HandleFunc("GET /api/healthz", healthCheckHandler())

	ServeMux.HandleFunc("GET /admin/metrics", api.getFileServerHitsHandler())

	ServeMux.HandleFunc("POST /admin/reset", api.resetHitsHandler())

	ServeMux.HandleFunc("POST /api/validate_chirp", validateChirpHandler())

	log.Println("Starting server on", port)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalln(err.Error())
	}
}
