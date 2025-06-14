package main

import (
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

	log.Println("Starting server on", port)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalln(err.Error())
	}
}
