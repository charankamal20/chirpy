package main

import (
	"log"
	"net/http"
)

func healthCheckHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("OK"))
	}
}

func main() {
	ServeMux := http.NewServeMux()

	port := ":8080"
	server := http.Server{
		Handler: ServeMux,
		Addr:    port,
	}

	ServeMux.Handle("/app/", http.StripPrefix("/app/", http.FileServer(
		http.Dir("./"),
	)))

	ServeMux.HandleFunc("/healthz", healthCheckHandler())

	log.Println("Starting server on", port)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalln(err.Error())
	}
}
