package main

import "net/http"



func main() {
	ServeMux := http.NewServeMux()

	server := http.Server{
		Handler: ServeMux,
		Addr:    ":8080",
	}

	ServeMux.Handle("/", http.FileServer(
		http.Dir("./"),
	))

	server.ListenAndServe()
}
