package main

import "net/http"



func main() {
	ServeMux := http.NewServeMux()

	server := http.Server{
		Handler: ServeMux,
		Addr:    ":8080",
	}

	server.ListenAndServe()

	
}
