package main

import (
	"log"
	"net/http"
	"vulnWeb/pkg/endpoints"
)

func main() {
	endpoints := endpoints.New("localhost:9999", http.NewServeMux())
	endpoints.FillEndpoints()
	log.Fatal(endpoints.ListenAndServe())
}
