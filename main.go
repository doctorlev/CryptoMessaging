package main

import (
	"log"
	"net/http"

	"github.com/doctorlev/CryptoMessaging/handlers"
)

func main() {

	http.HandleFunc("/api/v1/encrypt", handlers.Encrypt)
	http.HandleFunc("/api/v1/decrypt", handlers.Decrypt)

	log.Fatal(http.ListenAndServe(":8081", nil))
}
