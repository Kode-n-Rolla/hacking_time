package main

import (
	"fmt"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Request received:")
	fmt.Println("Method:", r.Method)
	fmt.Println("URL:", r.URL.String())
	fmt.Println("Headers:", r.Header)
	w.Write([]byte("Sniffed!"))
}

func main() {
	http.HandleFunc("/", handler)
	log.Println("Sniffer started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
