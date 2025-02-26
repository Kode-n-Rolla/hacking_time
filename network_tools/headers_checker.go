package main

import (
	"fmt"
	"net/http"
)

func main() {
	resp, err := http.Get("https://target.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("Headers:")
	for key, value := range resp.Header {
		fmt.Println(key, ":", value)
	}
}
