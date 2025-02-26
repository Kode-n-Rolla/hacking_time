package main

import (
	"fmt"
	"net"
)

func main() {
	ips, _ := net.LookupHost("target.com")
	for _, ip := range ips {
		fmt.Println("🔥 IP:", ip)
	}
}
