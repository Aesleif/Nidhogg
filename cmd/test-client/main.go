package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"golang.org/x/net/http2"
)

func main() {
	serverURL := "https://localhost:8443/"
	psk := "my-dev-key"
	dest := "example.com:80\n"
	httpReq := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"

	if len(os.Args) > 1 {
		serverURL = os.Args[1]
	}
	if len(os.Args) > 2 {
		psk = os.Args[2]
	}

	// io.Pipe for streaming request body
	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()
		// 1. Send PSK
		pw.Write([]byte(psk))
		// 2. Send destination
		pw.Write([]byte(dest))
		// 3. Send HTTP request through tunnel
		pw.Write([]byte(httpReq))
	}()

	// HTTP/2 client with self-signed cert support
	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: transport}

	req, err := http.NewRequest(http.MethodPost, serverURL, pr)
	if err != nil {
		log.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	fmt.Println("Connecting to server...")
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("Response status: %s\n", resp.Status)
	fmt.Printf("Response headers: %v\n\n", resp.Header)

	// Read and print response body (tunneled data from upstream)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("read response: %v", err)
	}
	fmt.Printf("--- Tunneled response (%d bytes) ---\n%s\n", len(body), string(body))
}
