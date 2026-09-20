package main

import (
	"embed"
	"fmt"
	"io/fs"
	"time"
)

//go:embed ui
var uiFiles embed.FS

func main() {
	// Derive sub-filesystem rooted at "ui/"
	sub, err := fs.Sub(uiFiles, "ui")
	if err != nil {
		panic(err)
	}

	// Start HTTP server in background
	go func() {
		if err := startServer(9731, sub); err != nil {
			fmt.Println("[FATAL] Server:", err)
		}
	}()

	// Give the server a moment to bind
	time.Sleep(350 * time.Millisecond)

	openWebView("http://localhost:9731", "Arpanet Suite", 1200, 750)
}
