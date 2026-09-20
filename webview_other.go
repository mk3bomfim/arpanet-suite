//go:build !windows

package main

import "fmt"

func openWebView(url, title string, width, height int) {
	fmt.Printf("[HEADLESS] Serving Arpanet Suite at %s (window suppressed)\n", url)
	select {}
}
