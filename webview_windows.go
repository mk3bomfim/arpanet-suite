//go:build windows

package main

import webview "github.com/jchv/go-webview2"

func openWebView(url, title string, width, height int) {
	w := webview.New(false)
	defer w.Destroy()
	w.SetTitle(title)
	w.SetSize(width, height, webview.HintNone)
	w.Navigate(url)
	w.Run()
}
