//go:build !go1.23

package sitegoose

import "net/http"

// requestPattern: before Go 1.23 a request doesn't carry its pattern; the
// middleware asks the ServeMux it wraps instead (ServeMux.Handler).
func requestPattern(r *http.Request) string { return "" }
