//go:build go1.23

package sitegoose

import "net/http"

// requestPattern is the ServeMux pattern that matched r (Go 1.23's r.Pattern).
func requestPattern(r *http.Request) string { return r.Pattern }
