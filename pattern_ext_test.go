//go:build go1.22

//go:debug httpmuxgo121=0

package sitegoose_test

// Go 1.22's patterns ("GET /orders/{id}") name the route, method and host left
// out. The go:debug line: this module says go 1.21, which keeps the old
// ServeMux for its own tests; an app on go 1.22 or later has the new one.

import (
	"context"
	"net/http"
	"testing"
)

func TestServeMuxPatternsNameTheRoute(t *testing.T) {
	f := newFake(t)
	p := newPlatform(t, f)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /orders/{id}", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("POST /orders/{id}/items", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201) })
	h := p.Middleware(mux)
	serve(h, "GET", "/orders/1")
	serve(h, "GET", "/orders/2")
	serve(h, "POST", "/orders/2/items")
	serve(h, "GET", "/missing/9")
	p.Flush(context.Background())
	got := map[string]float64{}
	for _, row := range f.rows("/events/server-requests", "rows") {
		got[row["method"].(string)+" "+row["route"].(string)] += row["count"].(float64)
	}
	want := map[string]float64{"GET /orders/{id}": 2, "POST /orders/{id}/items": 1, "GET /(not found)": 1}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%v", got)
		}
	}
}
