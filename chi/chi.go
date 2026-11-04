// Package sitegoosechi runs the platform in a chi router, with Server speed
// and errors under chi's route pattern ("/orders/{id}").
//
//	r := chi.NewRouter()
//	r.Use(sitegoosechi.Middleware(p))
//
// It is sitegoose.Middleware with chi's route; wrapping the router in
// sitegoose.Middleware as well is fine.
package sitegoosechi

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	sitegoose "github.com/sitegoose/sitegoose-go"
)

// Middleware is the platform as chi middleware.
func Middleware(p *sitegoose.Platform) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		named := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// chi knows the pattern once it has routed, so after next, and
			// on the way past a panic too.
			defer func() {
				if rc := chi.RouteContext(r.Context()); rc != nil {
					sitegoose.SetRoute(r.Context(), rc.RoutePattern())
				}
			}()
			next.ServeHTTP(w, r)
		})
		return p.Middleware(named)
	}
}
