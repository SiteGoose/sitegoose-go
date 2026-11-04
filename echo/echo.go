// Package sitegooseecho runs the platform in an echo app: the firewall, the
// proxy and maintenance mode before the handlers, then errors (panics, a
// handler's returned error answered 5xx, 5xx answers) and Server speed under
// echo's route ("/orders/:id").
//
//	e := echo.New()
//	e.Use(middleware.Recover())
//	e.Use(sitegooseecho.Middleware(p))
//
// Add it after middleware.Recover, so a panic reaches it first. A handler's
// error is answered here (c.Error) so its status is known, then returned as
// echo's own middleware does: echo's error handler leaves an answer that has
// been sent alone, and a custom one should check c.Response().Committed too.
package sitegooseecho

import (
	"bufio"
	"net"
	"net/http"

	"github.com/labstack/echo/v4"

	sitegoose "github.com/sitegoose/sitegoose-go"
)

// Middleware is the platform as echo middleware.
func Middleware(p *sitegoose.Platform) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ex := p.Begin(c.Response(), c.Request())
			if ex == nil {
				return nil
			}
			c.SetRequest(ex.Request())
			c.Response().Writer = &hijackWatch{ResponseWriter: c.Response().Writer, ex: ex}
			ex.SecurityHeaders(c.Response().Header())
			defer func() {
				if v := recover(); v != nil {
					ex.SetRoute(c.Path())
					ex.Recovered(v)
					ex.Finish(500, c.Response().Size)
					panic(v)
				}
			}()
			err := next(c)
			ex.SetRoute(c.Path())
			if err != nil {
				c.Error(err)
				ex.Error(err, c.Response().Status)
			}
			ex.Finish(c.Response().Status, c.Response().Size)
			return err
		}
	}
}

// hijackWatch tells the platform when a handler takes the connection over
// (a WebSocket upgrade): that request isn't timed.
type hijackWatch struct {
	http.ResponseWriter
	ex *sitegoose.Exchange
}

func (w *hijackWatch) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err == nil {
		w.ex.Hijacked()
	}
	return conn, rw, err
}

func (w *hijackWatch) Flush() { http.NewResponseController(w.ResponseWriter).Flush() }

func (w *hijackWatch) FlushError() error { return http.NewResponseController(w.ResponseWriter).Flush() }

// Unwrap lets http.ResponseController reach the server's own writer.
func (w *hijackWatch) Unwrap() http.ResponseWriter { return w.ResponseWriter }
