// Package sitegoosegin runs the platform in a gin app: the firewall, the
// proxy and maintenance mode before the handlers, then errors (panics,
// c.Errors and 5xx answers) and Server speed under gin's route
// ("/orders/:id").
//
//	r := gin.Default()
//	r.Use(sitegoosegin.Middleware(p))
//
// Add it after gin.Recovery (gin.Default has it), so a panic reaches it
// first. It also works inside sitegoose.Middleware wrapping the engine, where
// it only names the route and passes c.Errors on.
package sitegoosegin

import (
	"bufio"
	"net"

	"github.com/gin-gonic/gin"

	sitegoose "github.com/sitegoose/sitegoose-go"
)

// Middleware is the platform as gin middleware.
func Middleware(p *sitegoose.Platform) gin.HandlerFunc {
	return func(c *gin.Context) {
		ex := p.Begin(c.Writer, c.Request)
		if ex == nil {
			c.Abort()
			return
		}
		c.Request = ex.Request()
		c.Writer = &hijackWatch{ResponseWriter: c.Writer, ex: ex}
		ex.SecurityHeaders(c.Writer.Header())
		finish := func(status int) {
			ex.SetRoute(c.FullPath())
			for _, e := range c.Errors {
				ex.Error(e.Err, status)
			}
			size := c.Writer.Size()
			if size < 0 {
				size = 0
			}
			ex.Finish(status, int64(size))
		}
		defer func() {
			if v := recover(); v != nil {
				ex.SetRoute(c.FullPath())
				ex.Recovered(v)
				finish(500)
				panic(v)
			}
		}()
		c.Next()
		finish(c.Writer.Status())
	}
}

// hijackWatch tells the platform when a handler takes the connection over
// (a WebSocket upgrade): that request isn't timed.
type hijackWatch struct {
	gin.ResponseWriter
	ex *sitegoose.Exchange
}

func (w *hijackWatch) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := w.ResponseWriter.Hijack()
	if err == nil {
		w.ex.Hijacked()
	}
	return conn, rw, err
}
