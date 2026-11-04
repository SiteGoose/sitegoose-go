package sitegoose

// Stacks in the form runtime/debug.Stack prints them, which is the form the
// collector reads Go frames in (expresscollect/utils/jsError.js goFrames):
//
//	main.(*Shop).charge(...)
//		/app/shop.go:42 +0x1d
//
// The package's own frames are left out, so the top frame outside the
// runtime and the frameworks is always the app's own code.

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
)

const (
	ourPackage = "github.com/sitegoose/sitegoose-go"
	maxFrames  = 64
	maxStack   = 4000
)

func ours(function string) bool {
	if !strings.HasPrefix(function, ourPackage) {
		return false
	}
	rest := function[len(ourPackage):]
	// The package and its adapters, never an app module whose path merely
	// starts with ours, and never this package's tests.
	return (strings.HasPrefix(rest, ".") || strings.HasPrefix(rest, "/")) && !strings.Contains(rest, "_test.")
}

// modulePaths are the main module's and its dependencies', from the build
// info: a frame of none of them (and not of package main) is the standard
// library's.
var modulePaths = sync.OnceValue(func() []string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}
	paths := []string{info.Main.Path}
	for _, dep := range info.Deps {
		paths = append(paths, dep.Path)
		if dep.Replace != nil {
			paths = append(paths, dep.Replace.Path)
		}
	}
	return paths
})

func standardLibrary(function string) bool {
	if function == "" || strings.HasPrefix(function, "main.") {
		return false
	}
	for _, m := range modulePaths() {
		if m != "" && (strings.HasPrefix(function, m+".") || strings.HasPrefix(function, m+"/")) {
			return false
		}
	}
	// The standard library's import paths have no dot in their first
	// element; other modules' (github.com/..., golang.org/x/...) do. A main
	// module named without one ("myapp") is in the build info above.
	first, _, found := strings.Cut(function, "/")
	if !found {
		first, _, _ = strings.Cut(function, ".")
	}
	return !strings.Contains(first, ".")
}

// formatStack writes pcs as Go's own traces do, without this package's frames.
// afterPanic drops everything up to and including the runtime's panic
// machinery, so a recovered panic starts at the line that panicked; without
// it (a stack taken where an error was captured, logged or answered with a
// 5xx) the standard library's frames on top go too: log/slog and http.Error
// are where it was reported, not where it went wrong.
func formatStack(pcs []uintptr, root string, afterPanic bool) string {
	if len(pcs) == 0 {
		return ""
	}
	type frame struct {
		function, file string
		line           int
		pc             uintptr
	}
	var all []frame
	frames := runtime.CallersFrames(pcs)
	for {
		f, more := frames.Next()
		if f.Function != "" || f.File != "" {
			all = append(all, frame{f.Function, f.File, f.Line, f.PC - f.Entry})
		}
		if !more {
			break
		}
	}
	if afterPanic {
		for i, f := range all {
			if f.function == "runtime.gopanic" {
				rest := all[i+1:]
				// runtime.panicmem, runtime.sigpanic, runtime.goPanicIndex...
				for len(rest) > 0 && strings.HasPrefix(rest[0].function, "runtime.") {
					rest = rest[1:]
				}
				all = rest
				break
			}
		}
	}
	if !afterPanic {
		for len(all) > 0 && (ours(all[0].function) || standardLibrary(all[0].function)) {
			all = all[1:]
		}
	}
	var b strings.Builder
	for _, f := range all {
		if ours(f.function) {
			continue
		}
		file := f.file
		if root != "" {
			file = strings.TrimPrefix(file, root+"/")
		}
		fmt.Fprintf(&b, "%s(...)\n\t%s:%d +0x%x\n", firstNonEmpty(f.function, "???"), file, f.line, f.pc)
		if b.Len() > maxStack {
			break
		}
	}
	return truncate(b.String(), maxStack)
}

// callers is the stack where it is called from, skip frames up.
func callers(skip int) []uintptr {
	pcs := make([]uintptr, maxFrames)
	n := runtime.Callers(skip+2, pcs)
	return pcs[:n]
}

// carriedStack is the stack an error recorded where it was made, when it
// carries one: github.com/pkg/errors (StackTrace() of uintptr frames) and
// github.com/go-errors/errors (Callers() []uintptr), found by shape so
// neither is a dependency. The innermost error that has one wins: it is the
// closest to where things went wrong.
func carriedStack(err error) []uintptr {
	var found []uintptr
	for e := err; e != nil; e = errors.Unwrap(e) {
		if pcs := stackOf(e); len(pcs) > 0 {
			found = pcs
		}
	}
	return found
}

func stackOf(e error) (pcs []uintptr) {
	defer func() {
		if recover() != nil {
			pcs = nil
		}
	}()
	if c, ok := e.(interface{ Callers() []uintptr }); ok {
		return c.Callers()
	}
	method := reflect.ValueOf(e).MethodByName("StackTrace")
	if !method.IsValid() || method.Type().NumIn() != 0 || method.Type().NumOut() != 1 {
		return nil
	}
	out := method.Call(nil)[0]
	if out.Kind() != reflect.Slice || out.Type().Elem().Kind() != reflect.Uintptr {
		return nil
	}
	pcs = make([]uintptr, out.Len())
	for i := range pcs {
		// pkg/errors keeps each frame as its pc + 1, as runtime.Callers does.
		pcs[i] = uintptr(out.Index(i).Uint())
	}
	return pcs
}

// Error types that say nothing about what went wrong: the chain is followed
// past them to one that does.
var plainErrorTypes = map[string]bool{
	"errors.errorString": true, "fmt.wrapError": true, "fmt.wrapErrors": true, "errors.joinError": true,
	"github.com/pkg/errors.fundamental": true, "github.com/pkg/errors.withStack": true,
	"github.com/pkg/errors.withMessage": true, "errors.fundamental": true, "errors.withStack": true,
	"errors.withMessage": true,
}

func typeName(v any) string {
	t := reflect.TypeOf(v)
	if t == nil {
		return ""
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	// The package's name, as Go writes the type ("fs.PathError"), not the
	// last element of its import path.
	return t.String()
}

// errorType names an error as the Errors report shows it: "fs.PathError",
// "runtime.boundsError", "net.OpError"; "error" when every error in the chain
// is a plain one (errors.New, fmt.Errorf).
func errorType(err error) string {
	for e := err; e != nil; e = errors.Unwrap(e) {
		name := typeName(e)
		full := name
		if t := reflect.TypeOf(e); t != nil {
			for t.Kind() == reflect.Pointer {
				t = t.Elem()
			}
			full = t.PkgPath() + "." + t.Name()
		}
		if name != "" && !plainErrorTypes[name] && !plainErrorTypes[full] {
			return name
		}
	}
	return "error"
}
