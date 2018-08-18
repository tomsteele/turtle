package turtle

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/tomsteele/boom"
	"github.com/unrolled/render"
)

// AuthMode constants.
const (
	AUTHMODEREQUIRED = "required"
	AUTMODETRY       = "try"
	AUTHMODENONE     = "none"
)

var validMode = map[string]bool{AUTHMODEREQUIRED: true, AUTHMODENONE: true, AUTMODETRY: true}

func isValidAuthMode(mode string) bool {
	_, ok := validMode[mode]
	return ok
}

// CtxCredentials is the key for the request context value
// holding credentials returned from Scheme.Authenticate.
type CtxCredentials struct{}

// ErrorWriter implements error handling for bundles HandlerFunc.
// err is a boom.Error and has information such as status codes.
// Seee DefaultErrorWriter for implementation details.
type ErrorWriter interface {
	WriteError(w http.ResponseWriter, r *http.Request, err error)
}

// DefaultErrorWriter is the default ErrorWriter used by Bundler.
type DefaultErrorWriter struct {
	r *render.Render
}

// WriteError writes an error to the ResponseWriter as JSON.
func (d DefaultErrorWriter) WriteError(w http.ResponseWriter, _ *http.Request, err error) {
	boomError, ok := err.(boom.Error)
	if !ok {
		d.r.JSON(w, 500, boom.BadImplementation(err)) // Should never happen.
		return
	}
	d.r.JSON(w, boomError.StatusCode, boomError)
}

// Roler is in interface used during authorization to
// validate that the implementer has the required role.
type Roler interface {
	HasRole(role string) bool
}

// Bundler bundles authentication, authorization, validation and per HandlerFunc logic into a nice package.
type Bundler struct {
	schemes       map[string]Scheme
	defaultScheme string
	EW            ErrorWriter
}

// NewBundler returns a new Bundler.
func NewBundler() *Bundler {
	return &Bundler{
		schemes: make(map[string]Scheme),
		EW:      DefaultErrorWriter{r: render.New()},
	}
}

// RegisterScheme registers the scheme by name with bundler.
// It can then be used in O.Schemes.
func (b *Bundler) RegisterScheme(name string, scheme Scheme) {
	b.schemes[name] = scheme
}

// SetDefaultScheme sets the scheme name that will be used for every bundled HandlerFunc.
// Error will be returned if the scheme has not been registered.
func (b *Bundler) SetDefaultScheme(name string) error {
	if _, ok := b.schemes[name]; !ok {
		return errors.New("scheme not registered")
	}
	b.defaultScheme = name
	return nil
}

// O are options to pass to Bundle.
type O struct {
	Allow       []string     // Content-Types to allow.
	Roles       []string     // Roles to allow, object in request context with key CtxCredentials must implement Roler.
	Schemes     []string     // A series of authentication schemes to try in order. Must be registered with Bundler.
	AuthMode    string       // 'try', 'required', 'none'.
	Before      []HandleWrap // A series of HandlerFuncs to execute before Handle.
	After       []HandleWrap // A serios of HandlerFuncs to execute after Handle.
	HandlerFunc func(http.ResponseWriter, *http.Request)
}

// HandleWrap is a function that takes a HandlerFunc and returns a HandlerFunc.
type HandleWrap func(func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request)

// WrapSlice takes a variable amount of HandleWraps and returns a slice.
// This is a convienience function for setting O.Before.
func WrapSlice(funcs ...HandleWrap) []HandleWrap {
	chain := make([]HandleWrap, len(funcs))
	for i, f := range funcs {
		chain[i] = f
	}
	return chain
}

// New returns a bundled HandlerFunc. New may panic if options are incorrect that could result in a
// invalid or insecure configuration.
func (b *Bundler) New(options O) func(http.ResponseWriter, *http.Request) {
	// Panic here because we don't want our app to run with an invalid authmode.
	if !isValidAuthMode(options.AuthMode) {
		panic(fmt.Sprintf("invalid auth mode: %s", options.AuthMode))
	}
	if options.AuthMode != AUTHMODEREQUIRED && len(options.Roles) != 0 {
		panic(fmt.Sprintf("invalid authentication mode %s for amount of roles %d", options.AuthMode, len(options.Roles)))
	}
	if options.HandlerFunc == nil {
		panic(fmt.Sprintf("HandlerFunc not not be nil"))
	}
	for _, k := range options.Schemes {
		if _, ok := b.schemes[k]; !ok {
			panic(fmt.Sprintf("invalid scheme in RO.Schemes: %s", k))
		}
	}
	// Load the default scheme.
	if len(options.Schemes) < 1 && b.defaultScheme != "" {
		options.Schemes = append(options.Schemes, b.defaultScheme)
	}

	bindle := bundle{bundler: b, opts: options}

	// Prepend auth HandlerFunc chain.
	bindle.chain = append(bindle.chain, bindle.authenticate)
	bindle.chain = append(bindle.chain, bindle.authorize)
	bindle.chain = append(bindle.chain, bindle.allow)
	bindle.chain = append(bindle.chain, bindle.opts.Before...)

	// Turtles all the way down...
	for i := (len(bindle.chain) - 1); i >= 0; i-- {
		bindle.opts.HandlerFunc = bindle.chain[i](bindle.opts.HandlerFunc)
	}

	var after func(http.ResponseWriter, *http.Request)
	if len(bindle.opts.After) > 0 {
		// A function that does nothing calls to next in After handlers don't panic.
		after = func(w http.ResponseWriter, r *http.Request) {
			return
		}
	}
	for i := (len(bindle.opts.After) - 1); i >= 0; i-- {
		after = bindle.opts.After[i](after)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		bindle.opts.HandlerFunc(w, r)
		if after != nil {
			after(w, r)
		}
	}
}

type bundle struct {
	bundler *Bundler
	opts    O
	chain   []HandleWrap
}

// authenticate attempts to authenticate a request for the configured schemes.
func (b *bundle) authenticate(next func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if b.opts.AuthMode == AUTHMODENONE {
			next(w, r)
			return
		}

		for i, k := range b.opts.Schemes {
			scheme, ok := b.bundler.schemes[k]
			if !ok {
				b.bundler.EW.WriteError(w, r, boom.BadImplementation(errors.New("authentication scheme not registered")))
				return
			}
			user, err := scheme.Authenticate(w, r)
			if err != nil {
				if b.opts.AuthMode == AUTHMODEREQUIRED {
					// Last in the chain.
					if i == len(b.opts.Schemes)-1 {
						b.bundler.EW.WriteError(w, r, boom.Unauthorized(""))
						return
					}
				}
			} else {
				r = r.WithContext(context.WithValue(r.Context(), CtxCredentials{}, user))
				break
			}
		}
		next(w, r)
	}
}

// authorize ensures the user from CtxCredentials has a valid role for the bundle.
func (b *bundle) authorize(next func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(b.opts.Roles) < 1 {
			next(w, r)
			return
		}
		roler, ok := r.Context().Value(CtxCredentials{}).(Roler)
		if !ok {
			b.bundler.EW.WriteError(w, r, boom.BadImplementation(errors.New("CtxCredentials does not implement Roler")))
			return
		}
		var isAllowed bool
		for _, r := range b.opts.Roles {
			if roler.HasRole(r) {
				isAllowed = true
				break
			}
		}
		if !isAllowed {
			b.bundler.EW.WriteError(w, r, boom.Forbidden(fmt.Sprintf("missing required roles: %s", strings.Join(b.opts.Roles, " "))))
			return
		}
		next(w, r)
	}
}

// allow checks the content-type header of a request and ensures that it is allowed.
func (b *bundle) allow(next func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(b.opts.Allow) < 1 {
			next(w, r)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "DELETE" {
			contentType := r.Header.Get("Content-Type")
			var found bool
			for _, allowed := range b.opts.Allow {
				if strings.Contains(contentType, allowed) {
					found = true
					break
				}
			}
			if !found {
				b.bundler.EW.WriteError(w, r, boom.BadRequest(fmt.Sprintf("invalid request content-type: %s", contentType), nil))
				return
			}
		}
		next(w, r)
	}
}
