package kp

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sing3demons/oauth_server/internal/config"
	"github.com/sing3demons/oauth_server/pkg/logger"
)

type MyHandler func(ctx *Ctx)
type HandleFunc func(http.Handler) http.Handler
type Middleware HandleFunc

type IMicroservice interface {
	Start()
	// GET(path string, handler http.HandlerFunc, middlewares ...Middleware)
	GET(path string, handler MyHandler, middlewares ...Middleware)
	// POST(path string, handler http.HandlerFunc, middlewares ...Middleware)
	POST(path string, handler MyHandler, middlewares ...Middleware)
	// PUT(path string, handler http.HandlerFunc, middlewares ...Middleware)
	PUT(path string, handler MyHandler, middlewares ...Middleware)
	// DELETE(path string, handler http.HandlerFunc, middlewares ...Middleware)
	DELETE(path string, handler MyHandler, middlewares ...Middleware)
	// PATCH(path string, handler http.HandlerFunc, middlewares ...Middleware)
	PATCH(path string, handler MyHandler, middlewares ...Middleware)

	Use(middleware Middleware)
	// multiple methods (GET, POST, PUT, DELETE, PATCH)
	// Any(path string, handler MyHandler, middlewares ...Middleware)
	Any(methods, path string, handler MyHandler, middlewares ...Middleware)

	// kafka
	// Consumer(topic string, handler MyHandler)
}

type Microservice struct {
	config        *config.Config
	mux           *http.ServeMux
	middlewares   []Middleware
	detailLogger  logger.BaseLoggerInterface
	summaryLogger logger.BaseLoggerInterface
}

func NewApplication(cfg *config.Config, detailLogger logger.BaseLoggerInterface, summaryLogger logger.BaseLoggerInterface) *Microservice {
	return &Microservice{
		config:        cfg,
		mux:           http.NewServeMux(),
		detailLogger:  detailLogger,
		summaryLogger: summaryLogger,
	}
}

func (m *Microservice) Start() {
	var handler http.Handler = m.mux
	// Apply global middlewares in reverse order so the first added wraps the outermost
	for i := len(m.middlewares) - 1; i >= 0; i-- {
		handler = m.middlewares[i](handler)
	}
	srv := http.Server{
		Addr:         ":" + m.config.Port,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second, // ป้องกัน Slowloris Attack
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// wg
	var wg sync.WaitGroup
	wg.Go(func() {
		log.Printf("starting server on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && errors.Is(err, http.ErrServerClosed) {
			log.Printf("server listen err: %v", err)
		}
	})

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("server forced to shutdown: %v", err)
		os.Exit(1)
	}
	wg.Wait()
	log.Println("server exited")
}

func (m *Microservice) Use(middleware Middleware) {
	m.middlewares = append(m.middlewares, middleware)
}
func (m *Microservice) preHandle(handler MyHandler, middlewares ...Middleware) http.HandlerFunc {
	// Wrap MyHandler into http.HandlerFunc
	final := func(w http.ResponseWriter, r *http.Request) {
		handler(newMuxContext(r, w, m.config))
	}
	// Apply middlewares in reverse order (so the first is outermost)
	for i := len(middlewares) - 1; i >= 0; i-- {
		final = middlewares[i](http.HandlerFunc(final)).ServeHTTP
	}
	return final
}

func (m *Microservice) add(method, path string, handler MyHandler, middlewares ...Middleware) {
	m.mux.HandleFunc(fmt.Sprintf("%s %s", method, path), m.preHandle(handler, middlewares...))
}
func (m *Microservice) GET(path string, handler MyHandler, middlewares ...Middleware) {
	m.add(http.MethodGet, path, handler, middlewares...)
}

func (m *Microservice) POST(path string, handler MyHandler, middlewares ...Middleware) {
	// m.mux.HandleFunc(fmt.Sprintf("%s %s", http.MethodPost, path), m.preHandle(handler, middlewares...))
	m.add(http.MethodPost, path, handler, middlewares...)
}

func (m *Microservice) PUT(path string, handler MyHandler, middlewares ...Middleware) {
	// m.mux.HandleFunc(fmt.Sprintf("%s %s", http.MethodPut, path), m.preHandle(handler, middlewares...))
	m.add(http.MethodPut, path, handler, middlewares...)
}

func (m *Microservice) DELETE(path string, handler MyHandler, middlewares ...Middleware) {
	// m.mux.HandleFunc(fmt.Sprintf("%s %s", http.MethodDelete, path), m.preHandle(handler, middlewares...))
	m.add(http.MethodDelete, path, handler, middlewares...)
}

func (m *Microservice) PATCH(path string, handler MyHandler, middlewares ...Middleware) {
	// m.mux.HandleFunc(fmt.Sprintf("%s %s", http.MethodPatch, path), m.preHandle(handler, middlewares...))
	m.add(http.MethodPatch, path, handler, middlewares...)
}

func (m *Microservice) Any(methods []string, path string, handler MyHandler, middlewares ...Middleware) {
	allowMethods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}
	if len(methods) == 0 {
		panic("methods cannot be empty")
	}

	// Validate methods
	for _, method := range methods {
		method = strings.ToUpper(method)
		if !contains(allowMethods, method) {
			panic(fmt.Sprintf("invalid HTTP method: %s", method))
		}
	}
	for _, method := range methods {
		m.add(strings.ToUpper(method), path, handler, middlewares...)
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
