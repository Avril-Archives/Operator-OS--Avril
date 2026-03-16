package health

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"sync"
	"time"

	"github.com/operatoronline/Operator-OS/pkg/metrics"
)

type Server struct {
	server    *http.Server
	mu        sync.RWMutex
	ready     bool
	checks    map[string]Check
	checker   *Checker
	startTime time.Time
}

type Check struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	Message   string    `json:"message,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

type StatusResponse struct {
	Status string           `json:"status"`
	Uptime string           `json:"uptime"`
	Checks map[string]Check `json:"checks,omitempty"`
}

func NewServer(host string, port int) *Server {
	mux := http.NewServeMux()
	s := &Server{
		ready:     false,
		checks:    make(map[string]Check),
		startTime: time.Now(),
	}

	mux.HandleFunc("/health", s.healthHandler)
	mux.HandleFunc("/ready", s.readyHandler)
	mux.Handle("/metrics", metrics.Handler())

	addr := fmt.Sprintf("%s:%d", host, port)
	s.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	return s
}

func (s *Server) Start() error {
	s.mu.Lock()
	s.ready = true
	s.mu.Unlock()
	return s.server.ListenAndServe()
}

func (s *Server) StartContext(ctx context.Context) error {
	s.mu.Lock()
	s.ready = true
	s.mu.Unlock()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.server.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return s.server.Shutdown(context.Background())
	}
}

func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	s.ready = false
	s.mu.Unlock()
	return s.server.Shutdown(ctx)
}

func (s *Server) SetReady(ready bool) {
	s.mu.Lock()
	s.ready = ready
	s.mu.Unlock()
}

func (s *Server) RegisterCheck(name string, checkFn func() (bool, string)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	status, msg := checkFn()
	s.checks[name] = Check{
		Name:      name,
		Status:    statusString(status),
		Message:   msg,
		Timestamp: time.Now(),
	}
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	uptime := time.Since(s.startTime)
	resp := StatusResponse{
		Status: "ok",
		Uptime: uptime.String(),
	}

	json.NewEncoder(w).Encode(resp)
}

func (s *Server) readyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	s.mu.RLock()
	ready := s.ready
	checks := make(map[string]Check)
	maps.Copy(checks, s.checks)
	s.mu.RUnlock()

	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(StatusResponse{
			Status: "not ready",
			Checks: checks,
		})
		return
	}

	for _, check := range checks {
		if check.Status == "fail" {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(StatusResponse{
				Status: "not ready",
				Checks: checks,
			})
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	uptime := time.Since(s.startTime)
	json.NewEncoder(w).Encode(StatusResponse{
		Status: "ready",
		Uptime: uptime.String(),
		Checks: checks,
	})
}

// RegisterOnMux registers /health and /ready handlers onto the given mux.
// This allows the health endpoints to be served by a shared HTTP server.
func (s *Server) RegisterOnMux(mux *http.ServeMux) {
	mux.HandleFunc("/health", s.healthHandler)
	mux.HandleFunc("/ready", s.readyHandler)
	mux.HandleFunc("/health/detailed", s.detailedHandler)
	mux.Handle("/metrics", metrics.Handler())
}

// SetChecker attaches an advanced health Checker to the server.
// When set, the /health/detailed endpoint returns component-level health data.
func (s *Server) SetChecker(c *Checker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checker = c
}

// detailedHandler returns component-level health data from the advanced Checker.
func (s *Server) detailedHandler(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	c := s.checker
	s.mu.RUnlock()

	if c == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "no checker configured"})
		return
	}

	results := c.CheckCached()
	overall := OverallStatus(results)

	type componentDetail struct {
		Status     ComponentStatus `json:"status"`
		Type       ComponentType   `json:"type"`
		Critical   bool            `json:"critical"`
		DurationMs float64         `json:"duration_ms"`
		Message    string          `json:"message,omitempty"`
	}

	components := make(map[string]componentDetail, len(results))
	healthy, degraded, unhealthy := 0, 0, 0

	c.mu.RLock()
	for name, result := range results {
		cs := c.components[name]
		components[name] = componentDetail{
			Status:     result.Status,
			Type:       cs.config.Type,
			Critical:   cs.config.Critical,
			DurationMs: result.DurationMs,
			Message:    result.Message,
		}
		switch result.Status {
		case StatusHealthy:
			healthy++
		case StatusDegraded:
			degraded++
		default:
			unhealthy++
		}
	}
	c.mu.RUnlock()

	status := http.StatusOK
	if overall == StatusUnhealthy {
		status = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"status":         overall,
		"uptime":         c.Uptime().String(),
		"uptime_seconds": c.Uptime().Seconds(),
		"timestamp":      time.Now().UTC(),
		"components":     components,
		"summary": map[string]int{
			"total":     healthy + degraded + unhealthy,
			"healthy":   healthy,
			"degraded":  degraded,
			"unhealthy": unhealthy,
		},
	})
}

func statusString(ok bool) string {
	if ok {
		return "ok"
	}
	return "fail"
}
