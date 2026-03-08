package worker

import (
	"context"
	"fmt"
	"sync"

	"github.com/operatoronline/Operator-OS/pkg/bus"
	"github.com/operatoronline/Operator-OS/pkg/logger"
	"github.com/operatoronline/Operator-OS/pkg/session"
)

// Pool manages a group of workers for horizontal scaling.
// Each worker in the pool processes messages independently.
type Pool struct {
	workers []*Worker
	mu      sync.RWMutex
}

// PoolConfig configures a worker pool.
type PoolConfig struct {
	// Size is the number of workers in the pool.
	Size int

	// WorkerConfig is the base config for each worker. The ID field will be
	// suffixed with the worker index (e.g., "worker-0", "worker-1").
	WorkerConfig Config

	// Bus is the shared message bus.
	Bus bus.Bus

	// Processor is the shared message processor.
	Processor MessageProcessor

	// Sessions is the shared session store (optional).
	Sessions session.SessionStore
}

// NewPool creates a pool of workers. Each worker gets a unique ID derived from
// the base config ID (e.g., "base-0", "base-1").
func NewPool(cfg PoolConfig) (*Pool, error) {
	if cfg.Size < 1 {
		return nil, fmt.Errorf("pool size must be at least 1, got %d", cfg.Size)
	}
	if cfg.Bus == nil {
		return nil, fmt.Errorf("bus is required")
	}
	if cfg.Processor == nil {
		return nil, fmt.Errorf("processor is required")
	}

	workers := make([]*Worker, 0, cfg.Size)
	for i := 0; i < cfg.Size; i++ {
		wcfg := cfg.WorkerConfig
		wcfg.ID = fmt.Sprintf("%s-%d", cfg.WorkerConfig.ID, i)

		w, err := New(wcfg, cfg.Bus, cfg.Processor, cfg.Sessions)
		if err != nil {
			return nil, fmt.Errorf("failed to create worker %d: %w", i, err)
		}
		workers = append(workers, w)
	}

	return &Pool{workers: workers}, nil
}

// Run starts all workers and blocks until all have stopped.
// If the context is canceled, all workers initiate graceful shutdown.
func (p *Pool) Run(ctx context.Context) error {
	p.mu.RLock()
	workers := p.workers
	p.mu.RUnlock()

	logger.InfoCF("worker", "Starting worker pool", map[string]any{
		"pool_size": len(workers),
	})

	var wg sync.WaitGroup
	errCh := make(chan error, len(workers))

	for _, w := range workers {
		wg.Add(1)
		go func(w *Worker) {
			defer wg.Done()
			if err := w.Run(ctx); err != nil {
				errCh <- fmt.Errorf("worker %s: %w", w.cfg.ID, err)
			}
		}(w)
	}

	wg.Wait()
	close(errCh)

	// Collect errors
	var errs []error
	for err := range errCh {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("pool errors: %v", errs)
	}
	return nil
}

// Stop initiates graceful shutdown of all workers.
func (p *Pool) Stop() {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, w := range p.workers {
		w.Stop()
	}
}

// Stats returns statistics for all workers in the pool.
func (p *Pool) Stats() []WorkerStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := make([]WorkerStats, len(p.workers))
	for i, w := range p.workers {
		stats[i] = w.Stats()
	}
	return stats
}

// Size returns the number of workers in the pool.
func (p *Pool) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.workers)
}
