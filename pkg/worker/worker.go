// Package worker provides a stateless, horizontally-scalable message processing
// architecture for Operator OS. Workers pull inbound messages from the bus,
// process them through the agent loop (LLM calls, tool execution), and publish
// responses back to the bus. All state is read from and written to external
// stores (SessionStore, StateStore), making each worker instance stateless and
// independently scalable.
//
// In self-hosted mode, a single Worker with Concurrency=1 replaces the embedded
// AgentLoop. In SaaS mode, multiple Worker instances (potentially on different
// machines) consume from the same NATS JetStream queue for horizontal scaling.
package worker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/operatoronline/Operator-OS/pkg/bus"
	"github.com/operatoronline/Operator-OS/pkg/logger"
	"github.com/operatoronline/Operator-OS/pkg/metrics"
	"github.com/operatoronline/Operator-OS/pkg/session"
)

// ErrWorkerStopped is returned when operations are attempted on a stopped worker.
var ErrWorkerStopped = errors.New("worker is stopped")

// MessageProcessor is the function signature for processing inbound messages.
// It receives a context (with timeout), the message, a session manager backed
// by a persistent store, and returns the response text or an error.
// This decouples the worker from the agent loop implementation — the agent loop
// is injected as a MessageProcessor.
type MessageProcessor func(ctx context.Context, msg bus.InboundMessage) (string, error)

// Worker is a stateless message processing unit that pulls from a bus,
// delegates to a MessageProcessor, and publishes results back.
type Worker struct {
	cfg       Config
	bus       bus.Bus
	processor MessageProcessor
	sessions  session.SessionStore

	running atomic.Bool
	stopped atomic.Bool
	wg      sync.WaitGroup
	cancel  context.CancelFunc

	// stats
	processed atomic.Int64
	failed    atomic.Int64
	startTime time.Time
}

// New creates a new Worker with the given configuration. Returns an error if
// required dependencies are missing.
func New(cfg Config, b bus.Bus, processor MessageProcessor, sessions session.SessionStore) (*Worker, error) {
	if cfg.ID == "" {
		return nil, errors.New("worker ID is required")
	}
	if b == nil {
		return nil, errors.New("bus is required")
	}
	if processor == nil {
		return nil, errors.New("message processor is required")
	}
	cfg.validate()

	return &Worker{
		cfg:       cfg,
		bus:       b,
		processor: processor,
		sessions:  sessions,
	}, nil
}

// Run starts the worker and blocks until the context is canceled or Stop is called.
// It spawns cfg.Concurrency goroutines, each consuming and processing messages.
func (w *Worker) Run(ctx context.Context) error {
	if w.stopped.Load() {
		return ErrWorkerStopped
	}
	if !w.running.CompareAndSwap(false, true) {
		return errors.New("worker is already running")
	}
	defer w.running.Store(false)

	w.startTime = time.Now()

	ctx, w.cancel = context.WithCancel(ctx)
	defer w.cancel()

	logger.InfoCF("worker", "Starting worker", map[string]any{
		"worker_id":   w.cfg.ID,
		"concurrency": w.cfg.Concurrency,
	})

	// Start consumer goroutines
	for i := 0; i < w.cfg.Concurrency; i++ {
		w.wg.Add(1)
		go w.consumeLoop(ctx, i)
	}

	// Wait for all consumers to finish
	w.wg.Wait()

	logger.InfoCF("worker", "Worker stopped", map[string]any{
		"worker_id": w.cfg.ID,
		"processed": w.processed.Load(),
		"failed":    w.failed.Load(),
	})

	return nil
}

// Stop initiates graceful shutdown. In-flight messages are given ShutdownTimeout
// to complete before the worker forcefully exits.
func (w *Worker) Stop() {
	if w.stopped.CompareAndSwap(false, true) {
		logger.InfoCF("worker", "Stopping worker", map[string]any{
			"worker_id": w.cfg.ID,
		})
		if w.cancel != nil {
			w.cancel()
		}
	}
}

// Stats returns current worker statistics.
func (w *Worker) Stats() WorkerStats {
	uptime := time.Duration(0)
	if !w.startTime.IsZero() {
		uptime = time.Since(w.startTime)
	}
	return WorkerStats{
		ID:        w.cfg.ID,
		Running:   w.running.Load(),
		Processed: w.processed.Load(),
		Failed:    w.failed.Load(),
		Uptime:    uptime,
	}
}

// WorkerStats holds runtime statistics for a worker.
type WorkerStats struct {
	ID        string        `json:"id"`
	Running   bool          `json:"running"`
	Processed int64         `json:"processed"`
	Failed    int64         `json:"failed"`
	Uptime    time.Duration `json:"uptime"`
}

// consumeLoop is the per-goroutine message consumption loop.
func (w *Worker) consumeLoop(ctx context.Context, workerIdx int) {
	defer w.wg.Done()

	logFields := map[string]any{
		"worker_id":  w.cfg.ID,
		"worker_idx": workerIdx,
	}

	logger.DebugCF("worker", "Consumer started", logFields)

	for {
		select {
		case <-ctx.Done():
			logger.DebugCF("worker", "Consumer stopping (context canceled)", logFields)
			return
		default:
		}

		msg, ok := w.bus.ConsumeInbound(ctx)
		if !ok {
			// Bus closed or context canceled
			return
		}

		w.processMessage(ctx, msg, workerIdx)
	}
}

// processMessage handles a single inbound message with timeout and error handling.
func (w *Worker) processMessage(ctx context.Context, msg bus.InboundMessage, workerIdx int) {
	start := time.Now()
	logFields := map[string]any{
		"worker_id":   w.cfg.ID,
		"worker_idx":  workerIdx,
		"channel":     msg.Channel,
		"chat_id":     msg.ChatID,
		"sender_id":   msg.SenderID,
		"session_key": msg.SessionKey,
	}

	logger.InfoCF("worker", "Processing message", logFields)

	// Create a timeout context for this message
	processCtx, cancel := context.WithTimeout(ctx, w.cfg.ProcessTimeout)
	defer cancel()

	// Delegate to the message processor
	response, err := w.processor(processCtx, msg)

	duration := time.Since(start)

	if err != nil {
		w.failed.Add(1)
		logger.ErrorCF("worker", "Message processing failed", map[string]any{
			"worker_id":   w.cfg.ID,
			"worker_idx":  workerIdx,
			"channel":     msg.Channel,
			"chat_id":     msg.ChatID,
			"error":       err.Error(),
			"duration_ms": duration.Milliseconds(),
		})

		// Publish error response to user
		if msg.Channel != "" && msg.ChatID != "" {
			errMsg := fmt.Sprintf("Error processing message: %v", err)
			pubCtx, pubCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer pubCancel()
			_ = w.bus.PublishOutbound(pubCtx, bus.OutboundMessage{
				Channel: msg.Channel,
				ChatID:  msg.ChatID,
				Content: errMsg,
			})
		}

		// Record metrics
		metrics.RecordBusMessage("inbound_failed")
		return
	}

	w.processed.Add(1)

	// Publish response if non-empty
	if response != "" {
		pubCtx, pubCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer pubCancel()
		pubErr := w.bus.PublishOutbound(pubCtx, bus.OutboundMessage{
			Channel: msg.Channel,
			ChatID:  msg.ChatID,
			Content: response,
		})
		if pubErr != nil {
			logger.ErrorCF("worker", "Failed to publish response", map[string]any{
				"worker_id": w.cfg.ID,
				"error":     pubErr.Error(),
			})
		}
	}

	logger.InfoCF("worker", "Message processed", map[string]any{
		"worker_id":    w.cfg.ID,
		"worker_idx":   workerIdx,
		"channel":      msg.Channel,
		"chat_id":      msg.ChatID,
		"duration_ms":  duration.Milliseconds(),
		"response_len": len(response),
	})

	// Record metrics
	metrics.RecordBusMessage("inbound_processed")
}

// IsRunning returns whether the worker is actively processing messages.
func (w *Worker) IsRunning() bool {
	return w.running.Load()
}

// IsStopped returns whether Stop has been called.
func (w *Worker) IsStopped() bool {
	return w.stopped.Load()
}
