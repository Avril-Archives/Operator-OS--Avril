package worker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/operatoronline/Operator-OS/pkg/bus"
)

// mockBus implements bus.Bus for testing.
type mockBus struct {
	inbound  chan bus.InboundMessage
	outbound chan bus.OutboundMessage
	media    chan bus.OutboundMediaMessage
	closed   atomic.Bool
}

func newMockBus() *mockBus {
	return &mockBus{
		inbound:  make(chan bus.InboundMessage, 100),
		outbound: make(chan bus.OutboundMessage, 100),
		media:    make(chan bus.OutboundMediaMessage, 100),
	}
}

func (m *mockBus) PublishInbound(_ context.Context, msg bus.InboundMessage) error {
	if m.closed.Load() {
		return bus.ErrBusClosed
	}
	m.inbound <- msg
	return nil
}

func (m *mockBus) ConsumeInbound(ctx context.Context) (bus.InboundMessage, bool) {
	select {
	case <-ctx.Done():
		return bus.InboundMessage{}, false
	case msg, ok := <-m.inbound:
		return msg, ok
	}
}

func (m *mockBus) PublishOutbound(_ context.Context, msg bus.OutboundMessage) error {
	if m.closed.Load() {
		return bus.ErrBusClosed
	}
	m.outbound <- msg
	return nil
}

func (m *mockBus) SubscribeOutbound(ctx context.Context) (bus.OutboundMessage, bool) {
	select {
	case <-ctx.Done():
		return bus.OutboundMessage{}, false
	case msg, ok := <-m.outbound:
		return msg, ok
	}
}

func (m *mockBus) PublishOutboundMedia(_ context.Context, msg bus.OutboundMediaMessage) error {
	if m.closed.Load() {
		return bus.ErrBusClosed
	}
	m.media <- msg
	return nil
}

func (m *mockBus) SubscribeOutboundMedia(ctx context.Context) (bus.OutboundMediaMessage, bool) {
	select {
	case <-ctx.Done():
		return bus.OutboundMediaMessage{}, false
	case msg, ok := <-m.media:
		return msg, ok
	}
}

func (m *mockBus) Close() {
	if m.closed.CompareAndSwap(false, true) {
		close(m.inbound)
	}
}

// --- Config Tests ---

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig("test-worker")
	assert.Equal(t, "test-worker", cfg.ID)
	assert.Equal(t, 1, cfg.Concurrency)
	assert.Equal(t, 30*time.Second, cfg.ShutdownTimeout)
	assert.Equal(t, 3, cfg.MaxRetries)
	assert.Equal(t, 5*time.Minute, cfg.ProcessTimeout)
	assert.Equal(t, 30*time.Second, cfg.HeartbeatInterval)
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name     string
		modify   func(*Config)
		checkFn  func(*testing.T, *Config)
	}{
		{
			name:   "defaults applied to zero config",
			modify: func(c *Config) { *c = Config{ID: "x"} },
			checkFn: func(t *testing.T, c *Config) {
				assert.Equal(t, 1, c.Concurrency)
				assert.Equal(t, 30*time.Second, c.ShutdownTimeout)
				assert.Equal(t, 5*time.Minute, c.ProcessTimeout)
			},
		},
		{
			name:   "negative concurrency set to 1",
			modify: func(c *Config) { c.Concurrency = -5 },
			checkFn: func(t *testing.T, c *Config) {
				assert.Equal(t, 1, c.Concurrency)
			},
		},
		{
			name:   "negative retries set to 0",
			modify: func(c *Config) { c.MaxRetries = -1 },
			checkFn: func(t *testing.T, c *Config) {
				assert.Equal(t, 0, c.MaxRetries)
			},
		},
		{
			name:   "valid config preserved",
			modify: func(c *Config) { c.Concurrency = 4; c.ProcessTimeout = 10 * time.Minute },
			checkFn: func(t *testing.T, c *Config) {
				assert.Equal(t, 4, c.Concurrency)
				assert.Equal(t, 10*time.Minute, c.ProcessTimeout)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig("test")
			tt.modify(&cfg)
			cfg.validate()
			tt.checkFn(t, &cfg)
		})
	}
}

// --- Constructor Tests ---

func TestNew_EmptyID(t *testing.T) {
	_, err := New(Config{}, newMockBus(), func(context.Context, bus.InboundMessage) (string, error) { return "", nil }, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "worker ID is required")
}

func TestNew_NilBus(t *testing.T) {
	_, err := New(DefaultConfig("w1"), nil, func(context.Context, bus.InboundMessage) (string, error) { return "", nil }, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bus is required")
}

func TestNew_NilProcessor(t *testing.T) {
	_, err := New(DefaultConfig("w1"), newMockBus(), nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "message processor is required")
}

func TestNew_Success(t *testing.T) {
	b := newMockBus()
	w, err := New(DefaultConfig("w1"), b, func(context.Context, bus.InboundMessage) (string, error) { return "", nil }, nil)
	require.NoError(t, err)
	assert.NotNil(t, w)
	assert.Equal(t, "w1", w.cfg.ID)
	assert.False(t, w.IsRunning())
	assert.False(t, w.IsStopped())
}

func TestNew_NilSessionsOK(t *testing.T) {
	// sessions are optional
	w, err := New(DefaultConfig("w1"), newMockBus(), func(context.Context, bus.InboundMessage) (string, error) { return "", nil }, nil)
	require.NoError(t, err)
	assert.Nil(t, w.sessions)
}

// --- Run/Stop Tests ---

func TestWorkerRunAndStop(t *testing.T) {
	b := newMockBus()
	w, err := New(DefaultConfig("w1"), b, func(context.Context, bus.InboundMessage) (string, error) {
		return "ok", nil
	}, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	// Wait for worker to start
	time.Sleep(50 * time.Millisecond)
	assert.True(t, w.IsRunning())

	w.Stop()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not stop in time")
	}

	assert.False(t, w.IsRunning())
	assert.True(t, w.IsStopped())
}

func TestWorkerRunAfterStop(t *testing.T) {
	b := newMockBus()
	w, err := New(DefaultConfig("w1"), b, func(context.Context, bus.InboundMessage) (string, error) {
		return "", nil
	}, nil)
	require.NoError(t, err)

	w.Stop()
	err = w.Run(context.Background())
	assert.ErrorIs(t, err, ErrWorkerStopped)
}

func TestWorkerDoubleRun(t *testing.T) {
	b := newMockBus()
	w, err := New(DefaultConfig("w1"), b, func(context.Context, bus.InboundMessage) (string, error) {
		return "", nil
	}, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	time.Sleep(50 * time.Millisecond)

	// Second run should fail
	err = w.Run(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")

	cancel()
	<-done
}

func TestWorkerContextCancellation(t *testing.T) {
	b := newMockBus()
	w, err := New(DefaultConfig("w1"), b, func(context.Context, bus.InboundMessage) (string, error) {
		return "", nil
	}, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not stop after context cancel")
	}
}

// --- Message Processing Tests ---

func TestWorkerProcessesMessage(t *testing.T) {
	b := newMockBus()
	var processed atomic.Bool

	w, err := New(DefaultConfig("w1"), b, func(_ context.Context, msg bus.InboundMessage) (string, error) {
		processed.Store(true)
		return "Hello, " + msg.SenderID, nil
	}, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	// Send a message
	b.inbound <- bus.InboundMessage{
		Channel:  "telegram",
		SenderID: "user1",
		ChatID:   "chat1",
		Content:  "hi",
	}

	// Wait for response
	select {
	case resp := <-b.outbound:
		assert.Equal(t, "Hello, user1", resp.Content)
		assert.Equal(t, "telegram", resp.Channel)
		assert.Equal(t, "chat1", resp.ChatID)
	case <-time.After(5 * time.Second):
		t.Fatal("no response received")
	}

	assert.True(t, processed.Load())
	cancel()
	<-done
}

func TestWorkerProcessesMultipleMessages(t *testing.T) {
	b := newMockBus()
	var count atomic.Int64

	w, err := New(DefaultConfig("w1"), b, func(_ context.Context, msg bus.InboundMessage) (string, error) {
		count.Add(1)
		return fmt.Sprintf("reply-%s", msg.Content), nil
	}, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	// Send 5 messages
	for i := 0; i < 5; i++ {
		b.inbound <- bus.InboundMessage{
			Channel: "test",
			ChatID:  "c1",
			Content: fmt.Sprintf("msg-%d", i),
		}
	}

	// Collect 5 responses
	for i := 0; i < 5; i++ {
		select {
		case <-b.outbound:
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for response %d", i)
		}
	}

	assert.Equal(t, int64(5), count.Load())
	cancel()
	<-done
}

func TestWorkerEmptyResponse(t *testing.T) {
	b := newMockBus()
	w, err := New(DefaultConfig("w1"), b, func(_ context.Context, _ bus.InboundMessage) (string, error) {
		return "", nil // empty response
	}, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	b.inbound <- bus.InboundMessage{Channel: "test", ChatID: "c1", Content: "hi"}

	// Give it time to process
	time.Sleep(200 * time.Millisecond)

	// Should NOT have published anything (empty response)
	select {
	case resp := <-b.outbound:
		t.Fatalf("expected no response, got: %q", resp.Content)
	default:
		// good
	}

	cancel()
	<-done
}

func TestWorkerProcessorError(t *testing.T) {
	b := newMockBus()
	w, err := New(DefaultConfig("w1"), b, func(_ context.Context, _ bus.InboundMessage) (string, error) {
		return "", errors.New("LLM unavailable")
	}, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	b.inbound <- bus.InboundMessage{Channel: "test", ChatID: "c1", Content: "hi"}

	// Should get error response
	select {
	case resp := <-b.outbound:
		assert.Contains(t, resp.Content, "LLM unavailable")
	case <-time.After(5 * time.Second):
		t.Fatal("no error response received")
	}

	stats := w.Stats()
	assert.Equal(t, int64(1), stats.Failed)
	assert.Equal(t, int64(0), stats.Processed)

	cancel()
	<-done
}

func TestWorkerProcessTimeout(t *testing.T) {
	b := newMockBus()
	cfg := DefaultConfig("w1")
	cfg.ProcessTimeout = 100 * time.Millisecond

	w, err := New(cfg, b, func(ctx context.Context, _ bus.InboundMessage) (string, error) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(5 * time.Second):
			return "should not reach", nil
		}
	}, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	b.inbound <- bus.InboundMessage{Channel: "test", ChatID: "c1", Content: "slow"}

	// Should get timeout error
	select {
	case resp := <-b.outbound:
		assert.Contains(t, resp.Content, "context deadline exceeded")
	case <-time.After(5 * time.Second):
		t.Fatal("no timeout error response")
	}

	cancel()
	<-done
}

// --- Stats Tests ---

func TestWorkerStats(t *testing.T) {
	b := newMockBus()
	w, err := New(DefaultConfig("w-stats"), b, func(_ context.Context, _ bus.InboundMessage) (string, error) {
		return "ok", nil
	}, nil)
	require.NoError(t, err)

	// Stats before run
	stats := w.Stats()
	assert.Equal(t, "w-stats", stats.ID)
	assert.False(t, stats.Running)
	assert.Equal(t, int64(0), stats.Processed)
	assert.Equal(t, int64(0), stats.Failed)
	assert.Equal(t, time.Duration(0), stats.Uptime)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	time.Sleep(50 * time.Millisecond)

	// Stats during run
	stats = w.Stats()
	assert.True(t, stats.Running)
	assert.True(t, stats.Uptime > 0)

	// Process a message
	b.inbound <- bus.InboundMessage{Channel: "test", ChatID: "c1", Content: "hi"}
	<-b.outbound

	stats = w.Stats()
	assert.Equal(t, int64(1), stats.Processed)

	cancel()
	<-done
}

// --- Concurrency Tests ---

func TestWorkerConcurrency(t *testing.T) {
	b := newMockBus()
	cfg := DefaultConfig("w-concurrent")
	cfg.Concurrency = 4

	var active atomic.Int64
	var maxActive atomic.Int64
	var wg sync.WaitGroup

	w, err := New(cfg, b, func(_ context.Context, _ bus.InboundMessage) (string, error) {
		curr := active.Add(1)
		// Track max concurrent
		for {
			old := maxActive.Load()
			if curr <= old || maxActive.CompareAndSwap(old, curr) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond) // Simulate work
		active.Add(-1)
		return "done", nil
	}, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	time.Sleep(50 * time.Millisecond)

	// Send messages fast
	msgCount := 20
	wg.Add(msgCount)
	for i := 0; i < msgCount; i++ {
		b.inbound <- bus.InboundMessage{Channel: "test", ChatID: "c1", Content: fmt.Sprintf("msg-%d", i)}
	}

	// Collect responses
	go func() {
		for i := 0; i < msgCount; i++ {
			select {
			case <-b.outbound:
				wg.Done()
			case <-time.After(10 * time.Second):
				return
			}
		}
	}()

	wg.Wait()

	stats := w.Stats()
	assert.Equal(t, int64(msgCount), stats.Processed)

	// With 4 consumers, max active should be > 1 (likely 4)
	assert.Greater(t, maxActive.Load(), int64(1), "should have concurrent processing")

	cancel()
	<-done
}

// --- Pool Tests ---

func TestNewPool_InvalidSize(t *testing.T) {
	_, err := NewPool(PoolConfig{Size: 0})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pool size must be at least 1")
}

func TestNewPool_NilBus(t *testing.T) {
	_, err := NewPool(PoolConfig{
		Size:         2,
		WorkerConfig: DefaultConfig("pool"),
		Processor:    func(context.Context, bus.InboundMessage) (string, error) { return "", nil },
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bus is required")
}

func TestNewPool_NilProcessor(t *testing.T) {
	_, err := NewPool(PoolConfig{
		Size:         2,
		WorkerConfig: DefaultConfig("pool"),
		Bus:          newMockBus(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "processor is required")
}

func TestNewPool_Success(t *testing.T) {
	b := newMockBus()
	pool, err := NewPool(PoolConfig{
		Size:         3,
		WorkerConfig: DefaultConfig("pool"),
		Bus:          b,
		Processor:    func(context.Context, bus.InboundMessage) (string, error) { return "", nil },
	})
	require.NoError(t, err)
	assert.Equal(t, 3, pool.Size())
}

func TestPoolWorkerIDs(t *testing.T) {
	b := newMockBus()
	pool, err := NewPool(PoolConfig{
		Size:         3,
		WorkerConfig: DefaultConfig("base"),
		Bus:          b,
		Processor:    func(context.Context, bus.InboundMessage) (string, error) { return "", nil },
	})
	require.NoError(t, err)

	stats := pool.Stats()
	require.Len(t, stats, 3)
	assert.Equal(t, "base-0", stats[0].ID)
	assert.Equal(t, "base-1", stats[1].ID)
	assert.Equal(t, "base-2", stats[2].ID)
}

func TestPoolRunAndStop(t *testing.T) {
	b := newMockBus()
	pool, err := NewPool(PoolConfig{
		Size:         2,
		WorkerConfig: DefaultConfig("pool"),
		Bus:          b,
		Processor: func(_ context.Context, msg bus.InboundMessage) (string, error) {
			return "pooled: " + msg.Content, nil
		},
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- pool.Run(ctx) }()

	time.Sleep(100 * time.Millisecond)

	// Send a message
	b.inbound <- bus.InboundMessage{Channel: "test", ChatID: "c1", Content: "hello"}

	select {
	case resp := <-b.outbound:
		assert.Equal(t, "pooled: hello", resp.Content)
	case <-time.After(5 * time.Second):
		t.Fatal("no response from pool")
	}

	pool.Stop()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("pool did not stop")
	}
}

func TestPoolStats(t *testing.T) {
	b := newMockBus()
	pool, err := NewPool(PoolConfig{
		Size:         2,
		WorkerConfig: DefaultConfig("stats"),
		Bus:          b,
		Processor:    func(context.Context, bus.InboundMessage) (string, error) { return "ok", nil },
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- pool.Run(ctx) }()

	time.Sleep(50 * time.Millisecond)

	// Send messages
	for i := 0; i < 4; i++ {
		b.inbound <- bus.InboundMessage{Channel: "test", ChatID: "c1", Content: "hi"}
	}

	// Collect responses
	for i := 0; i < 4; i++ {
		select {
		case <-b.outbound:
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout waiting for response %d", i)
		}
	}

	stats := pool.Stats()
	totalProcessed := int64(0)
	for _, s := range stats {
		totalProcessed += s.Processed
		assert.True(t, s.Running)
	}
	assert.Equal(t, int64(4), totalProcessed)

	cancel()
	<-done
}

// --- Bus Closed Tests ---

func TestWorkerBusClosed(t *testing.T) {
	b := newMockBus()
	w, err := New(DefaultConfig("w1"), b, func(_ context.Context, _ bus.InboundMessage) (string, error) {
		return "ok", nil
	}, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	time.Sleep(50 * time.Millisecond)

	// Close the bus
	b.Close()

	select {
	case err := <-done:
		assert.NoError(t, err) // should exit cleanly
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not stop after bus closed")
	}
}

// --- ErrWorkerStopped Tests ---

func TestErrWorkerStopped(t *testing.T) {
	assert.Equal(t, "worker is stopped", ErrWorkerStopped.Error())
}

// --- Double Stop Tests ---

func TestWorkerDoubleStop(t *testing.T) {
	b := newMockBus()
	w, err := New(DefaultConfig("w1"), b, func(_ context.Context, _ bus.InboundMessage) (string, error) {
		return "", nil
	}, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	time.Sleep(50 * time.Millisecond)

	// Stop twice should not panic
	w.Stop()
	w.Stop()

	<-done
}

// --- Interface Compliance ---

func TestBusInterfaceCompliance(t *testing.T) {
	var _ bus.Bus = (*mockBus)(nil)
}
