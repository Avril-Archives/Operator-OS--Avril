package bus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/standardws/operator/pkg/logger"
	"github.com/standardws/operator/pkg/metrics"
)

// NATS JetStream subjects.
const (
	SubjectInbound       = "operator.inbound"
	SubjectOutbound      = "operator.outbound"
	SubjectOutboundMedia = "operator.outbound.media"

	DefaultStreamName = "OPERATOR"

	defaultAckWait    = 30 * time.Second
	defaultMaxDeliver = 5
	defaultFetchBatch = 1
	defaultFetchWait  = 5 * time.Second
)

// NATSConfig configures the NATS JetStream message bus.
type NATSConfig struct {
	// URL is the NATS server URL (e.g., "nats://localhost:4222").
	URL string

	// StreamName overrides the default stream name (default: "OPERATOR").
	StreamName string

	// AckWait is how long NATS waits for an ack before redelivery (default: 30s).
	AckWait time.Duration

	// MaxDeliver is the maximum number of delivery attempts (default: 5).
	MaxDeliver int

	// ConsumerPrefix is prepended to consumer names for multi-instance isolation
	// (e.g., "worker-1"). Empty means shared consumers.
	ConsumerPrefix string

	// NATSOptions are additional nats.Option values passed to nats.Connect.
	NATSOptions []nats.Option
}

// DefaultNATSConfig returns a NATSConfig with sensible defaults.
func DefaultNATSConfig(url string) NATSConfig {
	return NATSConfig{
		URL:        url,
		StreamName: DefaultStreamName,
		AckWait:    defaultAckWait,
		MaxDeliver: defaultMaxDeliver,
	}
}

// NATSBus implements the Bus interface using NATS JetStream for durable,
// at-least-once message delivery. Suitable for multi-worker SaaS deployments.
type NATSBus struct {
	conn   *nats.Conn
	js     jetstream.JetStream
	stream jetstream.Stream
	cfg    NATSConfig

	// consumers for each subject
	inboundConsumer       jetstream.Consumer
	outboundConsumer      jetstream.Consumer
	outboundMediaConsumer jetstream.Consumer

	closed atomic.Bool
	done   chan struct{}
	mu     sync.Mutex
}

// NewNATSBus connects to NATS, creates/updates the JetStream stream, and
// creates durable consumers for each subject. Returns an error if the
// connection or stream setup fails.
func NewNATSBus(cfg NATSConfig) (*NATSBus, error) {
	if cfg.URL == "" {
		return nil, errors.New("nats: URL is required")
	}
	if cfg.StreamName == "" {
		cfg.StreamName = DefaultStreamName
	}
	if cfg.AckWait <= 0 {
		cfg.AckWait = defaultAckWait
	}
	if cfg.MaxDeliver <= 0 {
		cfg.MaxDeliver = defaultMaxDeliver
	}

	opts := append([]nats.Option{
		nats.Name("operator-bus"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				logger.WarnCF("nats-bus", "NATS disconnected", map[string]any{"error": err.Error()})
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			logger.InfoCF("nats-bus", "NATS reconnected", map[string]any{"url": nc.ConnectedUrl()})
		}),
	}, cfg.NATSOptions...)

	nc, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("nats: connect: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("nats: jetstream: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create or update the stream with all three subjects.
	stream, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name: cfg.StreamName,
		Subjects: []string{
			SubjectInbound,
			SubjectOutbound,
			SubjectOutboundMedia,
		},
		Retention:  jetstream.WorkQueuePolicy,
		MaxAge:     24 * time.Hour,
		Storage:    jetstream.FileStorage,
		Replicas:   1,
		Duplicates: 2 * time.Minute,
	})
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("nats: create stream %q: %w", cfg.StreamName, err)
	}

	nb := &NATSBus{
		conn:   nc,
		js:     js,
		stream: stream,
		cfg:    cfg,
		done:   make(chan struct{}),
	}

	// Create durable consumers for each subject.
	nb.inboundConsumer, err = nb.createConsumer(ctx, "inbound", SubjectInbound)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("nats: inbound consumer: %w", err)
	}

	nb.outboundConsumer, err = nb.createConsumer(ctx, "outbound", SubjectOutbound)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("nats: outbound consumer: %w", err)
	}

	nb.outboundMediaConsumer, err = nb.createConsumer(ctx, "outbound-media", SubjectOutboundMedia)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("nats: outbound-media consumer: %w", err)
	}

	logger.InfoCF("nats-bus", "NATS JetStream bus connected", map[string]any{
		"url":    cfg.URL,
		"stream": cfg.StreamName,
	})

	return nb, nil
}

// createConsumer creates or updates a durable pull consumer for a subject.
func (nb *NATSBus) createConsumer(ctx context.Context, name, subject string) (jetstream.Consumer, error) {
	consumerName := name
	if nb.cfg.ConsumerPrefix != "" {
		consumerName = nb.cfg.ConsumerPrefix + "-" + name
	}

	return nb.stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Name:          consumerName,
		Durable:       consumerName,
		FilterSubject: subject,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       nb.cfg.AckWait,
		MaxDeliver:    nb.cfg.MaxDeliver,
		DeliverPolicy: jetstream.DeliverAllPolicy,
	})
}

// PublishInbound publishes an inbound message to NATS JetStream.
func (nb *NATSBus) PublishInbound(ctx context.Context, msg InboundMessage) error {
	return nb.publish(ctx, SubjectInbound, msg, "inbound")
}

// ConsumeInbound blocks until an inbound message is available from JetStream.
func (nb *NATSBus) ConsumeInbound(ctx context.Context) (InboundMessage, bool) {
	var msg InboundMessage
	ok := nb.consume(ctx, nb.inboundConsumer, &msg)
	return msg, ok
}

// PublishOutbound publishes an outbound message to NATS JetStream.
func (nb *NATSBus) PublishOutbound(ctx context.Context, msg OutboundMessage) error {
	return nb.publish(ctx, SubjectOutbound, msg, "outbound")
}

// SubscribeOutbound blocks until an outbound message is available from JetStream.
func (nb *NATSBus) SubscribeOutbound(ctx context.Context) (OutboundMessage, bool) {
	var msg OutboundMessage
	ok := nb.consume(ctx, nb.outboundConsumer, &msg)
	return msg, ok
}

// PublishOutboundMedia publishes an outbound media message to NATS JetStream.
func (nb *NATSBus) PublishOutboundMedia(ctx context.Context, msg OutboundMediaMessage) error {
	return nb.publish(ctx, SubjectOutboundMedia, msg, "outbound")
}

// SubscribeOutboundMedia blocks until an outbound media message is available from JetStream.
func (nb *NATSBus) SubscribeOutboundMedia(ctx context.Context) (OutboundMediaMessage, bool) {
	var msg OutboundMediaMessage
	ok := nb.consume(ctx, nb.outboundMediaConsumer, &msg)
	return msg, ok
}

// Close shuts down the NATS connection and marks the bus as closed.
func (nb *NATSBus) Close() {
	if nb.closed.CompareAndSwap(false, true) {
		close(nb.done)
		if nb.conn != nil {
			// Drain ensures in-flight messages are processed before closing.
			if err := nb.conn.Drain(); err != nil {
				logger.WarnCF("nats-bus", "NATS drain error", map[string]any{"error": err.Error()})
			}
		}
		logger.InfoCF("nats-bus", "NATS bus closed", nil)
	}
}

// Conn returns the underlying NATS connection for health checks or diagnostics.
func (nb *NATSBus) Conn() *nats.Conn {
	return nb.conn
}

// Stream returns the underlying JetStream stream for diagnostics.
func (nb *NATSBus) Stream() jetstream.Stream {
	return nb.stream
}

// publish serializes a message to JSON and publishes it to a JetStream subject.
func (nb *NATSBus) publish(ctx context.Context, subject string, msg any, direction string) error {
	if nb.closed.Load() {
		return ErrBusClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("nats: marshal %s: %w", subject, err)
	}

	// Publish with acknowledgment from JetStream (at-least-once guarantee).
	_, err = nb.js.Publish(ctx, subject, data)
	if err != nil {
		return fmt.Errorf("nats: publish %s: %w", subject, err)
	}

	metrics.RecordBusMessage(direction)
	return nil
}

// consume fetches one message from a JetStream consumer, deserializes it,
// and acknowledges it. Returns false if the bus is closed or context canceled.
func (nb *NATSBus) consume(ctx context.Context, consumer jetstream.Consumer, target any) bool {
	for {
		if nb.closed.Load() {
			return false
		}

		select {
		case <-nb.done:
			return false
		case <-ctx.Done():
			return false
		default:
		}

		// Fetch one message with a timeout. If no message is available,
		// loop and retry (respecting context/close).
		fetchCtx, cancel := context.WithTimeout(ctx, defaultFetchWait)
		msgs, err := consumer.Fetch(defaultFetchBatch, jetstream.FetchMaxWait(defaultFetchWait))
		cancel()

		if err != nil {
			if nb.closed.Load() || ctx.Err() != nil {
				return false
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) {
				continue // no message available, retry
			}
			logger.WarnCF("nats-bus", "NATS fetch error", map[string]any{
				"error": err.Error(),
			})
			continue
		}

		_ = fetchCtx // used for timeout only

		for natsMsg := range msgs.Messages() {
			if err := json.Unmarshal(natsMsg.Data(), target); err != nil {
				logger.ErrorCF("nats-bus", "NATS unmarshal error", map[string]any{
					"error":   err.Error(),
					"subject": natsMsg.Subject(),
				})
				// Nak with no delay so it can be retried or dead-lettered.
				_ = natsMsg.Nak()
				continue
			}

			// Acknowledge successful processing.
			if err := natsMsg.Ack(); err != nil {
				logger.WarnCF("nats-bus", "NATS ack error", map[string]any{
					"error": err.Error(),
				})
			}
			return true
		}

		// Check for fetch errors (e.g., consumer deleted).
		if fetchErr := msgs.Error(); fetchErr != nil {
			if nb.closed.Load() || ctx.Err() != nil {
				return false
			}
			if !errors.Is(fetchErr, context.DeadlineExceeded) && !errors.Is(fetchErr, nats.ErrTimeout) {
				logger.WarnCF("nats-bus", "NATS fetch iteration error", map[string]any{
					"error": fetchErr.Error(),
				})
			}
		}
	}
}

// compile-time assertion: NATSBus implements Bus.
var _ Bus = (*NATSBus)(nil)
