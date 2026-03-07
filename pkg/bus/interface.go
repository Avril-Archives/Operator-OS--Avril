package bus

import "context"

// Bus defines the message bus interface for publishing and consuming messages.
// Both the in-memory MessageBus and NATSBus implement this interface.
// Self-hosted deployments use the in-memory implementation; SaaS deployments
// use NATS JetStream for at-least-once delivery and horizontal scaling.
type Bus interface {
	// PublishInbound publishes a message from a channel to the agent loop.
	PublishInbound(ctx context.Context, msg InboundMessage) error

	// ConsumeInbound blocks until an inbound message is available.
	// Returns ok=false when the bus is closed or context is canceled.
	ConsumeInbound(ctx context.Context) (InboundMessage, bool)

	// PublishOutbound publishes a response from the agent to channels.
	PublishOutbound(ctx context.Context, msg OutboundMessage) error

	// SubscribeOutbound blocks until an outbound message is available.
	// Returns ok=false when the bus is closed or context is canceled.
	SubscribeOutbound(ctx context.Context) (OutboundMessage, bool)

	// PublishOutboundMedia publishes media attachments from the agent to channels.
	PublishOutboundMedia(ctx context.Context, msg OutboundMediaMessage) error

	// SubscribeOutboundMedia blocks until an outbound media message is available.
	// Returns ok=false when the bus is closed or context is canceled.
	SubscribeOutboundMedia(ctx context.Context) (OutboundMediaMessage, bool)

	// Close shuts down the bus, draining pending messages.
	Close()
}

// compile-time assertion: MessageBus implements Bus.
var _ Bus = (*MessageBus)(nil)
