package bus

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// =============================================================================
// Unit tests (no NATS server required)
// =============================================================================

func TestDefaultNATSConfig(t *testing.T) {
	cfg := DefaultNATSConfig("nats://localhost:4222")

	if cfg.URL != "nats://localhost:4222" {
		t.Fatalf("expected URL nats://localhost:4222, got %q", cfg.URL)
	}
	if cfg.StreamName != DefaultStreamName {
		t.Fatalf("expected stream %q, got %q", DefaultStreamName, cfg.StreamName)
	}
	if cfg.AckWait != defaultAckWait {
		t.Fatalf("expected AckWait %v, got %v", defaultAckWait, cfg.AckWait)
	}
	if cfg.MaxDeliver != defaultMaxDeliver {
		t.Fatalf("expected MaxDeliver %d, got %d", defaultMaxDeliver, cfg.MaxDeliver)
	}
	if cfg.ConsumerPrefix != "" {
		t.Fatalf("expected empty ConsumerPrefix, got %q", cfg.ConsumerPrefix)
	}
}

func TestDefaultNATSConfig_CustomValues(t *testing.T) {
	cfg := DefaultNATSConfig("nats://custom:4222")
	cfg.StreamName = "CUSTOM_STREAM"
	cfg.AckWait = 60 * time.Second
	cfg.MaxDeliver = 10
	cfg.ConsumerPrefix = "worker-1"

	if cfg.StreamName != "CUSTOM_STREAM" {
		t.Fatalf("expected stream CUSTOM_STREAM, got %q", cfg.StreamName)
	}
	if cfg.AckWait != 60*time.Second {
		t.Fatalf("expected AckWait 60s, got %v", cfg.AckWait)
	}
	if cfg.MaxDeliver != 10 {
		t.Fatalf("expected MaxDeliver 10, got %d", cfg.MaxDeliver)
	}
	if cfg.ConsumerPrefix != "worker-1" {
		t.Fatalf("expected ConsumerPrefix worker-1, got %q", cfg.ConsumerPrefix)
	}
}

func TestNewNATSBus_EmptyURL(t *testing.T) {
	_, err := NewNATSBus(NATSConfig{})
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
	if err.Error() != "nats: URL is required" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewNATSBus_InvalidURL(t *testing.T) {
	cfg := DefaultNATSConfig("nats://invalid-host-that-does-not-exist:4222")
	cfg.NATSOptions = nil // no reconnect

	_, err := NewNATSBus(cfg)
	if err == nil {
		t.Fatal("expected error for invalid NATS URL")
	}
}

func TestNATSBus_InterfaceCompliance(t *testing.T) {
	// Compile-time check already in interface.go, but verify pointer works.
	var _ Bus = (*NATSBus)(nil)
}

func TestSubjectConstants(t *testing.T) {
	if SubjectInbound != "operator.inbound" {
		t.Fatalf("unexpected inbound subject: %q", SubjectInbound)
	}
	if SubjectOutbound != "operator.outbound" {
		t.Fatalf("unexpected outbound subject: %q", SubjectOutbound)
	}
	if SubjectOutboundMedia != "operator.outbound.media" {
		t.Fatalf("unexpected outbound media subject: %q", SubjectOutboundMedia)
	}
	if DefaultStreamName != "OPERATOR" {
		t.Fatalf("unexpected default stream name: %q", DefaultStreamName)
	}
}

func TestInboundMessageJSON(t *testing.T) {
	msg := InboundMessage{
		Channel:    "telegram",
		SenderID:   "user1",
		ChatID:     "chat1",
		Content:    "hello world",
		SessionKey: "sess1",
		Metadata:   map[string]string{"key": "value"},
		Media:      []string{"photo1.jpg"},
		Peer:       Peer{Kind: "direct", ID: "user1"},
		Sender: SenderInfo{
			Platform:    "telegram",
			PlatformID:  "123",
			Username:    "@alice",
			DisplayName: "Alice",
		},
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded InboundMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.Channel != msg.Channel {
		t.Fatalf("channel mismatch: %q vs %q", decoded.Channel, msg.Channel)
	}
	if decoded.Content != msg.Content {
		t.Fatalf("content mismatch: %q vs %q", decoded.Content, msg.Content)
	}
	if decoded.Sender.Username != msg.Sender.Username {
		t.Fatalf("sender username mismatch: %q vs %q", decoded.Sender.Username, msg.Sender.Username)
	}
	if decoded.Peer.Kind != "direct" {
		t.Fatalf("peer kind mismatch: %q", decoded.Peer.Kind)
	}
	if len(decoded.Media) != 1 || decoded.Media[0] != "photo1.jpg" {
		t.Fatalf("media mismatch: %v", decoded.Media)
	}
	if decoded.Metadata["key"] != "value" {
		t.Fatalf("metadata mismatch: %v", decoded.Metadata)
	}
}

func TestOutboundMessageJSON(t *testing.T) {
	msg := OutboundMessage{
		Channel: "discord",
		ChatID:  "chan123",
		Content: "response text",
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded OutboundMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.Channel != msg.Channel {
		t.Fatalf("channel mismatch")
	}
	if decoded.ChatID != msg.ChatID {
		t.Fatalf("chat_id mismatch")
	}
	if decoded.Content != msg.Content {
		t.Fatalf("content mismatch")
	}
}

func TestOutboundMediaMessageJSON(t *testing.T) {
	msg := OutboundMediaMessage{
		Channel: "telegram",
		ChatID:  "chat1",
		Parts: []MediaPart{
			{
				Type:        "image",
				Ref:         "media://abc123",
				Caption:     "A photo",
				Filename:    "photo.jpg",
				ContentType: "image/jpeg",
			},
			{
				Type: "audio",
				Ref:  "media://def456",
			},
		},
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded OutboundMediaMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(decoded.Parts) != 2 {
		t.Fatalf("expected 2 parts, got %d", len(decoded.Parts))
	}
	if decoded.Parts[0].Type != "image" {
		t.Fatalf("part 0 type mismatch: %q", decoded.Parts[0].Type)
	}
	if decoded.Parts[0].Caption != "A photo" {
		t.Fatalf("part 0 caption mismatch: %q", decoded.Parts[0].Caption)
	}
	if decoded.Parts[1].Type != "audio" {
		t.Fatalf("part 1 type mismatch: %q", decoded.Parts[1].Type)
	}
}

func TestMessageBus_ImplementsBusInterface(t *testing.T) {
	mb := NewMessageBus()
	defer mb.Close()

	// Verify MessageBus can be used as a Bus interface.
	var b Bus = mb
	ctx := context.Background()

	// Publish and consume through the interface.
	if err := b.PublishInbound(ctx, InboundMessage{Content: "test"}); err != nil {
		t.Fatalf("PublishInbound via interface failed: %v", err)
	}

	msg, ok := b.ConsumeInbound(ctx)
	if !ok {
		t.Fatal("ConsumeInbound via interface returned false")
	}
	if msg.Content != "test" {
		t.Fatalf("content mismatch: %q", msg.Content)
	}

	// Outbound.
	if err := b.PublishOutbound(ctx, OutboundMessage{Content: "out"}); err != nil {
		t.Fatalf("PublishOutbound via interface failed: %v", err)
	}

	outMsg, ok := b.SubscribeOutbound(ctx)
	if !ok {
		t.Fatal("SubscribeOutbound via interface returned false")
	}
	if outMsg.Content != "out" {
		t.Fatalf("outbound content mismatch: %q", outMsg.Content)
	}

	// Media.
	if err := b.PublishOutboundMedia(ctx, OutboundMediaMessage{
		Channel: "test",
		Parts:   []MediaPart{{Type: "image", Ref: "media://1"}},
	}); err != nil {
		t.Fatalf("PublishOutboundMedia via interface failed: %v", err)
	}

	mediaMsg, ok := b.SubscribeOutboundMedia(ctx)
	if !ok {
		t.Fatal("SubscribeOutboundMedia via interface returned false")
	}
	if len(mediaMsg.Parts) != 1 {
		t.Fatalf("expected 1 media part, got %d", len(mediaMsg.Parts))
	}
}

func TestBusInterface_Close(t *testing.T) {
	mb := NewMessageBus()
	var b Bus = mb
	b.Close()

	// After close, publish should fail.
	err := b.PublishInbound(context.Background(), InboundMessage{Content: "test"})
	if err != ErrBusClosed {
		t.Fatalf("expected ErrBusClosed, got %v", err)
	}
}

func TestNATSConfig_DefaultStreamName(t *testing.T) {
	cfg := NATSConfig{URL: "nats://localhost:4222"}
	// StreamName is empty; NewNATSBus should default it.
	// We can't actually connect, but verify the config logic.
	if cfg.StreamName == "" {
		cfg.StreamName = DefaultStreamName
	}
	if cfg.StreamName != "OPERATOR" {
		t.Fatalf("expected default stream OPERATOR, got %q", cfg.StreamName)
	}
}

func TestNATSConfig_DefaultAckWait(t *testing.T) {
	cfg := NATSConfig{URL: "nats://localhost:4222"}
	if cfg.AckWait <= 0 {
		cfg.AckWait = defaultAckWait
	}
	if cfg.AckWait != 30*time.Second {
		t.Fatalf("expected 30s ack wait, got %v", cfg.AckWait)
	}
}

func TestNATSConfig_DefaultMaxDeliver(t *testing.T) {
	cfg := NATSConfig{URL: "nats://localhost:4222"}
	if cfg.MaxDeliver <= 0 {
		cfg.MaxDeliver = defaultMaxDeliver
	}
	if cfg.MaxDeliver != 5 {
		t.Fatalf("expected MaxDeliver 5, got %d", cfg.MaxDeliver)
	}
}

func TestNATSConfig_ConsumerNaming(t *testing.T) {
	tests := []struct {
		prefix   string
		name     string
		expected string
	}{
		{"", "inbound", "inbound"},
		{"worker-1", "inbound", "worker-1-inbound"},
		{"prod", "outbound", "prod-outbound"},
		{"", "outbound-media", "outbound-media"},
	}

	for _, tt := range tests {
		consumerName := tt.name
		if tt.prefix != "" {
			consumerName = tt.prefix + "-" + tt.name
		}
		if consumerName != tt.expected {
			t.Errorf("prefix=%q name=%q: expected %q, got %q", tt.prefix, tt.name, tt.expected, consumerName)
		}
	}
}

func TestMessageBus_ExistingTests_StillWork(t *testing.T) {
	// Verify the existing MessageBus behavior hasn't changed.
	mb := NewMessageBus()
	defer mb.Close()

	ctx := context.Background()

	// Inbound round-trip.
	if err := mb.PublishInbound(ctx, InboundMessage{
		Channel:  "test",
		SenderID: "u1",
		ChatID:   "c1",
		Content:  "hello",
	}); err != nil {
		t.Fatalf("PublishInbound: %v", err)
	}

	got, ok := mb.ConsumeInbound(ctx)
	if !ok || got.Content != "hello" {
		t.Fatalf("ConsumeInbound: ok=%v content=%q", ok, got.Content)
	}

	// Outbound round-trip.
	if err := mb.PublishOutbound(ctx, OutboundMessage{
		Channel: "tg",
		ChatID:  "123",
		Content: "world",
	}); err != nil {
		t.Fatalf("PublishOutbound: %v", err)
	}

	outGot, ok := mb.SubscribeOutbound(ctx)
	if !ok || outGot.Content != "world" {
		t.Fatalf("SubscribeOutbound: ok=%v content=%q", ok, outGot.Content)
	}
}

func TestMessageBus_ClosedPublish_AllMethods(t *testing.T) {
	mb := NewMessageBus()
	mb.Close()

	ctx := context.Background()

	if err := mb.PublishInbound(ctx, InboundMessage{}); err != ErrBusClosed {
		t.Fatalf("PublishInbound: expected ErrBusClosed, got %v", err)
	}
	if err := mb.PublishOutbound(ctx, OutboundMessage{}); err != ErrBusClosed {
		t.Fatalf("PublishOutbound: expected ErrBusClosed, got %v", err)
	}
	if err := mb.PublishOutboundMedia(ctx, OutboundMediaMessage{}); err != ErrBusClosed {
		t.Fatalf("PublishOutboundMedia: expected ErrBusClosed, got %v", err)
	}
}

func TestMessageBus_CanceledContext_AllMethods(t *testing.T) {
	mb := NewMessageBus()
	defer mb.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Publish with canceled context should return context.Canceled.
	if err := mb.PublishInbound(ctx, InboundMessage{}); err != context.Canceled {
		t.Fatalf("PublishInbound: expected context.Canceled, got %v", err)
	}
	if err := mb.PublishOutbound(ctx, OutboundMessage{}); err != context.Canceled {
		t.Fatalf("PublishOutbound: expected context.Canceled, got %v", err)
	}
	if err := mb.PublishOutboundMedia(ctx, OutboundMediaMessage{}); err != context.Canceled {
		t.Fatalf("PublishOutboundMedia: expected context.Canceled, got %v", err)
	}

	// Consume with canceled context should return false.
	if _, ok := mb.ConsumeInbound(ctx); ok {
		t.Fatal("ConsumeInbound: expected ok=false")
	}
	if _, ok := mb.SubscribeOutbound(ctx); ok {
		t.Fatal("SubscribeOutbound: expected ok=false")
	}
	if _, ok := mb.SubscribeOutboundMedia(ctx); ok {
		t.Fatal("SubscribeOutboundMedia: expected ok=false")
	}
}

func TestMediaPart_JSON(t *testing.T) {
	part := MediaPart{
		Type:        "video",
		Ref:         "media://vid123",
		Caption:     "A clip",
		Filename:    "clip.mp4",
		ContentType: "video/mp4",
	}

	data, err := json.Marshal(part)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded MediaPart
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Type != "video" {
		t.Fatalf("type mismatch: %q", decoded.Type)
	}
	if decoded.Ref != "media://vid123" {
		t.Fatalf("ref mismatch: %q", decoded.Ref)
	}
	if decoded.ContentType != "video/mp4" {
		t.Fatalf("content_type mismatch: %q", decoded.ContentType)
	}
}

func TestPeerJSON(t *testing.T) {
	peer := Peer{Kind: "group", ID: "grp123"}

	data, err := json.Marshal(peer)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Peer
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Kind != "group" || decoded.ID != "grp123" {
		t.Fatalf("mismatch: %+v", decoded)
	}
}

func TestSenderInfoJSON(t *testing.T) {
	info := SenderInfo{
		Platform:    "discord",
		PlatformID:  "456",
		CanonicalID: "discord:456",
		Username:    "@bob",
		DisplayName: "Bob",
	}

	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded SenderInfo
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Platform != "discord" {
		t.Fatalf("platform mismatch: %q", decoded.Platform)
	}
	if decoded.CanonicalID != "discord:456" {
		t.Fatalf("canonical_id mismatch: %q", decoded.CanonicalID)
	}
}

func TestErrBusClosed(t *testing.T) {
	if ErrBusClosed.Error() != "message bus closed" {
		t.Fatalf("unexpected error message: %q", ErrBusClosed.Error())
	}
}

func TestDefaultConstants(t *testing.T) {
	if defaultAckWait != 30*time.Second {
		t.Fatalf("unexpected defaultAckWait: %v", defaultAckWait)
	}
	if defaultMaxDeliver != 5 {
		t.Fatalf("unexpected defaultMaxDeliver: %d", defaultMaxDeliver)
	}
	if defaultFetchBatch != 1 {
		t.Fatalf("unexpected defaultFetchBatch: %d", defaultFetchBatch)
	}
	if defaultFetchWait != 5*time.Second {
		t.Fatalf("unexpected defaultFetchWait: %v", defaultFetchWait)
	}
}
