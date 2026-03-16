# Provider-Specific Quirks & Rate Limits

This document catalogs provider-specific behaviors, rate limits, and workarounds for each supported LLM and messaging channel provider.

## LLM Providers

### OpenAI (GPT-4, GPT-4o, o1)

| Property | Value |
|----------|-------|
| Rate Limits | Tier-based: 500 RPM (Tier 1) → 10,000 RPM (Tier 5) |
| Context Windows | GPT-4o: 128K, o1: 200K |
| Max Output Tokens | GPT-4o: 16K, o1: 100K |
| Streaming | Supported via SSE |

**Quirks:**
- `o1` and `o1-mini` do **not** support system messages — Operator OS converts them to user messages with a `[System]` prefix automatically.
- `o1` models do **not** support `temperature` — the parameter is silently ignored (no error). Set `temperature: 1.0` or omit.
- Tool call IDs from OpenAI are prefixed `call_` — Operator OS normalizes these.
- Images in messages must be `base64` or `url` format — `media://` refs are resolved before sending.
- Rate limit headers (`x-ratelimit-remaining-requests`, `x-ratelimit-reset-requests`) are logged for debugging.

### Anthropic (Claude 4.6, Claude Sonnet 4.6)

| Property | Value |
|----------|-------|
| Rate Limits | Tier-based: 50 RPM (Tier 1) → 4,000 RPM (Tier 4) |
| Context Windows | 200K tokens |
| Max Output Tokens | 8,192 (default) → 64K (extended thinking) |
| Streaming | Supported via SSE |

**Quirks:**
- Requires `anthropic-version` header — Operator OS sends `2023-10-01`.
- System prompt must be sent as a top-level `system` field, **not** as a message with `role: "system"`.
- Tool use follows the Anthropic tool use format (`tool_use` content blocks, not OpenAI-style `tool_calls`). The provider adapter normalizes this.
- `extended_thinking` mode increases max output to 64K but has higher latency.
- Cache control (`cache_control: {"type": "ephemeral"}`) is supported for system prompts to reduce cost.
- Images require `source.type: "base64"` with explicit `media_type`.

### Google Gemini (Gemini 2.0, Gemini 2.5)

| Property | Value |
|----------|-------|
| Rate Limits | 60 RPM (free) → 1,000 RPM (paid) |
| Context Windows | Gemini 2.0 Flash: 1M, Gemini 2.5 Pro: 2M |
| Max Output Tokens | 8K (default), 65K (with thinking) |
| Streaming | Supported |

**Quirks:**
- Tool declarations use `functionDeclarations` format — different from OpenAI's `tools` array.
- System instructions use a `systemInstruction` field (not in messages).
- `thinkingConfig` for reasoning models (`budgetTokens` parameter).
- Safety settings may block tool outputs containing code — disable `HARM_CATEGORY_DANGEROUS_CONTENT` if tools produce code.
- Gemini returns `finishReason: "SAFETY"` when content is filtered — Operator OS retries once without the triggering content.

### Groq

| Property | Value |
|----------|-------|
| Rate Limits | 30 RPM (free), 100 RPM (paid) |
| Context Windows | Model-dependent (8K-32K) |
| Streaming | Supported |

**Quirks:**
- Uses OpenAI-compatible API — the `openai_compat` provider works directly.
- Very fast inference (100+ tok/s) but aggressive rate limiting on free tier.
- Tool calling support is **model-dependent** — Llama 3.3 supports tools, others may not.
- No image support.

### Ollama (Local)

| Property | Value |
|----------|-------|
| Rate Limits | None (local hardware) |
| Context Windows | Model-dependent |
| Streaming | Supported |

**Quirks:**
- Uses OpenAI-compatible API at `http://localhost:11434/v1`.
- No API key required — set `api_key: "ollama"` as a placeholder.
- Models must be pulled first (`ollama pull llama3.3`).
- Context window is limited by available VRAM — large contexts may OOM.
- Tool calling quality varies significantly by model. Llama 3.3 70B and Qwen2.5 72B work well.
- First request after model load is slow (loading weights into VRAM).

### DeepSeek

| Property | Value |
|----------|-------|
| Rate Limits | Varies by plan |
| Context Windows | 64K (DeepSeek V3) |
| Streaming | Supported |

**Quirks:**
- Uses OpenAI-compatible API.
- Reasoning content returned in a separate `reasoning_content` field.
- JSON mode may produce malformed JSON with very long outputs — use structured outputs or validate.
- Tool calling works but may hallucinate tool names not in the definitions.

---

## Messaging Channels

### Slack

| Property | Value |
|----------|-------|
| Rate Limits | 1 message/sec per channel (Tier 3) |
| Message Size | 40,000 characters max |
| Attachments | Files via `files.upload` API |

**Quirks:**
- Messages over 4,000 characters should use `blocks` format for proper rendering.
- Markdown uses Slack-flavored mrkdwn (not standard Markdown) — `*bold*` not `**bold**`.
- Thread replies require `thread_ts` parameter — Operator OS tracks this per chat session.
- Bot messages in DMs don't trigger `app_mention` events.
- Rate limit errors return HTTP 429 with `Retry-After` header.

### Discord

| Property | Value |
|----------|-------|
| Rate Limits | 5 messages/5 sec per channel |
| Message Size | 2,000 characters max |
| Attachments | 25MB max per file |

**Quirks:**
- Messages over 2,000 characters are automatically split at paragraph boundaries.
- Embeds have a separate 4,096 character description limit.
- Markdown is Discord-flavored — code blocks work, but some HTML entities don't.
- Slash commands must be registered via the API (not automatic).
- Rate limits are per-route, not global — different endpoints have different limits.

### Telegram

| Property | Value |
|----------|-------|
| Rate Limits | 30 msg/sec (global), 20 msg/min per group |
| Message Size | 4,096 characters max |
| Attachments | 50MB files, 20MB photos |

**Quirks:**
- Supports MarkdownV2 format — special characters must be escaped: `_*[]()~>#+\-=|{}.!`
- Long messages are split at 4,096 chars with continuation.
- Inline keyboards for interactive responses (confirmation dialogs).
- `parse_mode: "MarkdownV2"` is set by default. HTML mode available as fallback.
- Bot must be added to group and have message permissions.
- Flood control: 429 errors include `retry_after` parameter (seconds).

### WhatsApp (via WhatsApp Business API)

| Property | Value |
|----------|-------|
| Rate Limits | Tier-based: 1K-100K messages/day |
| Message Size | 4,096 characters (text), 1,024 chars (template) |
| Session Window | 24-hour conversation window from last user message |

**Quirks:**
- Messages outside 24-hour window require **approved templates**.
- Media messages require URLs (not inline base64).
- No markdown support in standard messages — use `*bold*` and `_italic_` only.
- Phone numbers must include country code without `+` prefix.
- Webhook verification requires echo challenge on setup.
- Read receipts and typing indicators are optional (enabled by default in Operator OS).

### LINE

| Property | Value |
|----------|-------|
| Rate Limits | 500 push messages/month (free), unlimited (paid) |
| Message Size | 5,000 characters max |
| Attachments | Images, video, audio via URL |

**Quirks:**
- Reply API requires `replyToken` (valid for 1 minute only).
- Push API is for proactive messages (uses monthly quota on free plan).
- Flex Messages for rich layouts — Operator OS converts markdown to Flex JSON.
- No standard markdown support — text-only or Flex Messages.
- Multi-message send (up to 5 messages per reply).

### DingTalk

| Property | Value |
|----------|-------|
| Rate Limits | 20 msg/sec per bot |
| Message Size | 20,000 characters max |
| Streaming | Supported via server-sent events |

**Quirks:**
- Uses stream-based SDK for real-time events.
- Markdown support is limited — only basic formatting.
- Mentions require `@` with user ID (not display name).
- Requires `timestamp` + `sign` for webhook security validation.
- Group chat requires `chatbotUserId` for at-mentions.

### Feishu (Lark)

| Property | Value |
|----------|-------|
| Rate Limits | 50 msg/sec per app |
| Message Size | Varies by message type |
| Attachments | Images, files via upload API |

**Quirks:**
- Uses `tenant_access_token` authentication (auto-refreshed by SDK).
- Rich text messages use Feishu's custom JSON format (not markdown).
- Card messages for interactive UI — Operator OS maps to card format for long responses.
- Event subscription requires challenge verification on setup.
- User IDs come in multiple formats (`open_id`, `union_id`, `user_id`) — Operator OS uses `open_id`.

---

## General Rate Limit Handling

Operator OS handles rate limits across all providers with:

1. **Exponential backoff**: 1s → 2s → 4s → 8s → 16s (5 retries max)
2. **Retry-After header**: Respected when present (overrides exponential backoff)
3. **Circuit breaker**: After 5 consecutive failures, provider is marked unhealthy for 30 seconds
4. **Fallback chain**: If primary provider is rate-limited, automatically falls back to next candidate
5. **Health checks**: `/health/detailed` endpoint reports per-provider rate limit status

Configure thresholds in `config.json`:

```json
{
  "gateway": {
    "rate_limit": {
      "requests_per_minute": 60,
      "burst": 10
    }
  }
}
```
