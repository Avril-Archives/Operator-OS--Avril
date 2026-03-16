# Anthropic Provider Setup

## Prerequisites

- An Anthropic API key from [console.anthropic.com](https://console.anthropic.com/)

## Configuration

Add to your `~/.operator/config.json`:

```json
{
  "model_list": [
    {
      "model_name": "Claude Sonnet 4.6",
      "model": "anthropic/claude-sonnet-4-6-20250514",
      "api_key": "sk-ant-..."
    },
    {
      "model_name": "Claude Haiku 4.5",
      "model": "anthropic/claude-haiku-4-5-20251001",
      "api_key": "sk-ant-..."
    }
  ]
}
```

### Using Environment Variables

```bash
export OPERATOR_PROVIDERS_ANTHROPIC_API_KEY="sk-ant-..."
```

### Legacy Configuration

```json
{
  "providers": {
    "anthropic": {
      "api_key": "sk-ant-..."
    }
  }
}
```

## Available Models

| Model | ID | Context | Notes |
|-------|-----|---------|-------|
| Claude Opus 4.6 | `claude-opus-4-6` | 200K | Most capable |
| Claude Sonnet 4.6 | `claude-sonnet-4-6-20250514` | 200K | Best balance of speed and intelligence |
| Claude Haiku 4.5 | `claude-haiku-4-5-20251001` | 200K | Fastest, most cost-effective |

## Custom API Base

For API proxies or regional endpoints:

```json
{
  "model_name": "Claude Sonnet (Proxy)",
  "model": "anthropic/claude-sonnet-4-6-20250514",
  "api_base": "https://your-proxy.example.com",
  "api_key": "sk-ant-..."
}
```

## Rate Limits

Anthropic enforces rate limits based on your usage tier (requests per minute and tokens per minute). Operator OS handles rate limit responses automatically with exponential backoff retry.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `401 authentication_error` | Verify your API key starts with `sk-ant-` |
| `429 rate_limit_error` | Rate limited; Operator retries automatically |
| `529 overloaded_error` | Anthropic API is temporarily overloaded; retries automatically |
| `model_not_found` | Check the model ID against the current Anthropic model list |
