# OpenAI Provider Setup

## Prerequisites

- An OpenAI API key from [platform.openai.com](https://platform.openai.com/api-keys)

## Configuration

Add to your `~/.operator/config.json`:

```json
{
  "model_list": [
    {
      "model_name": "GPT-4o",
      "model": "openai/gpt-4o",
      "api_base": "https://api.openai.com/v1",
      "api_key": "sk-..."
    },
    {
      "model_name": "GPT-4o Mini",
      "model": "openai/gpt-4o-mini",
      "api_base": "https://api.openai.com/v1",
      "api_key": "sk-..."
    }
  ]
}
```

### Using Environment Variables

```bash
export OPERATOR_PROVIDERS_OPENAI_API_KEY="sk-..."
```

### Legacy Configuration

```json
{
  "providers": {
    "openai": {
      "api_key": "sk-...",
      "web_search": true
    }
  }
}
```

## Available Models

| Model | ID | Context | Notes |
|-------|-----|---------|-------|
| GPT-4o | `gpt-4o` | 128K | Flagship multimodal model |
| GPT-4o Mini | `gpt-4o-mini` | 128K | Cost-effective, fast |
| GPT-4.1 | `gpt-4.1` | 1M | Extended context |
| o3 | `o3` | 200K | Reasoning model |
| o4-mini | `o4-mini` | 200K | Fast reasoning |

## OpenAI-Compatible Providers

Any provider with an OpenAI-compatible API can be configured using the `openai/` protocol prefix with a custom `api_base`:

### Groq

```json
{
  "model_name": "Llama 3.3 70B (Groq)",
  "model": "openai/llama-3.3-70b-versatile",
  "api_base": "https://api.groq.com/openai/v1",
  "api_key": "gsk_..."
}
```

### DeepSeek

```json
{
  "model_name": "DeepSeek V3",
  "model": "openai/deepseek-chat",
  "api_base": "https://api.deepseek.com/v1",
  "api_key": "sk-..."
}
```

### OpenRouter

```json
{
  "model_name": "Claude via OpenRouter",
  "model": "openai/anthropic/claude-sonnet-4.6",
  "api_base": "https://openrouter.ai/api/v1",
  "api_key": "sk-or-..."
}
```

## Rate Limits

OpenAI enforces rate limits based on your usage tier. Operator OS handles rate limit responses (HTTP 429) automatically with exponential backoff retry. If you consistently hit limits, consider:

- Upgrading your OpenAI usage tier
- Using a smaller/faster model for routine tasks
- Configuring model fallbacks in your agent configuration

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `401 Unauthorized` | Verify your API key is correct and active |
| `429 Too Many Requests` | You've hit rate limits; Operator retries automatically |
| `model_not_found` | Check the model ID matches OpenAI's current model list |
| Connection timeout | Check `request_timeout` setting or network/proxy configuration |
