# Provider Setup Guides

Operator OS supports multiple LLM providers. Each provider can be configured via the `model_list` array in `config.json` or via legacy provider-specific fields.

## Supported Providers

| Provider | Protocol Prefix | Guide |
|----------|----------------|-------|
| OpenAI | `openai/` (default) | [openai.md](openai.md) |
| Anthropic | `anthropic/` | [anthropic.md](anthropic.md) |
| Google Gemini | `openai/` | [gemini.md](gemini.md) |
| Ollama | `openai/` | [ollama.md](ollama.md) |
| Groq | `openai/` | See OpenAI-compatible setup |
| DeepSeek | `openai/` | See OpenAI-compatible setup |
| OpenRouter | `openai/` | See OpenAI-compatible setup |

## Quick Configuration

All providers use the `model_list` format in `~/.operator/config.json`:

```json
{
  "model_list": [
    {
      "model_name": "My Model",
      "model": "protocol/model-id",
      "api_base": "https://api.example.com/v1",
      "api_key": "your-key"
    }
  ]
}
```

See individual guides for provider-specific details.
