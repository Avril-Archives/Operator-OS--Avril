# Ollama Provider Setup

## Prerequisites

- [Ollama](https://ollama.com/) installed and running locally
- At least one model pulled (e.g., `ollama pull llama3.3`)

## Installation

```bash
# macOS / Linux
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama (runs on port 11434 by default)
ollama serve
```

## Configuration

Ollama exposes an OpenAI-compatible API. Add to your `~/.operator/config.json`:

```json
{
  "model_list": [
    {
      "model_name": "Llama 3.3 70B",
      "model": "openai/llama3.3:70b",
      "api_base": "http://localhost:11434/v1",
      "api_key": "ollama"
    },
    {
      "model_name": "Qwen 2.5 Coder 32B",
      "model": "openai/qwen2.5-coder:32b",
      "api_base": "http://localhost:11434/v1",
      "api_key": "ollama"
    }
  ]
}
```

> **Note:** Ollama doesn't require authentication, but the `api_key` field must be set to any non-empty string (e.g., `"ollama"`).

### Using Environment Variables

```bash
export OPERATOR_PROVIDERS_OLLAMA_API_KEY="ollama"
export OPERATOR_PROVIDERS_OLLAMA_API_BASE="http://localhost:11434/v1"
```

### Legacy Configuration

```json
{
  "providers": {
    "ollama": {
      "api_key": "ollama",
      "api_base": "http://localhost:11434/v1"
    }
  }
}
```

## Popular Models

Pull models with `ollama pull <model>`:

| Model | Command | Size | Notes |
|-------|---------|------|-------|
| Llama 3.3 70B | `ollama pull llama3.3:70b` | ~40GB | Best open-source general model |
| Llama 3.2 3B | `ollama pull llama3.2:3b` | ~2GB | Fast, runs on small hardware |
| Qwen 2.5 Coder 32B | `ollama pull qwen2.5-coder:32b` | ~18GB | Excellent for code |
| Mistral Small | `ollama pull mistral-small` | ~12GB | Good balance |
| Phi-4 | `ollama pull phi4` | ~8GB | Compact, capable |
| DeepSeek R1 | `ollama pull deepseek-r1:32b` | ~18GB | Reasoning model |

## Network Configuration

### Remote Ollama Server

If Ollama runs on a different machine:

```json
{
  "model_name": "Remote Llama",
  "model": "openai/llama3.3:70b",
  "api_base": "http://192.168.1.100:11434/v1",
  "api_key": "ollama"
}
```

Ensure Ollama is configured to accept remote connections:

```bash
OLLAMA_HOST=0.0.0.0:11434 ollama serve
```

### Docker Network

When running Operator OS in Docker alongside Ollama:

```json
{
  "api_base": "http://host.docker.internal:11434/v1"
}
```

Or use Docker Compose networking:

```json
{
  "api_base": "http://ollama:11434/v1"
}
```

## Hardware Requirements

| Model Size | RAM Required | GPU VRAM | Notes |
|-----------|-------------|----------|-------|
| 3B | 4GB | 4GB | Runs on most hardware |
| 7-8B | 8GB | 8GB | Good for Raspberry Pi 5 (CPU) |
| 13B | 16GB | 16GB | Needs decent GPU or lots of RAM |
| 32B | 32GB | 24GB | Requires high-end GPU |
| 70B | 64GB | 48GB | Needs A100 or multi-GPU |

Models run on CPU if no GPU is available, but performance is significantly slower.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Connection refused | Ensure `ollama serve` is running |
| Model not found | Pull the model first: `ollama pull <model>` |
| Out of memory | Use a smaller model or add `--num-gpu 0` for CPU-only |
| Slow responses | Consider a smaller model or check GPU utilization |
| Docker can't connect | Use `host.docker.internal` or Docker network hostname |
