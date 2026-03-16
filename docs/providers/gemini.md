# Google Gemini Provider Setup

## Prerequisites

- A Google AI API key from [aistudio.google.com](https://aistudio.google.com/apikey)

## Configuration

Gemini uses the OpenAI-compatible API endpoint. Add to your `~/.operator/config.json`:

```json
{
  "model_list": [
    {
      "model_name": "Gemini 2.5 Pro",
      "model": "openai/gemini-2.5-pro",
      "api_base": "https://generativelanguage.googleapis.com/v1beta/openai",
      "api_key": "AIza..."
    },
    {
      "model_name": "Gemini 2.5 Flash",
      "model": "openai/gemini-2.5-flash",
      "api_base": "https://generativelanguage.googleapis.com/v1beta/openai",
      "api_key": "AIza..."
    }
  ]
}
```

### Using Environment Variables

```bash
export OPERATOR_PROVIDERS_GEMINI_API_KEY="AIza..."
```

### Legacy Configuration

```json
{
  "providers": {
    "gemini": {
      "api_key": "AIza...",
      "api_base": "https://generativelanguage.googleapis.com/v1beta/openai"
    }
  }
}
```

## Available Models

| Model | ID | Context | Notes |
|-------|-----|---------|-------|
| Gemini 2.5 Pro | `gemini-2.5-pro` | 1M | Most capable, thinking model |
| Gemini 2.5 Flash | `gemini-2.5-flash` | 1M | Fast, cost-effective |
| Gemini 2.0 Flash | `gemini-2.0-flash` | 1M | Previous generation fast model |

## Vertex AI (Google Cloud)

For enterprise deployments using Vertex AI:

```json
{
  "model_name": "Gemini Pro (Vertex)",
  "model": "openai/gemini-2.5-pro",
  "api_base": "https://REGION-aiplatform.googleapis.com/v1beta1/projects/PROJECT_ID/locations/REGION/endpoints/openapi",
  "api_key": "your-vertex-api-key"
}
```

Replace `REGION` and `PROJECT_ID` with your Google Cloud values.

## Rate Limits

Google AI Studio has per-minute rate limits that vary by model and API key tier. The free tier has lower limits. Operator OS handles rate limit responses automatically.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `400 API_KEY_INVALID` | Verify your API key from Google AI Studio |
| `429 RESOURCE_EXHAUSTED` | Rate limited; consider upgrading to paid tier |
| `403 PERMISSION_DENIED` | Enable the Generative Language API in Google Cloud Console |
| Connection errors | Verify `api_base` URL is correct for your region |
