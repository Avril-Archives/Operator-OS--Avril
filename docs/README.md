# Operator OS — Documentation

## Setup & Configuration
- [Configuration Reference](configuration.md) — All config keys documented
- [Configuration Example](../config/config.example.json) — Sample config file
- [Tools Configuration](tools_configuration.md) — Configure built-in tools
- [Self-Hosting Guide](self-hosting.md) — Docker, Kubernetes, and bare metal deployment
- [Troubleshooting](troubleshooting.md) — Common issues and fixes
- [Environment Variables](../.env.example) — Required env vars

## Channels
Setup guides for each messaging channel:
- [Telegram](channels/telegram/README.md)
- [Discord](channels/discord/README.md)
- [Slack](channels/slack/README.md)
- [WhatsApp](channels/wecom/README.md)
- [DingTalk](channels/dingtalk/README.md)
- [Feishu / Lark](channels/feishu/README.md)
- [LINE](channels/line/README.md)
- [QQ](channels/qq/README.md)
- [OneBot](channels/onebot/README.md)
- [WeCom](channels/wecom/README.md) — [App](channels/wecom/wecom_app/README.md) · [Bot](channels/wecom/wecom_bot/README.md) · [AI Bot](channels/wecom/wecom_aibot/README.md)
- [MaixCAM](channels/maixcam/README.md)

## Providers
- [Provider Setup Overview](providers/README.md) — All providers at a glance
- [OpenAI](providers/openai.md) — GPT-4o, GPT-4.1, o3, and OpenAI-compatible providers
- [Anthropic](providers/anthropic.md) — Claude Opus, Sonnet, Haiku
- [Google Gemini](providers/gemini.md) — Gemini 2.5 Pro/Flash via AI Studio or Vertex AI
- [Ollama](providers/ollama.md) — Local models (Llama, Qwen, Mistral, DeepSeek)
- [Antigravity (Google Cloud Code Assist)](providers/ANTIGRAVITY_AUTH.md) — Auth & setup
- [Antigravity Usage Guide](providers/ANTIGRAVITY_USAGE.md)

## Deployment
- [Docker Compose](../docker/) — Container deployment
- [Helm Chart](../deploy/helm/) — Kubernetes deployment
- [GoReleaser](../.goreleaser.yaml) — Release builds

## Contributing & Security
- [Contributing Guide](../CONTRIBUTING.md) — Code style, PR process, testing
- [Security Policy](../SECURITY.md) — Responsible disclosure, security model

## Architecture
See the main [README](../README.md) for architecture overview, supported hardware, and quick start.
