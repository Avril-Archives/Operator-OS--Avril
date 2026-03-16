<div align="center">
  <img src="assets/logo.png" alt="Operator OS" width="512">

  <h1>Operator OS</h1>

  <p>by <strong>Standard Compute</strong></p>

  <p><strong>The Ultra-Lightweight AI Agent Framework for Constrained Environments</strong></p>

  <p>
    <img src="https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go&logoColor=white" alt="Go">
    <img src="https://img.shields.io/badge/React-19-61DAFB?style=flat&logo=react&logoColor=white" alt="React">
    <img src="https://img.shields.io/badge/Architecture-x86__64%20%7C%20ARM64%20%7C%20RISC--V-blue" alt="Architecture">
    <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
    <br>
    <a href="https://operator.ws"><img src="https://img.shields.io/badge/Website-operator.ws-blue?style=flat&logo=google-chrome&logoColor=white" alt="Website"></a>
    <a href="https://discord.gg/Ve9eakT9n"><img src="https://img.shields.io/badge/Discord-Community-4c60eb?style=flat&logo=discord&logoColor=white" alt="Discord"></a>
  </p>
</div>

---

**Operator OS** is an ultra-lightweight, high-performance personal AI Agent framework written in Go. Designed to run on hardware as inexpensive as $10 with a memory footprint of less than 10MB, Operator OS brings true continuous intelligence to the edge.

Built from the ground up to support autonomous agents, persistent memory, and multi-channel messaging, it bridges the gap between complex reasoning models and constrained runtime environments.

## ✨ Core Capabilities

- **Ultra-Lightweight Engine**: Consumes <10MB of RAM—99% smaller than typical Node.js or Python-based agent frameworks.
- **Lightning Fast Boot**: Cold starts in under 1 second, even on single-core 0.6GHz processors.
- **True Portability**: Deploys as a single, self-contained binary across RISC-V, ARM, and x86 architectures.
- **Continuous Memory**: Structural, persistent long-term memory that carries context seamlessly across sessions and reboots.
- **Multi-Channel Integration**: Natively supports Slack, Discord, Telegram, and WhatsApp out of the box.
- **Universal Model Support**: Drop-in support for OpenAI (5.x), Anthropic (Claude 4.x), Google Gemini (3.x Pro), and local Ollama.

## 🛠️ Typical Workflows

| Autonomous Engineering | System Automation | Information Retrieval |
| :---: | :---: | :---: |
| <img src="assets/operator_code.gif" width="240"> | <img src="assets/operator_memory.gif" width="240"> | <img src="assets/operator_search.gif" width="240"> |
| **Develop • Deploy • Scale**<br>Agents can access your local terminal and execute complex multi-step coding tasks. | **Schedule • Automate • Recall**<br>Native Cron tooling allows agents to run periodic health checks and background jobs. | **Discovery • Insights**<br>Agents can securely search the web and extract data without human intervention. |

## 🚀 Installation & Quick Start

### Precompiled Binaries
Download the appropriate binary for your system from our [Releases](https://github.com/operatoronline/Operator-OS/releases) page.

### Build from Source
Requires Go 1.25+.

```bash
git clone https://github.com/operatoronline/Operator-OS.git
cd Operator-OS
make deps
make build
```

### Initializing the Agent

**1. Initialize your workspace**
```bash
operator onboard
```

**2. Configure your API keys**
Edit `~/.operator/config.json` to link your preferred LLM and messaging channels:

```json
{
  "model_list": [
    {
      "model_name": "gpt-5.2",
      "model": "openai/gpt-5.2",
      "api_key": "sk-your-openai-key"
    },
    {
      "model_name": "claude-4-5-sonnet",
      "model": "anthropic/claude-4-5-sonnet-20260220",
      "api_key": "sk-ant-your-key"
    },
    {
      "model_name": "gemini-3.1-pro",
      "model": "gemini/gemini-3.1-pro",
      "api_key": "AIza-your-google-key"
    }
  ],
  "agents": {
    "defaults": {
      "model": "claude-4-5-sonnet"
    }
  },
  "channels": {
    "slack": {
      "enabled": true,
      "bot_token": "xoxb-YOUR_SLACK_BOT_TOKEN",
      "app_token": "xapp-YOUR_SLACK_APP_TOKEN"
    }
  }
}
```

**3. Start the Gateway**
Run the Gateway daemon to bring your agent online and connect it to your configured channels.
```bash
operator gateway
```

You can now message your agent directly via Slack (or your chosen channel) or interact with it via the CLI:
```bash
operator agent -m "What is the status of the system?"
```

## 🔌 Supported AI Providers

Operator supports a zero-code model configuration system. Simply prefix the model name with the provider protocol in your `model_list`.

| Provider | Protocol Prefix | Example |
|---|---|---|
| **Anthropic** | `anthropic/` | `anthropic/claude-4-5-sonnet-20260220` |
| **OpenAI** | `openai/` | `openai/gpt-5.2` |
| **Google Gemini** | `gemini/` | `gemini/gemini-3.1-pro` |
| **Groq** | `groq/` | `groq/llama3-8b-8192` |
| **DeepSeek** | `deepseek/` | `deepseek/deepseek-chat` |
| **Ollama (Local)** | `ollama/` | `ollama/llama3` |

## 🖥️ Web Dashboard

Operator OS includes a full-featured web dashboard built with React 19, TypeScript, and Tailwind CSS v4.

```bash
cd web && npm install && npm run dev
# Open http://localhost:5173
```

Features include:
- **Chat interface** with streaming, markdown rendering, and file attachments
- **Agent management** with creation wizard and real-time status
- **Session management** with search, filters, pin, archive, and export
- **Usage analytics** with daily charts, model breakdown, and overage warnings
- **Billing management** with plan comparison and subscription controls
- **Admin panel** with user management, audit logs, and security dashboard
- **Integration hub** for connecting third-party services via OAuth or API keys
- **Settings** for profile, theme, API keys, notifications, and GDPR controls

The dashboard is mobile-first, accessible (WCAG 2.1 AA), and supports dark/light themes with OKLCH color tokens.

## 🛡️ Security & Sandboxing

By default, Operator OS runs its agents in a secure sandbox.
- **Workspace Confinement**: Agents are restricted to reading/writing files within the configured workspace directory (default: `~/.operator/workspace`).
- **Command Filtering**: The `exec` tool blocks dangerous system commands (`rm -rf`, disk formatting, system shutdowns) even if workspace restrictions are bypassed.

To grant the agent full access to your host system (e.g., for system administration workflows), you must explicitly disable the sandbox in your configuration:

```json
{
  "agents": {
    "defaults": {
      "restrict_to_workspace": false
    }
  }
}
```
*Note: Only disable sandboxing in trusted, single-user environments.*

## 🐳 Docker Deployment

To run the Gateway completely containerized without installing Go locally:

```bash
git clone https://github.com/operatoronline/Operator-OS.git
cd Operator-OS

# Generate the default configuration structure
docker compose -f docker/docker-compose.yml --profile gateway up

# Edit the generated config file with your keys
vim docker/data/config.json

# Start the Gateway in the background
docker compose -f docker/docker-compose.yml --profile gateway up -d
```

## 📖 Documentation

- [Configuration Reference](docs/configuration.md) — All config keys documented
- [Self-Hosting Guide](docs/self-hosting.md) — Docker, Kubernetes, and bare metal
- [Tools Configuration](docs/tools_configuration.md) — Built-in tools setup
- [Channel Setup Guides](docs/) — Telegram, Discord, Slack, WhatsApp, and more
- [Troubleshooting](docs/troubleshooting.md) — Common issues and fixes

## 🤝 Contributing

We welcome pull requests and issues! See the [Contributing Guide](CONTRIBUTING.md) for code style, PR process, and testing requirements.

## 🔒 Security

See [SECURITY.md](SECURITY.md) for our security policy and responsible disclosure process.

## 📄 License

This project is licensed under the [MIT License](LICENSE).
