# Slack

Slack is a leading enterprise messaging platform. Operator integrates via Slack's Socket Mode, meaning real-time two-way communication is supported without configuring public Webhook endpoints.

## Configuration

```json
{
  "channels": {
    "slack": {
      "enabled": true,
      "bot_token": "xoxb-...",
      "app_token": "xapp-...",
      "allow_from": []
    }
  }
}
```

| Field      | Type   | Required | Description                                                |
| ---------- | ------ | -------- | ---------------------------------------------------------- |
| enabled    | bool   | Yes      | Enable Slack channel                                       |
| bot_token  | string | Yes      | Slack Bot User OAuth Token (starts with `xoxb-`)           |
| app_token  | string | Yes      | Slack Socket Mode App Level Token (starts with `xapp-`)    |
| allow_from | array  | No       | Allowed user ID list (empty array allows all users)        |

## Setup Guide

1. Navigate to the [Slack API Dashboard](https://api.slack.com/apps) and create a new Slack App.
2. Enable Socket Mode to receive an App-Level Token (`xapp-`).
3. Under "OAuth & Permissions", add necessary Bot Token Scopes (e.g., `chat:write`, `im:history`, `app_mentions:read`).
4. Install the application to your workspace to generate a Bot User OAuth Token (`xoxb-`).
5. Insert both the Bot Token and App Token into your configuration file.
