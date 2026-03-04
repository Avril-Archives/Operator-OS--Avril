# LINE

LINE is a widely used messaging app in Asia. Operator supports the LINE Messaging API to process incoming webhook events and send responses back to users.

## Configuration

```json
{
  "channels": {
    "line": {
      "enabled": true,
      "channel_secret": "YOUR_CHANNEL_SECRET",
      "channel_access_token": "YOUR_CHANNEL_ACCESS_TOKEN",
      "webhook_path": "/webhook/line",
      "allow_from": []
    }
  }
}
```

| Field                | Type   | Required | Description                                       |
| -------------------- | ------ | -------- | ------------------------------------------------- |
| enabled              | bool   | Yes      | Enable LINE channel                               |
| channel_secret       | string | Yes      | LINE Channel Secret                               |
| channel_access_token | string | Yes      | LINE Channel Access Token                         |
| webhook_path         | string | No       | Path to expose the LINE Webhook (default: /webhook/line) |
| allow_from           | array  | No       | Allowed user ID list (empty array allows all)     |

## Setup Guide

1. Navigate to the [LINE Developers Console](https://developers.line.biz/).
2. Create a new Provider, and under it, create a "Messaging API" channel.
3. Under the "Basic settings" tab, copy your **Channel Secret**.
4. Under the "Messaging API" tab, generate and copy your **Channel Access Token**.
5. Set your Webhook URL in the dashboard to `https://your-public-url.com/webhook/line` and enable "Use webhook". (Operator must be exposed via HTTPS, e.g., using ngrok, Cloudflare Tunnels, or a reverse proxy).
