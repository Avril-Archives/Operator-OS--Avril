# WeCom AI Bot

The WeCom AI Bot is the official enterprise solution for deploying conversational agents within WeCom workspaces. It supports streaming pull protocols, eliminating standard webhook timeout restrictions for long-running generation tasks.

## Configuration

```json
{
  "channels": {
    "wecom_aibot": {
      "enabled": true,
      "token": "YOUR_VERIFICATION_TOKEN",
      "encoding_aes_key": "YOUR_43_CHAR_ENCODING_AES_KEY",
      "webhook_path": "/webhook/wecom-aibot",
      "allow_from": [],
      "welcome_message": "Hello! I am your AI assistant."
    }
  }
}
```

| Field            | Type   | Required | Description                                                  |
| ---------------- | ------ | -------- | ------------------------------------------------------------ |
| enabled          | bool   | Yes      | Enable WeCom AI Bot channel                                  |
| token            | string | Yes      | App verification token                                       |
| encoding_aes_key | string | Yes      | 43-character symmetric encryption key                        |
| webhook_path     | string | No       | Path to expose the callback hook (default: `/webhook/wecom-aibot`) |
| welcome_message  | string | No       | Automated greeting sent to new chats                         |

## Setup Guide

1. Navigate to the **WeCom Admin Console** -> **App Management** -> **AI Bot**.
2. Within the AI Bot settings, configure the callback URL: `http://your-server-ip:18791/webhook/wecom-aibot`.
3. Copy the **Token** and click "Random Generate" for the **EncodingAESKey**.
4. Configure these fields in the Operator `config.json`.
5. Start the gateway. If tasks take longer than 30 seconds, Operator will automatically switch from streaming push to asynchronous `response_url` delivery.
