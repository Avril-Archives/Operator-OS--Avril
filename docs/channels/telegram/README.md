# Telegram

The Telegram channel uses long-polling via the Telegram Bot API. It supports text messages, media attachments (photos, voice, audio, documents), voice transcription via Groq Whisper, and a built-in command processor.

## Configuration

```json
{
  "channels": {
    "telegram": {
      "enabled": true,
      "token": "123456789:ABCdefGHIjklMNOpqrsTUVwxyz",
      "allow_from": ["123456789"],
      "proxy": ""
    }
  }
}
```

| Field      | Type   | Required | Description                                               |
| ---------- | ------ | -------- | --------------------------------------------------------- |
| enabled    | bool   | Yes      | Enable Telegram channel                                   |
| token      | string | Yes      | Telegram Bot API Token                                    |
| allow_from | array  | No       | Allowed user ID list (empty array allows all users)       |
| proxy      | string | No       | Proxy URL for API connection (e.g. http://127.0.0.1:7890) |

## Setup Guide

1. Search for `@BotFather` in Telegram
2. Send `/newbot` and follow the prompts to create a new bot
3. Copy the HTTP API Token
4. Insert the token into your configuration file
5. (Optional) Restrict interaction by adding User IDs to `allow_from` (obtain your ID via `@userinfobot`)
