# Discord

Discord is a popular voice, video, and text communication service. Operator utilizes the Discord Bot API to receive and send messages within servers and DMs.

## Configuration

```json
{
  "channels": {
    "discord": {
      "enabled": true,
      "token": "YOUR_BOT_TOKEN",
      "allow_from": ["YOUR_USER_ID"],
      "group_trigger": {
        "mention_only": false
      }
    }
  }
}
```

| Field         | Type   | Required | Description                                     |
| ------------- | ------ | -------- | ----------------------------------------------- |
| enabled       | bool   | Yes      | Enable Discord channel                          |
| token         | string | Yes      | Discord Bot Token                               |
| allow_from    | array  | No       | Allowed user ID list (empty array allows all)   |
| group_trigger | object | No       | Group trigger settings (e.g., mention_only)     |

## Setup Guide

1. Navigate to the [Discord Developer Portal](https://discord.com/developers/applications) and create a new application.
2. Under "Bot", enable the following Privileged Gateway Intents:
   - Message Content Intent
   - Server Members Intent
3. Generate and copy the Bot Token.
4. Insert the Bot Token into your configuration file.
5. Use the OAuth2 URL Generator to invite the bot to your server with the required permissions (Send Messages, Read Message History, etc.).
