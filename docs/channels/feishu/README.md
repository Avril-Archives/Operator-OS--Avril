# Feishu

Feishu (Lark) is an advanced enterprise collaboration suite. Operator integrates with Feishu via WebSocket/SDK mode, eliminating the need to expose a public webhook URL to receive events.

## Configuration

```json
{
  "channels": {
    "feishu": {
      "enabled": true,
      "app_id": "cli_xxxxxxxxxxxx",
      "app_secret": "YOUR_APP_SECRET",
      "encrypt_key": "",
      "verification_token": "",
      "allow_from": []
    }
  }
}
```

| Field              | Type   | Required | Description                                         |
| ------------------ | ------ | -------- | --------------------------------------------------- |
| enabled            | bool   | Yes      | Enable Feishu channel                               |
| app_id             | string | Yes      | Feishu App ID (starts with `cli_`)                  |
| app_secret         | string | Yes      | Feishu App Secret                                   |
| encrypt_key        | string | No       | Feishu Encrypt Key (if using encrypted webhooks)    |
| verification_token | string | No       | Feishu Verification Token (for webhook validations) |
| allow_from         | array  | No       | Allowed user ID list (empty array allows all)       |

## Setup Guide

1. Navigate to the [Feishu Developer Console](https://open.feishu.cn/app/) and create a Custom App.
2. Under "Credentials and Basic Info", copy the App ID and App Secret.
3. Under "Permissions", grant the required permissions (Receive Messages in Private Chats, Receive Messages in Group Chats, Send Messages).
4. Under "Event Subscriptions", enable WebSocket mode to receive events directly via the internal SDK connection.
5. Create a version and publish the app for your workspace.
