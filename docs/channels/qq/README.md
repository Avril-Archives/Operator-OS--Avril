# QQ

The QQ channel integrates natively using the Tencent QQ Open Platform API. Operator operates as a certified QQ Bot to send and receive rich messages in standard chat windows and groups.

## Configuration

```json
{
  "channels": {
    "qq": {
      "enabled": true,
      "app_id": "YOUR_APP_ID",
      "app_secret": "YOUR_APP_SECRET",
      "token": "YOUR_QQ_BOT_TOKEN",
      "allow_from": []
    }
  }
}
```

| Field      | Type   | Required | Description                                       |
| ---------- | ------ | -------- | ------------------------------------------------- |
| enabled    | bool   | Yes      | Enable QQ channel                                 |
| app_id     | string | Yes      | App ID from the QQ Open Platform                  |
| app_secret | string | Yes      | App Secret from the QQ Open Platform              |
| token      | string | Yes      | Bot connection Token                              |
| allow_from | array  | No       | Allowed user ID list (empty array allows all)     |

## Setup Guide

1. Navigate to the [QQ Open Platform](https://q.qq.com/#/).
2. Create a new QQ Bot application and complete the necessary developer verifications.
3. Retrieve your `app_id`, `app_secret`, and `token` from the developer dashboard.
4. Input the credentials into the Operator config file.
5. In group chats, ensure the bot is explicitly `@mentioned` to invoke a response.
