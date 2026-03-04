# DingTalk

DingTalk is a popular enterprise communication platform. Operator integrates via DingTalk's Bot API to provide interactive messaging and intelligent assistance within enterprise groups and private chats.

## Configuration

```json
{
  "channels": {
    "dingtalk": {
      "enabled": true,
      "client_id": "YOUR_CLIENT_ID",
      "client_secret": "YOUR_CLIENT_SECRET",
      "allow_from": []
    }
  }
}
```

| Field         | Type   | Required | Description                                     |
| ------------- | ------ | -------- | ----------------------------------------------- |
| enabled       | bool   | Yes      | Enable DingTalk channel                         |
| client_id     | string | Yes      | DingTalk App Client ID (AppKey)                 |
| client_secret | string | Yes      | DingTalk App Client Secret (AppSecret)          |
| allow_from    | array  | No       | Allowed user ID list (empty array allows all)   |

## Setup Guide

1. Navigate to the [DingTalk Open Platform](https://open.dingtalk.com/) and log in.
2. Create an Internal Enterprise App (H5 or Miniapp).
3. Under "App Credentials", copy the Client ID (AppKey) and Client Secret (AppSecret).
4. Insert these credentials into your configuration file.
5. In the Developer console, enable Bot features and configure the message callback URL if using webhook mode, or utilize the internal polling/stream mode if supported.
