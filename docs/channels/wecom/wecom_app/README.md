# WeCom Custom App

The WeCom Custom App integration allows Operator to act as a 1-on-1 private messaging agent for enterprise users, with the ability to initiate proactive notifications. 

## Configuration

```json
{
  "channels": {
    "wecom_app": {
      "enabled": true,
      "corp_id": "wwxxxxxxxxxxxxxxxx",
      "corp_secret": "YOUR_CORP_SECRET",
      "agent_id": 1000002,
      "token": "YOUR_TOKEN",
      "encoding_aes_key": "YOUR_ENCODING_AES_KEY",
      "webhook_path": "/webhook/wecom-app",
      "allow_from": []
    }
  }
}
```

| Field            | Type   | Required | Description                                               |
| ---------------- | ------ | -------- | --------------------------------------------------------- |
| enabled          | bool   | Yes      | Enable WeCom Custom App channel                           |
| corp_id          | string | Yes      | Enterprise ID from the "My Company" admin page            |
| corp_secret      | string | Yes      | Secret key generated for this specific App                |
| agent_id         | number | Yes      | App internal ID                                           |
| token            | string | Yes      | API verification token                                    |
| encoding_aes_key | string | Yes      | Message encryption/decryption key                         |

## Setup Guide

1. Navigate to the **WeCom Admin Console** -> **App Management** -> **Create App**.
2. Note your newly created **AgentId** and **Secret**.
3. Under the app details, click **"Receive Message"** -> **"Set API"**.
4. Set the API URL to point to your Operator webhook (e.g., `http://your-server:18790/webhook/wecom-app`).
5. Generate the **Token** and **EncodingAESKey** from the interface and insert them alongside your `corp_id` into your `config.json`.
6. Start the gateway.
