# WeCom

WeCom (Enterprise WeChat) provides enterprise-grade collaboration and internal communication. Operator natively supports three flavors of WeCom integration to suit various organizational architectures.

## Integration Modes

Choose the architecture that best fits your environment.

| Mode | Setup Difficulty | Group Support | Proactive Messaging | Use Case |
|---|---|---|---|---|
| [**WeCom Group Bot**](./wecom_bot/README.md) | Easy | Yes | Webhook Only | Quick notifications and in-group querying. |
| [**WeCom Custom App**](./wecom_app/README.md) | Medium | No | Yes | Private 1-on-1 enterprise assistance. |
| [**WeCom AI Bot**](./wecom_aibot/README.md) | Medium | Yes | Yes | Fully featured internal AI knowledge base. |

## Quick Configuration (Bot Mode)

```json
{
  "channels": {
    "wecom": {
      "enabled": true,
      "token": "YOUR_TOKEN",
      "encoding_aes_key": "YOUR_ENCODING_AES_KEY",
      "webhook_url": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=YOUR_KEY",
      "webhook_path": "/webhook/wecom"
    }
  }
}
```

Please refer to the subdirectories linked above for the specific setup flow and dashboard configurations corresponding to your chosen mode.
