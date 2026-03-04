# OneBot

OneBot is a universal chatbot standard that allows Operator to integrate with multiple chat protocols (most notably QQ) using standard WebSocket communication.

## Configuration

```json
{
  "channels": {
    "onebot": {
      "enabled": true,
      "ws_url": "ws://127.0.0.1:6700",
      "access_token": "OPTIONAL_TOKEN",
      "allow_from": []
    }
  }
}
```

| Field        | Type   | Required | Description                                       |
| ------------ | ------ | -------- | ------------------------------------------------- |
| enabled      | bool   | Yes      | Enable OneBot channel                             |
| ws_url       | string | Yes      | WebSocket URL of the OneBot-compliant server      |
| access_token | string | No       | Authentication token for the OneBot server        |
| allow_from   | array  | No       | Allowed user ID list (empty array allows all)     |

## Setup Guide

1. Deploy a OneBot V11 compatible server (such as go-cqhttp, Lagrange, or NapCatQQ) to act as the protocol bridge.
2. Configure the bridge to expose a WebSocket Server (e.g., `ws://127.0.0.1:6700`).
3. Set the `ws_url` in Operator to point to your OneBot server.
4. Restart Operator. It will connect to the bridge and begin answering queries based on the allowed groups/users.
