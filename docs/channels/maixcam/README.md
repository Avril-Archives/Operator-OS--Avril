# MaixCAM

MaixCAM integration provides hardware-level vision and automation hooks designed for intelligent edge cameras. Operator acts as the processing backend to handle triggers sent from the MaixCAM hardware.

## Configuration

```json
{
  "channels": {
    "maixcam": {
      "enabled": true,
      "endpoint": "http://192.168.1.100",
      "auth_token": "YOUR_DEVICE_TOKEN",
      "allow_from": []
    }
  }
}
```

| Field      | Type   | Required | Description                                       |
| ---------- | ------ | -------- | ------------------------------------------------- |
| enabled    | bool   | Yes      | Enable MaixCAM channel                            |
| endpoint   | string | Yes      | IP or endpoint of the MaixCAM device on the network |
| auth_token | string | No       | Authentication token for the device API (if set)  |
| allow_from | array  | No       | Allowed user ID list (empty array allows all)     |

## Setup Guide

1. Ensure your MaixCAM device is connected to the same local network as the Operator Gateway.
2. Obtain the IP address of the MaixCAM from its built-in display or router interface.
3. Configure the endpoint URL in your Operator config.
4. When Operator initializes, it will establish a connection with the MaixCAM API to listen for vision events, hardware triggers, and stream inferences.
