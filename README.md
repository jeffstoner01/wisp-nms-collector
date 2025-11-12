# WISP NMS Collector Agent

The collector agent runs on your local network and collects SNMP data from your devices, then sends it to the NMS web application via secure API calls.

## Features

- **Multi-vendor support**: MikroTik, Ubiquiti, and generic SNMP devices
- **Concurrent polling**: Collect from multiple devices simultaneously
- **Automatic device discovery**: Devices are automatically registered in the NMS
- **Metrics collection**: CPU, memory, bandwidth, uptime, temperature, and more
- **Heartbeat monitoring**: Regular check-ins with the NMS
- **Error handling**: Robust error handling and logging

## Installation

### Prerequisites

- Python 3.7 or higher
- Network access to your devices (SNMP enabled)
- Internet access to reach the NMS web application

### Setup

1. **Install Python dependencies:**

```bash
cd collector-agent
pip install -r requirements.txt
```

2. **Configure the collector:**

```bash
cp config.example.yaml config.yaml
```

3. **Edit `config.yaml`** with your settings:

```yaml
nms:
  url: "https://your-nms-url.com"
  api_key: "your-api-key-here"

devices:
  - name: "Main Router"
    ip: "192.168.1.1"
    vendor: "mikrotik"
    type: "router"
    deviceId: "main-router"
    snmp:
      community: "public"
      version: "2c"
```

### Getting Your API Key

1. Log into the NMS web application as an admin
2. Go to **Settings** → **Collector Agents**
3. Click **Create New Agent**
4. Copy the generated API key
5. Paste it into your `config.yaml`

## Usage

### Run the collector:

```bash
python collector.py
```

### Test mode (single collection cycle):

```bash
python collector.py --test
```

### Run with custom config file:

```bash
python collector.py --config /path/to/config.yaml
```

### Run as a background service (Linux):

```bash
nohup python collector.py > collector.log 2>&1 &
```

## Configuration

### NMS Settings

- `url`: The URL of your NMS web application
- `api_key`: Your collector agent API key (get from NMS admin panel)

### Collector Settings

- `interval`: How often to collect data (in seconds, default: 60)
- `max_workers`: Maximum concurrent device polls (default: 10)

### Device Configuration

Each device requires:

- `name`: Friendly name for the device
- `ip`: IP address of the device
- `vendor`: Device vendor (`mikrotik`, `ubiquiti`, or `generic`)
- `type`: Device type (`router`, `switch`, `ap`, `cpe`, `tower`, or `other`)
- `deviceId`: Unique identifier for the device
- `snmp`: SNMP configuration
  - `community`: SNMP community string (default: `public`)
  - `version`: SNMP version (`2c` or `3`)
  - `port`: SNMP port (default: 161)

### Example Device Configurations

**MikroTik Router:**
```yaml
- name: "Core Router"
  ip: "192.168.1.1"
  vendor: "mikrotik"
  type: "router"
  deviceId: "core-router-1"
  snmp:
    community: "public"
    version: "2c"
```

**Ubiquiti Access Point:**
```yaml
- name: "Tower AP 1"
  ip: "192.168.10.1"
  vendor: "ubiquiti"
  type: "ap"
  deviceId: "tower-ap-1"
  family: "LTU"
  snmp:
    community: "public"
    version: "2c"
```

**Generic Switch:**
```yaml
- name: "Distribution Switch"
  ip: "192.168.1.2"
  vendor: "generic"
  type: "switch"
  deviceId: "dist-switch-1"
  snmp:
    community: "public"
    version: "2c"
```

## Collected Metrics

### All Devices (via SNMP)
- System information (name, description, uptime)
- Interface statistics (bytes in/out, packets in/out)

### MikroTik Devices
- CPU usage
- Memory usage
- Temperature
- Voltage
- Interface details

### Ubiquiti Devices
- Signal strength
- Noise level
- TX power
- Frequency

## Troubleshooting

### Device not showing up in NMS

1. Check that the device IP is reachable from the collector
2. Verify SNMP is enabled on the device
3. Confirm the SNMP community string is correct
4. Check the collector logs: `tail -f collector.log`

### Connection errors

1. Verify the NMS URL is correct and accessible
2. Check that your API key is valid
3. Ensure firewall allows outbound HTTPS connections

### SNMP timeout errors

1. Increase SNMP timeout in the collector code (default: 5 seconds)
2. Check network latency to the device
3. Verify the device isn't overloaded

## Running as a System Service

### Linux (systemd)

Create `/etc/systemd/system/nms-collector.service`:

```ini
[Unit]
Description=WISP NMS Collector Agent
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/collector-agent
ExecStart=/usr/bin/python3 /path/to/collector-agent/collector.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable nms-collector
sudo systemctl start nms-collector
sudo systemctl status nms-collector
```

View logs:
```bash
sudo journalctl -u nms-collector -f
```

## Architecture

```
┌─────────────────────────────────────┐
│   Your Network                      │
│                                     │
│  ┌──────┐  ┌──────┐  ┌──────┐     │
│  │Router│  │  AP  │  │ CPE  │     │
│  └──┬───┘  └──┬───┘  └──┬───┘     │
│     │         │         │          │
│     └─────────┴─────────┘          │
│              │ SNMP                │
│     ┌────────▼────────┐            │
│     │ Collector Agent │            │
│     └────────┬────────┘            │
└──────────────┼─────────────────────┘
               │ HTTPS API
               ▼
    ┌──────────────────┐
    │   NMS Web App    │
    │   (Cloud/Server) │
    └──────────────────┘
```

## Support

For issues or questions:
1. Check the collector logs
2. Review the NMS admin panel for device status
3. Verify network connectivity between collector and devices

## License

Part of the WISP NMS project.
