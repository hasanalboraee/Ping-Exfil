# 📡 Ping Exfiltration Framework
![Status](https://img.shields.io/badge/Status-Operational-brightgreen)
![Python](https://img.shields.io/badge/Python-3.x-blue)
![Go](https://img.shields.io/badge/Go-1.20+-cyan)
![Platform](https://img.shields.io/badge/Platform-Windows%20|%20Linux-lightgrey)

**A covert ICMP-only Command & Control framework for Red Team operations.**
A covert Command & Control (C2) framework that uses ICMP packets (Ping) for communication. This project allows you to execute commands and exfiltrate files from agents behind strict firewalls that allow ICMP traffic.

## Features

- **Covert Communication:** Uses standard ICMP Echo Request/Reply packets.
- **Cross-Platform Agents:**
  - **Python:** Full-featured (Command Execution, File Exfiltration, Persistence, Shell). Works on Windows & Linux.
  - **Go:** High-performance Beacon & Exfiltration.
  - **Bash/Batch:** Lightweight beacons for constrained environments.
- **Web Dashboard:** Real-time agent status, interactive shell, and live log monitoring.
- **Resilient:** Agents automatically detect the correct network interface for communication.

## Architecture

1.  **Controller:** A Python Flask server that listens for ICMP packets, manages agents, and serves the Web UI.
2.  **Agents:** Scripts running on target machines that beacon to the controller and execute commands embedded in ICMP replies.

## Prerequisites

- **Controller:**
  - Linux (preferred) or Windows with Npcap.
  - Python 3.x
  - Root/Administrator privileges (for raw sockets).
- **Agents:**
  - Python 3 (for Python agent) or Go (for Go agent).
  - Administrator/Root privileges (usually required for creating raw ICMP packets).

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-repo/ping-exfiltration.git
    cd ping-exfiltration
    ```

2.  **Install Controller dependencies:**
    ```bash
    cd controller
    pip install -r requirements.txt
    ```

## Usage

### 1. Start the Controller

Run the controller on your C2 server (requires `sudo` for socket access):

```bash
sudo python3 web_server.py
```

- Web UI: http://localhost:5050
- Config: `controller/config.json` (Default interface: 0.0.0.0, Port: 5050)

### 2. Configure Agents

Edit the `CONTROLLER_IP` variable in your desired agent script to match your controller's IP address.

- **Python:** `agents/python/agent.py`
- **Go:** `agents/go/agent.go`
- **Bash:** `agents/bash/agent.sh`
- **Batch:** `agents/batch/agent.bat`

### 3. Run an Agent

**Python Agent (Recommended):**
```bash
# Windows or Linux
sudo python3 agent.py
# Or on Windows (Admin)
python agent.py
```

**Bash Agent:**
```bash
sudo ./agent.sh
```

### 4. Interactions

1.  Open the Web UI (`http://localhost:5050`).
2.  Wait for agents to appear in the "Agents" list.
3.  Click an agent to select it.
4.  Type commands in the console (`ls`, `whoami`, `cat /etc/passwd`).

## Troubleshooting

-   **No Agents Appearing?**
    -   Ensure Controller IP is correct in agent scripts.
    -   Ensure ICMP (Ping) is allowed through firewalls.
    -   On Windows, ensure Npcap is installed if using packet sniffing features.
-   **Commands Not Executing?**
    -   Run the controller in verbose mode to see packet logs.
    -   Ensure the agent has privileges to execute commands.
    -   If using WSL/Virtual Machines, ensure network bridging is correctly configured.

## Disclaimer

This project is for educational purposes and authorized security testing only. Misuse of this software is strictly prohibited.
