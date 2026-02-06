# Testing Locally on Windows

Since Windows doesn't allow capturing ICMP packets sent to the local machine's own IP, we need to use **WSL (Windows Subsystem for Linux)** to test the framework on a single machine.

## Setup Instructions

### 1. Start the Controller (WSL)

**IMPORTANT**: The controller needs `sudo` to capture raw ICMP packets in Linux/WSL.

Run the controller in WSL:

```bash
cd /mnt/e/projects/ping-exfiltration/controller
sudo python3 web_server.py
```

The controller will start on `http://localhost:5050` (accessible from both WSL and Windows)

### 2. Find Your WSL Host IP

In PowerShell, run:

```powershell
ipconfig | findstr "vEthernet (WSL"
```

Look for the IPv4 address (e.g., `172.26.48.1`). This is the IP that WSL will use to reach your Windows host.

### 3. Run the Agent in WSL

Open WSL and navigate to the project:

```bash
cd /mnt/e/projects/ping-exfiltration/agents/python
```

Install dependencies:

```bash
sudo apt update
sudo apt install python3-pip -y
pip3 install scapy
```

Edit the agent to target your WSL host IP:

```bash
# Edit agent.py and change CONTROLLER_IP to your WSL host IP (e.g., 172.26.48.1)
nano agent.py
```

Run the agent with sudo (required for raw sockets):

```bash
sudo python3 agent.py
```

### 4. Verify Connection

1. Open `http://localhost:5050` in your browser
2. You should see the agent appear in the "Active Agents" section
3. Try sending a command like `whoami` or `pwd`

## Troubleshooting

### Agent Not Appearing

1. **Check WSL Host IP**: Make sure the agent is targeting the correct IP (the vEthernet WSL adapter IP)
2. **Run as Admin**: Both controller and agent need elevated privileges
3. **Check Logs**: Look at `controller.log` for any ICMP packet captures
4. **Windows Firewall**: Temporarily disable to test if it's blocking ICMP

### WSL Not Installed

If you don't have WSL, install it:

```powershell
wsl --install
```

Then restart your computer and follow the setup wizard.
