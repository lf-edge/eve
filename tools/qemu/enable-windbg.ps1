# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# enable-windbg.ps1 - Configure a Windows guest for kernel debugging
# over a serial port that EVE's pillar exposes as a unix socket on the
# host (`/run/hypervisor/kvm/<domain>/cons` by default — pillar wires
# it via virtio-serial, but the same socket is reachable from the
# operator's machine over `ssh -L`).
#
# Run this once, in an elevated PowerShell prompt, inside the Windows
# guest you want to debug.  After running it and rebooting the guest,
# WinDbg can attach to the host socket and break in at any time.
#
# Two transports are supported:
#
#  * net   (default) — kdnet, UDP-based.  Best perf, but the Windows
#                      guest must be able to reach the WinDbg host on
#                      a chosen UDP port.  Works through the EVE NI's
#                      NAT egress.
#
#  * serial          — debug over COM1.  No network needed; qemu's
#                      serial port (a unix socket on the host) carries
#                      the kdbg traffic.  Operator forwards the socket
#                      with `ssh -L 1234:/run/hypervisor/kvm/<dom>/cons`
#                      and connects WinDbg to TCP 1234.
#
# Both transports require Windows to be rebooted once after the
# bcdedit changes take effect.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('net', 'serial')]
    [string]$Transport,

    # Required for -Transport net: IP of the WinDbg host the Windows
    # guest will send debug packets to.
    [string]$HostIP,

    # Required for -Transport net: UDP port the WinDbg host listens on.
    [int]$Port = 50000,

    # Required for -Transport net: 4-part dotted key, e.g. "1.2.3.4".
    # The WinDbg host must be launched with the SAME key.
    [string]$Key,

    # Optional for -Transport serial: COM port number (1 -> COM1).
    [int]$ComPort = 1,

    # Optional for -Transport serial: baud rate.
    [int]$BaudRate = 115200
)

function Require-Admin {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run from an elevated PowerShell prompt (Run as Administrator)."
    }
}

Require-Admin

Write-Host "Enabling kernel debug..."
& bcdedit /debug on | Out-Null

if ($Transport -eq 'net') {
    if (-not $HostIP -or -not $Key) {
        throw "-Transport net requires -HostIP and -Key.  Example:
    .\enable-windbg.ps1 -Transport net -HostIP 192.0.2.5 -Port 50000 -Key 1.2.3.4"
    }
    Write-Host "Configuring kdnet to $HostIP`:$Port (UDP) with key '$Key'..."
    & bcdedit /dbgsettings net "hostip:$HostIP" "port:$Port" "key:$Key" | Out-Null
}
else {
    Write-Host "Configuring serial debug on COM$ComPort @ $BaudRate baud..."
    & bcdedit /dbgsettings serial "debugport:$ComPort" "baudrate:$BaudRate" | Out-Null
}

Write-Host ""
Write-Host "Current bcdedit /dbgsettings:"
& bcdedit /dbgsettings

Write-Host ""
Write-Host "Done.  Reboot Windows so the changes take effect."
Write-Host ""
if ($Transport -eq 'net') {
    Write-Host "On the WinDbg host, launch with:"
    Write-Host "  windbg.exe -k net:port=$Port,key=$Key"
}
else {
    Write-Host "On the EVE host, forward qemu's console socket to a TCP port:"
    Write-Host "  socat TCP-LISTEN:5555,reuseaddr,fork UNIX-CONNECT:/run/hypervisor/kvm/<domain>/cons"
    Write-Host "Then from the operator's machine:"
    Write-Host "  ssh -L 5555:<eve-node>:5555 <eve-node>"
    Write-Host "  windbg.exe -k com:pipe,port=\\.\pipe\some-pipe,baud=$BaudRate,reconnect"
    Write-Host "(or use WinDbg Preview's 'Attach to kernel' -> COM with these settings)"
}
