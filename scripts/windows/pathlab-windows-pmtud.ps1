<#
.SYNOPSIS
  Simulate a PMTUD black-hole on Windows without drivers.

.DESCRIPTION
  Lowers MTU on a selected interface and blocks ICMPv4 "Fragmentation Needed" (Type 3, Code 4).
  This causes oversized packets with DF to be dropped silently, reproducing the black-hole symptom.

.USAGE
  Run as Administrator, then revert after tests.

.PARAMETERS
  -Interface "vEthernet (WSL)"
  -MTU 1300
#>

param(
  [string]$Interface = "",
  [int]$MTU = 1300,
  [switch]$Revert
)

function Ensure-Admin {
  $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object System.Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run in elevated PowerShell"
  }
}

Ensure-Admin

if ($Revert) {
  if ($Interface) {
    netsh interface ipv4 set subinterface "$Interface" mtu=1500 store=active
  }
  netsh advfirewall firewall delete rule name="Block ICMP Frag Needed"
  Write-Host "Reverted MTU and firewall rule."
  exit 0
}

if (-not $Interface) {
  Write-Host "Available interfaces:"
  Get-NetIPInterface | Select-Object InterfaceAlias, AddressFamily, NlMtu
  throw "Specify -Interface 'Name'"
}

Write-Host "Setting MTU $MTU on interface '$Interface'"
& netsh interface ipv4 set subinterface "$Interface" mtu=$MTU store=active

Write-Host "Blocking ICMPv4 Fragmentation Needed (Type 3, Code 4)"
netsh advfirewall firewall add rule name="Block ICMP Frag Needed" dir=in action=block protocol=icmpv4:3,4

Write-Host "Done. To revert: .\pathlab-windows-pmtud.ps1 -Interface '$Interface' -Revert"
