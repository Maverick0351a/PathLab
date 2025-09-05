<#
Launch PathLab local test environment on Windows.
- Picks free high ports for upstream TLS server and admin if requested.
- Starts self-signed upstream (example/upstream.go) with chosen port.
- Starts PathLab pointing at that upstream.
- Provides convenience curl commands.
#>
param(
    [int]$UpstreamPort = 0,
    [int]$ListenPort = 10443,
    [int]$AdminPort = 0
)

function Get-FreePort {
    param([int]$Start = 15000, [int]$End = 20000)
    for ($p=$Start; $p -le $End; $p++) {
        if (-not (netstat -ano | Select-String ":$p")) { return $p }
    }
    throw 'No free port found in range.'
}

if ($UpstreamPort -eq 0) { $UpstreamPort = Get-FreePort }
if ($AdminPort -eq 0) {
    do { $AdminPort = Get-FreePort } while ($AdminPort -eq $UpstreamPort)
}

Write-Host "UpstreamPort=$UpstreamPort ListenPort=$ListenPort AdminPort=$AdminPort"

$windowsDir = Split-Path -Parent $MyInvocation.MyCommand.Path          # .../scripts/windows
$scriptsDir = Split-Path $windowsDir                                   # .../scripts
$repoRoot = Split-Path $scriptsDir                                     # .../pathlab
$example = Join-Path $repoRoot 'example'
$binPath = Join-Path $repoRoot 'bin'
$upstreamSrc = Join-Path $example 'upstream.go'
$upstreamExe = Join-Path $example 'upstream-flex.exe'

if (-not (Test-Path $upstreamExe)) {
    Write-Host 'Building upstream-flex.exe...'
    Push-Location $example
    go build -o upstream-flex.exe upstream.go
    Pop-Location
}

Write-Host 'Starting upstream...' ;
Start-Process -FilePath $upstreamExe -ArgumentList '-port',"$UpstreamPort" -WindowStyle Hidden
Start-Sleep -Seconds 2

Write-Host 'Starting PathLab...' ;
$pathlabExe = Join-Path $binPath 'pathlab.exe'
if (-not (Test-Path $pathlabExe)) { throw "Missing $pathlabExe. Build pathlab first." }
Start-Process -FilePath $pathlabExe -ArgumentList '-listen',":$ListenPort",'-upstream',"127.0.0.1:$UpstreamPort",'-admin',":$AdminPort" -WindowStyle Hidden
Start-Sleep -Seconds 2

Write-Host "Environment started. Test with:" -ForegroundColor Green
Write-Host " curl -k https://localhost:$ListenPort/"
Write-Host " curl http://localhost:$AdminPort/impair/status"
Write-Host ' Profiles:'
Write-Host "  curl -XPOST http://localhost:$AdminPort/impair/apply?profile=ABORT_AFTER_CH"
Write-Host "  curl -XPOST http://localhost:$AdminPort/impair/apply?profile=MTU1300_BLACKHOLE&threshold_bytes=1300"
Write-Host "  curl -XPOST http://localhost:$AdminPort/impair/apply?profile=LATENCY_50MS_JITTER_10&latency_ms=80&jitter_ms=20"
Write-Host "  curl -XPOST http://localhost:$AdminPort/impair/apply?profile=BANDWIDTH_1MBPS&bandwidth_kbps=500"
Write-Host "  curl -XPOST http://localhost:$AdminPort/impair/clear"
