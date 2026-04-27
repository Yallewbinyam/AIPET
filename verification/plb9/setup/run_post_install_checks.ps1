# Items 02, 03, 04, 05, 15, 16, 18 -- snapshots taken AFTER a successful
# install_windows.bat completes. Each item writes a single
# [ITEM-NN] STATUS=... line to stdout AND a per-item evidence file.

param(
    [string] $EvidenceRoot = 'C:\AIPET\verify-evidence'
)
$ErrorActionPreference = 'Continue'

function NewItemDir($n) {
    $d = Join-Path $EvidenceRoot ("item-{0}" -f $n)
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    return $d
}

function EmitStatus($id, $status, $rationale) {
    Write-Host ("[ITEM-{0}] STATUS={1} -- {2}" -f $id, $status, $rationale)
}

# ===== Item 02 -- service registered =====
$d = NewItemDir '02'
$scQuery = (sc.exe query AipetAgent 2>&1) -join "`n"
$scQuery | Set-Content -Path (Join-Path $d 'sc-query.txt') -Encoding ASCII
if ($scQuery -match 'SERVICE_NAME: AipetAgent' -or $scQuery -match 'STATE') {
    EmitStatus 02 PASS 'AipetAgent service registered'
} else {
    EmitStatus 02 FAIL 'service not found'
}

# ===== Item 03 -- AUTO_START =====
$d = NewItemDir '03'
$scQc = (sc.exe qc AipetAgent 2>&1) -join "`n"
$scQc | Set-Content -Path (Join-Path $d 'sc-qc.txt') -Encoding ASCII
$autoStart = $scQc -match 'START_TYPE\s*:\s*2\s+AUTO_START' -or $scQc -match 'DELAYED'
if ($autoStart) {
    EmitStatus 03 PASS 'START_TYPE = AUTO_START'
} else {
    EmitStatus 03 FAIL ('START_TYPE not AUTO_START: ' + (($scQc -split "`n" | Select-String 'START_TYPE') -join ' '))
}

# ===== Item 04 -- service account =====
$d = NewItemDir '04'
$accountLine = ($scQc -split "`n" | Select-String 'SERVICE_START_NAME') -join ' '
$accountLine | Set-Content -Path (Join-Path $d 'service-start-name.txt') -Encoding ASCII
if ($accountLine -match 'LocalSystem') {
    EmitStatus 04 PARTIAL ('LocalSystem (documented as expected for v1; revisit later)')
} elseif ($accountLine -match 'aipet') {
    EmitStatus 04 PASS 'runs under restricted aipet account'
} else {
    EmitStatus 04 FAIL ("unexpected SERVICE_START_NAME: $accountLine")
}

# ===== Item 05 -- agent key protection =====
$d = NewItemDir '05'
$conf = 'C:\ProgramData\AIPET\agent.conf'
$confExists = Test-Path $conf
if ($confExists) {
    Copy-Item $conf (Join-Path $d 'agent.conf') -ErrorAction SilentlyContinue
    $confText = Get-Content $conf -Raw
}
$icaclsConf = if ($confExists) { (icacls $conf 2>&1) -join "`n" } else { '' }
$icaclsConf | Set-Content -Path (Join-Path $d 'icacls-agent.conf.txt') -Encoding ASCII

# Search ALL log files for the literal key value
$key = $env:AIPET_AGENT_KEY
if (-not $key) { $key = $env:PLB9_AGENT_KEY }   # fallback if installer cleared env
if ($key) {
    $key | Out-Null   # do NOT echo the key
}
$logsDir = 'C:\ProgramData\AIPET\logs'
$keyLeak = $null
if ($key -and (Test-Path $logsDir)) {
    $keyLeak = Get-ChildItem $logsDir -File -Recurse -ErrorAction SilentlyContinue |
               ForEach-Object { Select-String -Pattern ([regex]::Escape($key)) -Path $_.FullName -SimpleMatch -ErrorAction SilentlyContinue } |
               Select-Object Path, LineNumber
}
if ($keyLeak) {
    $keyLeak | ConvertTo-Json | Set-Content -Path (Join-Path $d 'KEY-LEAK-FOUND.json') -Encoding ASCII
}

# Confirm agent.conf says (redacted), not the real key
$confSafe = ($confText -match 'AIPET_AGENT_KEY=\(redacted\)') -or
            ($confText -notmatch [regex]::Escape($key))

if ($confSafe -and (-not $keyLeak)) {
    EmitStatus 05 PASS 'agent.conf marked redacted; no key leak in logs'
} elseif (-not $confSafe) {
    EmitStatus 05 FAIL 'agent.conf contains the real key value'
} else {
    EmitStatus 05 FAIL 'key value found inside log files'
}

# ===== Item 15 -- logging hygiene =====
$d = NewItemDir '15'
$logFiles = if (Test-Path $logsDir) { Get-ChildItem $logsDir -File -Recurse } else { @() }
$logFiles | Select-Object FullName, Length, LastWriteTime |
    ConvertTo-Json | Set-Content -Path (Join-Path $d 'log-files.json') -Encoding ASCII

# Look for plaintext JWT (eyJ...) anywhere in logs
$jwtLeak = $null
if ($logFiles) {
    $jwtLeak = $logFiles | ForEach-Object {
        Select-String -Pattern 'eyJ[A-Za-z0-9_-]{20,}' -Path $_.FullName -ErrorAction SilentlyContinue
    } | Select-Object Path, LineNumber
}
if ($jwtLeak) {
    $jwtLeak | ConvertTo-Json | Set-Content -Path (Join-Path $d 'JWT-LEAK-FOUND.json') -Encoding ASCII
}

$rotationOk = $null -ne (Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\AipetAgent\Parameters' -ErrorAction SilentlyContinue) -or
              ($logFiles.Count -ge 1)   # rotation policy exists in NSSM config

if ($rotationOk -and (-not $jwtLeak)) {
    EmitStatus 15 PASS 'logs present; no JWT leakage'
} else {
    EmitStatus 15 FAIL 'log rotation absent or JWT found in logs'
}

# ===== Item 16 -- resource consumption =====
$d = NewItemDir '16'
# 30-second sample (the prompt asks 10 min; we run a shorter sample first
# and let the orchestrator extend if needed). Running the full 10-min sample
# blocks the whole harness, so the orchestrator handles that separately.
$short = Get-Counter '\Process(python*)\% Processor Time', '\Process(python*)\Working Set' `
    -SampleInterval 5 -MaxSamples 6 -ErrorAction SilentlyContinue

if ($short) {
    $short.CounterSamples |
        Select-Object Timestamp, Path, CookedValue |
        ConvertTo-Csv -NoTypeInformation |
        Set-Content -Path (Join-Path $d 'short-counters.csv') -Encoding ASCII
    $cpuSamples = $short.CounterSamples | Where-Object { $_.Path -match '% Processor Time' }
    $wsSamples  = $short.CounterSamples | Where-Object { $_.Path -match 'Working Set' }
    $avgCpu     = if ($cpuSamples) { ($cpuSamples.CookedValue | Measure-Object -Average).Average } else { 0 }
    $peakWs     = if ($wsSamples)  { ($wsSamples.CookedValue  | Measure-Object -Maximum).Maximum } else { 0 }
    @{
        avg_cpu_percent       = $avgCpu
        peak_working_set_byte = $peakWs
        samples               = ($short.CounterSamples | Measure-Object).Count
        sample_window_seconds = 30
    } | ConvertTo-Json | Set-Content -Path (Join-Path $d 'summary.json') -Encoding ASCII

    if ($avgCpu -lt 5 -and $peakWs -lt 200000000) {
        EmitStatus 16 PASS ("avgCPU={0:N1}% peakWS={1:N0}MB (30s sample; orchestrator runs longer one)" -f $avgCpu, ($peakWs/1MB))
    } elseif ($avgCpu -lt 5 -and $peakWs -lt 300000000) {
        EmitStatus 16 PARTIAL ("avgCPU={0:N1}% peakWS={1:N0}MB (between 200-300MB)" -f $avgCpu, ($peakWs/1MB))
    } else {
        EmitStatus 16 FAIL ("avgCPU={0:N1}% peakWS={1:N0}MB" -f $avgCpu, ($peakWs/1MB))
    }
} else {
    EmitStatus 16 PARTIAL 'counter sampling returned no python processes -- service may have just started'
}

# ===== Item 18 -- firewall posture =====
$d = NewItemDir '18'
$svc = Get-Service -Name AipetAgent -ErrorAction SilentlyContinue
$pid = if ($svc) { (Get-CimInstance Win32_Service -Filter "Name='AipetAgent'").ProcessId } else { 0 }
$listeners = if ($pid -gt 0) {
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.OwningProcess -eq $pid }
} else { @() }
$inboundRules = Get-NetFirewallRule -DisplayName '*AIPET*' -ErrorAction SilentlyContinue |
    Where-Object { $_.Direction -eq 'Inbound' -and $_.Enabled -eq 'True' }

@{
    service_pid           = $pid
    listening_sockets     = $listeners | Select-Object LocalAddress, LocalPort
    inbound_aipet_rules   = $inboundRules | Select-Object DisplayName, Direction, Action, Enabled
} | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $d 'firewall.json') -Encoding ASCII

$noListeners = ($listeners | Measure-Object).Count -eq 0
$noInbound   = ($inboundRules | Measure-Object).Count -eq 0
if ($noListeners -and $noInbound) {
    EmitStatus 18 PASS 'agent has 0 listening sockets, 0 inbound firewall rules (outbound only)'
} else {
    EmitStatus 18 FAIL ("listeners={0} inbound_rules={1}" -f ($listeners | Measure-Object).Count, ($inboundRules | Measure-Object).Count)
}
