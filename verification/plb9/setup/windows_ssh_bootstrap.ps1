# =============================================================
# AIPET X -- PLB-9 Windows VM SSH bootstrap
#
# Run ONCE on the Windows VM as Administrator. Sets up OpenSSH Server,
# creates the local user 'aipet' if missing, installs the WSL public key
# with the strict ACLs sshd requires.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\windows_ssh_bootstrap.ps1 `
#       -PubKeyPath C:\Temp\wsl_key.pub
#
# Optional:
#   -AipetPassword <SecureString>   skip the password prompt (CI use only)
# =============================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $PubKeyPath,

    [SecureString] $AipetPassword
)

$ErrorActionPreference = "Stop"

function Write-Step($msg)    { Write-Host "[..] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)      { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Warn($msg)    { Write-Host "[!!] $msg" -ForegroundColor Yellow }
function Write-Fail($msg)    { Write-Host "[XX] $msg" -ForegroundColor Red }

# --- 0. Sanity ---------------------------------------------
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Fail "This script needs to run as Administrator."
    Write-Host "    Right-click PowerShell -> Run as administrator, then re-run."
    exit 1
}

if (-not (Test-Path $PubKeyPath)) {
    Write-Fail "Public key not found at: $PubKeyPath"
    exit 1
}

$pubKey = (Get-Content $PubKeyPath -Raw).Trim()
if (-not ($pubKey -match '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+) ')) {
    Write-Fail "File at $PubKeyPath does not look like an SSH public key."
    exit 1
}

Write-Ok "Public key loaded ($($pubKey.Length) chars)"

# --- 1. Install OpenSSH Server -----------------------------
Write-Step "Installing OpenSSH Server feature"
$cap = Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction SilentlyContinue
if ($cap.State -ne "Installed") {
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
    Write-Ok "OpenSSH Server feature installed"
} else {
    Write-Ok "OpenSSH Server already installed"
}

# --- 2. Service start + autorun ----------------------------
Write-Step "Starting and enabling sshd service"
Start-Service sshd -ErrorAction SilentlyContinue
Set-Service -Name sshd -StartupType Automatic
Write-Ok "sshd is running and set to Automatic start"

# --- 3. Firewall rule --------------------------------------
Write-Step "Opening firewall on TCP 22"
$existingRule = Get-NetFirewallRule -Name sshd -ErrorAction SilentlyContinue
if (-not $existingRule) {
    New-NetFirewallRule -Name sshd -DisplayName "OpenSSH Server (sshd)" `
        -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
    Write-Ok "Firewall rule created"
} else {
    Write-Ok "Firewall rule already present"
}

# --- 4. aipet local user -----------------------------------
Write-Step "Ensuring local user 'aipet' exists"
$user = Get-LocalUser -Name aipet -ErrorAction SilentlyContinue
if (-not $user) {
    if (-not $AipetPassword) {
        $AipetPassword = Read-Host -AsSecureString -Prompt "Set a password for the new 'aipet' Windows account"
    }
    New-LocalUser -Name aipet -Password $AipetPassword `
        -FullName "AIPET Verification" -Description "PLB-9 verification account" `
        -PasswordNeverExpires -AccountNeverExpires | Out-Null
    Write-Ok "User 'aipet' created"
} else {
    Write-Ok "User 'aipet' already exists"
}

# Add aipet to Administrators so it can run sc.exe / Get-Service / installer.
# This also means we use administrators_authorized_keys (Windows OpenSSH quirk).
Add-LocalGroupMember -Group "Administrators" -Member aipet -ErrorAction SilentlyContinue
Write-Ok "aipet is in the Administrators group (required for service tests)"

# --- 5. Profile + .ssh dir ---------------------------------
Write-Step "Ensuring %USERPROFILE%\.ssh exists for aipet"
$aipetProfile = "C:\Users\aipet"
if (-not (Test-Path $aipetProfile)) {
    # Profile is created on first interactive login. Trigger creation by
    # running a noop process as the user. Fall back to manual mkdir if that
    # fails (uncommon -- but keeps the script forward-progress).
    try {
        $cred = New-Object System.Management.Automation.PSCredential("aipet", $AipetPassword)
        Start-Process -FilePath cmd.exe -ArgumentList "/c","exit" `
            -Credential $cred -LoadUserProfile -Wait `
            -WindowStyle Hidden -ErrorAction SilentlyContinue
    } catch { }
    if (-not (Test-Path $aipetProfile)) { New-Item -ItemType Directory -Path $aipetProfile | Out-Null }
}
$sshDir = Join-Path $aipetProfile ".ssh"
if (-not (Test-Path $sshDir)) { New-Item -ItemType Directory -Path $sshDir | Out-Null }
Write-Ok "$sshDir present"

# --- 6. authorized_keys (per-user) -------------------------
Write-Step "Installing public key into per-user authorized_keys"
$authKeys = Join-Path $sshDir "authorized_keys"
if (Test-Path $authKeys) {
    $existing = (Get-Content $authKeys -Raw -ErrorAction SilentlyContinue)
    if ($existing -and ($existing -match [regex]::Escape($pubKey))) {
        Write-Ok "Public key already present"
    } else {
        Add-Content -Path $authKeys -Value $pubKey
        Write-Ok "Public key appended to existing authorized_keys"
    }
} else {
    Set-Content -Path $authKeys -Value $pubKey -Encoding ASCII
    Write-Ok "authorized_keys created with public key"
}

# Strict ACLs -- sshd will refuse keys with permissive ACLs
Write-Step "Tightening ACLs on authorized_keys"
icacls $authKeys /inheritance:r | Out-Null
icacls $authKeys /grant:r "aipet:F" "SYSTEM:F" "Administrators:F" | Out-Null
icacls $authKeys /remove "Authenticated Users" | Out-Null
icacls $authKeys /remove "Users" | Out-Null
takeown /F $authKeys /A | Out-Null
Write-Ok "ACLs locked down"

# --- 7. administrators_authorized_keys (because aipet is admin) ---
# Windows OpenSSH on Server-class behaviour: when the connecting user is in
# Administrators, sshd ignores ~/.ssh/authorized_keys and ONLY reads
# %ProgramData%\ssh\administrators_authorized_keys. Matters here.
Write-Step "Mirroring key into administrators_authorized_keys"
$admKeysDir = "$env:ProgramData\ssh"
$admKeys = Join-Path $admKeysDir "administrators_authorized_keys"
if (-not (Test-Path $admKeys)) { New-Item -ItemType File -Path $admKeys -Force | Out-Null }
$admExisting = (Get-Content $admKeys -Raw -ErrorAction SilentlyContinue)
if (-not ($admExisting -and ($admExisting -match [regex]::Escape($pubKey)))) {
    Add-Content -Path $admKeys -Value $pubKey
    Write-Ok "Key appended to administrators_authorized_keys"
} else {
    Write-Ok "Key already in administrators_authorized_keys"
}

icacls $admKeys /inheritance:r | Out-Null
icacls $admKeys /grant:r "Administrators:F" "SYSTEM:F" | Out-Null
icacls $admKeys /remove "Authenticated Users" "Users" | Out-Null
Write-Ok "administrators_authorized_keys ACLs locked"

# --- 8. sshd_config sanity ---------------------------------
Write-Step "Verifying sshd_config allows public-key auth"
$cfg = "$env:ProgramData\ssh\sshd_config"
if (Test-Path $cfg) {
    $cfgText = Get-Content $cfg -Raw
    if ($cfgText -match '(?m)^\s*PubkeyAuthentication\s+no\b') {
        Write-Warn "sshd_config explicitly DISABLES public-key auth. Patching."
        $cfgText = [regex]::Replace($cfgText, '(?m)^\s*PubkeyAuthentication\s+no\b', 'PubkeyAuthentication yes')
        Set-Content -Path $cfg -Value $cfgText -Encoding ASCII
    }
} else {
    Write-Warn "sshd_config not found at $cfg (continuing -- OpenSSH defaults)"
}

# --- 9. Restart sshd to pick up changes --------------------
Write-Step "Restarting sshd to apply key + ACL changes"
Restart-Service sshd
Write-Ok "sshd restarted"

# --- 10. Summary -------------------------------------------
$ip = (Get-NetIPAddress -AddressFamily IPv4 |
       Where-Object { $_.InterfaceAlias -notmatch 'Loopback' -and $_.IPAddress -notlike '169.254.*' } |
       Select-Object -ExpandProperty IPAddress -First 1)

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  SSH bootstrap complete." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "    From WSL, test with:" -ForegroundColor Gray
Write-Host "      ssh aipet@$ip 'whoami'" -ForegroundColor White
Write-Host ""
Write-Host "    Expected output:  aipet" -ForegroundColor Gray
Write-Host ""
Write-Host "    If it asks for a password, ACLs on authorized_keys or"   -ForegroundColor Yellow
Write-Host "    administrators_authorized_keys are still wrong. Re-run"  -ForegroundColor Yellow
Write-Host "    this script -- the icacls steps are idempotent."         -ForegroundColor Yellow
Write-Host ""
exit 0
