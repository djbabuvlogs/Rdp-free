<#
  setup-rdp-tailscale.ps1
  Usage (Admin PowerShell):
    Set-ExecutionPolicy Bypass -Scope Process -Force
    $env:TAILSCALE_AUTH_KEY = "tskey-auth-kdws9gb1xg11CNTRL-bdT4fso6B91hFM3vg8NV81vGh7SrgZBh"   # OR pass interactively below
    .\setup-rdp-tailscale.ps1
#>

# --------- Configuration ----------
$Username = "RDP"
$CredFilePath = "C:\Users\Public\rdp_creds.txt"   # change path if you want
$TailscaleMsiUrl = "https://pkgs.tailscale.com/stable/tailscale-setup-1.82.0-amd64.msi"
$AllowRdpFrom = "100.64.0.0/10"  # Tailscale DERP range (restricts RDP to tailscale)
# ---------------------------------

function Ensure-Admin {
    if (-not ([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))) {
        Write-Error "This script must be run as Administrator."
        exit 1
    }
}

Ensure-Admin

# ----- Enable Remote Desktop (keep NLA enabled by default) -----
# Set fDenyTSConnections = 0 to enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0 -Force

# Recommended: keep NLA (UserAuthentication) = 1 and SecurityLayer = 2 for security
# If you *must* disable NLA for specific legacy clients, set UserAuthentication=0 and SecurityLayer=0
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1 -Force
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "SecurityLayer" -Value 2 -Force

# Restart service to apply changes
Restart-Service -Name TermService -Force

# ----- Create a strong local user -----
if (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue) {
    Write-Host "User '$Username' already exists. Skipping creation."
} else {
    # build a strong random password (16+ chars)
    $pw = [System.Web.Security.Membership]::GeneratePassword(20,4)
    # Convert to secure string and create user
    $securePass = ConvertTo-SecureString $pw -AsPlainText -Force
    New-LocalUser -Name $Username -Password $securePass -AccountNeverExpires -PasswordNeverExpires
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Username
    Add-LocalGroupMember -Group "Administrators" -Member $Username

    # Save credentials to a local file with restricted ACL
    $credText = "Username: $Username`nPassword: $pw`nGeneratedAt: $(Get-Date -Format 'u')"
    $credText | Out-File -FilePath $CredFilePath -Encoding UTF8 -Force

    # Restrict file permissions: allow only Administrators
    icacls $CredFilePath /inheritance:r /grant:r "Administrators:F" /remove "Users" | Out-Null

    Write-Host "Created user '$Username' and saved credentials to $CredFilePath"
}

# ----- Install Tailscale if not installed -----
$tailscaleExe = Join-Path $env:ProgramFiles "Tailscale\tailscale.exe"
if (-not (Test-Path $tailscaleExe)) {
    Write-Host "Downloading and installing Tailscale..."
    $installerPath = Join-Path $env:TEMP "tailscale.msi"
    Invoke-WebRequest -Uri $TailscaleMsiUrl -OutFile $installerPath -UseBasicParsing
    Start-Process msiexec.exe -ArgumentList "/i", "`"$installerPath`"", "/quiet", "/norestart" -Wait
    Remove-Item $installerPath -Force
} else {
    Write-Host "Tailscale already installed."
}

# ----- Start/Up Tailscale -----
# Acquire auth key from env or ask interactively
if (-not $env:TAILSCALE_AUTH_KEY) {
    Write-Host "No environment variable TAILSCALE_AUTH_KEY found."
    $authKey = Read-Host -Prompt "Enter Tailscale auth key (or paste a machine key)"
} else {
    $authKey = $env:TAILSCALE_AUTH_KEY
}

# Set a hostname for the machine on tailscale
$hostname = "vps-$(Get-Random -Maximum 99999)"

# Bring up tailscale
& "$tailscaleExe" up --authkey=$authKey --hostname=$hostname | Out-Null

# Wait a bit and get the IPv4 address assigned by tailscale
$tsIP = $null
$retries = 0
while (-not $tsIP -and $retries -lt 12) {
    Start-Sleep -Seconds 3
    $ips = & "$tailscaleExe" ip -4 2>$null
    # tailscale ip -4 prints e.g. "100.x.x.x" possibly multiple lines; pick first non-loopback
    $tsIP = ($ips -split "`n" | Where-Object { $_ -match '^\d+\.' } | Select-Object -First 1).Trim()
    $retries++
}

if (-not $tsIP) {
    Write-Error "Tailscale IP not assigned. Check 'tailscale status' or your auth key."
    exit 1
}
Write-Host "Tailscale IPv4: $tsIP"

# ----- Firewall: allow RDP only from Tailscale address range -----
# Remove prior rule if exists
netsh advfirewall firewall delete rule name="RDP-Tailscale" 2>$null | Out-Null

# Add new rule restricting remote IPs to Tailscale subnet
netsh advfirewall firewall add rule name="RDP-Tailscale" dir=in action=allow protocol=TCP localport=3389 remoteip=$AllowRdpFrom

Write-Host "Firewall rule 'RDP-Tailscale' added: port 3389 allowed from $AllowRdpFrom"

# ----- Test RDP connectivity locally (TCP test) -----
$test = Test-NetConnection -ComputerName $tsIP -Port 3389 -InformationLevel Quiet
if ($test) {
    Write-Host "TCP test succeeded to $tsIP:3389"
} else {
    Write-Warning "TCP test failed to $tsIP:3389. Ensure Tailscale is connected and firewall rules correct."
}

# ----- Summary for user -----
Write-Host ""
Write-Host "=== RDP ACCESS INFO ==="
Write-Host "Tailscale IP: $tsIP"
Write-Host "Username: $Username"
Write-Host "Credentials file (local): $CredFilePath"
Write-Host "You can connect via RDP to $tsIP (use Tailscale network)."
Write-Host "========================"