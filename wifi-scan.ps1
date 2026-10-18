param(
    [string]$OutputPath = (Join-Path ([Environment]::GetFolderPath("Desktop")) "wifi-scan.json")
)

$ErrorActionPreference = "Stop"

function Get-NetshValue {
    param([string[]]$Lines, [string]$Label)
    foreach ($line in $Lines) {
        if ($line -match "^\s*$([regex]::Escape($Label))\s*:\s*(.+?)\s*$") {
            return $Matches[1].Trim()
        }
    }
    return $null
}

function Get-SignalPercent {
    param([string]$Value)
    if ($Value -match "(\d{1,3})") {
        return [Math]::Max(0, [Math]::Min(100, [int]$Matches[1]))
    }
    return 0
}

$lines = @(netsh wlan show interfaces 2>&1 | ForEach-Object { [string]$_ })
if ($LASTEXITCODE -ne 0) {
    throw "Wi-Fi command failed"
}

$state = Get-NetshValue -Lines $lines -Label "State"
if (-not $state -or $state -notmatch "connected") {
    throw "No connected Wi-Fi network was found"
}

$ssid = Get-NetshValue -Lines $lines -Label "SSID"
$authentication = Get-NetshValue -Lines $lines -Label "Authentication"
$cipher = Get-NetshValue -Lines $lines -Label "Cipher"
$signal = Get-SignalPercent (Get-NetshValue -Lines $lines -Label "Signal")

if ([string]::IsNullOrWhiteSpace($ssid) -or $ssid -eq "N/A") {
    throw "Windows did not report a Wi-Fi SSID"
}

if ([string]::IsNullOrWhiteSpace($authentication)) { $authentication = "UNKNOWN" }
if ([string]::IsNullOrWhiteSpace($cipher)) { $cipher = "UNKNOWN" }

$authUpper = $authentication.ToUpperInvariant()
$cipherUpper = $cipher.ToUpperInvariant()
$securityEnabled = $authUpper -notmatch "OPEN|NONE"

$scan = [ordered]@{
    schemaVersion = 1
    capturedAtUtc = [DateTime]::UtcNow.ToString("o")
    interfaceName = "netsh wlan"
    ssid = $ssid
    signalQualityPercent = $signal
    authentication = $authentication
    cipher = $cipher
    securityEnabled = [bool]$securityEnabled
    enterpriseAuthentication = $authUpper -match "ENTERPRISE|802\.1X"
}

$json = ConvertTo-Json -InputObject ([pscustomobject]$scan) -Depth 4
$resolvedOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$outputDirectory = [System.IO.Path]::GetDirectoryName($resolvedOutputPath)
if (-not [System.IO.Directory]::Exists($outputDirectory)) {
    [System.IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
}
[System.IO.File]::WriteAllText($resolvedOutputPath, $json, [System.Text.UTF8Encoding]::new($false))
Write-Output "Wi-Fi scan report saved to: $resolvedOutputPath"
