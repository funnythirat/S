param(
    [string]$OutputPath = (Join-Path ([Environment]::GetFolderPath("Desktop")) "wifi-scan.json")
)

$ErrorActionPreference = "Stop"
$netsh = Join-Path $env:SystemRoot "System32\netsh.exe"
$lines = @(& $netsh wlan show networks mode=bssid 2>&1 | ForEach-Object { [string]$_ })
if ($LASTEXITCODE -ne 0) {
    throw "Windows could not scan nearby Wi-Fi networks. Check that the WLAN service and adapter are enabled."
}

$networks = [System.Collections.Generic.List[object]]::new()
$current = $null
foreach ($line in $lines) {
    if ($line -match '^\s*SSID\s+\d+\s*:\s*(.*)$') {
        $current = [ordered]@{
            ssid = $Matches[1].Trim()
            authentication = "UNKNOWN"
            cipher = "UNKNOWN"
            signalQualityPercent = 0
            bssidCount = 0
        }
        $networks.Add([pscustomobject]$current)
        continue
    }
    if ($null -eq $current) { continue }
    if ($line -match '^\s*Authentication\s*:\s*(.*?)\s*$') {
        $current.authentication = $Matches[1].Trim()
    } elseif ($line -match '^\s*Encryption\s*:\s*(.*?)\s*$') {
        $current.cipher = $Matches[1].Trim()
    } elseif ($line -match '^\s*BSSID\s+\d+\s*:') {
        $current.bssidCount++
    } elseif ($line -match '^\s*Signal\s*:\s*(\d{1,3})%') {
        $quality = [Math]::Max(0, [Math]::Min(100, [int]$Matches[1]))
        if ($quality -gt $current.signalQualityPercent) {
            $current.signalQualityPercent = $quality
        }
    }
}

foreach ($network in $networks) {
    $authentication = $network.authentication.ToUpperInvariant()
    $cipher = $network.cipher.ToUpperInvariant()
    $network | Add-Member -NotePropertyName securityEnabled -NotePropertyValue ([bool]($authentication -notmatch 'OPEN|NONE' -and $cipher -ne 'NONE'))
}

$report = [ordered]@{
    schemaVersion = 2
    capturedAtUtc = [DateTime]::UtcNow.ToString("o")
    interfaceName = "Windows WLAN"
    networks = @($networks | Sort-Object -Property @{ Expression = "signalQualityPercent"; Descending = $true }, ssid)
}
$json = ConvertTo-Json -InputObject ([pscustomobject]$report) -Depth 5
$resolvedOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$outputDirectory = [System.IO.Path]::GetDirectoryName($resolvedOutputPath)
if (-not [System.IO.Directory]::Exists($outputDirectory)) {
    [System.IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
}
[System.IO.File]::WriteAllText($resolvedOutputPath, $json, [System.Text.UTF8Encoding]::new($false))
Write-Output "Nearby Wi-Fi scan report saved to: $resolvedOutputPath"
Write-Output ("Networks found: " + $networks.Count)
