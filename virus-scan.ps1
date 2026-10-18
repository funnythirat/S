param(
    [ValidateSet("QuickScan", "FullScan", "CustomScan")]
    [string]$ScanType = "FullScan",
    [string]$ScanPath,
    [string]$OutputPath = (Join-Path ([Environment]::GetFolderPath("Desktop")) "virus-scan-report.json")
)

$ErrorActionPreference = "Stop"

try {
    $status = Get-MpComputerStatus -ErrorAction Stop
    if (-not $status.AntivirusEnabled) {
        throw "Microsoft Defender Antivirus is not enabled. No scan was started."
    }
} catch {
    throw "Could not use Microsoft Defender Antivirus: $($_.Exception.Message)"
}

if ($ScanType -eq "CustomScan") {
    if ([string]::IsNullOrWhiteSpace($ScanPath)) {
        Add-Type -AssemblyName System.Windows.Forms
        $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $dialog.Description = "Select a folder to scan locally with Microsoft Defender"
        if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
            Write-Output "Scan cancelled; no files were scanned."
            exit 0
        }
        $ScanPath = $dialog.SelectedPath
        $dialog.Dispose()
    }
    if (-not (Test-Path -LiteralPath $ScanPath)) {
        throw "Scan path does not exist: $ScanPath"
    }
}

$before = @(Get-MpThreatDetection -ErrorAction Stop | ForEach-Object { [string]$_.DetectionID })
$started = [DateTime]::UtcNow

if ($ScanType -eq "CustomScan") {
    Start-MpScan -ScanType CustomScan -ScanPath ([System.IO.Path]::GetFullPath($ScanPath)) -ErrorAction Stop
} else {
    Start-MpScan -ScanType $ScanType -ErrorAction Stop
}

$finished = [DateTime]::UtcNow
$after = @(Get-MpThreatDetection -ErrorAction Stop)
$newDetections = @($after | Where-Object {
    $id = [string]$_.DetectionID
    $initial = $_.InitialDetectionTime
    $changed = $_.LastThreatStatusChangeTime
    ($before -notcontains $id) -and (($initial -and $initial.ToUniversalTime() -ge $started.AddSeconds(-5)) -or ($changed -and $changed.ToUniversalTime() -ge $started.AddSeconds(-5)))
})

$threatIds = @($newDetections | ForEach-Object { $_.ThreatID } | Sort-Object -Unique)
$threats = @(Get-MpThreat -ErrorAction Stop | Where-Object { $threatIds -contains $_.ThreatID } | ForEach-Object {
    $severity = switch ([int]$_.SeverityID) { 1 { "low"; break } 2 { "medium"; break } 4 { "high"; break } 5 { "high"; break } default { "info" } }
    [pscustomobject]@{ name = $_.ThreatName; severity = $severity }
})

$report = [ordered]@{
    schemaVersion = 2
    engine = "Microsoft Defender"
    scanType = $ScanType
    scanPath = if ($ScanType -eq "CustomScan") { [System.IO.Path]::GetFullPath($ScanPath) } else { $null }
    scanStartedAtUtc = $started.ToString("o")
    scanFinishedAtUtc = $finished.ToString("o")
    files = @([pscustomobject]@{ fileName = if ($ScanType -eq "CustomScan") { [System.IO.Path]::GetFileName($ScanPath) } else { $ScanType }; sizeBytes = 0; status = "completed"; error = $null })
    threatDetectionCount = $newDetections.Count
    threats = $threats
}

$resolved = [System.IO.Path]::GetFullPath($OutputPath)
[System.IO.File]::WriteAllText($resolved, (ConvertTo-Json -InputObject $report -Depth 5), [System.Text.UTF8Encoding]::new($false))
Write-Output "Local Defender scan completed. Report saved to: $resolved"
