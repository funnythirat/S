$ErrorActionPreference = "Stop"

try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
    if (-not $defenderStatus.AntivirusEnabled) {
        throw "Microsoft Defender Antivirus is not enabled. No files were scanned."
    }
} catch {
    throw "Could not use Microsoft Defender Antivirus: $($_.Exception.Message)"
}

Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Title = "Select files to scan locally with Microsoft Defender"
$dialog.Filter = "All files (*.*)|*.*"
$dialog.Multiselect = $true
$dialog.CheckFileExists = $true

if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
    Write-Output "Scan cancelled; no files were scanned."
    exit 0
}

$selectedFiles = @($dialog.FileNames)
$dialog.Dispose()

$previousDetectionIds = @(
    Get-MpThreatDetection -ErrorAction Stop |
        ForEach-Object { [string]$_.DetectionID }
)
$scanStartedAt = [DateTime]::UtcNow
$scanResults = @()

foreach ($path in $selectedFiles) {
    $file = Get-Item -LiteralPath $path -ErrorAction Stop
    $fileResult = [ordered]@{
        fileName = $file.Name
        sizeBytes = $file.Length
        status = "failed"
        error = $null
    }

    try {
        Start-MpScan -ScanType CustomScan -ScanPath $file.FullName -ErrorAction Stop
        $fileResult.status = "completed"
    } catch {
        $fileResult.error = "Microsoft Defender did not complete the scan for this file."
    }

    $scanResults += [pscustomobject]$fileResult
}

$scanFinishedAt = [DateTime]::UtcNow
$newDetections = @(
    Get-MpThreatDetection -ErrorAction Stop |
        Where-Object {
            $detectionId = [string]$_.DetectionID
            $initialTime = $_.InitialDetectionTime
            $recentChangeTime = $_.LastThreatStatusChangeTime
            ($previousDetectionIds -notcontains $detectionId) -and
                (
                    ($initialTime -and $initialTime.ToUniversalTime() -ge $scanStartedAt.AddSeconds(-5)) -or
                    ($recentChangeTime -and $recentChangeTime.ToUniversalTime() -ge $scanStartedAt.AddSeconds(-5))
                )
        }
)

$threatIds = @($newDetections | ForEach-Object { $_.ThreatID } | Sort-Object -Unique)
$threatDetails = @()
if ($threatIds.Count -gt 0) {
    $threatDetails = @(
        Get-MpThreat -ErrorAction Stop |
            Where-Object { $threatIds -contains $_.ThreatID } |
            ForEach-Object {
                $severity = switch ([int]$_.SeverityID) {
                    1 { "low"; break }
                    2 { "medium"; break }
                    4 { "high"; break }
                    5 { "high"; break }
                    default { "info" }
                }
                [pscustomobject]@{
                    name = $_.ThreatName
                    severity = $severity
                }
            }
    )
}

$report = [ordered]@{
    schemaVersion = 1
    engine = "Microsoft Defender"
    scanStartedAtUtc = $scanStartedAt.ToString("o")
    scanFinishedAtUtc = $scanFinishedAt.ToString("o")
    files = @($scanResults)
    threatDetectionCount = $newDetections.Count
    threats = @($threatDetails)
}

$desktop = [Environment]::GetFolderPath("Desktop")
$reportPath = Join-Path $desktop "virus-scan-report.json"
$saveDialog = New-Object System.Windows.Forms.SaveFileDialog
$saveDialog.Title = "Save local virus scan report"
$saveDialog.Filter = "JSON report (*.json)|*.json"
$saveDialog.FileName = "virus-scan-report.json"
$saveDialog.InitialDirectory = $desktop
$saveDialog.OverwritePrompt = $true
if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    $reportPath = $saveDialog.FileName
}
$saveDialog.Dispose()

$json = ConvertTo-Json -InputObject $report -Depth 5
[System.IO.File]::WriteAllText(
    [System.IO.Path]::GetFullPath($reportPath),
    $json,
    [System.Text.UTF8Encoding]::new($false)
)
Write-Output "Local scan report saved to: $reportPath"
