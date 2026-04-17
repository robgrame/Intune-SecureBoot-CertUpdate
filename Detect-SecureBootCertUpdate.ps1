<#
.SYNOPSIS
    Intune Detection Script - Secure Boot 2023 Certificate Update
.DESCRIPTION
    Detects whether the Secure Boot AvailableUpdates registry key needs to be set to 0x5944
    to trigger the Microsoft 2023 Secure Boot certificate rollout.

    Supported devices:
    - Dell Latitude 5340 (BIOS >= 1.24.1)
    - Dell Latitude 5540 (BIOS >= 1.24.1)
    - Dell Latitude 5550 (BIOS >= 1.16.2)
    - Lenovo model 11JQ   (BIOS M47KT3FA >= 1.63)

    Pre-checks:
    1. Secure Boot must be enabled
    2. Manufacturer must be Dell Inc. or LENOVO
    3. Model must be in the supported list
    4. BIOS must be at minimum version for 2023 certificate support
    5. Checks if the 2023 certificate is already present in the active Secure Boot DB
    6. Checks if AvailableUpdates is already set to 0x5944

    Exit 0 = Compliant (no action needed)
    Exit 1 = Non-compliant (triggers remediation)
#>

#region Configuration
# Dell: model name matched against Win32_ComputerSystem.Model
$DellSupportedModels = @{
    "Latitude 5340" = [version]"1.24.1"
    "Latitude 5540" = [version]"1.24.1"
    "Latitude 5550" = [version]"1.16.2"
}

# Lenovo: model prefix matched against Win32_ComputerSystem.Model, BIOS family + min version
$LenovoSupportedModels = @(
    @{
        ModelPrefix    = "11JQ"
        BiosFamily     = "M47KT3FA"
        MinBiosVersion = [version]"1.63"
    }
)

$RegistryPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
$RegistryName  = "AvailableUpdates"
$DesiredValue  = 0x5944
#endregion

#region Functions
function Test-SecureBootEnabled {
    try {
        return (Confirm-SecureBootUEFI)
    }
    catch {
        return $false
    }
}

function Test-UEFICA2023Present {
    try {
        $db = Get-SecureBootUEFI -Name db
        $dbContent = [System.Text.Encoding]::ASCII.GetString($db.Bytes)
        return ($dbContent -match "Windows UEFI CA 2023")
    }
    catch {
        return $false
    }
}

function Get-DellModelMatch {
    $model = (Get-CimInstance -ClassName Win32_ComputerSystem).Model
    foreach ($supported in $DellSupportedModels.Keys) {
        if ($model -like "*$supported*") {
            return $supported
        }
    }
    return $null
}

function Get-DellBiosVersion {
    $biosVersion = (Get-CimInstance -ClassName Win32_BIOS).SMBIOSBIOSVersion
    if ($biosVersion -match '(\d+\.\d+\.\d+)') {
        return [version]$Matches[1]
    }
    elseif ($biosVersion -match '(\d+\.\d+)') {
        return [version]"$($Matches[1]).0"
    }
    return $null
}

function Get-LenovoModelMatch {
    $model = (Get-CimInstance -ClassName Win32_ComputerSystem).Model
    foreach ($entry in $LenovoSupportedModels) {
        if ($model -like "$($entry.ModelPrefix)*") {
            return $entry
        }
    }
    return $null
}

function Test-LenovoBiosVersion {
    param([hashtable]$ModelEntry)

    $bios = Get-CimInstance -ClassName Win32_BIOS
    $biosText = "$($bios.Caption) $($bios.Description)"

    if ($biosText -notmatch [regex]::Escape($ModelEntry.BiosFamily)) {
        Write-Output "Lenovo BIOS family '$($ModelEntry.BiosFamily)' not found in BIOS info: $biosText"
        return $false
    }

    # Extract version number from BIOS string, e.g. "M47KT3FA(1.63)" -> 1.63
    if ($biosText -match "$([regex]::Escape($ModelEntry.BiosFamily))\((\d+\.\d+)\)") {
        $currentVersion = [version]$Matches[1]
        if ($currentVersion -ge $ModelEntry.MinBiosVersion) {
            Write-Output "Lenovo BIOS version $currentVersion meets minimum $($ModelEntry.MinBiosVersion)."
            return $true
        }
        else {
            Write-Output "Lenovo BIOS version $currentVersion is below minimum $($ModelEntry.MinBiosVersion)."
            return $false
        }
    }

    Write-Output "Unable to parse Lenovo BIOS version from: $biosText"
    return $false
}
#endregion

#region Main Detection Logic
try {
    # 1. Check if Secure Boot is enabled (if disabled, nothing to do)
    if (-not (Test-SecureBootEnabled)) {
        Write-Output "Secure Boot is not enabled. No action required."
        exit 0
    }
    Write-Output "Secure Boot is enabled."

    # 2. Identify manufacturer and model
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $manufacturer = $cs.Manufacturer
    $deviceModel  = $cs.Model
    Write-Output "Manufacturer: $manufacturer | Model: $deviceModel"

    $biosCheckPassed = $false

    if ($manufacturer -eq "Dell Inc.") {
        # 3a. Dell: check supported model
        $dellModel = Get-DellModelMatch
        if (-not $dellModel) {
            Write-Output "Dell model '$deviceModel' is not in the supported list. No action required."
            exit 0
        }
        Write-Output "Matched Dell model: $dellModel"

        # 4a. Dell: check BIOS version
        $currentBios = Get-DellBiosVersion
        $requiredBios = $DellSupportedModels[$dellModel]
        if ($null -eq $currentBios) {
            Write-Output "Unable to determine Dell BIOS version. Skipping BIOS check."
        }
        elseif ($currentBios -lt $requiredBios) {
            Write-Output "Dell BIOS $currentBios is below minimum $requiredBios. BIOS update required first."
            exit 0
        }
        else {
            Write-Output "Dell BIOS $currentBios meets minimum ($requiredBios)."
            $biosCheckPassed = $true
        }
    }
    elseif ($manufacturer -eq "LENOVO") {
        # 3b. Lenovo: check supported model prefix
        $lenovoEntry = Get-LenovoModelMatch
        if (-not $lenovoEntry) {
            Write-Output "Lenovo model '$deviceModel' is not in the supported list. No action required."
            exit 0
        }
        Write-Output "Matched Lenovo model prefix: $($lenovoEntry.ModelPrefix)"

        # 4b. Lenovo: check BIOS family and version
        if (-not (Test-LenovoBiosVersion -ModelEntry $lenovoEntry)) {
            Write-Output "Lenovo BIOS does not meet requirements. BIOS update required first."
            exit 0
        }
        $biosCheckPassed = $true
    }
    else {
        Write-Output "Manufacturer '$manufacturer' is not supported. No action required."
        exit 0
    }

    # 5. Check if 2023 certificate is already in active Secure Boot DB
    if (Test-UEFICA2023Present) {
        Write-Output "Windows UEFI CA 2023 certificate is already present. No action required."
        exit 0
    }
    Write-Output "Windows UEFI CA 2023 certificate NOT found in active DB."

    # 6. Check current registry value
    $currentValue = $null
    try {
        $currentValue = Get-ItemPropertyValue -Path $RegistryPath -Name $RegistryName -ErrorAction Stop
    }
    catch {
        # Value does not exist
    }

    if ($currentValue -eq $DesiredValue) {
        Write-Output "AvailableUpdates is already set to 0x5944. Update in progress or pending reboot."
        exit 0
    }

    # All checks passed - remediation is needed
    Write-Output "Remediation required: AvailableUpdates needs to be set to 0x5944."
    exit 1
}
catch {
    Write-Output "Detection error: $($_.Exception.Message)"
    exit 0
}
#endregion
