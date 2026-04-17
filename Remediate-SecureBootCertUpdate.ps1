<#
.SYNOPSIS
    Intune Remediation Script - Secure Boot 2023 Certificate Update
.DESCRIPTION
    Sets the AvailableUpdates registry value to 0x5944 under
    HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot
    to trigger the Microsoft 2023 Secure Boot certificate deployment.

    Supported devices:
    - Dell Latitude 5340 (BIOS >= 1.24.1)
    - Dell Latitude 5540 (BIOS >= 1.24.1)
    - Dell Latitude 5550 (BIOS >= 1.16.2)
    - Lenovo model 11JQ   (BIOS M47KT3FA >= 1.63)

    Pre-checks (safety):
    1. Secure Boot must be enabled
    2. Manufacturer must be Dell Inc. or LENOVO
    3. Model must be in the supported list
    4. BIOS must be at minimum version for 2023 certificate support

    The update completes after a reboot. Status can be monitored via:
    - UEFICA2023Status (NotStarted -> InProgress -> Updated)
    - UEFICA2023Error  (0 = success)

    Exit 0 = Remediation successful
    Exit 1 = Remediation failed or skipped
#>

#region Configuration
$DellSupportedModels = @{
    "Latitude 5340" = [version]"1.24.1"
    "Latitude 5540" = [version]"1.24.1"
    "Latitude 5550" = [version]"1.16.2"
}

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

#region Main Remediation Logic
try {
    # Safety check 1: Secure Boot enabled (if disabled, nothing to do)
    if (-not (Test-SecureBootEnabled)) {
        Write-Output "Secure Boot is not enabled. Remediation skipped."
        exit 1
    }

    # Safety check 2-4: Manufacturer, model, BIOS version
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $manufacturer = $cs.Manufacturer
    $deviceModel  = $cs.Model

    if ($manufacturer -eq "Dell Inc.") {
        $dellModel = Get-DellModelMatch
        if (-not $dellModel) {
            Write-Output "Dell model '$deviceModel' is not supported. Remediation skipped."
            exit 1
        }
        $currentBios = Get-DellBiosVersion
        $requiredBios = $DellSupportedModels[$dellModel]
        if ($null -ne $currentBios -and $currentBios -lt $requiredBios) {
            Write-Output "Dell BIOS $currentBios is below minimum $requiredBios for $dellModel. Update BIOS first."
            exit 1
        }
        Write-Output "Dell $dellModel - BIOS OK."
    }
    elseif ($manufacturer -eq "LENOVO") {
        $lenovoEntry = Get-LenovoModelMatch
        if (-not $lenovoEntry) {
            Write-Output "Lenovo model '$deviceModel' is not supported. Remediation skipped."
            exit 1
        }
        if (-not (Test-LenovoBiosVersion -ModelEntry $lenovoEntry)) {
            Write-Output "Lenovo BIOS does not meet requirements. Update BIOS first."
            exit 1
        }
        Write-Output "Lenovo $deviceModel - BIOS OK."
    }
    else {
        Write-Output "Manufacturer '$manufacturer' is not supported. Remediation skipped."
        exit 1
    }

    # Check if update is already in progress or completed
    $currentValue = $null
    try {
        $currentValue = Get-ItemPropertyValue -Path $RegistryPath -Name $RegistryName -ErrorAction Stop
    }
    catch { }

    if ($currentValue -eq $DesiredValue) {
        Write-Output "AvailableUpdates is already set to 0x5944. Update pending reboot. Remediation skipped."
        exit 0
    }

    if ($currentValue -eq 0x4100 -or $currentValue -eq 0x4000) {
        Write-Output "AvailableUpdates is 0x$($currentValue.ToString('X4')). Update already in progress or completed. Remediation skipped."
        exit 0
    }

    # Apply the registry change
    if (-not (Test-Path $RegistryPath)) {
        Write-Output "Registry path $RegistryPath does not exist. Cannot remediate."
        exit 1
    }

    Set-ItemProperty -Path $RegistryPath -Name $RegistryName -Type DWord -Value $DesiredValue -Force
    Write-Output "Successfully set $RegistryName to 0x5944 (decimal $DesiredValue)."
    Write-Output "A reboot is required to complete the Secure Boot certificate update."

    # Verify the value was written correctly
    $verifyValue = Get-ItemPropertyValue -Path $RegistryPath -Name $RegistryName
    if ($verifyValue -eq $DesiredValue) {
        Write-Output "Verification passed. Registry value confirmed."
        exit 0
    }
    else {
        Write-Output "Verification FAILED. Expected $DesiredValue but found $verifyValue."
        exit 1
    }
}
catch {
    Write-Output "Remediation error: $($_.Exception.Message)"
    exit 1
}
#endregion
