<#PSScriptInfo

.VERSION 1.0

.AUTHOR Mickaël CHAVE

.DESCRIPTION 
Automated renaming of computers with a prefix and serial number, handling AD, AAD, and workgroup scenarios, with error handling and improved logging.

Based on the original script by Michael Niehaus, with modifications by Mickaël CHAVE.
https://github.com/mtniehaus/RenameComputer

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $False)] 
    [string]$Prefix = ""
)

# Initial setup and logging
$logPath = "$($env:ProgramData)\Microsoft\IntuneManagementExtension\Logs\RenameComputer"
$logFile = "$logPath\RenameComputer.log"
$tagFile = "$logPath\RenameComputer.tag"
if (-not (Test-Path $logPath)) { mkdir $logPath }

function Write-Log {
    param([string]$message)
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Write-Host "$timestamp $message"
    Add-Content -Path $logFile -Value "$timestamp $message"
}

function Test-ADConnected {
    try {
        $dcInfo = [ADSI]"LDAP://RootDSE"
        return ($null -ne $dcInfo.dnsHostName)
    } catch {
        return $false
    }
}

function New-ComputerName {
    param([string]$prefix, [string]$serial)
    $serialPart = $serial.Substring([Math]::Max(0, $serial.Length - (15 - $prefix.Length - 1)))
    return "$prefix-$serialPart"
}

Start-Transcript -Path $logFile -Append

try {
    # Relaunch in 64-bit mode if necessary
    if ("$env:PROCESSOR_ARCHITEW6432" -ne "ARM64") {
        if (Test-Path "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe") {
            & "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$PSCommandPath" -Prefix $Prefix
            Exit $lastexitcode
        }
    }

    # Exit if prefix is set but doesn't match
    $details = Get-ComputerInfo
    if ($Prefix -and (-not $details.CsName.StartsWith($Prefix))) {
        Write-Log "Prefix mismatch, exiting. Prefix=$Prefix ComputerName=$($details.CsName)"
        Stop-Transcript
        Exit 0
    }

    # See if we are AD or AAD joined
    $isAD = $false
    $tenantID = $null
    if ($details.CsPartOfDomain) {
        Write-Log "Device is joined to AD domain: $($details.CsDomain)"
        $isAD = $true
        $goodToGo = $false
    } else {
        $goodToGo = $true
        if (Test-Path "HKLM:/SYSTEM/CurrentControlSet/Control/CloudDomainJoin/JoinInfo") {
            $subKey = Get-Item "HKLM:/SYSTEM/CurrentControlSet/Control/CloudDomainJoin/JoinInfo"
            $guids = $subKey.GetSubKeyNames()
            foreach($guid in $guids) {
                $guidSubKey = $subKey.OpenSubKey($guid)
                $tenantId = $guidSubKey.GetValue("TenantId")
            }
        }
        if ($null -ne $tenantID) {
            Write-Log "Device is joined to AAD tenant: $tenantID"
        } else {
            Write-Log "Not part of a AAD or AD, in a workgroup."
        }
    }

    # Ensure AD connectivity if applicable
    if ($isAD) {
        $goodToGo = Test-ADConnected
    } else {
        $goodToGo = $true
    }
    if ($isAD -and -not $goodToGo) {
        Write-Log "No connectivity to the AD domain, unable to rename."
        Stop-Transcript
        Exit 1
    }

    # Generate the new computer name
    $systemEnclosure = Get-CimInstance -ClassName Win32_SystemEnclosure
    $serialNumber = if ($systemEnclosure.SMBIOSAssetTag) { $systemEnclosure.SMBIOSAssetTag } else { $details.BiosSerialNumber }
    $newName = New-ComputerName -prefix $Prefix -serial $serialNumber

    # Exit if name is already set
    if ($newName -ieq $details.CsName) {
        Write-Log "No need to rename, current name is already set to $newName"
        Set-Content -Path $tagFile -Value "Installed"
        Stop-Transcript
        Exit 0
    }

    # Rename the computer
    Write-Log "Renaming computer to $newName"
    Rename-Computer -NewName $newName -Force

    # Reboot during OOBE if necessary
    if ($details.CsUserName -match "defaultUser") {
        Write-Log "In OOBE, exiting with return code 1641 for immediate reboot."
        Set-Content -Path $tagFile -Value "Installed"
        Stop-Transcript
        Exit 1641
    } else {
        Set-Content -Path $tagFile -Value "Installed"
        Write-Log "Initiating a restart in 10 minutes"
        & shutdown.exe /g /t 600 /f /c "Restarting due to computer name change. Save your work."
    }

} catch {
    Write-Log "Error: $($_.Exception.Message)"
    Stop-Transcript
    Exit 1
}

Stop-Transcript