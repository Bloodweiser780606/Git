<# 
.Synopsis 
Duo for Windows Logon Support Script. This script creates a zip file with log files and the sanitized Duo configuration.
.Description
This command has the following flags:
-duodebug :defaults off; $true enabled debug in registry; $false disables debug in registry
-out :sets the preferred log path; defaults to desktop if not set
-eventlogs : Will export application and/or security logs: options: all, application, security
-days: Setting this will grab logs from the last X days, for both duo native logs and event logs
-tls: Export Client TLS settings from registry
.Example
PS C:\>Winlogon-Diag.ps1 -duodebug $true 
PS C:\>Winlogon-Diag.ps1 -logdirectory C:\testing -eventlogs security -days 2
.LINK
https://duo.com/support
#>

#==================================================
# Duo for Windows Logon Support Script
# version: 0.5
# date: 07/21/21
# Release notes: Now gathers network info to troubleshoot Trusted Sessions
#==================================================



param (
  [string]$duodebug = $null,
  [string]$out = (Get-Location).path + "\",
  [switch]$help,
  [switch]$tls,
  [Parameter(ParameterSetName='Extra',Mandatory=$false)][string]$eventlogs = $false,
  [Parameter(ParameterSetName='Extra',Mandatory=$false)][string]$days = $false
    )
#all the variables 
$credfilter = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters"
$credprov = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers"
$localreg = "HKLM:\SOFTWARE\Duo Security\DuoCredProv"
$GPOReg = "HKLM:\SOFTWARE\Policies\Duo Security\DuoCredProv"
$uninstallkey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"
$DuoLog = "$env:ProgramData\Duo Security\duo.log"
$logpath = ($out).TrimEnd('\')
$newlogfolder = new-item -path "$logpath\DuoSupport_$(get-date -f yyyy-MM-dd-hh-mm-ss)" -ItemType directory
$LogFile = New-Item -path "$newlogfolder\DuoSupport.log" -ItemType File

#logging function
function LogMessage{
  [cmdletbinding()]
  param([string]$Message)
    ((Get-Date).ToString() + " - " + $Message) >> $LogFile;
 }
#check if user context is administrative
function Get-adminstatus {
  [cmdletbinding()]
  param ()
  try {
      $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
      $principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $identity
      return $principal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )
  } catch {
      throw "Failed to determine if the current user has elevated privileges. The error was: '{0}'." -f $_
  }
 }
#Check the version of duo installed by parsing the Registry Uninstall Keys
Function Get-DuoVersion{
  [cmdletbinding()]
  param ()
  Try{
    Get-ChildItem $uninstallkey -Recurse -ErrorAction Stop | ForEach-Object {
    $CurrentKey = (Get-ItemProperty -Path $_.PsPath)
    if ($CurrentKey -match "Duo Authentication for Windows Logon") {
      $DV = write-output "$($CurrentKey.DisplayName) $($CurrentKey.DisplayVersion)"
      }
  }
  If ($DV -eq $null){
    Write-Output "Duo for Windows Logon (Microsoft RDP) not installed."
    }
  Else {
    Write-output $DV
  }
  }
  catch{
    Write-Output "Cannot determine if Duo for Windows Logon (Microsoft RDP) is installed."
  }
}
#Exporting existing credential providers to another file in the running directory
Function Get-CredProv{
[cmdletbinding()]  
param ()
  Get-ChildItem -Path $credprov | Format-Table -AutoSize | Out-File $newlogfolder\credprov.txt 
  Get-ChildItem -Path $credfilter | Format-Table -AutoSize | Out-File $newlogfolder\credprov.txt -Append
}
#Allows for enabling and disabling the debug registry flag
Function Enable-Debug{
[cmdletbinding()]  
param ()

  try{
  If ($duodebug -eq $true){
    Set-ItemProperty -Path $localreg -Name Debug -Value 1 -type DWORD
    $t = $host.ui.RawUI.ForegroundColor
    $host.ui.RawUI.ForegroundColor = "DarkGreen"
    Write-Output "Log Debugging has been enabled"
    $host.ui.RawUI.ForegroundColor = $t
  }
  elseif($duodebug -eq $false){
    Set-ItemProperty -Path $localreg -Name Debug -Value 0 -type DWORD
    $t = $host.ui.RawUI.ForegroundColor
    $host.ui.RawUI.ForegroundColor = "Yellow"
    Write-Output "Log Debugging has been disabled"
    $host.ui.RawUI.ForegroundColor = $t
  }
  }
  Catch [System.Management.Automation.PSArgumentException]{
  "Registry Key Property missing"
  }
  Catch [System.Management.Automation.ItemNotFoundException]{
  "Registry Key itself is missing"
  }
  Finally {
  $ErrorActionPreference = "Continue"
  }
}

# Export networking information for trusted sessions
function Get-Network {
  [cmdletbinding()]
  param ()
  Write-Output "Default Route:" | Out-File $newlogfolder\NetworkSettings.txt
  $DefaultRoute =  Get-NetRoute -DestinationPrefix "0.0.0.0/0"
  $DefaultRoute | Format-List | Out-File $newlogfolder\NetworkSettings.txt -Append
  Get-NetNeighbor -IPAddress $DefaultRoute.NextHop | Format-List | Out-File $newlogfolder\NetworkSettings.txt -Append
  
  Write-Output "Default Adapter:" | Out-File $newlogfolder\NetworkSettings.txt -Append
  Get-NetAdapter -IfIndex $DefaultRoute.ifIndex | Format-List | Out-File $newlogfolder\NetworkSettings.txt -Append
  
  Write-Output "Wireless Settings:" | Out-File $newlogfolder\NetworkSettings.txt -Append
  netsh wlan show interfaces | Format-List | Out-File $newlogfolder\NetworkSettings.txt -Append 
}

#Export duo logs, default to whole log but when used with $days flag it will limit time range
function Get-DuoLog {
  [cmdletbinding()]
  param ()
  if ($days -eq $false){
    Copy-Item $DuoLog -Destination $newlogfolder
  }
  else{
    $backdate = (get-date).AddDays(-$days).ToString("MM/dd/yy")
    Get-Content $DuoLog | % { if ($_ -ge $backdate) {Write-Output $_ | Out-file $newlogfolder\Duo.Log -force -Append }}
 }
}

#Export security logs must be used with $days flag to limit time range
function export-securitylog{
  [cmdletbinding()]  
  param ()
  if($days -ne $false){
    $old = (get-date).AddDays(-$days)
    $miltime = (New-TimeSpan -Start (Get-Date) -End $old).totalmilliseconds
    wevtutil epl security /q:"*[System[TimeCreated[timediff(@SystemTime) <= $miltime]]]" "$newlogfolder\security.evtx" /overwrite:true
  }
  else{
    $t = $host.ui.RawUI.ForegroundColor
    $host.ui.RawUI.ForegroundColor = "Red"
    Write-Output "Please re-run script with -days <value> set"
    $host.ui.RawUI.ForegroundColor = $t
  }
}

#Export application logs must be used with $days flag to limit time range
function export-applicationlog{
  [cmdletbinding()]
  param ()  
  if($days -ne $false){
    $old = (get-date).AddDays(-$days)
    $miltime = (New-TimeSpan -Start (Get-Date) -End $old).totalmilliseconds
    wevtutil epl application /q:"*[System[TimeCreated[timediff(@SystemTime) <= $miltime]]]" "$newlogfolder\application.evtx" /overwrite:true
    }
    else{
      $t = $host.ui.RawUI.ForegroundColor
      $host.ui.RawUI.ForegroundColor = "Red"
      Write-Output "Please re-run script with -days <value> set"
      $host.ui.RawUI.ForegroundColor = $t
    }
}
$localreg = "HKLM:\SOFTWARE\Duo Security\DuoCredProv"

Function get-duocheck{

$RegProperty = (Get-ItemProperty $localreg -name Host).Host 
$RestError = $null
try
    {
    $IWR = Invoke-WebRequest -Uri https://$RegProperty/auth/v2/ping 
    Write-Output "Connectivity Response to Duo:" $IWR.StatusDescription
    }
catch
    {
    $RestError = $_
  Write-Output "Connectivity Response to Duo failed due to:" $RestError.Exception 
      }
}

if ($help){
  get-help .\Winlogon-Diag.ps1
  EXIT
}

# Check Admin status
$admin = Get-adminstatus

if ((Test-Path $localreg) -eq $false){
  $t = $host.ui.RawUI.ForegroundColor
  $host.ui.RawUI.ForegroundColor = "Red"
  $installstatus = "Duo for Windows Logon (Microsoft RDP) not installed."
  Write-Output $installstatus
  $host.ui.RawUI.ForegroundColor = $t
  Remove-Item $newlogfolder -recurse -force
  }
  elseif($admin -eq $false){
    $t = $host.ui.RawUI.ForegroundColor
    $host.ui.RawUI.ForegroundColor = "Red"
    $adminstatus = "Please re-run script as an administrator"
    Write-Output $adminstatus
    $host.ui.RawUI.ForegroundColor = $t
    Remove-Item $newlogfolder -recurse -force
    }
  else{
    $t = $host.ui.RawUI.ForegroundColor
    $host.ui.RawUI.ForegroundColor = "Green"
    $adminstatus = "Script has been run with administrative access"
    Write-Output $adminstatus
    $host.ui.RawUI.ForegroundColor = $t
  # Check Debug status  
if ($duodebug -eq $true -or $duodebug -eq $false){
        Enable-Debug  
        exit
      }
    
if ((Get-ItemProperty -Path $localreg).debug -eq 0){
  $initaldebug = "Debug Off"
  }
if ((Get-ItemProperty -Path $localreg).debug -eq 1){
  $initaldebug = "Debug On"
  }
#Check if 2016+/Win10+
$majorver = ([System.Environment]::OSVersion.Version).major
if ($majorver -eq 10){
 $win10 = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion').releaseID
 $osInfo = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, ServicePackMajorVersion, OSArchitecture, CSName, WindowsDirectory

}
else {
  $win10 = $null
  $osInfo = [System.Environment]::OSVersion
}
Get-DuoLog
#export app logs
if($days -ne $false -and $eventlogs -eq "application" -or $eventlogs -eq "all" )
{export-applicationlog}
#export sec logs
if($days -ne $false -and $eventlogs -eq "security" -or $eventlogs -eq "all" )
{export-securitylog}

#Get variables for logging
$lastlogonprov = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI').LastLoggedOnProvider
$lastloggedonduo =  if ($lastlogonprov -eq '{44E2ED41-48C7-4712-A3C3-250C5E6D5D84}'){
                        Write-Output "Yes"
                    } else {
                      Write-Output "No"
                    }

$SSLduocheck = get-duocheck
$credprovs = Get-CredProv
$network = Get-Network
$duoversion = Get-DuoVersion 
$gpostatus = Test-Path $GPOReg
$proxies = If ((Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').proxyServer -eq $Null){
    Write-Output "No Browser Proxy"
    }else{
    Write-Output (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').proxyServer
    }
$output = netsh winhttp show proxy
$null, $proxy = $output -like '*proxy server(s)*' -split ' +: +', 2
$sysprox = if ($proxy) {$proxy} else {'No System Proxy'}
if ($majorver -gt 8){
$bitlockerstatus = Try {(Get-BitLockerVolume $env:systemdrive).volumestatus} catch {Write-Output "Not Detected"}
$avinstalled = Try{(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct).displayname}  catch {Write-Output "Not Detected"}
$tpmstatus = Try{(get-tpm).tpmpresent} catch {Write-Output "Not Detected"}
}
if ($majorver -lt 7){
$oldtpm = Try {(Get-WmiObject -class Win32_Tpm -namespace root\CIMV2\Security\MicrosoftTpm).isactivated_initialvalue } catch {Write-Output "Not Detected"}
$oldtime = Try{(Get-WmiObject -Class win32_timezone).caption} catch {Write-Output "Not Detected"}
$query = 'Select ProtectionStatus from Win32_EncryptableVolume WHERE DriveLetter = ''$env:systemdrive:'''
$query = $ExecutionContext.InvokeCommand.ExpandString($query)
$obl = manage-bde.exe -status $env:systemdrive 
$oldbitlocker = try {Write-Output $obl | findstr /i "Protection Status"} catch {Write-Output "Not Detected"}
$oldavwmiQuery = "SELECT * FROM AntiVirusProduct" 
$oldavinstalled = try {Get-WmiObject -Namespace "root\SecurityCenter2" -Query $oldavwmiQuery} catch {Write-Output "Not Detected"}
}
#Get all the things to message out
LogMessage -Message ==============================================================================
LogMessage -Message "$SSLduocheck"
LogMessage -Message ==============================================================================
LogMessage -Message "Installed Version: $duoversion"
LogMessage -Message "GPO deployed: $gpostatus"
LogMessage -Message ==============================================================================
LogMessage -Message $adminstatus
LogMessage -Message "Status: $initaldebug"
LogMessage -Message ==============================================================================
LogMessage -Message "Host Information"
LogMessage -Message "Hostname: $env:computername"
LogMessage -Message "Username: $env:UserName"
LogMessage -Message "Domain: $env:UserDomain"
LogMessage -Message "System Proxy: $sysprox"
LogMessage -Message "Browser Proxy: $proxies"
#Win 7/2008 logging
if ($majorver -lt 8){
    LogMessage -Message "OS Version: $(($osinfo).VersionString)"
    LogMessage -Message "OS Build: $(($osinfo).version)"
    LogMessage -Message "OS Bit: $(($osinfo).Platform)"
    LogMessage -Message "Bitlocker Status: $oldbitlocker"
    LogMessage -Message "AV Product: $(($oldavinstalled).displayName)"
    LogMessage -Message "TPM Available: $oldtpm"
    LogMessage -Message "Timezone: $oldtime"    
    } 
#Win8/2012 and higher    
if ($majorver -ge 8){
LogMessage -Message "OS Version: $(($osinfo).caption), $win10"
LogMessage -Message "OS Build: $(($osinfo).version)"
LogMessage -Message "OS Bit: $(($osinfo).OSArchitecture)"
LogMessage -Message "Bitlocker Status: $bitlockerstatus"
LogMessage -Message "AV Product: $avinstalled"
LogMessage -Message "TPM Available: $tpmstatus"
LogMessage -Message "Timezone: $((get-timezone).id)"    
} 
LogMessage -Message "Last Logged On Provider GUID: $lastlogonprov"
LogMessage -Message "Was Last Logon Provider Duo: $lastloggedonduo"
LogMessage -Message ==============================================================================
LogMessage -Message "Credential Providers exported to:"
LogMessage -Message $newlogfolder\credprov.txt
LogMessage -Message ==============================================================================
LogMessage -Message "Duo.log exported to:"
LogMessage -Message $newlogfolder\Duo.Log 
LogMessage -Message ==============================================================================
LogMessage -Message "Network settings exported to:"
LogMessage -Message $newlogfolder\NetworkSettings.txt
LogMessage -Message ==============================================================================
LogMessage -Message "Duo Registry Keys:" 
If (Test-Path -Path $localreg) {
(Get-ItemProperty $localreg | Select-Object * -ExcludeProperty SKey,PS* | fl | Out-File $LogFile -force -Append)
} else {LogMessage -Message "Duo Registry Keys Not Present"}
LogMessage -Message ==============================================================================
LogMessage -Message "Offline Registry Keys:" 
If (Test-path -Path "$localreg\offline"){
(Get-ItemProperty "$localreg\offline" | Select-Object * -ExcludeProperty PS* | fl | Out-File $LogFile -force -Append)
}
else {LogMessage -Message "Duo Offline Not Present"  }
LogMessage -Message ============================================================================== 
$duoTime = Invoke-RestMethod -Uri "https://api.duosecurity.com/auth/v2/ping"
$duounixtimestamp = $duoTime.response.time
$MaxDateTime = (Get-Date).ToUniversalTime().AddMinutes(2)
$MaxPCTime = [System.Math]::Truncate((Get-Date -Date $MaxDateTime -UFormat %s))
$MinDateTime = (Get-Date).ToUniversalTime().AddMinutes(-2)
$MinPCTime = [System.Math]::Truncate((Get-Date -Date $MinDateTime -UFormat %s))
$timesource = w32tm /query /source
LogMessage -Message "NTP Settings:"
LogMessage -Message "Time Source: $($timesource) "
if ($MinPCTime -ge $duounixtimestamp -and $MaxPCTime -le $duounixtimestamp) {
  LogMessage -Message:"Time is currently out of Sync with Duo Service"
 }
 else {
  LogMessage -Message:"Time is within valid range of Duo Service"
 }
LogMessage -Message ============================================================================== 
$UserHT = @{0 = "Automatically deny elevation requests"; 1 = "Prompt for credentials on the secure desktop"; 3 = "(Default) Prompt for credentials"}
$AdminHT = @{0 = "Elevate without prompting"; 1 = "Prompt for credentials on the secure desktop"; 2 = "Prompt for consent on the secure desktop"; 3 = "Prompt for credentials"; 4 = "Prompt for consent"; 5 = "(Default) Prompt for consent for non-Windows binaries"}
$Key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" 
$ConsentPromptBehaviorAdmin_Name = "ConsentPromptBehaviorAdmin" 
$ConsentPromptBehaviorUser_Name = "ConsentPromptBehaviorUser" 

$ConsentPromptBehaviorAdmin_Value = Get-ItemPropertyValue $Key $ConsentPromptBehaviorAdmin_Name 
$ConsentPromptBehaviorUser_Value = Get-ItemPropertyValue $Key $ConsentPromptBehaviorUser_Name 
LogMessage -Message "UAC Settings:"
LogMessage -Message  "User UAC Settings: $($UserHT.$ConsentPromptBehaviorUser_Value) "
LogMessage -Message  "Administrator UAC Settings: $($AdminHT.$ConsentPromptBehaviorAdmin_Value) "

#Conditonal log for app/sec logs
If ($eventlogs -eq "application" -or $eventlogs -eq "all"){
LogMessage -Message "Application Event Log exported to:"
LogMessage -Message "$newlogfolder\security.evtx"
LogMessage -Message ==============================================================================
}
If ($eventlogs -eq "security" -or $eventlogs -eq "all"){
LogMessage -Message "Security Event Log exported to:"
LogMessage -Message "$newlogfolder\security.evtx"
LogMessage -Message ==============================================================================
}
If ($tls){
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client")
		{$SSL2ClientReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client")
		{$SSL3ClientReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client")
		{$TLS1ClientReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client")
		{$TLS11ClientReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client")
		{$TLS12ClientReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"}
	
    if ($SSL3ClientReg.Enabled -ne 0)
		 {LogMessage -Message "SSL3 is Enabled (NOT default)"}
		else
			 {LogMessage -Message "SSL3 is Disabled (default)"}
	
    if ($TLS1ClientReg.Enabled -ne 0) 
		 {LogMessage -Message "TLS 1.0 is Enabled (default)"}
		else
			 {LogMessage -Messaget "TLS 1.0 is Disabled (NOT default)"}
	 
    if ($TLS11ClientReg.Enabled -ne 0)
		 {LogMessage -Message "TLS 1.1 s Enabled (default)"}
		else
			 {LogMessage -Message "TLS 1.1 is Disabled (NOT default)"}
	 
    if ($TLS12ClientReg.Enabled -ne 0)
		 {LogMessage -Message "TLS 1.2 is Enabled (default)"}
		else
			 {LogMessage -Message "TLS 1.2 is Disabled (NOT default)"}
LogMessage -Message ==============================================================================
}

#print messages
cat $LogFile

#export to zip
$srcdir = "$newlogfolder"
$zipFilename = "DuoSupport$(get-date -f yyyy-MM-dd-hh-mm-ss).zip"
$zipFilepath = "$out"
$zipFile = "$zipFilepath$zipFilename"

#Prepare zip file
if(-not (test-path($zipFile))) {
    set-content $zipFile ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18))
    (dir $zipFile).IsReadOnly = $false  
}

$shellApplication = new-object -com shell.application
$zipPackage = $shellApplication.NameSpace($zipFile)
$files = Get-ChildItem -Path $srcdir | where{! $_.PSIsContainer}

foreach($file in $files) { 
    $zipPackage.CopyHere($file.FullName)
#using this method, sometimes files can be 'skipped'
#this 'while' loop checks each file is added before moving to the next
    while($zipPackage.Items().Item($file.name) -eq $null){
        Start-sleep -seconds 1
    }
}
#remove temp folder
Remove-Item $newlogfolder -recurse -force

#support file path
$t = $host.ui.RawUI.ForegroundColor
$host.ui.RawUI.ForegroundColor = "DarkGreen"
Write-Output "Please send $zipfile to Duo Support"
$host.ui.RawUI.ForegroundColor = $t
}
# SIG # Begin signature block
# MIIZowYJKoZIhvcNAQcCoIIZlDCCGZACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU7e2df1hVLOHkNhnTi8PICLNC
# Na+gghSgMIIE/jCCA+agAwIBAgIQDUJK4L46iP9gQCHOFADw3TANBgkqhkiG9w0B
# AQsFADByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFz
# c3VyZWQgSUQgVGltZXN0YW1waW5nIENBMB4XDTIxMDEwMTAwMDAwMFoXDTMxMDEw
# NjAwMDAwMFowSDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MSAwHgYDVQQDExdEaWdpQ2VydCBUaW1lc3RhbXAgMjAyMTCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAMLmYYRnxYr1DQikRcpja1HXOhFCvQp1dU2UtAxQ
# tSYQ/h3Ib5FrDJbnGlxI70Tlv5thzRWRYlq4/2cLnGP9NmqB+in43Stwhd4CGPN4
# bbx9+cdtCT2+anaH6Yq9+IRdHnbJ5MZ2djpT0dHTWjaPxqPhLxs6t2HWc+xObTOK
# fF1FLUuxUOZBOjdWhtyTI433UCXoZObd048vV7WHIOsOjizVI9r0TXhG4wODMSlK
# XAwxikqMiMX3MFr5FK8VX2xDSQn9JiNT9o1j6BqrW7EdMMKbaYK02/xWVLwfoYer
# vnpbCiAvSwnJlaeNsvrWY4tOpXIc7p96AXP4Gdb+DUmEvQECAwEAAaOCAbgwggG0
# MA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsG
# AQUFBwMIMEEGA1UdIAQ6MDgwNgYJYIZIAYb9bAcBMCkwJwYIKwYBBQUHAgEWG2h0
# dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAfBgNVHSMEGDAWgBT0tuEgHf4prtLk
# YaWyoiWyyBc1bjAdBgNVHQ4EFgQUNkSGjqS6sGa+vCgtHUQ23eNqerwwcQYDVR0f
# BGowaDAyoDCgLoYsaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL3NoYTItYXNzdXJl
# ZC10cy5jcmwwMqAwoC6GLGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9zaGEyLWFz
# c3VyZWQtdHMuY3JsMIGFBggrBgEFBQcBAQR5MHcwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBPBggrBgEFBQcwAoZDaHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0U0hBMkFzc3VyZWRJRFRpbWVzdGFtcGluZ0NB
# LmNydDANBgkqhkiG9w0BAQsFAAOCAQEASBzctemaI7znGucgDo5nRv1CclF0CiNH
# o6uS0iXEcFm+FKDlJ4GlTRQVGQd58NEEw4bZO73+RAJmTe1ppA/2uHDPYuj1UUp4
# eTZ6J7fz51Kfk6ftQ55757TdQSKJ+4eiRgNO/PT+t2R3Y18jUmmDgvoaU+2QzI2h
# F3MN9PNlOXBL85zWenvaDLw9MtAby/Vh/HUIAHa8gQ74wOFcz8QRcucbZEnYIpp1
# FUL1LTI4gdr0YKK6tFL7XOBhJCVPst/JKahzQ1HavWPWH1ub9y4bTxMd90oNcX6X
# t/Q/hOvB46NJofrOp79Wz7pZdmGJX36ntI5nePk2mOHLKNpbh6aKLzCCBTAwggQY
# oAMCAQICEAQJGBtf1btmdVNDtW+VUAgwDQYJKoZIhvcNAQELBQAwZTELMAkGA1UE
# BhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2lj
# ZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4X
# DTEzMTAyMjEyMDAwMFoXDTI4MTAyMjEyMDAwMFowcjELMAkGA1UEBhMCVVMxFTAT
# BgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEx
# MC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIENvZGUgU2lnbmluZyBD
# QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPjTsxx/DhGvZ3cH0wsx
# SRnP0PtFmbE620T1f+Wondsy13Hqdp0FLreP+pJDwKX5idQ3Gde2qvCchqXYJawO
# eSg6funRZ9PG+yknx9N7I5TkkSOWkHeC+aGEI2YSVDNQdLEoJrskacLCUvIUZ4qJ
# RdQtoaPpiCwgla4cSocI3wz14k1gGL6qxLKucDFmM3E+rHCiq85/6XzLkqHlOzEc
# z+ryCuRXu0q16XTmK/5sy350OTYNkO/ktU6kqepqCquE86xnTrXE94zRICUj6whk
# PlKWwfIPEvTFjg/BougsUfdzvL2FsWKDc0GCB+Q4i2pzINAPZHM8np+mM6n9Gd8l
# k9ECAwEAAaOCAc0wggHJMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQD
# AgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHkGCCsGAQUFBwEBBG0wazAkBggrBgEF
# BQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRw
# Oi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0Eu
# Y3J0MIGBBgNVHR8EejB4MDqgOKA2hjRodHRwOi8vY3JsNC5kaWdpY2VydC5jb20v
# RGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMDqgOKA2hjRodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsME8GA1UdIARI
# MEYwOAYKYIZIAYb9bAACBDAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdp
# Y2VydC5jb20vQ1BTMAoGCGCGSAGG/WwDMB0GA1UdDgQWBBRaxLl7KgqjpepxA8Bg
# +S32ZXUOWDAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzANBgkqhkiG
# 9w0BAQsFAAOCAQEAPuwNWiSz8yLRFcgsfCUpdqgdXRwtOhrE7zBh134LYP3DPQ/E
# r4v97yrfIFU3sOH20ZJ1D1G0bqWOWuJeJIFOEKTuP3GOYw4TS63XX0R58zYUBor3
# nEZOXP+QsRsHDpEV+7qvtVHCjSSuJMbHJyqhKSgaOnEoAjwukaPAJRHinBRHoXpo
# aK+bp1wgXNlxsQyPu6j4xRJon89Ay0BEpRPw5mQMJQhCMrI2iiQC/i9yfhzXSUWW
# 6Fkd6fp0ZGuy62ZD2rOwjNXpDd32ASDOmTFjPQgaGLOBm0/GkxAG/AeB+ova+YJJ
# 92JuoVP6EpQYhS6SkepobEQysmah5xikmmRR7zCCBTEwggQZoAMCAQICEATXXWwF
# Amc0oYJANZC+s04wDQYJKoZIhvcNAQELBQAwcjELMAkGA1UEBhMCVVMxFTATBgNV
# BAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8G
# A1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIENvZGUgU2lnbmluZyBDQTAe
# Fw0xOTAyMTEwMDAwMDBaFw0yMjAyMTUxMjAwMDBaMG4xCzAJBgNVBAYTAlVTMREw
# DwYDVQQIEwhNaWNoaWdhbjESMBAGA1UEBxMJQW5uIEFyYm9yMRswGQYDVQQKExJE
# dW8gU2VjdXJpdHksIEluYy4xGzAZBgNVBAMTEkR1byBTZWN1cml0eSwgSW5jLjCC
# ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALkvmkFWWRtA+5EAkLznwWs+
# GGbpaQjnhEDEG15JG1+W2ZF2s8xgQLqP2qi/sNbeWjeyAWkDcMGjpGeOc1t5ShE9
# FflJWPP3I95KTd+/S67AeQ5I9O6EQK4z4kotwcOTU/RmRMT92aks9BEuRKiUp1xG
# xU+W3sQiR7pQqNnJ05mY93Pycu4SOuMFNGDF2F0waYaSC2vNXWVDnE4iMcf/80zh
# VC2wKb7WxCIX/BYagWrbG3WZeBovKYWoRTkUY66eL4RJFfCg7/wjLh/OlOGcaMWU
# GJzFsyJuGpgDnf8II8p8WiarHhI5w2hs/LOALR41f+wKsXm+hwVwfLuai0UwZtEC
# AwEAAaOCAcUwggHBMB8GA1UdIwQYMBaAFFrEuXsqCqOl6nEDwGD5LfZldQ5YMB0G
# A1UdDgQWBBRQNxhKzQ9yurjOF8R58do+SEamrDAOBgNVHQ8BAf8EBAMCB4AwEwYD
# VR0lBAwwCgYIKwYBBQUHAwMwdwYDVR0fBHAwbjA1oDOgMYYvaHR0cDovL2NybDMu
# ZGlnaWNlcnQuY29tL3NoYTItYXNzdXJlZC1jcy1nMS5jcmwwNaAzoDGGL2h0dHA6
# Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9zaGEyLWFzc3VyZWQtY3MtZzEuY3JsMEwGA1Ud
# IARFMEMwNwYJYIZIAYb9bAMBMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRp
# Z2ljZXJ0LmNvbS9DUFMwCAYGZ4EMAQQBMIGEBggrBgEFBQcBAQR4MHYwJAYIKwYB
# BQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBOBggrBgEFBQcwAoZCaHR0
# cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0U0hBMkFzc3VyZWRJRENv
# ZGVTaWduaW5nQ0EuY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEB
# AGfi8s7jagGJM7xzZi7Ru0ZGDsCdmYi03F5jeWiSRYL4yAaUcvHh3DmK0zqBcHRX
# amVKfRNSPtah+T+34KNKIuB9LXsw7EdmESVHl/SbV6s0o4xgLj6q10rz9I18ylGo
# 75vceLDbnjn1DcoKn2ni03JbUiEueYmqU28mJA9Y8q6rS2ayXjP+doKoVrUiwtKX
# uf+6lvt+h8qbf3hkqDY8iMGNtcj3czrbfO4zqAM6RaoQK+ZQcrZlG6GOxpgtJo3Y
# zJ4QHBtfCjGOlr2ddagaJbfwxVMxgMXz33F2OYag4kelIY1qsyB3q5j1MHph9eK/
# IWcrmLvCrIuLZ2CTxmoHdTIwggUxMIIEGaADAgECAhAKoSXW1jIbfkHkBdo2l8IV
# MA0GCSqGSIb3DQEBCwUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lD
# ZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0xNjAxMDcxMjAwMDBaFw0zMTAxMDcx
# MjAwMDBaMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAX
# BgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERpZ2lDZXJ0IFNIQTIg
# QXNzdXJlZCBJRCBUaW1lc3RhbXBpbmcgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
# DwAwggEKAoIBAQC90DLuS82Pf92puoKZxTlUKFe2I0rEDgdFM1EQfdD5fU1ofue2
# oPSNs4jkl79jIZCYvxO8V9PD4X4I1moUADj3Lh477sym9jJZ/l9lP+Cb6+NGRwYa
# VX4LJ37AovWg4N4iPw7/fpX786O6Ij4YrBHk8JkDbTuFfAnT7l3ImgtU46gJcWvg
# zyIQD3XPcXJOCq3fQDpct1HhoXkUxk0kIzBdvOw8YGqsLwfM/fDqR9mIUF79Zm5W
# YScpiYRR5oLnRlD9lCosp+R1PrqYD4R/nzEU1q3V8mTLex4F0IQZchfxFwbvPc3W
# Te8GQv2iUypPhR3EHTyvz9qsEPXdrKzpVv+TAgMBAAGjggHOMIIByjAdBgNVHQ4E
# FgQU9LbhIB3+Ka7S5GGlsqIlssgXNW4wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGL
# p6chnfNtyA8wEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwEwYD
# VR0lBAwwCgYIKwYBBQUHAwgweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwgYEG
# A1UdHwR6MHgwOqA4oDaGNGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dEFzc3VyZWRJRFJvb3RDQS5jcmwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwUAYDVR0gBEkwRzA4Bgpg
# hkgBhv1sAAIEMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNv
# bS9DUFMwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4IBAQBxlRLpUYdWac3v
# 3dp8qmN6s3jPBjdAhO9LhL/KzwMC/cWnww4gQiyvd/MrHwwhWiq3BTQdaq6Z+Cei
# Zr8JqmDfdqQ6kw/4stHYfBli6F6CJR7Euhx7LCHi1lssFDVDBGiy23UC4HLHmNY8
# ZOUfSBAYX4k4YU1iRiSHY4yRUiyvKYnleB/WCxSlgNcSR3CzddWThZN+tpJn+1Nh
# iaj1a5bA9FhpDXzIAbG5KHW3mWOFIoxhynmUfln8jA/jb7UBJrZspe6HUSHkWGCb
# ugwtK22ixH67xCUrRwIIfEmuE7bhfEJCKMYYVs9BNLZmXbZ0e/VWMyIvIjayS6JK
# ldj1po5SMYIEbTCCBGkCAQEwgYYwcjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERp
# Z2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UEAxMo
# RGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIENvZGUgU2lnbmluZyBDQQIQBNddbAUC
# ZzShgkA1kL6zTjAJBgUrDgMCGgUAoIGIMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3
# AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEW
# BBSSTgDZGZBbSU80gRiGLZ+AuFCDKzAoBgorBgEEAYI3AgEMMRowGKEWgBR3d3cu
# ZHVvc2VjdXJpdHkuY29tIDANBgkqhkiG9w0BAQEFAASCAQBLr57y175LGoZ1zZsL
# ArRBnRa2Db3n1tjNikYUvdNxWcUzs9JyAKmtA4Zr/QR4HucCFnhn17MdQsEWSmE8
# kMb75CZ7KyOHptnMs9bcg2PeGS5zxyeifA3Sfk1m0yUcyvNcFyODjlzwJZvvrvRV
# aLUQIIithiLhVWvJiQw5P4R/NRPIwU+v8UQCvlGrt8i8zc0OulT5CR13+JlfIhbF
# oh44//sOLX0aUsyaIc7+9J7GDeuCN/sxtJeUSxSECupBjZ+dN1St9jmcxESg8IGI
# XcNZLTjdbmyte2apaA7fRZfG5wfQIAY3fFgdklz6esfD4cZ7FnRkXu0U8XzIr4a/
# jKPdoYICMDCCAiwGCSqGSIb3DQEJBjGCAh0wggIZAgEBMIGGMHIxCzAJBgNVBAYT
# AlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2Vy
# dC5jb20xMTAvBgNVBAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBUaW1lc3Rh
# bXBpbmcgQ0ECEA1CSuC+Ooj/YEAhzhQA8N0wDQYJYIZIAWUDBAIBBQCgaTAYBgkq
# hkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMTA5MTUxODAy
# MThaMC8GCSqGSIb3DQEJBDEiBCAskQkdNUGVB34i0BE2yF9xwsKamgPZ/k5Cvl8H
# YFZ73DANBgkqhkiG9w0BAQEFAASCAQB7AX1ocgmo0JTYR5jP77MmKHHmsYRezOG3
# pZKyLEvZWv2+zN9LCJUYrZqd34w74xJPxFXAItCwKH4O4JPIqgxvNJAE7V83/HwS
# zhU7aJVbu+7FPqoT40zVM1xsKXc6O+MhbFZj8fRvbsqzvORSDLLbQk+p1GMupruN
# lillD/r7krByfC7w88fclgk5klpOI5IwqCEU8gdbWMAK+PQ3rSoy+FLT567BGFBK
# Nw0aXYA/pHUx9ieZUyjvV5Vuk45/qNgyM1rqUJ+Ew1H+h+5T33FAZSQkFzo2k/gv
# nqigw/pUsPRmoir7UNF6wf6401FplnpWEkk