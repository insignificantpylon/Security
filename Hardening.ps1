#Requires -RunAsAdministrator

<#
    CombinedSecurityScript.ps1 - Comprehensive System Hardening Script
    Author: Adapted by Grok 3 (xAI) from original scripts
    Date: February 28, 2025
    Description: Combines browser virtualization, audio settings configuration, WebRTC/remote desktop/plugin management,
                 network/service hardening, privilege rights, and WDAC policies into a single hardening script.
#>

param (
    [switch]$AddToStartup = $false
)

# Ensure unrestricted execution policy for this session
$originalPolicy = Get-ExecutionPolicy -Scope Process
if ($originalPolicy -ne "Unrestricted") {
    Write-Host "[$(Get-Date)] Setting execution policy to Unrestricted for this session..." -ForegroundColor Cyan
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
}

# Function to log messages
function Write-LogMessage {
    param ([string]$Message, [string]$Color = "Green")
    Write-Host "[$(Get-Date)] $Message" -ForegroundColor $Color
}

# Function to virtualize browsers with App-V
function Harden-BrowserVirtualization {
    Write-LogMessage "Starting browser virtualization..."

    function IsVirtualizedProcess([string]$processName) {
        $virtualizedProcesses = Get-AppvClientPackage | Get-AppvClientProcess -ErrorAction SilentlyContinue
        return $virtualizedProcesses.Name -contains $processName
    }

    function LaunchVirtualizedProcess([string]$executablePath) {
        if (Test-Path $executablePath) {
            Write-LogMessage "Launching virtualized process: $executablePath"
            Start-AppvVirtualProcess -AppvClientObject (Get-AppvClientPackage) -AppvVirtualPath $executablePath -ErrorAction SilentlyContinue
        } else {
            Write-LogMessage "Error: Executable not found at $executablePath" "Red"
        }
    }

    function EnableAppV {
        $hyperVAppVState = (Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-AppV" -ErrorAction SilentlyContinue).State
        if ($hyperVAppVState -ne "Enabled") {
            Write-LogMessage "Enabling App-V feature..."
            Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-AppV" -NoRestart -ErrorAction Stop
        }
    }

    $installedBrowsers = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                         Where-Object { $_.DisplayName -match "chrome|firefox|msedge|opera|waterfox|chromium|ur|vivaldi|brave" } |
                         Select-Object -ExpandProperty DisplayName

    foreach ($browser in $installedBrowsers) {
        if (-not (IsVirtualizedProcess "$browser.exe")) {
            EnableAppV
            $virtualizedPath = "C:\Program Files\AppVirt\VirtualizedBrowsers\$($browser).exe"
            LaunchVirtualizedProcess $virtualizedPath
        }
    }
    Write-LogMessage "Browser virtualization complete."
}

# Function to configure audio settings (AEC and Noise Suppression)
function Harden-AudioSettings {
    Write-LogMessage "Configuring audio settings..."
    $renderDevicesKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render"
    $audioDevices = Get-ChildItem -Path $renderDevicesKey -ErrorAction SilentlyContinue

    foreach ($device in $audioDevices) {
        $fxPropertiesKey = "$($device.PSPath)\FxProperties"
        if (-not (Test-Path $fxPropertiesKey)) {
            New-Item -Path $fxPropertiesKey -Force | Out-Null
            Write-LogMessage "Created FxProperties key for device: $($device.PSChildName)"
        }

        $aecKey = "{1c7b1faf-caa2-451b-b0a4-87b19a93556a},6"
        $noiseKey = "{e0f158e1-cb04-43d5-b6cc-3eb27e4db2a1},3"
        $enableValue = 1

        $currentAEC = Get-ItemProperty -Path $fxPropertiesKey -Name $aecKey -ErrorAction SilentlyContinue
        if ($currentAEC.$aecKey -ne $enableValue) {
            Set-ItemProperty -Path $fxPropertiesKey -Name $aecKey -Value $enableValue
            Write-LogMessage "Acoustic Echo Cancellation enabled for device: $($device.PSChildName)" "Yellow"
        }

        $currentNoise = Get-ItemProperty -Path $fxPropertiesKey -Name $noiseKey -ErrorAction SilentlyContinue
        if ($currentNoise.$noiseKey -ne $enableValue) {
            Set-ItemProperty -Path $fxPropertiesKey -Name $noiseKey -Value $enableValue
            Write-LogMessage "Noise Suppression enabled for device: $($device.PSChildName)" "Yellow"
        }
    }
    Write-LogMessage "Audio settings configured."
}

# Function to configure WebRTC, remote desktop, and plugins
function Harden-BrowserSettings {
    Write-LogMessage "Configuring browser settings (WebRTC, remote desktop, plugins)..."
    
    $desiredSettings = @{
        "media_stream" = 2
        "webrtc"       = 2
        "remote" = @{
            "enabled" = $false
            "support" = $false
        }
    }

    function Check-And-Apply-Settings {
        param ([string]$browserName, [string]$prefsPath)
        if (Test-Path $prefsPath) {
            $prefsContent = Get-Content -Path $prefsPath -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($prefsContent) {
                $settingsChanged = $false
                
                if ($prefsContent.profile -and $prefsContent.profile["default_content_setting_values"]) {
                    foreach ($key in $desiredSettings.Keys | Where-Object { $_ -ne "remote" }) {
                        if ($prefsContent.profile["default_content_setting_values"][$key] -ne $desiredSettings[$key]) {
                            $prefsContent.profile["default_content_setting_values"][$key] = $desiredSettings[$key]
                            $settingsChanged = $true
                        }
                    }
                }

                if ($prefsContent.remote) {
                    foreach ($key in $desiredSettings["remote"].Keys) {
                        if ($prefsContent.remote[$key] -ne $desiredSettings["remote"][$key]) {
                            $prefsContent.remote[$key] = $desiredSettings["remote"][$key]
                            $settingsChanged = $true
                        }
                    }
                }

                if ($settingsChanged) {
                    $prefsContent | ConvertTo-Json -Compress | Set-Content -Path $prefsPath
                    Write-LogMessage "${browserName}: Updated WebRTC and remote desktop settings."
                }
            }

            if ($prefsContent.plugins) {
                foreach ($plugin in $prefsContent.plugins) {
                    $plugin.enabled = $false
                }
                Write-LogMessage "${browserName}: Plugins disabled."
            }
        }
    }

    function Configure-Firefox {
        $firefoxProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
        if (Test-Path $firefoxProfilePath) {
            $firefoxProfiles = Get-ChildItem -Path $firefoxProfilePath -Directory
            foreach ($profile in $firefoxProfiles) {
                $prefsJsPath = "$($profile.FullName)\prefs.js"
                if (Test-Path $prefsJsPath) {
                    $prefsJsContent = Get-Content -Path $prefsJsPath
                    if ($prefsJsContent -notmatch 'user_pref\("media.peerconnection.enabled", false\)') {
                        Add-Content -Path $prefsJsPath 'user_pref("media.peerconnection.enabled", false);'
                        Write-LogMessage "Firefox profile ${profile.FullName}: WebRTC disabled."
                    }
                }
            }
        }
    }

    $browsers = @{
        "Chrome" = "$env:LOCALAPPDATA\Google\Chrome\User Data\Preferences"
        "Brave" = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Preferences"
        "Vivaldi" = "$env:LOCALAPPDATA\Vivaldi\User Data\Preferences"
        "Edge" = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Preferences"
        "Opera" = "$env:APPDATA\Opera Software\Opera Stable\Preferences"
        "OperaGX" = "$env:APPDATA\Opera Software\Opera GX Stable\Preferences"
    }

    foreach ($browser in $browsers.GetEnumerator()) {
        if (Test-Path $browser.Value) {
            Check-And-Apply-Settings -browserName $browser.Key -prefsPath $browser.Value
        }
    }

    Configure-Firefox
    Write-LogMessage "Browser settings configured."
}

# Function to disable Chrome Remote Desktop
function Disable-ChromeRemoteDesktop {
    Write-LogMessage "Disabling Chrome Remote Desktop..."

    $serviceName = "chrome-remote-desktop-host"
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        Stop-Service -Name $serviceName -Force
        Set-Service -Name $serviceName -StartupType Disabled
        Write-LogMessage "Chrome Remote Desktop Host service stopped and disabled."
    }

    $browsers = @("chrome", "msedge", "brave", "vivaldi", "opera", "operagx")
    foreach ($browser in $browsers) {
        $processes = Get-Process -Name $browser -ErrorAction SilentlyContinue
        if ($processes) {
            Stop-Process -Name $browser -Force
            Write-LogMessage "Terminated process: $browser"
        }
    }

    $ruleName = "Block CRD Ports"
    if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -DisplayName $ruleName
    }
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort 443 -Action Block -Profile Any
    Write-LogMessage "Chrome Remote Desktop disabled."
}

# Function to harden network and services
function Harden-NetworkAndServices {
    Write-LogMessage "Hardening network and services..."

    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0
    Stop-Service -Name "TermService" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "TermService" -StartupType Disabled -ErrorAction SilentlyContinue
    Disable-PSRemoting -Force -ErrorAction SilentlyContinue
    Stop-Service -Name "WinRM" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "WinRM" -StartupType Disabled -ErrorAction SilentlyContinue

    Set-SmbServerConfiguration -EnableSMB1Protocol $false -EnableSMB2Protocol $false -Force -ErrorAction SilentlyContinue
    Disable-WindowsOptionalFeature -Online -FeatureName "TelnetClient" -NoRestart -ErrorAction SilentlyContinue

    Get-NetAdapter | ForEach-Object {
        Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName "Wake on Magic Packet" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
        Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName "Wake on Pattern Match" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
    }

    $rules = @(
        @{DisplayName="Block RDP"; LocalPort=3389; Protocol="TCP"},
        @{DisplayName="Block SMB TCP 445"; LocalPort=445; Protocol="TCP"},
        @{DisplayName="Block Telnet"; LocalPort=23; Protocol="TCP"}
    )
    foreach ($rule in $rules) {
        if (-not (Get-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $rule.DisplayName -Direction Inbound -LocalPort $rule.LocalPort -Protocol $rule.Protocol -Action Block -ErrorAction SilentlyContinue
        }
    }

    $serviceName = "gpsvc"
    $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
    $acl = Get-Acl -Path $servicePath
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $acl.SetOwner([System.Security.Principal.NTAccount]$currentUser)
    $accessRule = New-Object System.Security.AccessControl.RegistryAccessRule ($currentUser, "FullControl", "Allow")
    $acl.SetAccessRule($accessRule)
    Set-Acl -Path $servicePath -AclObject $acl
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue

    Write-LogMessage "Network and services hardened."
}

# Function to apply privilege rights
function Harden-PrivilegeRights {
    Write-LogMessage "Applying privilege rights..."
    $privilegeSettings = @'
[Privilege Rights]
SeChangeNotifyPrivilege = *S-1-1-0
SeInteractiveLogonRight = *S-1-5-32-544
SeDenyNetworkLogonRight = *S-1-5-11
SeDenyInteractiveLogonRight = Guest
SeDenyRemoteInteractiveLogonRight = *S-1-5-11
SeDenyServiceLogonRight = *S-1-5-32-545
SeNetworkLogonRight=
SeRemoteShutdownPrivilege=
SeAssignPrimaryTokenPrivilege=
SeBackupPrivilege=
SeCreateTokenPrivilege=
SeDebugPrivilege=
SeImpersonatePrivilege=
SeLoadDriverPrivilege=
SeRemoteInteractiveLogonRight=
SeServiceLogonRight=
'@
    $cfgPath = "C:\secpol.cfg"
    secedit /export /cfg $cfgPath /quiet
    $privilegeSettings | Out-File -Append -FilePath $cfgPath
    secedit /configure /db c:\windows\security\local.sdb /cfg $cfgPath /areas USER_RIGHTS /quiet
    Remove-Item $cfgPath -Force
    Write-LogMessage "Privilege rights applied."
}

# Function to apply WDAC policy
function Harden-WDACPolicy {
    Write-LogMessage "Applying WDAC policy..."
    Import-Module -Name WDAC -ErrorAction SilentlyContinue
    $WDACPolicyXML = @"
<?xml version="1.0" encoding="UTF-8"?>
<SIPolicy PolicyType="SignedAndUnsigned" Version="1">
  <Settings>
    <Setting Value="Enabled:Unsigned System Integrity Policy" Key="PolicyType"/>
    <Setting Value="Enforced" Key="PolicyState"/>
  </Settings>
  <Rules>
    <Rule ID="1" Action="Allow" FriendlyName="Allow Windows System Binaries">
      <Conditions>
        <FilePathCondition>C:\Windows\System32\</FilePathCondition>
      </Conditions>
    </Rule>
    <Rule ID="2" Action="Allow" FriendlyName="Allow Microsoft Signed">
      <Conditions>
        <FilePublisherCondition>
          <PublisherName>Microsoft Corporation</PublisherName>
          <ProductName>Windows</ProductName>
        </FilePublisherCondition>
      </Conditions>
    </Rule>
    <Rule ID="3" Action="Allow" FriendlyName="Allow User Scripts">
      <Conditions>
        <FilePathCondition>C:\Windows\Setup\Scripts\*.ps1</FilePathCondition>
      </Conditions>
    </Rule>
  </Rules>
</SIPolicy>
"@
    $PolicyPath = "C:\WDACPolicy.xml"
    $WDACBinaryPath = "C:\Windows\System32\CodeIntegrity\SiPolicy.p7b"
    try {
        $WDACPolicyXML | Out-File -Encoding utf8 -FilePath $PolicyPath
        ConvertFrom-CIPolicy -XmlFilePath $PolicyPath -BinaryFilePath $WDACBinaryPath
        Copy-Item -Path $WDACBinaryPath -Destination "C:\Windows\System32\CodeIntegrity\SiPolicy.p7b" -Force
        Write-LogMessage "WDAC policy applied. Restart required."
    } catch {
        Write-LogMessage "Error applying WDAC policy: $_" "Red"
    }
    Remove-Item -Path $PolicyPath -Force -ErrorAction SilentlyContinue
}

# Function to add script to startup
function Add-ToStartup {
    $scriptPath = $MyInvocation.MyCommand.Definition
    $startupFolder = [Environment]::GetFolderPath("Startup")
    $shortcutPath = Join-Path $startupFolder "CombinedSecurity.lnk"
    if (-not (Test-Path $shortcutPath)) {
        Write-LogMessage "Adding script to startup..."
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = "powershell.exe"
        $shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
        $shortcut.Save()
    }
}

# Main execution
try {
    Write-LogMessage "Starting comprehensive security hardening process..."
    Harden-BrowserVirtualization
    Harden-AudioSettings
    Harden-BrowserSettings
    Disable-ChromeRemoteDesktop
    Harden-NetworkAndServices
    Harden-PrivilegeRights
    Harden-WDACPolicy
    if ($AddToStartup) { Add-ToStartup }
    Write-LogMessage "Security hardening completed successfully."
    Write-LogMessage "Recommendation: Ensure UAC is enabled (HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, EnableLUA = 1)" "Yellow"
} catch {
    Write-LogMessage "Error during hardening: $_" "Red"
} finally {
    if ($originalPolicy -ne "Unrestricted") {
        Set-ExecutionPolicy -ExecutionPolicy $originalPolicy -Scope Process -Force
    }
}