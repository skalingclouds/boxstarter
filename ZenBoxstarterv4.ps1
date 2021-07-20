
#Windows Tweaks
$Configuration = @(
    'DisableWiFiSense',
    'DisableMapUpdates',
    'DisableFeedback',
    'DisableWAPPush',
    'DisableSleepTimeout',
    'DisableRemoteAssistance',
    'UninstallMsftBloat',
    'UninstallThirdPartyBloat',
    'DisableFastStartup',
    'DisableSuperfetch',
    'SetUnknownNetworksPrivate',
    'DisableNetDevicesAutoInst',
    'DisableSmartScreen',
    'DisableIndexing'
)
$ManualDownloadInstall = @{
    'amd-chipsetdriver.exe'  = 'https://ftp.nluug.nl/pub/games/PC/guru3d/amd/[Guru3D.com]-amd-chipset-drivers.exe';
    'audio-driver.zip'       = 'https://dlcdnets.asus.com/pub/ASUS/mb/SocketAM4/ROG_CROSSHAIR_VIII_DARK_HERO/Realtek_Audio_Driver_V6.0.8960.1_WIN10_64-bit.zip';
    'l-connect.zip'          = 'https://lian-li.com/downloads/L-connect.zip';
    'device-cleanup-cmd.zip' = 'https://www.uwe-sieber.de/files/devicecleanupcmd.zip';
    'benchmate.exe'          = 'https://s3.eu-central-1.wasabisys.com/benchmate/downloads/bm-0.10.7.2-offline.exe';
    'MacriumV8-Latest.exe'   = 'https://skalingclouds.blob.core.windows.net/zenboxsetupfiles/Macrium_v8_x64.exe';
    'mobros.exe'             = 'https://skalingclouds.blob.core.windows.net/zenboxsetupfiles/MoBros.exe'
}
# Releases based github packages to download and install. I include Keeweb and the Hack font I love so dearly
$GithubReleasesPackages = @{
    'farag2/Windows-10-Sophia-Script' = 'Sophia.Script.v*.*.*.zip';
    'Maassoft/ColorControl'           = 'ColorControl.zip';
    'lostindark/DriverStoreExplorer'  = 'DriverStoreExplorer.v*.*.*.zip';
    'krlvm/BeautySearch'              = 'BeautySearch.exe';
    'sandboxie-plus/Sandboxie'        = 'Sandboxie-Plus-x64.exe';
    'stnkl/EverythingToolbar'         = 'EverythingToolbar-*.*.*.msi';
    'Hofknecht/SystemTrayMenu'        = 'SystemTrayMenu-*.*.*.*.zip';
    'Klocman/Bulk-Crap-Uninstaller'   = 'BCUninstaller_*.*_setup.exe';
    'svenmauch/WinSlap'               = 'WinSlap.exe';
    'AlexanderPro/SmartSystemMenu'    = 'SmartSystemMenu_v*.*.*.zip';
    'CXWorld/CapFrameX'               = 'CapFrameX_v*.*.*_Portable.zip'
}

# PowerShell Modules to install
$ModulesToBeInstalled = @(
    'Az',
    'AzureAD',
    'AzureADPreview',
    'Configuration',
    'CredentialManager',
    'EZOut',
    'HistoryPx',
    'InvokeBuild',
    'PackageManagement',
    'Pansies',
    'platyPS',
    'PowerLine',
    'PowerShellGet',
    'powershell-yaml',
    'psake',
    'PSCodeHealth',
    'PSDecode',
    'PSDepend',
    'PSGit',
    'PSGraph',
    'psmsgraph',
    'PSScriptAnalyzer',
    'SnippetPx',
    'WinSCP',
    'psWinGlue',
    'PSreadline',
    'oh-my-posh',
    'posh-git',
    'Terminal-Icons',
    'PowerPlan'
)
# Chocolatey packages to install
$ChocoInstalls = @(
    'powershell-core',
    'microsoft-windows-terminal',
    'chocolateygui',
    'gitkraken',
    'gpg4win',
    'git',
    'Git-Credential-Manager-for-Windows',
    'openssh',
    'vscode',
    'rufus',
    'powertoys',
    '7zip',
    'github-desktop',
    'notepadplusplus',
    'chocolateypackageupdater',
    'windirstat',
    'quicklook',
    'cascadia-code-nerd-font',
    'terminal-icons.powershell',
    'notion',
    'latencymon',
    'furmark',
    'aida64-extreme',
    'cpu-z',
    'gpu-z',
    'occt',
    'nvidia-geforce-now',
    'steam',
    'ubisoft-connect',
    'epicgameslauncher',
    'choco-cleaner',
    'brave',
    'curl',
    'dotnet-runtime',
    'gitextensions',
    'gh',
    'nano',
    'nmap',
    'paint.net',
    'PDFCreator',
    'procexp',
    'putty',
    'sharex',
    'toolsroot',
    'virtualbox',
    'VirtualCloneDrive',
    'vlc',
    'win32diskimager',
    'windirstat',
    'winscp',
    'yumi-uefi',
    'vscode',
    'vcredist140',
    'everything',
    'discord',
    'evga-precision-x1',
    'Spotify',
    'setuserfta',
    'taskbarx',
    'Autohotkey'
)

Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('http://boxstarter.org/bootstrapper.ps1')); get-boxstarter -Force
$UtilBinPath = "C:\ZenBoxSetup\UtilBin"
$UtilDownloadPath = "C:\ZenboxSetup\Downloads"
$CreatePowershellProfile = $true
$BoxStarter.Rebootok = $false
$BoxStarter.NoPassword = $true
$BoxStarter.AutoLogin = $false
Disable-MicrosoftUpdate
Disable-UAC
Enable-RemoteDesktop
choco feature enable -n allowGlobalConfirmation
# Need this to download via Invoke-WebRequest

[Net.ServicePointManager]::SecurityProtocol = [System.Security.Authentication.SslProtocols] "tls, tls11, tls12"
Set-ExecutionPolicy -ExecutionPolicy Bypass -Force
# Trust the psgallery for installs
Write-Host -ForegroundColor 'Yellow' 'Setting PSGallery as a trusted installation source...'
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

function Start-Proc {
    param([string]$Exe = $(Throw "An executable must be specified"),
        [string]$Arguments,
        [switch]$Hidden,
        [switch]$waitforexit)

    $startinfo = New-Object System.Diagnostics.ProcessStartInfo
    $startinfo.FileName = $Exe
    $startinfo.Arguments = $Arguments
    if ($Hidden) {
        $startinfo.WindowStyle = 'Hidden'
        $startinfo.CreateNoWindow = $True
    }
    $process = [System.Diagnostics.Process]::Start($startinfo)
    if ($waitforexit) { $process.WaitForExit() }
}

function Get-ChocoPackages {
    if (Get-Command clist -ErrorAction:SilentlyContinue) {
        clist -lo -r -all | ForEach-Object {
            $Name, $Version = $_ -split '\|'
            New-Object -TypeName psobject -Property @{
                'Name'    = $Name
                'Version' = $Version
            }
        }
    }
}

# Disable Wi-Fi Sense
Function DisableWiFiSense {
    Write-Host "Disabling Wi-Fi Sense..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Type Dword -Value 0
}

# Enable Wi-Fi Sense
Function EnableWiFiSense {
    Write-Host "Enabling Wi-Fi Sense..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 1
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -ErrorAction SilentlyContinue
}

# Disable SmartScreen Filter
Function DisableSmartScreen {
    Write-Host "Disabling SmartScreen Filter..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 0
    $edge = (Get-AppxPackage -AllUsers "Microsoft.MicrosoftEdge").PackageFamilyName
    If (!(Test-Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter")) {
        New-Item -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -Name "PreventOverride" -Type DWord -Value 0
}

# Enable SmartScreen Filter
Function EnableSmartScreen {
    Write-Host "Enabling SmartScreen Filter..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "RequireAdmin"
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -ErrorAction SilentlyContinue
    $edge = (Get-AppxPackage -AllUsers "Microsoft.MicrosoftEdge").PackageFamilyName
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -Name "PreventOverride" -ErrorAction SilentlyContinue
}

Function DisableMapUpdates {
    Write-Host "Disabling automatic Maps updates..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
}

# Enable automatic Maps updates
Function EnableMapUpdates {
    Write-Host "Enable automatic Maps updates..."
    Remove-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -ErrorAction SilentlyContinue
}

# Disable Feedback
Function DisableFeedback {
    Write-Host "Disabling Feedback..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
}

# Enable Feedback
Function EnableFeedback {
    Write-Host "Enabling Feedback..."
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -ErrorAction SilentlyContinue
    Enable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
    Enable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
}

# Disable Advertising ID
Function DisableAdvertisingID {
    Write-Host "Disabling Advertising ID..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type DWord -Value 0
}

# Enable Advertising ID
Function EnableAdvertisingID {
    Write-Host "Enabling Advertising ID..."
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -ErrorAction SilentlyContinue
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type DWord -Value 2
}

# Stop and disable WAP Push Service
Function DisableWAPPush {
    Write-Host "Stopping and disabling WAP Push Service..."
    Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
    Set-Service "dmwappushservice" -StartupType Disabled
}

# Enable and start WAP Push Service
Function EnableWAPPush {
    Write-Host "Enabling and starting WAP Push Service..."
    Set-Service "dmwappushservice" -StartupType Automatic
    Start-Service "dmwappushservice" -WarningAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "DelayedAutoStart" -Type DWord -Value 1
}

##########
# Service Tweaks
##########

# Lower UAC level (disabling it completely would break apps)
Function SetUACLow {
    Write-Host "Lowering UAC level..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
}

# Raise UAC level
Function SetUACHigh {
    Write-Host "Raising UAC level..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
}
Function SetCurrentNetworkPrivate {
    Write-Host "Setting current network profile to private..."
    Set-NetConnectionProfile -NetworkCategory Private
}

# Set current network profile to public (deny file sharing, device discovery, etc.)
Function SetCurrentNetworkPublic {
    Write-Host "Setting current network profile to public..."
    Set-NetConnectionProfile -NetworkCategory Public
}

# Set unknown networks profile to private (allow file sharing, device discovery, etc.)
Function SetUnknownNetworksPrivate {
    Write-Host "Setting unknown networks profile to private..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -Type DWord -Value 1
}

# Set unknown networks profile to public (deny file sharing, device discovery, etc.)
Function SetUnknownNetworksPublic {
    Write-Host "Setting unknown networks profile to public..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue
}

# Disable automatic installation of network devices
Function DisableNetDevicesAutoInst {
    Write-Host "Disabling automatic installation of network devices..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
}

# Enable automatic installation of network devices
Function EnableNetDevicesAutoInst {
    Write-Host "Enabling automatic installation of network devices..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -ErrorAction SilentlyContinue
}

# Disable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
Function DisableRemoteAssistance {
    Write-Host "Disabling Remote Assistance..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
}

# Enable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
Function EnableRemoteAssistance {
    Write-Host "Enabling Remote Assistance..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 1
}

Function DisableSuperfetch {
    Write-Host "Stopping and disabling Superfetch service..."
    Stop-Service "SysMain" -WarningAction SilentlyContinue
    Set-Service "SysMain" -StartupType Disabled
}

# Start and enable Superfetch service - Not applicable to Server
Function EnableSuperfetch {
    Write-Host "Starting and enabling Superfetch service..."
    Set-Service "SysMain" -StartupType Automatic
    Start-Service "SysMain" -WarningAction SilentlyContinue
}

# Stop and disable Windows Search indexing service
Function DisableIndexing {
    Write-Host "Stopping and disabling Windows Search indexing service..."
    Stop-Service "WSearch" -WarningAction SilentlyContinue
    Set-Service "WSearch" -StartupType Disabled
}

# Start and enable Windows Search indexing service
Function EnableIndexing {
    Write-Host "Starting and enabling Windows Search indexing service..."
    Set-Service "WSearch" -StartupType Automatic
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" -Name "DelayedAutoStart" -Type DWord -Value 1
    Start-Service "WSearch" -WarningAction SilentlyContinue
}

Function DisableSleepTimeout {
    Write-Host "Disabling display and sleep mode timeouts..."
    powercfg /X monitor-timeout-ac 0
    powercfg /X monitor-timeout-dc 0
    powercfg /X standby-timeout-ac 0
    powercfg /X standby-timeout-dc 0
}

# Enable display and sleep mode timeouts
Function EnableSleepTimeout {
    Write-Host "Enabling display and sleep mode timeouts..."
    powercfg /X monitor-timeout-ac 10
    powercfg /X monitor-timeout-dc 5
    powercfg /X standby-timeout-ac 30
    powercfg /X standby-timeout-dc 15
}

# Disable Fast Startup
Function DisableFastStartup {
    Write-Host "Disabling Fast Startup..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
}

# Enable Fast Startup
Function EnableFastStartup {
    Write-Host "Enabling Fast Startup..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 1
}

# Uninstall default Microsoft applications
Function UninstallMsftBloat {
    #This function finds any AppX/AppXProvisioned package and uninstalls it, except for Freshpaint, Windows Calculator, Windows Store, and Windows Photos.
    #Also, to note - This does NOT remove essential system services/software/etc such as .NET framework installations, Cortana, Edge, etc.

    #This will self elevate the script so with a UAC prompt since this script needs to be run as an Administrator in order to function properly.
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
        Write-Host "You didn't run this script as an Administrator. This script will self elevate to run as an Administrator and continue."
        Start-Sleep 1
        Write-Host "                                               3"
        Start-Sleep 1
        Write-Host "                                               2"
        Start-Sleep 1
        Write-Host "                                               1"
        Start-Sleep 1
        Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
        Exit
    }

    #no errors throughout
    $ErrorActionPreference = 'silentlycontinue'

    $DebloatFolder = "C:\Temp\Windows10Debloater"
    If (Test-Path $DebloatFolder) {
        Write-Output "$DebloatFolder exists. Skipping."
    }
    Else {
        Write-Output "The folder '$DebloatFolder' doesn't exist. This folder will be used for storing logs created after the script runs. Creating now."
        Start-Sleep 1
        New-Item -Path "$DebloatFolder" -ItemType Directory
        Write-Output "The folder $DebloatFolder was successfully created."
    }
    Start-Transcript -OutputDirectory "$DebloatFolder"
    Function DebloatAll {
        #Removes AppxPackages
        #Credit to /u/GavinEke for a modified version of my whitelist code
        $WhitelistedApps = 'Microsoft.ScreenSketch|Microsoft.Paint3D|Microsoft.WindowsCalculator|Microsoft.WindowsStore|Microsoft.Windows.Photos|CanonicalGroupLimited.UbuntuonWindows|`
    Microsoft.XboxGameCallableUI|Microsoft.XboxGamingOverlay|Microsoft.Xbox.TCUI|Microsoft.XboxGamingOverlay|Microsoft.XboxIdentityProvider|Microsoft.MicrosoftStickyNotes|Microsoft.MSPaint|Microsoft.WindowsCamera|.NET|Framework|`
    Microsoft.HEIFImageExtension|Microsoft.ScreenSketch|Microsoft.StorePurchaseApp|Microsoft.VP9VideoExtensions|Microsoft.WebMediaExtensions|Microsoft.WebpImageExtension|Microsoft.DesktopAppInstaller|WindSynthBerry|MIDIBerry|Slack'
        #NonRemovable Apps that where getting attempted and the system would reject the uninstall, speeds up debloat and prevents 'initalizing' overlay when removing apps
        $NonRemovable = '1527c705-839a-4832-9118-54d4Bd6a0c89|c5e2524a-ea46-4f67-841f-6a9465d9d515|E2A4F912-2574-4A75-9BB0-0D023378592B|F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE|InputApp|Microsoft.AAD.BrokerPlugin|Microsoft.AccountsControl|`
    Microsoft.BioEnrollment|Microsoft.CredDialogHost|Microsoft.ECApp|Microsoft.LockApp|Microsoft.MicrosoftEdgeDevToolsClient|Microsoft.MicrosoftEdge|Microsoft.PPIProjection|Microsoft.Win32WebViewHost|Microsoft.Windows.Apprep.ChxApp|`
    Microsoft.Windows.AssignedAccessLockApp|Microsoft.Windows.CapturePicker|Microsoft.Windows.CloudExperienceHost|Microsoft.Windows.ContentDeliveryManager|Microsoft.Windows.Cortana|Microsoft.Windows.NarratorQuickStart|`
    Microsoft.Windows.ParentalControls|Microsoft.Windows.PeopleExperienceHost|Microsoft.Windows.PinningConfirmationDialog|Microsoft.Windows.SecHealthUI|Microsoft.Windows.SecureAssessmentBrowser|Microsoft.Windows.ShellExperienceHost|`
    Microsoft.Windows.XGpuEjectDialog|Microsoft.XboxGameCallableUI|Windows.CBSPreview|windows.immersivecontrolpanel|Windows.PrintDialog|Microsoft.VCLibs.140.00|Microsoft.Services.Store.Engagement|Microsoft.UI.Xaml.2.0|*Nvidia*'
        Get-AppxPackage -AllUsers | Where-Object { $_.Name -NotMatch $WhitelistedApps -and $_.Name -NotMatch $NonRemovable } | Remove-AppxPackage
        Get-AppxPackage | Where-Object { $_.Name -NotMatch $WhitelistedApps -and $_.Name -NotMatch $NonRemovable } | Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -NotMatch $WhitelistedApps -and $_.PackageName -NotMatch $NonRemovable } | Remove-AppxProvisionedPackage -Online
    }

    Function DebloatBlacklist {
        $Bloatware = @(
            #Unnecessary Windows 10 AppX Apps
            "Microsoft.BingNews"
            "Microsoft.GetHelp"
            "Microsoft.Getstarted"
            "Microsoft.Messaging"
            "Microsoft.Microsoft3DViewer"
            "Microsoft.MicrosoftOfficeHub"
            "Microsoft.MicrosoftSolitaireCollection"
            "Microsoft.NetworkSpeedTest"
            "Microsoft.News"
            "Microsoft.Office.Lens"
            "Microsoft.Office.OneNote"
            "Microsoft.Office.Sway"
            "Microsoft.OneConnect"
            "Microsoft.People"
            "Microsoft.Print3D"
            "Microsoft.SkypeApp"
            "Microsoft.StorePurchaseApp"
            "Microsoft.Office.Todo.List"
            "Microsoft.WindowsAlarms"
            #"Microsoft.WindowsCamera"
            "microsoft.windowscommunicationsapps"
            "Microsoft.WindowsFeedbackHub"
            "Microsoft.WindowsMaps"
            "Microsoft.WindowsSoundRecorder"
            "Microsoft.ZuneMusic"
            "Microsoft.ZuneVideo"
            #Sponsored Windows 10 AppX Apps
            #Add sponsored/featured apps to remove in the "*AppName*" format
            "*EclipseManager*"
            "*ActiproSoftwareLLC*"
            "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
            "*Duolingo-LearnLanguagesforFree*"
            "*PandoraMediaInc*"
            "*CandyCrush*"
            "*BubbleWitch3Saga*"
            "*Wunderlist*"
            "*Flipboard*"
            "*Twitter*"
            "*Facebook*"
            "*Spotify*"
            "*Minecraft*"
            "*Royal Revolt*"
            "*Sway*"
            "*Speed Test*"
            #Optional: Typically not removed but you can if you need to for some reason
            #"*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*"
            #"*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*"
            #"*Microsoft.BingWeather*"
            #"*Microsoft.MSPaint*"
            #"*Microsoft.MicrosoftStickyNotes*"
            #"*Microsoft.Windows.Photos*"
            #"*Microsoft.WindowsCalculator*"
            #"*Microsoft.WindowsStore*"
        )
        foreach ($Bloat in $Bloatware) {
            Get-AppxPackage -Name $Bloat | Remove-AppxPackage
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -Like $Bloat | Remove-AppxProvisionedPackage -Online
            Write-Output "Trying to remove $Bloat."
        }
    }
    Function Remove-Keys {
        #These are the registry keys that it will delete.
        $Keys = @(

            #Remove Background Tasks
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            #Windows File
            "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
            #Scheduled Tasks to delete
            "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
            #Windows Protocol Keys
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            #Windows Share Target
            "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        )
        #This writes the output of each key it is removing and also removes the keys listed above.
        ForEach ($Key in $Keys) {
            Write-Output "Removing $Key from registry"
            Remove-Item $Key -Recurse
        }
    }
    Function Protect-Privacy {
        #Prevents bloatware applications from returning and removes Start Menu suggestions
        Write-Output "Adding Registry key to prevent bloatware apps from returning"
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        $registryOEM = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
        If (!(Test-Path $registryPath)) {
            New-Item $registryPath
        }
        Set-ItemProperty $registryPath DisableWindowsConsumerFeatures -Value 1

        If (!(Test-Path $registryOEM)) {
            New-Item $registryOEM
        }
        Set-ItemProperty $registryOEM ContentDeliveryAllowed -Value 0
        Set-ItemProperty $registryOEM OemPreInstalledAppsEnabled -Value 0
        Set-ItemProperty $registryOEM PreInstalledAppsEnabled -Value 0
        Set-ItemProperty $registryOEM PreInstalledAppsEverEnabled -Value 0
        Set-ItemProperty $registryOEM SilentInstalledAppsEnabled -Value 0
        Set-ItemProperty $registryOEM SystemPaneSuggestionsEnabled -Value 0

        #Preping mixed Reality Portal for removal
        Write-Output "Setting Mixed Reality Portal value to 0 so that you can uninstall it in Settings"
        $Holo = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic"
        If (Test-Path $Holo) {
            Set-ItemProperty $Holo FirstRunSucceeded -Value 0
        }
        #Disables People icon on Taskbar
        Write-Output "Disabling People icon on Taskbar"
        $People = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
        If (Test-Path $People) {
            Set-ItemProperty $People -Name PeopleBand -Value 0
        }

        #Disables scheduled tasks that are considered unnecessary
        Write-Output "Disabling scheduled tasks"
        Get-ScheduledTask UsbCeip | Disable-ScheduledTask
        Get-ScheduledTask DmClient | Disable-ScheduledTask
        Get-ScheduledTask DmClientOnScenarioDownload | Disable-ScheduledTask


        Function Revert-Changes {

            #This function will revert the changes you made when running the Start-Debloat function.

            #This line reinstalls all of the bloatware that was removed
            Get-AppxPackage -AllUsers | ForEach-Object { Add-AppxPackage -Verbose -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }

            #Tells Windows to enable your advertising information.
            Write-Output "Re-enabling key to show advertisement information"
            $Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
            If (Test-Path $Advertising) {
                Set-ItemProperty $Advertising Enabled -Value 1
            }

            #Enables Cortana to be used as part of your Windows Search Function
            Write-Output "Re-enabling Cortana to be used in your Windows Search"
            $Search = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
            If (Test-Path $Search) {
                Set-ItemProperty $Search AllowCortana -Value 1
            }

            #Re-enables the Windows Feedback Experience for sending anonymous data
            Write-Output "Re-enabling Windows Feedback Experience"
            $Period = "HKCU:\Software\Microsoft\Siuf\Rules"
            If (!(Test-Path $Period)) {
                New-Item $Period
            }
            Set-ItemProperty $Period PeriodInNanoSeconds -Value 1

            #Enables bloatware applications
            Write-Output "Adding Registry key to allow bloatware apps to return"
            $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
            If (!(Test-Path $registryPath)) {
                New-Item $registryPath
            }
            Set-ItemProperty $registryPath DisableWindowsConsumerFeatures -Value 0

            #Changes Mixed Reality Portal Key 'FirstRunSucceeded' to 1
            Write-Output "Setting Mixed Reality Portal value to 1"
            $Holo = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic"
            If (Test-Path $Holo) {
                Set-ItemProperty $Holo FirstRunSucceeded -Value 1
            }

            #Re-enables live tiles
            Write-Output "Enabling live tiles"
            $Live = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
            If (!(Test-Path $Live)) {
                New-Item $Live
            }
            Set-ItemProperty $Live NoTileApplicationNotification -Value 0

            #Re-enables data collection
            Write-Output "Re-enabling data collection"
            $DataCollection = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
            If (!(Test-Path $DataCollection)) {
                New-Item $DataCollection
            }
            Set-ItemProperty $DataCollection AllowTelemetry -Value 1

            #Re-enables People Icon on Taskbar
            Write-Output "Enabling People icon on Taskbar"
            $People = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"
            If (!(Test-Path $People)) {
                New-Item $People
            }
            Set-ItemProperty $People PeopleBand -Value 1

            #Re-enables suggestions on start menu
            Write-Output "Enabling suggestions on the Start Menu"
            $Suggestions = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
            If (!(Test-Path $Suggestions)) {
                New-Item $Suggestions
            }
            Set-ItemProperty $Suggestions SystemPaneSuggestionsEnabled -Value 1

            #Re-enables scheduled tasks that were disabled when running the Debloat switch
            Write-Output "Enabling scheduled tasks that were disabled"
            Get-ScheduledTask XblGameSaveTaskLogon | Enable-ScheduledTask
            Get-ScheduledTask XblGameSaveTask | Enable-ScheduledTask
            Get-ScheduledTask Consolidator | Enable-ScheduledTask
            Get-ScheduledTask UsbCeip | Enable-ScheduledTask
            Get-ScheduledTask DmClient | Enable-ScheduledTask
            Get-ScheduledTask DmClientOnScenarioDownload | Enable-ScheduledTask

            Write-Output "Re-enabling and starting WAP Push Service"
            #Enable and start WAP Push Service
            Set-Service "dmwappushservice" -StartupType Automatic
            Start-Service "dmwappushservice"

            Write-Output "Re-enabling and starting the Diagnostics Tracking Service"
            #Enabling the Diagnostics Tracking Service
            Set-Service "DiagTrack" -StartupType Automatic
            Start-Service "DiagTrack"

            Write-Output "Restoring 3D Objects in the 'My Computer' submenu in explorer"
            #Restoring 3D Objects in the 'My Computer' submenu in explorer
            Restore3dObjects
        }

        Function CheckDMWService {

            Param([switch]$Debloat)

            If (Get-Service -Name dmwappushservice | Where-Object { $_.StartType -eq "Disabled" }) {
                Set-Service -Name dmwappushservice -StartupType Automatic
            }

            If (Get-Service -Name dmwappushservice | Where-Object { $_.Status -eq "Stopped" }) {
                Start-Service -Name dmwappushservice
            }
        }

        Function Enable-EdgePDF {
            Write-Output "Setting Edge back to default"
            $NoPDF = "HKCR:\.pdf"
            $NoProgids = "HKCR:\.pdf\OpenWithProgids"
            $NoWithList = "HKCR:\.pdf\OpenWithList"
            #Sets edge back to default
            If (Get-ItemProperty $NoPDF NoOpenWith) {
                Remove-ItemProperty $NoPDF NoOpenWith
            }
            If (Get-ItemProperty $NoPDF NoStaticDefaultVerb) {
                Remove-ItemProperty $NoPDF NoStaticDefaultVerb
            }
            If (Get-ItemProperty $NoProgids NoOpenWith) {
                Remove-ItemProperty $NoProgids NoOpenWith
            }
            If (Get-ItemProperty $NoProgids NoStaticDefaultVerb) {
                Remove-ItemProperty $NoProgids NoStaticDefaultVerb
            }
            If (Get-ItemProperty $NoWithList NoOpenWith) {
                Remove-ItemProperty $NoWithList NoOpenWith
            }
            If (Get-ItemProperty $NoWithList NoStaticDefaultVerb) {
                Remove-ItemProperty $NoWithList NoStaticDefaultVerb
            }

            #Removes an underscore '_' from the Registry key for Edge
            $Edge2 = "HKCR:\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_"
            If (Test-Path $Edge2) {
                Set-Item $Edge2 AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723
            }
        }

        Function FixWhitelistedApps {

            If (!(Get-AppxPackage -AllUsers | Select-Object Microsoft.Paint3D, Microsoft.WindowsCalculator, Microsoft.WindowsStore, Microsoft.Windows.Photos)) {

                #Credit to abulgatz for these 4 lines of code
                Get-AppxPackage -AllUsers Microsoft.Paint3D | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
                Get-AppxPackage -AllUsers Microsoft.WindowsCalculator | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
                Get-AppxPackage -AllUsers Microsoft.WindowsStore | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
                Get-AppxPackage -AllUsers Microsoft.Windows.Photos | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
            }
        }

        Function UnpinStart {
            # https://superuser.com/a/1442733
            #Requires -RunAsAdministrator

            $START_MENU_LAYOUT = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
    <LayoutOptions StartTileGroupCellWidth="6" />
    <DefaultLayoutOverride>
        <StartLayoutCollection>
            <defaultlayout:StartLayout GroupCellWidth="6" />
        </StartLayoutCollection>
    </DefaultLayoutOverride>
</LayoutModificationTemplate>
"@

            $layoutFile = "C:\Windows\StartMenuLayout.xml"

            #Delete layout file if it already exists
            If (Test-Path $layoutFile) {
                Remove-Item $layoutFile
            }

            #Creates the blank layout file
            $START_MENU_LAYOUT | Out-File $layoutFile -Encoding ASCII

            $regAliases = @("HKLM", "HKCU")

            #Assign the start layout and force it to apply with "LockedStartLayout" at both the machine and user level
            foreach ($regAlias in $regAliases) {
                $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
                $keyPath = $basePath + "\Explorer"
                IF (!(Test-Path -Path $keyPath)) {
                    New-Item -Path $basePath -Name "Explorer"
                }
                Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1
                Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile
            }

            #Restart Explorer, open the start menu (necessary to load the new layout), and give it a few seconds to process
            Stop-Process -Name explorer
            Start-Sleep -s 5
            $wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys('^{ESCAPE}')
            Start-Sleep -s 5

            #Enable the ability to pin items again by disabling "LockedStartLayout"
            foreach ($regAlias in $regAliases) {
                $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
                $keyPath = $basePath + "\Explorer"
                Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0
            }

            #Restart Explorer and delete the layout file
            Stop-Process -Name explorer

            # Uncomment the next line to make clean start menu default for all new users
            #Import-StartLayout -LayoutPath $layoutFile -MountPath $env:SystemDrive\

            Remove-Item $layoutFile
        }

        Function Remove3dObjects {
            #Removes 3D Objects from the 'My Computer' submenu in explorer
            Write-Host "Removing 3D Objects from explorer 'My Computer' submenu"
            $Objects32 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
            $Objects64 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
            If (Test-Path $Objects32) {
                Remove-Item $Objects32 -Recurse
            }
            If (Test-Path $Objects64) {
                Remove-Item $Objects64 -Recurse
            }
        }

        Function Restore3dObjects {
            #Restores 3D Objects from the 'My Computer' submenu in explorer
            Write-Host "Restoring 3D Objects from explorer 'My Computer' submenu"
            $Objects32 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
            $Objects64 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
            If (!(Test-Path $Objects32)) {
                New-Item $Objects32
            }
            If (!(Test-Path $Objects64)) {
                New-Item $Objects64
            }
        }
        #Creates a "drive" to access the HKCR (HKEY_CLASSES_ROOT)
        Write-Host "Creating PSDrive 'HKCR' (HKEY_CLASSES_ROOT). This will be used for the duration of the script as it is necessary for the removal and modification of specific registry keys."
        New-PSDrive HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
        Start-Sleep 1
        Write-Host "Uninstalling bloatware, please wait."
        DebloatAll
        Write-Host "Bloatware removed."
        Start-Sleep 1
        Write-Host "Removing specific registry keys."
        Remove-Keys
        Write-Host "Leftover bloatware registry keys removed."
        Start-Sleep 1
        Write-Host "Checking to see if any Whitelisted Apps were removed, and if so re-adding them."
        Start-Sleep 1
        FixWhitelistedApps
        Start-Sleep 1
        Write-Host "Re-enabling DMWAppushservice if it was disabled"
        CheckDMWService
        Start-Sleep 1
        Write-Host "Removing 3D Objects from the 'My Computer' submenu in explorer"
        Remove3dObjects
        Start-Sleep 1
    }
    Write-Host "Unloading the HKCR drive..."
    Remove-PSDrive HKCR
    Write-Host "Script has finished. Exiting."
    Stop-Transcript
}

# In case you have removed them for good, you can try to restore the files using installation medium as follows
# New-Item C:\Mnt -Type Directory | Out-Null
# dism /Mount-Image /ImageFile:D:\sources\install.wim /index:1 /ReadOnly /MountDir:C:\Mnt
# robocopy /S /SEC /R:0 "C:\Mnt\Program Files\WindowsApps" "C:\Program Files\WindowsApps"
# dism /Unmount-Image /Discard /MountDir:C:\Mnt
# Remove-Item -Path C:\Mnt -Recurse

# Uninstall default third party applications
function UninstallThirdPartyBloat {
    Write-Host "Uninstalling default third party applications..."
    Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
    Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
    Get-AppxPackage "4DF9E0F8.Netflix" | Remove-AppxPackage
    Get-AppxPackage "Drawboard.DrawboardPDF" | Remove-AppxPackage
    Get-AppxPackage "D52A8D61.FarmVille2CountryEscape" | Remove-AppxPackage
    Get-AppxPackage "GAMELOFTSA.Asphalt8Airborne" | Remove-AppxPackage
    Get-AppxPackage "flaregamesGmbH.RoyalRevolt2" | Remove-AppxPackage
    Get-AppxPackage "AdobeSystemsIncorporated.AdobePhotoshopExpress" | Remove-AppxPackage
    Get-AppxPackage "ActiproSoftwareLLC.562882FEEB491" | Remove-AppxPackage
    Get-AppxPackage "D5EA27B7.Duolingo-LearnLanguagesforFree" | Remove-AppxPackage
    Get-AppxPackage "Facebook.Facebook" | Remove-AppxPackage
    Get-AppxPackage "46928bounde.EclipseManager" | Remove-AppxPackage
    Get-AppxPackage "A278AB0D.MarchofEmpires" | Remove-AppxPackage
    Get-AppxPackage "KeeperSecurityInc.Keeper" | Remove-AppxPackage
    Get-AppxPackage "king.com.BubbleWitch3Saga" | Remove-AppxPackage
    Get-AppxPackage "89006A2E.AutodeskSketchBook" | Remove-AppxPackage
    Get-AppxPackage "CAF9E577.Plex" | Remove-AppxPackage
    Get-AppxPackage "A278AB0D.DisneyMagicKingdoms" | Remove-AppxPackage
    Get-AppxPackage "828B5831.HiddenCityMysteryofShadows" | Remove-AppxPackage
    Get-AppxPackage "WinZipComputing.WinZipUniversal" | Remove-AppxPackage
    Get-AppxPackage "SpotifyAB.SpotifyMusic" | Remove-AppxPackage
    Get-AppxPackage "PandoraMediaInc.29680B314EFC2" | Remove-AppxPackage
    Get-AppxPackage "2414FC7A.Viber" | Remove-AppxPackage
    Get-AppxPackage "64885BlueEdge.OneCalendar" | Remove-AppxPackage
    Get-AppxPackage "41038Axilesoft.ACGMediaPlayer" | Remove-AppxPackage
}

# Install default third party applications
Function InstallThirdPartyBloat {
    Write-Host "Installing default third party applications..."
    Get-AppxPackage -AllUsers "9E2F88E3.Twitter" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "king.com.CandyCrushSodaSaga" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "4DF9E0F8.Netflix" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "Drawboard.DrawboardPDF" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "D52A8D61.FarmVille2CountryEscape" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "GAMELOFTSA.Asphalt8Airborne" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "flaregamesGmbH.RoyalRevolt2" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "AdobeSystemsIncorporated.AdobePhotoshopExpress" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "ActiproSoftwareLLC.562882FEEB491" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "D5EA27B7.Duolingo-LearnLanguagesforFree" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "Facebook.Facebook" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "46928bounde.EclipseManager" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "A278AB0D.MarchofEmpires" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "KeeperSecurityInc.Keeper" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "king.com.BubbleWitch3Saga" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "89006A2E.AutodeskSketchBook" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "CAF9E577.Plex" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "A278AB0D.DisneyMagicKingdoms" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "828B5831.HiddenCityMysteryofShadows" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "WinZipComputing.WinZipUniversal" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "SpotifyAB.SpotifyMusic" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "PandoraMediaInc.29680B314EFC2" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "2414FC7A.Viber" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "64885BlueEdge.OneCalendar" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
    Get-AppxPackage -AllUsers "41038Axilesoft.ACGMediaPlayer" | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
}

Function EnableF8BootMenu {
    Write-Host "Enabling F8 boot menu options..."
    bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null
}

# Disable F8 boot menu options
Function DisableF8BootMenu {
    Write-Host "Disabling F8 boot menu options..."
    bcdedit /set `{current`} bootmenupolicy Standard | Out-Null
}

$tweaks = @()

try {
    $tweaks = $Configuration
}
catch {
    throw 'Unable to load configuration file!'
}

if ($tweaks.count -gt 0) {
    $RunTweaks = 0
    Write-Host "Executing $($tweaks.count) system configuration tweaks"
    if ($RunTweaks -eq 0) {
        # Call the desired tweak functions
        $tweaks | ForEach-Object {
            Invoke-Expression $_
        }
    }
}

# Install/Update PowershellGet and PackageManager if needed
try {
    Import-Module PowerShellGet
}
catch {
    throw 'Unable to load PowerShellGet!'
}

$packages = Get-Package
if (@($packages | Where-Object { $_.Name -eq 'PackageManagement' }).Count -eq 0) {
    Write-Host -ForegroundColor cyan "PackageManager is installed but not being maintained via the PowerShell gallery (so it will never get updated). Forcing the install of this module through the gallery to rectify this now."
    Install-Module PackageManagement -Force
    Install-Module PowerShellGet -Force
    Write-Host -ForegroundColor:Red "PowerShellGet and PackageManagement have been installed from the gallery. You need to close and rerun this script for them to work properly!"
    Invoke-BoxStarter -RebootOk
    Invoke-Reboot
}
else {
    $InstalledModules = (Get-InstalledModule).name
    $ModulesToBeInstalled = $ModulesToBeInstalled | Where-Object { $InstalledModules -notcontains $_ }
    if ($ModulesToBeInstalled.Count -gt 0) {
        Write-Host -ForegroundColor:cyan "Installing modules that are not already installed via powershellget. Modules to be installed = $($ModulesToBeInstalled.Count)"
        foreach ($Module in $ModulesToBeInstalled) {
            Install-Module -Name $Module -AllowClobber -ErrorAction:SilentlyContinue
        }
    }
    else {
        Write-Output "No modules were found that needed to be installed."
    }
}

Write-Output "Installing software via chocolatey"

#Don't try to download and install a package if it shows already installed
$InstalledChocoPackages = (Get-ChocoPackages).Name
$ChocoInstalls = $ChocoInstalls | Where-Object { $InstalledChocoPackages -notcontains $_ }
if ($ChocoInstalls.Count -gt 0) {
    $ChocoInstalls | ForEach-Object {
        try {
            choco upgrade -y $_ --cacheLocation "$($env:userprofile)\AppData\Local\Temp\chocolatey"
        }
        catch {
            Write-Warning "Unable to install software package with Chocolatey: $($_)"
        }
    }
}
else {
    Write-Output 'There were no packages to install!'
}

<#
    Manually installed packages (not in chocolatey or packagemanager)
#>
If (-not (Test-Path $UtilDownloadPath)) {
    mkdir $UtilDownloadPath -Force
}
If (-not (Test-Path $UtilBinPath)) {
    mkdir $UtilBinPath -Force
}
$FilesDownloaded = @()

# Github releases based software.
Foreach ($software in $GithubReleasesPackages.keys) {
    $releases = "https://api.github.com/repos/$software/releases"
    Write-Output "Determining latest release for repo $Software"
    $tag = (Invoke-WebRequest $releases -UseBasicParsing | ConvertFrom-Json)[0]
    $tag.assets | ForEach-Object {
        $DownloadPath = (Join-Path $UtilDownloadPath $_.Name)
        if ($_.name -like $GithubReleasesPackages[$software]) {
            if ( -not (Test-Path $_.name)) {
                try {
                    Write-Output "Downloading $($_.name)..."
                    Invoke-WebRequest -ContentType "application/octet-stream" $_.'browser_download_url' -OutFile $DownloadPath
                    $FilesDownloaded += $_.Name
                }
                catch {}
            }
            else {
                Write-Warning "File is already downloaded, skipping: $($_.Name)"
            }
        }
    }
}
# Store all the file we download for later processing

Foreach ($software in $ManualDownloadInstall.keys) {
    Write-Output "Downloading $software"
    $DownloadPath = (Join-Path $UtilDownloadPath $software)
    if ( -not (Test-Path $software) ) {
        try {
            Invoke-WebRequest -ContentType "application/octet-stream" $ManualDownloadInstall[$software] -OutFile $DownloadPath -UseBasicParsing
            $FilesDownloaded += $software
        }
        catch {}
    }
    else {
        Write-Warning "File is already downloaded, skipping: $software"
    }
}

# Extracting self-contained binaries (zip files) to our bin folder
Write-Output 'Extracting self-contained binaries (zip files) to our bin folder'
Get-ChildItem -Path $UtilDownloadPath -File -Filter '*.zip' | Where-Object { $FilesDownloaded -contains $_.Name } | ForEach-Object {
    Expand-Archive -Path $_.FullName -DestinationPath (Join-Path $UtilBinPath ($_.name).split('.')[0]) -Force }

#Kick off exe installs
#Get-ChildItem -Path $UtilDownloadPath -File -Filter '*.exe' | Where-Object { $FilesDownloaded -contains $_.Name -and $_.Name -notcontains "*[Guru3D.com]*" } | foreach {
#    Start-Proc -Exe $_.FullName $Arguments  -waitforexit
#}

# Kick off msi installs
##Get-ChildItem -Path $UtilDownloadPath -File -Filter '*.msi' | Where {$FilesDownloaded -contains $_.Name} | Foreach {
#    Start-Proc -Exe $_.FullName -waitforexit
#}

#$MyPowerShellProfile | Out-File -FilePath $PROFILE -Encoding:utf8 -Force
function New-CustomTerminal {
    if ($CreatePowershellProfile -and (-not (Test-Path $PROFILE))) {
        Write-Output 'Creating user powershell profile...'
        #Powershell Setup#
        $Powershell7UserProfile = "$ENV:USERPROFILE\Documents\PowerShell\Microsoft.PowerShell_profile.ps1"
        $Powershell7UserProfileRoot = "$ENV:USERPROFILE\Documents\PowerShell"
        #$Powershell7AllUserProfile = "C:\Program Files\PowerShell\7\Profile.ps1"
        #$WindowsPowershellUserProfile = "$ENV:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
        $terminalProfile = "$ENV:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
        $PowerShellProfileUri = "https://gist.githubusercontent.com/skalingclouds/9844ba8d76bb2c1193db0e539be841f2/raw/powershellprofile.ps1"
        $TerminalProfileUri = "https://gist.githubusercontent.com/skalingclouds/4aaf3e87c7ea9d450282150776949966/raw/settings.json"
        $PoshProfileUri = "https://gist.githubusercontent.com/skalingclouds/c2612e34dfef58cf0b92ede3d59c2901/raw/jandedobbeleer-custom.omp.json"
        $poshDir = "$ENV:USERPROFILE\.poshthemes"
        $poshTheme = "$ENV:USERPROFILE\.poshthemes\jandedobbeleer-final.omp.json"
        $fontUri = "https://github.com/skalingclouds/boxstarter/raw/main/HackNFwin.ttf"
        $fontFile = "$UtilBinPath\hackNFwin.ttf"

        #Powershell Setup#
        if ((Get-Module -Name PowerShellGet -ListAvailable).Version.Minor -eq 0) {
            Install-PackageProvider -Name NuGet -Force
            Install-Module -Name PowershellGet -Repository PSGallery -Force -AllowClobber
            Update-Module -Name PackageManagement -Force
            Invoke-BoxStarter -RebootOk
            RefreshEnv.cmd
            
        }
        else {
            Remove-Module PowerShellGet, PackageManagement -Force
            Import-Module -Name PowerShellGet -Force
            Import-PackageProvider -Name PowerShellGet -Force -MinimumVersion 2.0.0
            
        }
        If (Test-Path $Powershell7UserProfile) {
            Remove-Item -Path $Powershell7UserProfile -Force
            Start-BitsTransfer -Source $PowerShellProfileUri -Destination $Powershell7UserProfile
        }
        If (!(Test-Path $Powershell7UserProfileRoot)) {
            Write-Host "Powershell 7 Root folder does not exist, creating..."
            New-Item -Path $Powershell7UserProfileRoot -ItemType Directory
        }
        Write-Host "Downloading Powershell Profile"
        Start-BitsTransfer -Source $PowerShellProfileUri -Destination $Powershell7UserProfile
    }
    #Font Setup#
    $fontisinstalled = Get-Fonts | Where-Object { $_.Name -contains "Hack NF" }
    if (!($fontisinstalled)) {
        Write-Host "Installing Font $Fontfile"
        Start-BitsTransfer -Source $fontUri -Destination "$fontFile"
        Install-Font -Path "$fontFile"
        Write-Host "Installed Hack NF Font"
    }
    else {
        Write-Host "Hack NF is installed"
    }
    #Terminal Config Setup
    if (Test-Path -Path $terminalProfile) {
        Remove-Item $terminalProfile -Force
        Write-Host "Terminal Profile Removed"
        Start-BitsTransfer -Source $TerminalProfileUri -Destination $terminalProfile
        Write-Host "Terminal Profile Downloaded"
        Set-TerminalIconsTheme DevBlackOps
    }
    else {
        Write-Host "No Terminal profile, Downloading... "
        Start-BitsTransfer -Source $TerminalProfileUri -Destination $terminalProfile
        Write-Host "Download Complete"
        Set-TerminalIconsTheme DevBlackOps
    }
    if (Test-Path -Path $poshDir) {
        Import-Module "oh-my-posh" -Force
        Remove-Item $poshDir -Recurse -Force
        Write-Host "Posh Dir removed"
        New-Item $poshDir -ItemType Directory
        Write-Host "Recreating Posh Dir"
        Start-BitsTransfer -Source $PoshProfileUri -Destination $poshTheme
        Write-Host "Downloading Posh Theme"
        Set-PoshPrompt -Theme $poshTheme
        Write-Host "Posh Theme Set"
    }
    else {
        Import-Module "oh-my-posh" -Force
        New-Item $poshDir -ItemType Directory
        Write-Host "No Posh Dir, Creating..."
        Start-BitsTransfer -Source $PoshProfileUri -Destination $poshTheme
        Write-Host "Downloading Posh Theme"
        Set-PoshPrompt -Theme $poshTheme
        Write-Host "Posh Theme Set"
    }
}

#Kick off Windows Cleanup
function Start-WindowsCleanup {
    If (!(Test-Path -Path "C:\WinCleanupComplete.txt")) {
        Set-StrictMode -Version Latest
        $ProgressPreference = 'SilentlyContinue'
        $ErrorActionPreference = 'SilentlyContinue'
        trap {
            Write-Host
            Write-Host "ERROR: $_"
            Write-Host (($_.ScriptStackTrace -split '\r?\n') -replace '^(.*)$', 'ERROR: $1')
            Write-Host (($_.Exception.ToString() -split '\r?\n') -replace '^(.*)$', 'ERROR EXCEPTION: $1')

        }
        #
        # enable TLS 1.1 and 1.2.
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol `
            -bor [Net.SecurityProtocolType]::Tls11 `
            -bor [Net.SecurityProtocolType]::Tls12
        #
        # run automatic maintenance.

        Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class Windows
{
    [DllImport("kernel32", SetLastError=true)]
    public static extern UInt64 GetTickCount64();
    public static TimeSpan GetUptime()
    {
        return TimeSpan.FromMilliseconds(GetTickCount64());
    }
}
'@

        function Wait-Condition {
            param(
                [scriptblock]$Condition,
                [int]$DebounceSeconds = 15
            )
            process {
                $begin = [Windows]::GetUptime()
                do {
                    Start-Sleep -Seconds 3
                    try {
                        $result = &$Condition
                    }
                    catch {
                        $result = $false
                    }
                    if (-not $result) {
                        $begin = [Windows]::GetUptime()
                        continue
                    }
                } while ((([Windows]::GetUptime()) - $begin).TotalSeconds -lt $DebounceSeconds)
            }
        }

        function Get-ScheduledTasks() {
            $s = New-Object -ComObject 'Schedule.Service'
            try {
                $s.Connect()
                Get-ScheduledTasksInternal $s.GetFolder('\')
            }
            finally {
                [System.Runtime.Interopservices.Marshal]::ReleaseComObject($s) | Out-Null
            }
        }
        function Get-ScheduledTasksInternal($Folder) {
            $Folder.GetTasks(0)
            $Folder.GetFolders(0) | ForEach-Object {
                Get-ScheduledTasksInternal $_
            }
        }
        function Test-IsMaintenanceTask([xml]$definition) {
            # see MaintenanceSettings (maintenanceSettingsType) Element at https://msdn.microsoft.com/en-us/library/windows/desktop/hh832151(v=vs.85).aspx
            $ns = New-Object System.Xml.XmlNamespaceManager($definition.NameTable)
            $ns.AddNamespace('t', $definition.DocumentElement.NamespaceURI)
            $null -ne $definition.SelectSingleNode("/t:Task/t:Settings/t:MaintenanceSettings", $ns)
        }

        Write-Host 'Running Automatic Maintenance...'
        MSchedExe.exe Start
        Wait-Condition { @(Get-ScheduledTasks | Where-Object { ($_.State -ge 4) -and (Test-IsMaintenanceTask $_.XML) }).Count -eq 0 } -DebounceSeconds 60
        #
        # generate the .net frameworks native images.
        # NB this is normally done in the Automatic Maintenance step, but for
        #    some reason, sometimes its not.update
        # see https://docs.microsoft.com/en-us/dotnet/framework/tools/ngen-exe-native-image-generator

        Get-ChildItem "$env:windir\Microsoft.NET\*\*\ngen.exe" | ForEach-Object {
            Write-Host "Generating the .NET Framework native images with $_..."
            &$_ executeQueuedItems /nologo /silent | Out-File "$UtilDownloadPath\WindowsCleanup.log" -Append
        }
        #
        # remove temporary files.
        # NB we ignore the packer generated files so it won't complain in the output.

        Write-Host 'Stopping services that might interfere with temporary file removal...'
        function Stop-ServiceForReal($name) {
            while ($true) {
                Stop-Service -ErrorAction SilentlyContinue $name
                if ((Get-Service $name).Status -eq 'Stopped') {
                    break
                }
            }
        }
        Stop-ServiceForReal TrustedInstaller   # Windows Modules Installer
        Stop-ServiceForReal wuauserv           # Windows Update
        Stop-ServiceForReal BITS               # Background Intelligent Transfer Service
        @(
            "$env:LOCALAPPDATA\Temp\*"
            "$env:windir\Temp\*"
            "$env:windir\Logs\*"
            "$env:windir\Panther\*"
            "$env:windir\WinSxS\ManifestCache\*"
            "$env:windir\SoftwareDistribution\Download"
        ) | Where-Object { Test-Path $_ } | ForEach-Object {
            Write-Host "Removing temporary files $_..."
            takeown.exe /D Y /R /F $_ | Out-Null
            icacls.exe $_ /grant:r Administrators:F /T /C /Q 2>&1  | Out-File "$UtilDownloadPath\WindowsCleanup.log" -Append
        }

        # cleanup the WinSxS folder.

        # NB even thou the automatic maintenance includes a component cleanup task,
        #    it will not clean everything, as such, dism will clean the rest.
        # NB to analyse the used space use: dism.exe /Online /Cleanup-Image /AnalyzeComponentStore
        # see https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/clean-up-the-winsxs-folder
        Write-Host 'Cleaning up the WinSxS folder...'
        dism.exe /Online /Quiet /Cleanup-Image /StartComponentCleanup /ResetBase | Out-File "$UtilDownloadPath\WindowsCleanup.log" -Append
        if ($LASTEXITCODE) {
            throw "Failed with Exit Code $LASTEXITCODE"
        }

        #even after cleaning up the WinSxS folder the "Backups and Disabled Features"
        #    field of the analysis report will display a non-zero number because the
        #    disabled features packages are still on disk. you can remove them with:
        #Get-WindowsOptionalFeature -Online `
        # | Where-Object { $_.State -eq 'Disabled' } `
        # | ForEach-Object {
        #    Write-Host "Removing feature $($_.FeatureName)..."
        #    dism.exe /Online /Quiet /Disable-Feature "/FeatureName:$($_.FeatureName)" /Remove | Out-File "$UtilDownloadPath\WindowsCleanup.log" -Append
        #}
        #    NB a removed feature can still be installed from other sources (e.g. windows update).
        Write-Host 'Analyzing the WinSxS folder...'
        dism.exe /Online /Cleanup-Image /AnalyzeComponentStore | Out-File "$UtilDownloadPath\WindowsCleanup.log" -Append
        DISM.EXE /Online /Cleanup-Image /ScanHealth | Out-File "$UtilDownloadPath\WindowsCleanup.log"
        DISM.EXE /online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-File "$UtilDownloadPath\WindowsCleanup.log" -Append
        Dism.exe /online /Cleanup-Image /SPSuperseded | Out-File "$UtilDownloadPath\WindowsCleanup.log" -Append
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Active Setup Temp Folders" -Name -type "StateFlags0001"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\BranchCache" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\D3D Shader Cache" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Delivery Optimization Files" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Diagnostic Data Viewer database files" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Downloaded Program Files" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Internet Cache Files" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Language Pack" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Old ChkDsk Files" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Recycle Bin" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\RetailDemo Offline Content" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Setup Log Files" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error memory dump files" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error minidump files" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\User file versions" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Defender" -Name "StateFlags0001" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Files" -Name "StateFlags0001" -Type DWord -Value 2
        cleanmgr.exe /SAGERUN:1
        #
        # reclaim the free disk space.

        Write-Host 'Reclaiming the free disk space...'
        $results = defrag.exe C: /H /L /B /O "$UtilDownloadPath\WindowsCleanup.log"
        if ($results -eq 'The operation completed successfully.') {
            $results
        }
        else {
            Write-Host 'Zero filling the free disk space...'
            (New-Object System.Net.WebClient).DownloadFile('https://download.sysinternals.com/files/SDelete.zip', "$env:TEMP\SDelete.zip")
            Expand-Archive "$env:TEMP\SDelete.zip" $env:TEMP
            Remove-Item "$env:TEMP\SDelete.zip"
            &"$env:TEMP\sdelete64.exe" -accepteula -z C:
        }
        Start-Service TrustedInstaller   # Windows Modules Installer
        Start-Service wuauserv           # Windows Update
        Start-Service BITS
        #sfc.exe /scannow
        Write-Output "Finished Windows Cleanup, Creating text file as flag to not run again" | Out-File "C:\WinCleanupComplete.txt"
    }
    else {
        Write-Output "Windows Cleanup Already Ran"
    }
}

function Start-SophiaScript {
    Get-ChildItem -Path "$UtilBinPath\Sophia" | Where-Object { $_.Name -like "*Powershell*" } | Remove-Item -Force -Recurse
    $SophiaFolderName = (Get-ChildItem -Path "$UtilBinPath\Sophia" -Filter 'Sophia*').Name
    $SophiaPath = "$UtilBinPath\Sophia\$SophiaFolderName"
    If (Test-Path C:\SophiaComplete.txt) {
        Write-Host "Sophia has Already been Installed"
    }
    else {
        $localizations = Join-Path $SophiaPath "Localizations"
        Remove-Module -Name Sophia -Force -ErrorAction Ignore
        Import-Module -Name "$SophiaPath\Manifest\Sophia.psd1" -PassThru -Force
        Import-LocalizedData -BindingVariable Global:Localization -FileName Sophia -BaseDirectory $localizations
        Logging
        CreateRestorePoint
        Checkings
        Logging
        CreateRestorePoint
        DiagnosticDataLevel -Minimal
        ErrorReporting -Disable
        WindowsFeedback -Disable
        SigninInfo -Enable
        LanguageListAccess -Enable
        AdvertisingID -Disable
        ShareAcrossDevices -Enable
        WindowsWelcomeExperience -Show
        WindowsTips -Disable
        SettingsSuggestedContent -Hide
        AppsSilentInstalling -Disable
        WhatsNewInWindows -Enable
        TailoredExperiences -Disable
        ThisPC -Show
        CheckBoxes -Enable
        HiddenItems -Disable
        FileExtensions -Show
        MergeConflicts -Hide
        OpenFileExplorerTo -ThisPC
        CortanaButton -Hide
        TaskViewButton -Hide
        PeopleTaskbar -Hide
        SecondsInSystemClock -Hide
        SnapAssist -Enable
        FileTransferDialog -Detailed
        FileExplorerRibbon -Minimized
        RecycleBinDeleteConfirmation -Disable
        3DObjects -Hide
        QuickAccessFrequentFolders -Show
        QuickAccessRecentFiles -Show
        TaskbarSearch -Hide
        WindowsInkWorkspace -Hidev
        MeetNow -Hide
        ControlPanelView -Category
        WindowsColorScheme -Dark
        AppMode -Dark
        NewAppInstalledNotification -Hide
        FirstLogonAnimation -Enable
        JPEGWallpapersQuality -Default
        TaskManagerWindow -Expanded
        ShortcutsSuffix -Disable
        PrtScnSnippingTool -Enable
        StorageSense -Enable
        StorageSenseFrequency -Month
        StorageSenseTempFiles -Enable
        StorageSenseRecycleBin -Enable
        Hibernate -Disable
        TempFolder -Default
        Win32LongPathLimit -Enable
        AdminApprovalMode -Disable
        WaitNetworkStartup -Disable
        UpdateMicrosoftProducts -Enable
        Get-Powerplan -High
        LatestInstalled.NET -Enable
        WinPrtScrFolder -Desktop
        RecommendedTroubleshooting -Automatic
        ReservedStorage -Disable
        F1HelpPage -Disable
        NumLock -Disable
        CapsLock -Disable
        StickyShift -Disable
        Autoplay -Disable
        RecentlyAddedApps -Show
        AppSuggestions -Hide
        RunPowerShellShortcut -Elevated
        PinToStart -Tiles PowerShell
        HEIF -Install
        BackgroundUWPApps -Enable
        CheckUWPAppsUpdates
        XboxGameBar -Enable
        XboxGameTips -Enable
        GPUScheduling -Enable
        CleanupTask -Register
        SoftwareDistributionTask -Register
        TempTask -Register
        AuditProcess -Enable
        AuditCommandLineProcess -Enable
        EventViewerCustomView -Enable
        AppsSmartScreen -Disable
        SaveZoneInformation -Disable
        WindowsScriptHost -Enable
        DismissMSAccount
        DismissSmartScreenFilter
        MSIExtractContext -Add
        CABInstallContext -Add
        RunAsDifferentUserContext -Add
        CastToDeviceContext -Hide
        EditWithPaint3DContext -Show
        EditWithPhotosContext -Show
        CreateANewVideoContext -Hide
        ImagesEditContext -Show
        PrintCMDContext -Show
        IncludeInLibraryContext -Hide
        SendToContext -Show
        BitLockerContext -Hide
        CompressedFolderNewContext -Add
        MultipleInvokeContext -Enable
        UseStoreOpenWith -Hide
        PreviousVersionsPage -Show
        RefreshEnvironment
        Errors
        Write-Output "Sophia Script Complete, writing complete txt in C:" | Out-File "C:\SophiaComplete.txt"
    }
}

function Start-WindowsOptimization {
    if (!(Test-Path "C:\WinOptimizationComplete.txt")) {
        # Disable Core Isolation Memory Integrity
        Write-Output "Disabling Core Isolation Memory Integrity..."
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
        # Enable Windows Script Host
        Write-Output "Enabling Windows Script Host..."
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue
        Write-Output "Hiding Documents icon from This PC..."
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -Recurse -ErrorAction SilentlyContinue
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Recurse -ErrorAction SilentlyContinue
        # Hide Documents icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
        Write-Output "Hiding Documents icon from Explorer namespace..."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
        # Hide Music icon from This PC - The icon remains in personal folders and open/save dialogs
        Write-Output "Hiding Music icon from This PC..."
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse -ErrorAction SilentlyContinue
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse -ErrorAction SilentlyContinue
        # Hide Music icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
        Write-Output "Hiding Music icon from Explorer namespace..."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
        # Hide Pictures icon from This PC - The icon remains in personal folders and open/save dialogs
        Write-Output "Hiding Pictures icon from This PC..."
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Recurse -ErrorAction SilentlyContinue
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Recurse -ErrorAction SilentlyContinue
        # Hide Pictures icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
        Write-Output "Hiding Pictures icon from Explorer namespace..."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
        # Hide Videos icon from This PC - The icon remains in personal folders and open/save dialogs
        Write-Output "Hiding Videos icon from This PC..."
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Recurse -ErrorAction SilentlyContinue
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Recurse -ErrorAction SilentlyContinue
        # Hide Videos icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
        Write-Output "Hiding Videos icon from Explorer namespace..."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
        # Hide 3D Objects icon from This PC - The icon remains in personal folders and open/save dialogs
        Write-Output "Hiding 3D Objects icon from This PC..."
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
        # Hide 3D Objects icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
        Write-Output "Hiding 3D Objects icon from Explorer namespace..."
        If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
        If (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
            New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
        # Set Photo Viewer association for bmp, gif, jpg, png and tif
        Write-Output "Setting Photo Viewer association for bmp, gif, jpg, png and tif..."
        If (!(Test-Path "HKCR:")) {
            New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
        }
        ForEach ($type in @("Paint.Picture", "giffile", "jpegfile", "pngfile")) {
            New-Item -Path $("HKCR:\$type\shell\open") -Force | Out-Null
            New-Item -Path $("HKCR:\$type\shell\open\command") | Out-Null
            Set-ItemProperty -Path $("HKCR:\$type\shell\open") -Name "MuiVerb" -Type ExpandString -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043"
            Set-ItemProperty -Path $("HKCR:\$type\shell\open\command") -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
        }
        # Add Photo Viewer to "Open with..."
        Write-Output "Adding Photo Viewer to `"Open with...`""
        If (!(Test-Path "HKCR:")) {
            New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
        }
        New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Force | Out-Null
        New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Force | Out-Null
        Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -Type String -Value "@photoviewer.dll,-3043"
        Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
        Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" -Type String -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"
        Write-Output "Finished Windows Optimization, Creating text file as flag to not run again" | Out-File "C:\WinOptimizationComplete.txt"
    }
    else {
        Write-Output "Optimization Already Ran"
    }
}

function Install-LatestNvidiaDriver {
    # Checking currently installed driver version
    Write-Host "Attempting to detect currently installed driver version..."

    $VideoController = Get-WmiObject -ClassName Win32_VideoController | Where-Object { $_.Name -match "NVIDIA" }
    $ins_version = ($VideoController.DriverVersion.Replace('.', '')[-5..-1] -join '').insert(3, '.')
    Write-Host "Installed version `t$ins_version"
    if ($version -eq $ins_version -or ((Get-WmiObject Win32_BaseBoard).Manufacturer -eq "Microsoft Corporation")){
        Write-Host "The installed version is the same as the latest version."
    }
    else {
            Param (
                [switch]$clean = $false, # Will delete old drivers and install the new ones
                [string]$folder = "$env:temp"   # Downloads and extracts the driver here
            )

            $scheduleTask = $false  # Creates a Scheduled Task to run to check for driver updates
            $scheduleDay = "Sunday" # When should the scheduled task run (Default = Sunday)
            $scheduleTime = "12pm"  # The time the scheduled task should run (Default = 12pm)

        # Checking if 7zip or WinRAR are installed
        # Check 7zip install path on registry
        $7zipinstalled = $false
        if ((Test-Path HKLM:\SOFTWARE\7-Zip\) -eq $true) {
            $7zpath = Get-ItemProperty -Path HKLM:\SOFTWARE\7-Zip\ -Name Path
            $7zpath = $7zpath.Path
            $7zpathexe = $7zpath + "7z.exe"
            if ((Test-Path $7zpathexe) -eq $true) {
                $archiverProgram = $7zpathexe
                $7zipinstalled = $true
            }
        }
        else {
            Write-Host "it looks like you don't have a supported archiver."
            Write-Host "Downloading 7zip Now"
            # Download and silently install 7-zip if the user presses y
            $7zip = "https://www.7-zip.org/a/7z1900-x64.exe"
            $output = "$PSScriptRoot\7Zip.exe"
            (New-Object System.Net.WebClient).DownloadFile($7zip, $output)
            Start-Process "7Zip.exe" -Wait -ArgumentList "/S"
            # Delete the installer once it completes
            Remove-Item "$PSScriptRoot\7Zip.exe"
        }
        # Checking latest driver version from Nvidia website
        $link = Invoke-WebRequest -Uri 'https://www.nvidia.com/Download/processFind.aspx?psid=101&pfid=816&osid=57&lid=1&whql=1&lang=en-us&ctk=0&dtcid=0' -Method GET -UseBasicParsing
        $link -match '<td class="gridItem">([^<]+?)</td>' | Out-Null
        $version = $matches[1]
        Write-Host "Latest version `t`t$version"
        # Comparing installed driver version to latest driver version from Nvidia
        # Checking Windows version
        if ([Environment]::OSVersion.Version -ge (New-Object 'Version' 9, 1)) {
            $windowsVersion = "win10"
        }
        else {
            $windowsVersion = "win8-win7"
        }
        # Checking Windows bitness
        if ([Environment]::Is64BitOperatingSystem) {
            $windowsArchitecture = "64bit"
        }
        else {
            $windowsArchitecture = "32bit"
        }
        # Create a new temp folder NVIDIA
        $nvidiaTempFolder = "$folder\NVIDIA"
        New-Item -Path $nvidiaTempFolder -ItemType Directory 2>&1 | Out-Null
        # Generating the download link
        $url = "https://international.download.nvidia.com/Windows/$version/$version-desktop-$windowsVersion-$windowsArchitecture-international-whql.exe"
        $rp_url = "https://international.download.nvidia.com/Windows/$version/$version-desktop-$windowsVersion-$windowsArchitecture-international-whql-rp.exe"
        # Downloading the installer
        $dlFile = "$nvidiaTempFolder\$version.exe"
        Write-Host "Downloading the latest version to $dlFile"
        Start-BitsTransfer -Source $url -Destination $dlFile
        if ($?) {
            Write-Host "Proceed..."
        }
        else {
            Write-Host "Download failed, trying alternative RP package now..."
            Start-BitsTransfer -Source $rp_url -Destination $dlFile
        }
        # Extracting setup files
        $extractFolder = "$nvidiaTempFolder\$version"
        $filesToExtract = "Display.Driver HDAudio NVI2 PhysX EULA.txt ListDevices.txt setup.cfg setup.exe"
        Write-Host "Download finished, extracting the files now..."
        if ($7zipinstalled) {
            Start-Process -FilePath $archiverProgram -NoNewWindow -ArgumentList "x -bso0 -bsp1 -bse1 -aoa $dlFile $filesToExtract -o""$extractFolder""" -Wait
        }
        elseif ($archiverProgram -eq $winrarpath) {
            Start-Process -FilePath $archiverProgram -NoNewWindow -ArgumentList 'x $dlFile $extractFolder -IBCK $filesToExtract' -Wait
        }
        else {
            Write-Host "Something went wrong. No archive program detected. This should not happen."
            Write-Output "Something went wrong. No archive program detected. This should not happen." | Out-File "C:\NvidiaErrorLog.Log" -Append
        }
        # Remove unneeded dependencies from setup.cfg
        (Get-Content "$extractFolder\setup.cfg") | Where-Object { $_ -notmatch 'name="\${{(EulaHtmlFile|FunctionalConsentFile|PrivacyPolicyFile)}}' } | Set-Content "$extractFolder\setup.cfg" -Encoding UTF8 -Force
        # Installing drivers
        Write-Host "Installing Nvidia drivers now..."
        $install_args = "-passive -noreboot -noeula -nofinish -s"
        if ($clean) {
            $install_args = $install_args + " -clean"
        }
        Start-Process -FilePath "$extractFolder\setup.exe" -ArgumentList $install_args -Wait
        # Creating a scheduled task if the $scheduleTask varible is set to TRUE
        if ($scheduleTask) {
            Write-Host "Creating A Scheduled Task..."
            New-Item C:\Task\ -type directory 2>&1 | Out-Null
            Copy-Item .\Nvidia.ps1 -Destination C:\Task\ 2>&1 | Out-Null
            $taskname = "Nvidia-Updater"
            $description = "Update Your Driver!"
            $action = New-ScheduledTaskAction -Execute "C:\Task\Nvidia.ps1"
            $trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval $scheduleTask -DaysOfWeek $scheduleDay -At $scheduleTime
            Register-ScheduledTask -TaskName $taskname -Action $action -Trigger $trigger -Description $description 2>&1 | Out-Null
        }
        # Cleaning up downloaded files
        Write-Host "Deleting downloaded files"
        Remove-Item $nvidiaTempFolder -Recurse -Force
    }
}

function Install-AudioDriver {
    if (!(Test-Path "C:\AudioDriverComplete.txt")) {
        $AudioDriverFolder = "audio-driver"
        $AudioDriverFileName = "AsusSetup.exe"
        Write-Host "audio driver install"
        Start-Process -FilePath "$UtilBinPath\$AudioDriverFolder\$AudioDriverFileName"
        Start-Sleep 45
        Write-Output "WinOptimization Complete, writing completed file to C:" | Out-File "C:\AudioDriverComplete.txt"
    }
    else {
        Write-Output "Audio Driver Alrady Ran"
    }
}

function Install-MacriumBackup {
    $MacriumFolderName = "MacriumV8-Latest"
    $MacriumFileName = "MacriumV8-Latest.exe"
    if (!(Test-Path "C:\MacriumComplete.txt")) {
        Write-Host "Installing Macrium"
        Write-Host "Importing License"
        $license = Get-Content -Path "C:\BoxStarterSetup\Licenses\MacriumLicense.txt"
        write-host "License is $license"
        Start-Process -FilePath "$UtilDownloadPath\$MacriumFolderName\$MacriumFileName" -ArgumentList "/passive /l log.txt $license"
        Write-Output "Macrium Install Complete, writing completed file to C:" | Out-File "C:\MacriumComplete.txt"
        Write-Output "sleeping 30 seconds.."
        Start-Sleep 30
    }
    else {
        Write-Output "Macrium Alrady Ran"
    }
}

function Start-WinImageBackup {
    if (!(Test-Path "C:\WindowsImageBackupComplete.txt")) {
        Write-Host "Starting Windows Image Backup!"
        wbadmin start backup -backuptarget:d: -include:c: -allcritical -quiet
        Write-Output "Image Backup Complete, writing completed file to C:" | Out-File "C:\WindowsImageBackupComplete.txt"
    }
    else {
        Write-Output "Image Backup Already Ran"
    }
}

function Set-PerformanceTweaks {
    if (!(Test-Path "C:\PerformanceTweaksComplete.txt")) {
        ##########
        # Master Branch : https://github.com/ChrisTitusTech/win10script
        # Current Author : Daddy Madu
        # Current Author Source: https://github.com/DaddyMadu/Windows10GamingFocus
        #
        #    Note from author: Never run scripts without reading them & understanding what they do.
        #
        #	Addition: One command to rule them all, One command to find it, and One command to Run it!
        #
        #     > powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://tweaks.daddymadu.gg')"
        #
        #     Changelogs Moved to ReadMe File for better mangement.
        #
        ##########
        Write-Host 'Gaming Focus Tweaker Now Running..';
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
        Clear-Host
        # Default preset
        $tweaks = @(
            ### Require administrator privileges ###
            "RequireAdmin",
            "CreateRestorePoint",
            ### Chris Titus Tech Additions
            "Write-ColorOutput", #Utilizing Colors for better warrning messages!
            "EnableUlimatePower", # DaddyMadu don't change order it will break other functions! just disable if you want with #
            #"MSIMode", #Enable Or Disable MSI Mode For Supported Cards, WARRNING ENABLING MSI MODE MIGHT CRUSH YOUR SYSTEM! IF IT HAPPENS PLEASE RESTORE LAST WORKING SYSTEM RESTORE POINT AND DON'T ENABLE MSI MODE ON THIS SYSTEM AGAIN!
            #"DisableNagle",
            #"DisableHibernation", # "EnableHibernation",
            #"DISGaming",
            ### Windows Tweaks ###
            #"PowerThrottlingOff",
            #"Win32PrioritySeparation",
            "BSODdetails",
            #"Disablelivetiles",
            #"wallpaperquality",
            #"DisableMouseKKS",
            #"TurnOffSafeSearch",
            #"SVCHostTweak",
            ### DaddyMadu Gaming Tweaks ###
            #"FullscreenOptimizationFIX",
            #"GameOptimizationFIX",
            "ApplyPCOptimizations",
            #"RawMouseInput",
            #"DetectnApplyMouseFIX",
            #"DisableHPET",
            #"EnableGameMode",
            #"EnableHAGS",
            #"DisableCoreParking",
            "DisableDMA",
            "DisablePKM",
            "DisallowDIP",
            "UseBigM",
            "ForceContiguousM",
            #"DecreaseMKBuffer",
            #"EnableRemoteDesktop",
            #"StophighDPC",
            #"NvidiaTweaks",
            #"NetworkOptimizations",
            #"RemoveEdit3D",
            "FixURLext", # fix issue with games shortcut that created by games lunchers turned white!
            #"UltimateCleaner",
            #'DisableIndexing'
            "Finished"
            ### Auxiliary Functions ###
        )

        #########
        # Pre Customizations
        #########

        #Utilizing Clolors For Better Warning Messages!
        function Write-ColorOutput {
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory = $False, Position = 1, ValueFromPipeline = $True, ValueFromPipelinebyPropertyName = $True)][Object] $Object,
                [Parameter(Mandatory = $False, Position = 2, ValueFromPipeline = $True, ValueFromPipelinebyPropertyName = $True)][ConsoleColor] $ForegroundColor,
                [Parameter(Mandatory = $False, Position = 3, ValueFromPipeline = $True, ValueFromPipelinebyPropertyName = $True)][ConsoleColor] $BackgroundColor,
                [Switch]$NoNewline
            )

            # Save previous colors
            $previousForegroundColor = $host.UI.RawUI.ForegroundColor
            $previousBackgroundColor = $host.UI.RawUI.BackgroundColor

            # Set BackgroundColor if available
            if ($BackgroundColor -ne $null) {
                $host.UI.RawUI.BackgroundColor = $BackgroundColor
            }

            # Set $ForegroundColor if available
            if ($ForegroundColor -ne $null) {
                $host.UI.RawUI.ForegroundColor = $ForegroundColor
            }

            # Always write (if we want just a NewLine)
            if ($Object -eq $null) {
                $Object = ""
            }

            if ($NoNewline) {
                [Console]::Write($Object)
            }
            else {
                Write-Output $Object
            }

            # Restore previous colors
            $host.UI.RawUI.ForegroundColor = $previousForegroundColor
            $host.UI.RawUI.BackgroundColor = $previousBackgroundColor
        }

        # Install the latest Microsoft Visual C++ 2010-2019 Redistributable Packages and Silverlight


        Function ChangeDefaultApps {
            Write-Output "Setting Default Programs - Notepad++ Brave VLC IrFanView"
            Start-BitsTransfer -Source "https://raw.githubusercontent.com/DaddyMadu/Windows10GamingFocus/master/MyDefaultAppAssociations.xml" -Destination $HOME\Desktop\MyDefaultAppAssociations.xml
            dism /online /Import-DefaultAppAssociations:"%UserProfile%\Desktop\MyDefaultAppAssociations.xml"
        }

        #Apply PC Optimizations
        Function ApplyPCOptimizations {
            Write-Output "Applying PC Optimizations..."
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 4294967295
        }


        #Enable Or Disable MSI Mode For Supported Cards, WARRNING ENABLING MSI MODE MIGHT CRUSH YOUR SYSTEM! IF IT HAPPENS PLEASE RESTORE LAST WORKING SYSTEM RESTORE POINT AND DON'T ENABLE MSI MODE ON THIS SYSTEM AGAIN!
        Function MSIMode {
            $errpref = $ErrorActionPreference #save actual preference
            $ErrorActionPreference = "silentlycontinue"
            $GPUIDS = @(
                (wmic path win32_VideoController get PNPDeviceID | Select-Object -Skip 2 | Format-List | Out-String).Trim()
            )
            foreach ($GPUID in $GPUIDS) {
                $CheckDeviceDes = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\$GPUID").DeviceDesc
            } if (($CheckDeviceDes -like "*GTX*") -or ($CheckDeviceDes -like "*RTX*") -or ($CheckDeviceDes -like "*AMD*")) {
                'GTX/RTX/AMD Compatible Card Found! Enabling MSI Mode...'
                New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\$GPUID\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties\" -Force | Out-Null
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\$GPUID\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties\" -Name "MSISupported" -Type DWord -Value 1
            }
            else {
                'No GTX/RTX/AMD Compatible Card Found! Skiping...'
            }
            $ErrorActionPreference = $errpref #restore previous preference
        }


        # Disable Link-Local Multicast Name Resolution (LLMNR) protocol
        Function DisableLLMNR {
            Write-Output "Disabling LLMNR..."
            If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0
        }

        # Enable Link-Local Multicast Name Resolution (LLMNR) protocol
        Function EnableLLMNR {
            Write-Output "Enabling LLMNR..."
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
        }
        #Ask User If He Want to Enable Or Disable Microsoft Software Protection Platform Service
        Function askMSPPS {
            Write-Output "Disabling Microsoft Software Protection Platform Service and related Processes..."
            Disable-ScheduledTask -TaskName "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask" | Out-Null
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\sppsvc" -Name "Start" -Type DWord -Value 4 -ErrorAction SilentlyContinue
            Clear-Host
        }
        Function enableMSPPS {
            Write-Output "Enabling Microsoft Software Protection Platform Service and related Processes..."
            Enable-ScheduledTask -TaskName "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask" | Out-Null
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\sppsvc" -Name "Start" -Type DWord -Value 2 -ErrorAction SilentlyContinue
            Clear-Host
        }

        # Set Data Execution Prevention (DEP) policy to OptOut
        Function SetDEPOptOut {
            Write-Output "Setting Data Execution Prevention (DEP) policy to OptOut..."
            bcdedit /set nx OptOut | Out-Null
        }

        # Set Data Execution Prevention (DEP) policy to OptIn
        Function SetDEPOptIn {
            Write-Output "Setting Data Execution Prevention (DEP) policy to OptIn..."
            bcdedit /set nx OptIn | Out-Null
        }

        # Enable Core Isolation Memory Integrity - Part of Windows Defender System Guard virtualization-based security - Supported from 1803
        Function EnableCIMemoryIntegrity {
            Write-Output "Enabling Core Isolation Memory Integrity..."
            If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) {
                New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Type DWord -Value 1
        }

        # Disable Core Isolation Memory Integrity -
        Function DisableCIMemoryIntegrity {
            Write-Output "Disabling Core Isolation Memory Integrity..."
            Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
        }

        # Disable Windows Script Host (execution of *.vbs scripts and alike)
        Function DisableScriptHost {
            Write-Output "Disabling Windows Script Host..."
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type DWord -Value 0
        }

        # Enable Windows Script Host
        Function EnableScriptHost {
            Write-Output "Enabling Windows Script Host..."
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue
        }

        # Enable strong cryptography for .NET Framework (version 4 and above)
        # https://stackoverflow.com/questions/36265534/invoke-webrequest-ssl-fails
        Function EnableDotNetStrongCrypto {
            Write-Output "Enabling .NET strong cryptography..."
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
        }

        # Disable strong cryptography for .NET Framework (version 4 and above)
        Function DisableDotNetStrongCrypto {
            Write-Output "Disabling .NET strong cryptography..."
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
        }

        # Enable Meltdown (CVE-2017-5754) compatibility flag - Required for January 2018 and all subsequent Windows updates
        # This flag is normally automatically enabled by compatible antivirus software (such as Windows Defender).
        # Use the tweak only if you have confirmed that your AV is compatible but unable to set the flag automatically or if you don't use any AV at all.
        # See https://support.microsoft.com/en-us/help/4072699/january-3-2018-windows-security-updates-and-antivirus-software for details.
        Function EnableMeltdownCompatFlag {
            Write-Output "Enabling Meltdown (CVE-2017-5754) compatibility flag..."
            If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat")) {
                New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -Type DWord -Value 0
        }

        # Disable Meltdown (CVE-2017-5754) compatibility flag
        Function DisableMeltdownCompatFlag {
            Write-Output "Disabling Meltdown (CVE-2017-5754) compatibility flag..."
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -ErrorAction SilentlyContinue
        }



        ##########
        # Service Tweaks
        ##########
        #Disabling Un nessessary Services For Gaming
        Function DISGaming {
            Write-Output "Stopping and disabling Un nessessary Services For Gaming..."
            $errpref = $ErrorActionPreference #save actual preference
            $ErrorActionPreference = "silentlycontinue"
            Stop-Service "wisvc" -WarningAction SilentlyContinue
            Set-Service "wisvc" -StartupType Disabled
            Stop-Service "MapsBroker" -WarningAction SilentlyContinue
            Set-Service "MapsBroker" -StartupType Disabled
            Stop-Service "PcaSvc" -WarningAction SilentlyContinue
            Set-Service "PcaSvc" -StartupType Disabled
            $ErrorActionPreference = $errpref #restore previous preference
        }

        # Disable offering of Malicious Software Removal Tool through Windows Update
        Function DisableUpdateMSRT {
            Write-Output "Disabling Malicious Software Removal Tool offering..."
            If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Type DWord -Value 1
        }

        # Enable offering of Malicious Software Removal Tool through Windows Update
        Function EnableUpdateMSRT {
            Write-Output "Enabling Malicious Software Removal Tool offering..."
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -ErrorAction SilentlyContinue
        }

        # Disable offering of drivers through Windows Update
        # Note: This doesn't work properly if you use a driver intended for another hardware model. E.g. Intel I219-V on WinServer works only with I219-LM driver.
        # Therefore Windows update will repeatedly try and fail to install I219-V driver indefinitely even if you use the tweak.
        Function DisableUpdateDriver {
            Write-Output "Disabling driver offering through Windows Update..."
            If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
            If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0
            If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
        }

        # Enable offering of drivers through Windows Update
        Function EnableUpdateDriver {
            Write-Output "Enabling driver offering through Windows Update..."
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
        }

        # Disable Windows Update automatic restart
        # Note: This doesn't disable the need for the restart but rather tries to ensure that the restart doesn't happen in the least expected moment. Allow the machine to restart as soon as possible anyway.
        Function DisableUpdateRestart {
            Write-Output "Disabling Windows Update automatic restart..."
            If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0
        }

        # Enable Windows Update automatic restart
        # Set BIOS time to UTC #sc.exe config w32time start= delayed-auto#
        Function SetBIOSTimeUTC {
            Write-Output "Setting BIOS time to UTC..."
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1
            Push-Location
            Set-Location HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers
            Set-ItemProperty . 0 "time.google.com"
            Set-ItemProperty . "(Default)" "0"
            Set-Location HKLM:\SYSTEM\CurrentControlSet\services\W32Time\Parameters
            Set-ItemProperty . NtpServer "time.google.com"
            Pop-Location
            Stop-Service w32time
            sc.exe config w32time start= auto
            Start-Service w32time
            W32tm /resync /force /nowait
        }

        # Set BIOS time to local time
        Function SetBIOSTimeLocal {
            Write-Output "Setting BIOS time to Local time..."
            Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -ErrorAction SilentlyContinue
            Push-Location
            Set-Location HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers
            Set-ItemProperty . 0 "time.google.com"
            Set-ItemProperty . "(Default)" "0"
            Set-Location HKLM:\SYSTEM\CurrentControlSet\services\W32Time\Parameters
            Set-ItemProperty . NtpServer "time.google.com"
            Pop-Location
            Stop-Service w32time
            sc.exe config w32time start= auto
            Start-Service w32time
            W32tm /resync /force /nowait
        }

        # Disable Fast Startup
        Function DisableFastStartup {
            Write-Output "Disabling Fast Startup..."
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
        }

        # Enable Fast Startup
        Function EnableFastStartup {
            Write-Output "Enabling Fast Startup..."
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 1
        }


        ##########
        # Windows Tweaks
        ##########
        #Disabling power throttling.
        Function PowerThrottlingOff {
            Write-Output "Disabling power throttling..."
            New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Type DWord -Value 1
        }

        #Setting Processor scheduling.
        Function Win32PrioritySeparation {
            Write-Output "Setting Processor scheduling..."
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Type DWord -Value 0x00000026
        }

        #Show BSOD details instead of the sad smiley.
        Function BSODdetails {
            Write-Output "Show BSOD details instead of the sad smiley..."
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\CrashControl" -Name "DisplayParameters" -Type DWord -Value 1
        }

        #Setting Wallpaper Quality to 100%.
        Function wallpaperquality {
            Write-Output "Setting Wallpaper Quality to 100%..."
            Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "JPEGImportQuality" -Type DWord -Value 100
        }

        #Disabling "- Shortcut" Word.
        Function Disableshortcutword {
            Write-Output "Disabling - Shortcut Word..."
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Type Binary -Value ([byte[]](0, 0, 0, 0))
        }

        #Disabling Mouse Keys Keyboard Shortcut.
        Function DisableMouseKKS {
            Write-Output "Disabling Mouse Keys Keyboard Shortcut..."
            Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\MouseKeys" -Name "Flags" -Type String -Value "186"
            Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\MouseKeys" -Name "MaximumSpeed" -Type String -Value "40"
            Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\MouseKeys" -Name "TimeToMaximumSpeed" -Type String -Value "3000"
        }

        # Add SVCHost Tweak
        Function SVCHostTweak {
            Write-Output "Adding SVCHost Tweak..."
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 4194304
        }

        ##########
        # Gaming Tweaks Functions
        ##########

        #Disable Fullscreen Optimizations
        Function FullscreenOptimizationFIX {
            Write-Output "Disabling Full ScreenOptimization..."
            Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Type DWord -Value 2
            Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Type DWord -Value 1
            Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Type DWord -Value 2
            Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type DWord -Value 1
            Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_EFSEFeatureFlags" -Type DWord -Value 0
            Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DSEBehavior" -Type DWord -Value 2
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Type DWord -Value 0
        }

        #Game Optimizations Priority Tweaks -Type String -Value "Deny"
        Function GameOptimizationFIX {
            Write-Output "Apply Gaming Optimization Fixs..."
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Type DWord -Value 8
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type DWord -Value 6
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Type String -Value "High"
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Type String -Value "High"
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "IRQ8Priority" -Type DWord -Value 1
        }

        #Forcing Raw Mouse Input
        Function RawMouseInput {
            Write-Output "Forcing RAW Mouse Input and Disabling Enhance Pointer Precision..."
            Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value "0"
            Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value "0"
            Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value "0"
            Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity" -Type String -Value "10"
            Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseHoverTime" -Type String -Value "0"
            Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseTrails" -Type String -Value "0"
        }

        #Detecting Windows Scale Layout Automatically and applying mouse fix according to it!
        Function DetectnApplyMouseFIX {
            Add-Type @'
            using System;
            using System.Runtime.InteropServices;
            using System.Drawing;

            public class DPI {
                [DllImport("gdi32.dll")]
                static extern int GetDeviceCaps(IntPtr hdc, int nIndex);

            public enum DeviceCap {
                VERTRES = 10,
                DESKTOPVERTRES = 117
            }

            public static float scaling() {
                Graphics g = Graphics.FromHwnd(IntPtr.Zero);
                IntPtr desktop = g.GetHdc();
                int LogicalScreenHeight = GetDeviceCaps(desktop, (int)DeviceCap.VERTRES);
                int PhysicalScreenHeight = GetDeviceCaps(desktop, (int)DeviceCap.DESKTOPVERTRES);

                return (float)PhysicalScreenHeight / (float)LogicalScreenHeight;
            }
        }
'@ -ReferencedAssemblies 'System.Drawing.dll'

            $checkscreenscale = [Math]::round([DPI]::scaling(), 2) * 100
            if ($checkscreenscale -eq "100") {
                Write-Output "Windows screen scale is Detected as 100%, Applying Mouse Fix for it..."
                $YourInputX = "00,00,00,00,00,00,00,00,C0,CC,0C,00,00,00,00,00,80,99,19,00,00,00,00,00,40,66,26,00,00,00,00,00,00,33,33,00,00,00,00,00"
                $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
                $RegPath = 'HKCU:\Control Panel\Mouse'
                $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
                $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
                Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
                Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
            }
            elseif ($checkscreenscale -eq "125") {
                Write-Output "Windows screen scale is Detected as 125%, Applying Mouse Fix for it..."
                $YourInputX = "00,00,00,00,00,00,00,00,00,00,10,00,00,00,00,00,00,00,20,00,00,00,00,00,00,00,30,00,00,00,00,00,00,00,40,00,00,00,00,00"
                $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
                $RegPath = 'HKCU:\Control Panel\Mouse'
                $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
                $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
                Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
                Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
            }
            elseif ($checkscreenscale -eq "150") {
                Write-Output "Windows screen scale is Detected as 150%, Applying Mouse Fix for it..."
                $YourInputX = "00,00,00,00,00,00,00,00,30,33,13,00,00,00,00,00,60,66,26,00,00,00,00,00,90,99,39,00,00,00,00,00,C0,CC,4C,00,00,00,00,00"
                $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
                $RegPath = 'HKCU:\Control Panel\Mouse'
                $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
                $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
                Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
                Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
            }
            elseif ($checkscreenscale -eq "175") {
                Write-Output "Windows screen scale is Detected as 175%, Applying Mouse Fix for it..."
                $YourInputX = "00,00,00,00,00,00,00,00,60,66,16,00,00,00,00,00,C0,CC,2C,00,00,00,00,00,20,33,43,00,00,00,00,00,80,99,59,00,00,00,00,00"
                $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
                $RegPath = 'HKCU:\Control Panel\Mouse'
                $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
                $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
                Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
                Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
            }
            elseif ($checkscreenscale -eq "200") {
                Write-Output "Windows screen scale is Detected as 200%, Applying Mouse Fix for it..."
                $YourInputX = "00,00,00,00,00,00,00,00,90,99,19,00,00,00,00,00,20,33,33,00,00,00,00,00,B0,CC,4C,00,00,00,00,00,40,66,66,00,00,00,00,00"
                $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
                $RegPath = 'HKCU:\Control Panel\Mouse'
                $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
                $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
                Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
                Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
            }
            elseif ($checkscreenscale -eq "225") {
                Write-Output "Windows screen scale is Detected as 225%, Applying Mouse Fix for it..."
                $YourInputX = "00,00,00,00,00,00,00,00,C0,CC,1C,00,00,00,00,00,80,99,39,00,00,00,00,00,40,66,56,00,00,00,00,00,00,33,73,00,00,00,00,00"
                $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
                $RegPath = 'HKCU:\Control Panel\Mouse'
                $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
                $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
                Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
                Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
            }
            elseif ($checkscreenscale -eq "250") {
                Write-Output "Windows screen scale is Detected as 250%, Applying Mouse Fix for it..."
                $YourInputX = "00,00,00,00,00,00,00,00,00,00,20,00,00,00,00,00,00,00,40,00,00,00,00,00,00,00,60,00,00,00,00,00,00,00,80,00,00,00,00,00"
                $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
                $RegPath = 'HKCU:\Control Panel\Mouse'
                $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
                $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
                Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
                Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
            }
            elseif ($checkscreenscale -eq "300") {
                Write-Output "Windows screen scale is Detected as 300%, Applying Mouse Fix for it..."
                $YourInputX = "00,00,00,00,00,00,00,00,60,66,26,00,00,00,00,00,C0,CC,4C,00,00,00,00,00,20,33,73,00,00,00,00,00,80,99,99,00,00,00,00,00"
                $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
                $RegPath = 'HKCU:\Control Panel\Mouse'
                $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
                $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
                Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
                Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
            }
            elseif ($checkscreenscale -eq "350") {
                Write-Output "Windows screen scale is Detected as 350%, Applying Mouse Fix for it..."
                $YourInputX = "00,00,00,00,00,00,00,00,C0,CC,2C,00,00,00,00,00,80,99,59,00,00,00,00,00,40,66,86,00,00,00,00,00,00,33,B3,00,00,00,00,00"
                $YourInputY = "00,00,00,00,00,00,00,00,00,00,38,00,00,00,00,00,00,00,70,00,00,00,00,00,00,00,A8,00,00,00,00,00,00,00,E0,00,00,00,00,00"
                $RegPath = 'HKCU:\Control Panel\Mouse'
                $hexifiedX = $YourInputX.Split(',') | ForEach-Object { "0x$_" }
                $hexifiedY = $YourInputY.Split(',') | ForEach-Object { "0x$_" }
                Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseXCurve" -Type Binary -Value (([byte[]]$hexifiedX))
                Set-ItemProperty -Path "$RegPath" -Name "SmoothMouseYCurve" -Type Binary -Value (([byte[]]$hexifiedY))
            }
            else {
                Write-Output "HOUSTON WE HAVE A PROBLEM! screen scale is not set to traditional value, nothing has been set!"
            }
        }

        ### Disable HPET ###
        Function DisableHPET {
            Write-Output "Disabling High Precision Event Timer..."
            $errpref = $ErrorActionPreference #save actual preference
            $ErrorActionPreference = "silentlycontinue"
            Invoke-WebRequest -Uri "https://git.io/JkrLn" -OutFile "$Env:windir\system32\SetTimerResolutionService.exe" -ErrorAction SilentlyContinue
            New-Service -Name "SetTimerResolutionService" -BinaryPathName "$Env:windir\system32\SetTimerResolutionService.exe" -StartupType Automatic | Out-Null -ErrorAction SilentlyContinue
            bcdedit /set x2apicpolicy Enable | Out-Null
            bcdedit /set configaccesspolicy Default | Out-Null
            bcdedit /set MSI Default | Out-Null
            bcdedit /set usephysicaldestination No | Out-Null
            bcdedit /set usefirmwarepcisettings No | Out-Null
            bcdedit /deletevalue useplatformclock | Out-Null
            bcdedit /set disabledynamictick yes | Out-Null
            bcdedit /set useplatformtick Yes | Out-Null
            bcdedit /set tscsyncpolicy Enhanced | Out-Null
            bcdedit /timeout 10 | Out-Null
            bcdedit /set nx optout | Out-Null
            bcdedit /set { globalsettings } custom:16000067 true | Out-Null
            bcdedit /set { globalsettings } custom:16000069 true | Out-Null
            bcdedit /set { globalsettings } custom:16000068 true | Out-Null
            wmic path Win32_PnPEntity where "name='High precision event timer'" call disable | Out-Null
            $ErrorActionPreference = $errpref #restore previous preference
        }

        #Enable Windows 10 Gaming Mode
        Function EnableGameMode {
            Write-Output "Enabling Gaming Mode..."
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Type DWord -Value 1
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 1
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "ShowStartupPanel" -Type DWord -Value 0
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "GamePanelStartupTipIndex" -Type DWord -Value 3
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -Type DWord -Value 0
        }

        #Enable Hardware-accelerated GPU scheduling
        Function EnableHAGS {
            Write-Output "Enabling HAGS..."
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Type DWord -Value 2
        }

        #Add Utimate Power Plan And Activate It
        Function EnableUlimatePower {
            Write-Output "Enabling and Activating Bitsum Highest Performance Power Plan..."
            Invoke-WebRequest -Uri "https://git.io/JsWhn" -OutFile "$Env:windir\system32\Bitsum-Highest-Performance.pow" -ErrorAction SilentlyContinue
            powercfg -import "$Env:windir\system32\Bitsum-Highest-Performance.pow" e6a66b66-d6df-666d-aa66-66f66666eb66 | Out-Null
            powercfg -setactive e6a66b66-d6df-666d-aa66-66f66666eb66 | Out-Null
        }

        #Disable Core Parking on current PowerPlan Ultimate Performance
        Function DisableCoreParking {
            Write-Output "Disabling Core Parking on current PowerPlan Ultimate Performance..."
            #powercfg -attributes SUB_PROCESSOR CPMINCORES -ATTRIB_HIDE | Out-Null
            #Powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100 | Out-Null
            #Powercfg -setactive scheme_current | Out-Null
        }

        #Disable DMA memory protection and cores isolation ("virtualization-based protection").
        Function DisableDMA {
            Write-Output "Disabling DMA memory protection and cores isolation..."
            $errpref = $ErrorActionPreference #save actual preference
            $ErrorActionPreference = "silentlycontinue"
            bcdedit /set vsmlaunchtype Off | Out-Null
            bcdedit /set vm No | Out-Null
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" | Out-Null -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "DisableExternalDMAUnderLock" -Type DWord -Value 0
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" | Out-Null -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Type DWord -Value 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "HVCIMATRequired" -Type DWord -Value 0
            $ErrorActionPreference = $errpref #restore previous preference
        }

        #Disable Process and Kernel Mitigations
        Function DisablePKM {
            Write-Output "Disabling Process and Kernel Mitigations..."
            $errpref = $ErrorActionPreference #save actual preference
            $ErrorActionPreference = "silentlycontinue"
            ForEach ($v in (Get-Command -Name "Set-ProcessMitigation").Parameters["Disable"].Attributes.ValidValues) { Set-ProcessMitigation -System -Disable $v.ToString() -ErrorAction SilentlyContinue }
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "KernelSEHOPEnabled" -Type DWord -Value 0
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "EnableCfg" -Type DWord -Value 0
            $ErrorActionPreference = $errpref #restore previous preference
        }

        #Disallow drivers to get paged into virtual memory.
        Function DisallowDIP {
            Write-Output "Disabling drivers get paged into virtual memory..."
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Type DWord -Value 1
        }

        #Use big system memory caching to improve microstuttering.
        Function UseBigM {
            Write-Output "Enabling big system memory caching to improve microstuttering..."
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Type DWord -Value 1
        }

        #Force contiguous memory allocation in the DirectX Graphics Kernel.
        Function ForceContiguousM {
            Write-Output "Forcing contiguous memory allocation in the DirectX Graphics Kernel..."
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "DpiMapIommuContiguous" -Type DWord -Value 1
        }

        #Tell Windows to stop tolerating high DPC/ISR latencies.
        Function StophighDPC {
            Write-Output "Forcing Windows to stop tolerating high DPC/ISR latencies..."
            $errpref = $ErrorActionPreference #save actual preference
            $ErrorActionPreference = "silentlycontinue"
            New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" | Out-Null -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "ExitLatency" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "ExitLatencyCheckEnabled" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "Latency" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "LatencyToleranceDefault" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "LatencyToleranceFSVP" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "LatencyTolerancePerfOverride" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "LatencyToleranceScreenOffIR" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "LatencyToleranceVSyncEnabled" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "RtlCapabilityCheckLatency" -Type DWord -Value 1
            New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" | Out-Null -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyActivelyUsed" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyIdleLongTime" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyIdleMonitorOff" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyIdleNoContext" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyIdleShortTime" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyIdleVeryLongTime" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceIdle0" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceIdle0MonitorOff" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceIdle1" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceIdle1MonitorOff" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceMemory" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceNoContext" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceNoContextMonitorOff" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceOther" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceTimerPeriod" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultMemoryRefreshLatencyToleranceActivelyUsed" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultMemoryRefreshLatencyToleranceMonitorOff" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultMemoryRefreshLatencyToleranceNoContext" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "Latency" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "MaxIAverageGraphicsLatencyInOneBucket" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "MiracastPerfTrackGraphicsLatency" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "MonitorLatencyTolerance" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "MonitorRefreshLatencyTolerance" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "TransitionLatency" -Type DWord -Value 1
            $ErrorActionPreference = $errpref #restore previous preference
        }

        #Decrease mouse and keyboard buffer sizes.
        Function DecreaseMKBuffer {
            Write-Output "Decreasing mouse and keyboard buffer sizes..."
            $errpref = $ErrorActionPreference #save actual preference
            $ErrorActionPreference = "silentlycontinue"
            New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" | Out-Null -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Name "MouseDataQueueSize" -Type DWord -Value 0x00000010
            New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" | Out-Null -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" -Name "KeyboardDataQueueSize" -Type DWord -Value 0x00000010
            $ErrorActionPreference = $errpref #restore previous preference
        }

        #Applying Nvidia Tweaks if GTX/RTX Card Detected!
        Function NvidiaTweaks {
            $CheckGPU = wmic path win32_VideoController get name
            if (($CheckGPU -like "*GTX*") -or ($CheckGPU -like "*RTX*")) {
                Write-Output "NVIDIA GTX/RTX Card Detected! Applying Nvidia Power Tweaks..."
                Invoke-WebRequest -Uri "https://git.io/JLP93" -OutFile "$Env:windir\system32\BaseProfile.nip" -ErrorAction SilentlyContinue
                Invoke-WebRequest -Uri "https://git.io/JLP9n" -OutFile "$Env:windir\system32\nvidiaProfileInspector.exe" -ErrorAction SilentlyContinue
                Push-Location
                Set-Location "$Env:windir\system32\"
                nvidiaProfileInspector.exe /s -load "BaseProfile.nip"
                Pop-Location
            }
            else {
                Write-Output "Nvidia GTX/RTX Card Not Detected! Skipping..."
            }
            $errpref = $ErrorActionPreference #save actual preference
            $ErrorActionPreference = "silentlycontinue"
            $CheckGPURegistryKey0 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000").DriverDesc
            $CheckGPURegistryKey1 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001").DriverDesc
            $CheckGPURegistryKey2 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002").DriverDesc
            $CheckGPURegistryKey3 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003").DriverDesc
            $ErrorActionPreference = $errpref #restore previous preference
            if (($CheckGPURegistryKey0 -like "*GTX*") -or ($CheckGPURegistryKey0 -like "*RTX*")) {
                Write-Output "Nvidia GTX/RTX Card Registry Path 0000 Detected! Applying Nvidia Latency Tweaks..."
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "D3PCLatency" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "F1TransitionLatency" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "LOWLATENCY" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "Node3DLowLatency" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "PciLatencyTimerControl" -Type DWord -Value "0x00000020"
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RMDeepL1EntryLatencyUsec" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RmGspcMaxFtuS" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RmGspcMinFtuS" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RmGspcPerioduS" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RMLpwrEiIdleThresholdUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RMLpwrGrIdleThresholdUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RMLpwrGrRgIdleThresholdUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "RMLpwrMsIdleThresholdUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "VRDirectFlipDPCDelayUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "VRDirectFlipTimingMarginUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "VRDirectJITFlipMsHybridFlipDelayUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "vrrCursorMarginUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "vrrDeflickerMarginUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name "vrrDeflickerMaxUs" -Type DWord -Value 1
            }
            elseif (($CheckGPURegistryKey1 -like "*GTX*") -or ($CheckGPURegistryKey1 -like "*RTX*")) {
                Write-Output "Nvidia GTX/RTX Card Registry Path 0001 Detected! Applying Nvidia Latency Tweaks..."
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "D3PCLatency" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "F1TransitionLatency" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "LOWLATENCY" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "Node3DLowLatency" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "PciLatencyTimerControl" -Type DWord -Value "0x00000020"
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RMDeepL1EntryLatencyUsec" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RmGspcMaxFtuS" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RmGspcMinFtuS" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RmGspcPerioduS" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RMLpwrEiIdleThresholdUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RMLpwrGrIdleThresholdUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RMLpwrGrRgIdleThresholdUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "RMLpwrMsIdleThresholdUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "VRDirectFlipDPCDelayUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "VRDirectFlipTimingMarginUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "VRDirectJITFlipMsHybridFlipDelayUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "vrrCursorMarginUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "vrrDeflickerMarginUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" -Name "vrrDeflickerMaxUs" -Type DWord -Value 1
            }
            elseif (($CheckGPURegistryKey2 -like "*GTX*") -or ($CheckGPURegistryKey2 -like "*RTX*")) {
                Write-Output "Nvidia GTX/RTX Card Registry Path 0002 Detected! Applying Nvidia Latency Tweaks..."
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "D3PCLatency" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "F1TransitionLatency" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "LOWLATENCY" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "Node3DLowLatency" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "PciLatencyTimerControl" -Type DWord -Value "0x00000020"
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RMDeepL1EntryLatencyUsec" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RmGspcMaxFtuS" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RmGspcMinFtuS" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RmGspcPerioduS" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RMLpwrEiIdleThresholdUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RMLpwrGrIdleThresholdUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RMLpwrGrRgIdleThresholdUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "RMLpwrMsIdleThresholdUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "VRDirectFlipDPCDelayUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "VRDirectFlipTimingMarginUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "VRDirectJITFlipMsHybridFlipDelayUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "vrrCursorMarginUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "vrrDeflickerMarginUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" -Name "vrrDeflickerMaxUs" -Type DWord -Value 1
            }
            elseif (($CheckGPURegistryKey3 -like "*GTX*") -or ($CheckGPURegistryKey3 -like "*RTX*")) {
                Write-Output "Nvidia GTX/RTX Card Registry Path 0003 Detected! Applying Nvidia Latency Tweaks..."
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "D3PCLatency" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "F1TransitionLatency" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "LOWLATENCY" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "Node3DLowLatency" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "PciLatencyTimerControl" -Type DWord -Value "0x00000020"
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RMDeepL1EntryLatencyUsec" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RmGspcMaxFtuS" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RmGspcMinFtuS" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RmGspcPerioduS" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RMLpwrEiIdleThresholdUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RMLpwrGrIdleThresholdUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RMLpwrGrRgIdleThresholdUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "RMLpwrMsIdleThresholdUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "VRDirectFlipDPCDelayUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "VRDirectFlipTimingMarginUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "VRDirectJITFlipMsHybridFlipDelayUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "vrrCursorMarginUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "vrrDeflickerMarginUs" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" -Name "vrrDeflickerMaxUs" -Type DWord -Value 1
            }
            else {
                Write-Output "No NVIDIA GTX/RTX Card Registry entry Found! Skipping..."
            }
        }



        #Optimizing Network and applying Tweaks for no throttle and maximum speed!
        Function NetworkOptimizations {
            Write-Output "Optimizing Network and applying Tweaks for no throttle and maximum speed!..."
            $errpref = $ErrorActionPreference #save actual preference
            $ErrorActionPreference = "silentlycontinue"
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters" -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" -Name "explorer.exe" -Type DWord -Value 10
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" -Name "explorer.exe" -Type DWord -Value 10
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "LocalPriority" -Type DWord -Value 4
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "HostsPriority" -Type DWord -Value 5
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "DnsPriority" -Type DWord -Value 6
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "NetbtPriority" -Type DWord -Value 7
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortlimit" -Type DWord -Value 0
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" -Name "Do not use NLA" -Type String -Value "1"
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "Size" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 20
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "MaxUserPort" -Type DWord -Value 65534
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpTimedWaitDelay" -Type DWord -Value 30
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL" -Type DWord -Value 64
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters" -Name "TCPNoDelay" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\Lsa" -Name "LmCompatibilityLevel" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableAutoDoh" -Type DWord -Value 2
            Set-NetTCPSetting -SettingName internet -EcnCapability disabled | Out-Null
            Set-NetOffloadGlobalSetting -Chimney disabled | Out-Null
            Set-NetTCPSetting -SettingName internet -Timestamps disabled | Out-Null
            Set-NetTCPSetting -SettingName internet -MaxSynRetransmissions 2 | Out-Null
            Set-NetTCPSetting -SettingName internet -NonSackRttResiliency disabled | Out-Null
            Set-NetTCPSetting -SettingName internet -InitialRto 2000 | Out-Null
            Set-NetTCPSetting -SettingName internet -MinRto 300 | Out-Null
            Set-NetTCPSetting -SettingName Internet -AutoTuningLevelLocal normal | Out-Null
            Set-NetTCPSetting -SettingName internet -ScalingHeuristics disabled | Out-Null
            netsh int tcp set supplemental internet congestionprovider=ctcp | Out-Null
            Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing enabled | Out-Null
            Set-NetOffloadGlobalSetting -ReceiveSideScaling enabled | Out-Null
            Disable-NetAdapterLso -Name * | Out-Null
            Disable-NetAdapterChecksumOffload -Name * | Out-Null
            Set-NetAdapterAdvancedProperty -Name * -DisplayName "Energy-Efficient Ethernet" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
            Set-NetAdapterAdvancedProperty -Name * -DisplayName "Energy Efficient Ethernet" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
            Set-NetAdapterAdvancedProperty -Name * -DisplayName "Energy Efficient Ethernet" -DisplayValue "Off" -ErrorAction SilentlyContinue
            Set-NetAdapterAdvancedProperty -Name * -DisplayName "Ultra Low Power Mode" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
            Set-NetAdapterAdvancedProperty -Name * -DisplayName "System Idle Power Saver" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
            Set-NetAdapterAdvancedProperty -Name * -DisplayName "Green Ethernet" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
            Set-NetAdapterAdvancedProperty -Name * -DisplayName "Power Saving Mode" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
            Set-NetAdapterAdvancedProperty -Name * -DisplayName "Gigabit Lite" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
            Set-NetAdapterAdvancedProperty -Name * -DisplayName "EEE" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
            Set-NetAdapterAdvancedProperty -Name * -DisplayName "Advanced EEE" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
            Set-NetAdapterAdvancedProperty -Name * -DisplayName "ARP Offload" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
            Set-NetAdapterAdvancedProperty -Name * -DisplayName "NS Offload" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
            Set-NetAdapterAdvancedProperty -Name * -DisplayName "Idle Power Saving" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
            Set-NetAdapterAdvancedProperty -Name * -DisplayName "Flow Control" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
            Set-NetAdapterAdvancedProperty -Name * -DisplayName "Interrupt Moderation" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
            Set-NetAdapterAdvancedProperty -Name * -DisplayName "Reduce Speed On Power Down" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
            Set-NetAdapterAdvancedProperty -Name * -DisplayName "Interrupt Moderation Rate" -DisplayValue "Off" -ErrorAction SilentlyContinue
            $ErrorActionPreference = $errpref #restore previous preference
            if ((Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType -ne 2) {
                $adapters = Get-NetAdapter -Physical | Get-NetAdapterPowerManagement | Where-Object -FilterScript { $_.AllowComputerToTurnOffDevice -ne "Unsupported" }
                foreach ($adapter in $adapters) {
                    $adapter.AllowComputerToTurnOffDevice = "Disabled"
                    $adapter | Set-NetAdapterPowerManagement
                }
            }
            Start-Sleep -s 5
        }

        # Disable Nagle's Algorithm
        Function DisableNagle {
            $errpref = $ErrorActionPreference #save actual preference
            $ErrorActionPreference = "silentlycontinue"
            $NetworkIDS = @(
                (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\*").PSChildName
            )
            foreach ($NetworkID in $NetworkIDS) {
                Write-Output "Disabling Nagles Algorithm..."
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$NetworkID" -Name "TcpAckFrequency" -Type DWord -Value 1
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$NetworkID" -Name "TCPNoDelay" -Type DWord -Value 1
            }
            $ErrorActionPreference = $errpref #restore previous preference
        }


        #fix issue with games shortcut that created by games lunchers turned white!
        Function FixURLext {
            Write-Host "Fixing White Games Shortcuts created by game launchers...."
            choco install -y setuserfta | Out-Null
            Start-Sleep -s 5
            Push-Location
            Set-Location "$env:ProgramData\chocolatey\lib\setuserfta\tools\SetUserFTA\"
            SetUserFTA.exe del .url | Out-Null
            SetUserFTA.exe .url, InternetShortcut | Out-Null
            Pop-Location
            choco uninstall -y setuserfta | Out-Null
        }

        #DaddyMadu Ultimate CLeaner
        Function UltimateCleaner {
            Write-Host "Running DaddyMadu Ultimate Cleaner => Temp folders & Flush DNS + Reset IP...."
            cmd /c 'netsh winsock reset 2>nul' >$null
            cmd /c 'netsh int ip reset 2>nul' >$null
            cmd /c 'ipconfig /release 2>nul' >$null
            cmd /c 'ipconfig /renew 2>nul' >$null
            cmd /c 'ipconfig /flushdns 2>nul' >$null
            cmd /c 'echo Flush DNS + IP Reset Completed Successfully!'
            cmd /c 'echo Clearing Temp folders....'
            cmd /c 'del /f /s /q %systemdrive%\*.tmp 2>nul' >$null
            cmd /c 'del /f /s /q %systemdrive%\*._mp 2>nul' >$null
            cmd /c 'del /f /s /q %systemdrive%\*.log 2>nul' >$null
            cmd /c 'del /f /s /q %systemdrive%\*.gid 2>nul' >$null
            cmd /c 'del /f /s /q %systemdrive%\*.chk 2>nul' >$null
            cmd /c 'del /f /s /q %systemdrive%\*.old 2>nul' >$null
            cmd /c 'del /f /s /q %systemdrive%\recycled\*.* 2>nul' >$null
            cmd /c 'del /f /s /q %windir%\*.bak 2>nul' >$null
            cmd /c 'del /f /s /q %windir%\prefetch\*.* 2>nul' >$null
            cmd /c 'del /f /q %userprofile%\cookies\*.* 2>nul' >$null
            cmd /c 'del /f /q %userprofile%\recent\*.* 2>nul' >$null
            cmd /c 'del /f /s /q %userprofile%\Local Settings\Temporary Internet Files\*.* 2>nul' >$null
            $errpref = $ErrorActionPreference #save actual preference
            $ErrorActionPreference = "silentlycontinue"
            Get-ChildItem -Path "$env:temp" -Exclude "dmtmp" | ForEach-Object ($_) {
                "CLEANING :" + $_.fullname
                Remove-Item $_.fullname -Force -Recurse
                "CLEANED... :" + $_.fullname
            }
            $ErrorActionPreference = $errpref #restore previous preference
            cmd /c 'del /f /s /q %userprofile%\recent\*.* 2>nul' >$null
            cmd /c 'del /f /s /q %windir%\Temp\*.* 2>nul' >$null
            cmd /c 'echo Temp folders Cleared Successfully!'
        }

        #Notifying user to reboot!
        Function Finished {
            Write-Output "Done! Please Reboot Your PC!"
        }

        ##########
        # Auxiliary Functions
        ##########

        # Relaunch the script with administrator privileges
        Function RequireAdmin {
            If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
                Exit
            }
        }

        # Wait for key press
        Function WaitForKey {
            Write-Output "Press any key to continue..."
            [Console]::ReadKey($true) | Out-Null
        }

        # Restart computer
        Function Restart {
            Write-Output "Restarting..."
            Restart-Computer
        }

        ###########
        # Titus Additions
        ###########

        Function EnableDarkMode {
            Write-Output "Enabling Dark Mode"
            Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0
        }

        Function DisableDarkMode {
            Write-Output "Disabling Dark Mode"
            Remove-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme
        }

        #Create Restore Point
        Function CreateRestorePoint {
            Write-Output "Creating Restore Point incase something bad happens"
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Value 0
            cmd /c 'vssadmin resize shadowstorage /on="%SystemDrive%" /For="%SystemDrive%" /MaxSize=5GB 2>nul' >$null
            Enable-ComputerRestore -Drive "$env:SystemDrive\"
            Checkpoint-Computer -Description "BeforeDaddyMaduScript" -RestorePointType "MODIFY_SETTINGS"
        }

        ##########
        # Parse parameters and apply tweaks
        ##########

        # Normalize path to preset file
        $preset = ""
        $PSCommandArgs = $args
        If ($args -And $args[0].ToLower() -eq "-preset") {
            $preset = Resolve-Path $($args | Select-Object -Skip 1)
            $PSCommandArgs = "-preset `"$preset`""
        }

        # Load function names from command line arguments or a preset file
        If ($args) {
            $tweaks = $args
            If ($preset) {
                $tweaks = Get-Content $preset -ErrorAction Stop | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" -and $_[0] -ne "#" }
            }
        }
        # Call the desired tweak functions
        $tweaks | ForEach-Object { Invoke-Expression $_ }
        Write-Output "Performance Tweaks Configuration Complete, writing completed file to C:" | Out-File "C:\PerformanceTweaksComplete.txt"
    } else {
        Write-Output "Performance Tweaks Already Ran"
    }
}

Function Set-StoragePoolConfig {
    #View the disks in the Storage Pool just created
    #Variables
    $StoragePoolName = "My Storage Pool"
    $TieredSpaceName = "My Tiered Space"
    $ResiliencySetting = "Simple"
    $SSDTierName = "SSDTier"
    $HDDTierName = "HDDTier"
    List all disks that can be pooled and output in table format (Format-Table)
    Get-PhysicalDisk -CanPool $True | Format-Table FriendlyName, OperationalStatus, Size, MediaType
    Store all physical disks that can be pooled into a variable, $PhysicalDisks
    $PhysicalDisks = (Get-PhysicalDisk -CanPool $True | Where-Object MediaType -NE UnSpecified)
    Create a new Storage Pool using the disks in variable $PhysicalDisks with a name of My Storage Pool
    $SubSysName = (Get-StorageSubSystem).FriendlyName
    New-StoragePool -PhysicalDisks $PhysicalDisks -StorageSubSystemFriendlyName $SubSysName -FriendlyName $StoragePoolName
    View the disks in the Storage Pool just created
    Get-StoragePool -FriendlyName $StoragePoolName | Get-PhysicalDisk | Select-Object FriendlyName, MediaType
    Create two tiers in the Storage Pool created. One for SSD disks and one for HDD disks
    $SSDTier = New-StorageTier -StoragePoolFriendlyName $StoragePoolName -FriendlyName $SSDTierName -MediaType SSD
    $HDDTier = New-StorageTier -StoragePoolFriendlyName $StoragePoolName -FriendlyName $HDDTierName -MediaType HDD
    Identify tier sizes within this storage pool
    $SSDTierSizes = (Get-StorageTierSupportedSize -FriendlyName $SSDTierName -ResiliencySettingName $ResiliencySetting).TierSizeMax
    $HDDTierSizes = (Get-StorageTierSupportedSize -FriendlyName $HDDTierName -ResiliencySettingName $ResiliencySetting).TierSizeMax
    Create a new virtual disk in the pool with a name of TieredSpace using the SSD and HDD tiers
    New-VirtualDisk -StoragePoolFriendlyName $StoragePoolName -FriendlyName $TieredSpaceName -ResiliencySettingName $ResiliencySetting -AutoWriteCacheSize -AutoNumberOfColumns
    New-VirtualDisk -StoragePoolFriendlyName $StoragePoolName -FriendlyName $TieredSpaceName -StorageTiers $SSDTier, $HDDTier -StorageTierSizes $SSDTierSizes, $HDDTierSizes -ResiliencySettingName $ResiliencySetting -AutoWriteCacheSize -AutoNumberOfColumns
    #Alternatively try adjusting the sizes manually:
    #New-VirtualDisk -StoragePoolFriendlyName $StoragePoolName -FriendlyName $TieredSpaceName -StorageTiers @($SSDTier,$HDDTier) -StorageTierSizes @(228GB,1.816TB) -ResiliencySettingName $ResiliencySetting -AutoWriteCacheSize -AutoNumberOfColumns
}

function Install-ChocoPackagesWithArgs {
    Write-Host "Starting Choco Installs with Args"
    cinst battle.net --allowemptychecksum -y
    cinst microsoft-office-deployment /64bit /DisableUpdate "FALSE" /"Current Channel (Preview)" /Language "MatchOS" /Product "O365HomePremRetail" /Exclude "Access,Skype,Publisher,OneDrive,Outlook,Lync,Groove,OneNote"
}

function Set-TestTweaks {
    ##Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 4194304
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Micro/ndows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 4294967295
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Type DWord -Value 8
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type DWord -Value
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Type String -Value "High"
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Type String -Value "High"
    #Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
    #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "IRQ8Priority" -Type Word -Value 1
    #Forcing contiguous memory allocation in the DirectX Graphics Kernel...
    #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "DpiMapIommuContiguous" -Type DWord -Value 1
    #Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
    #New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" | Out-Null -ErrorAction SilentlyContinue
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "DisableExternalDMAUnderLock" -Type DWord -Value 0
    #New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" | Out-Null -ErrorAction SilentlyContinue
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Type DWord -Value 0
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "HVCIMATRequired" -Type DWord -Value 0
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Type DWord -Value 0
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "DisableExternalDMAUnderLock" -Type DWord -Value 0
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Type DWord -Value 0
    #New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" | Out-Null -ErrorAction SilentlyContinue
    #Write-Output "Disabling Core Isolation Memory Integrity..."
    #Disabling Core Isolation Memory Integrity...
    #Get-Process C:\Users\skalinator> Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
    #Write-Output "Enabling and Activating Bitsum Highest Performance Power Plan..."
    #Enabling and Activating Bitsum Highest Performance Power Plan...
    #Invoke-WebRequest -Uri "https://git.io/JsWhn" -OutFile "$Env:windir\system32\Bitsum-Highest-Performance.pow" -ErrorAction SilentlyContinue
    #powercfg -import "$Env:windir\system32\Bitsum-Highest-Performance.pow" e6a66b66-d6df-666d-aa66-66f66666eb66 | Out-Null
    #powercfg -setactive e6a66b66-d6df-666d-aa66-66f66666eb66 | Out-Null
    #bcdedit /set vsmlaunchtype Off | Out-Null
    #bcdedit /set vm No | Out-Null
    bcdedit /set x2apicpolicy Enable
    #bcdedit /set nx OptOut | Out-Null
}

function Set-EdgeConfig {
    # Ensure Edge key exists
    $EdgeHome = 'HKCU:\Software\Policies\Microsoft\Edge'
    If ( -Not (Test-Path $EdgeHome)) {
        New-Item -Path $EdgeHome | Out-Null
    }
    # Set RestoreOnStartup value entry
    $IPHT = @{
        Path  = $EdgeHome
        Name  = 'RestoreOnStartup'
        Value = 4
        Type  = 'DWORD'
    }
    Set-ItemProperty @IPHT -Verbose
    # Create Startup URL's registry key
    $EdgeSUURL = "$EdgeHome\RestoreOnStartupURLs"
    If ( -Not (Test-Path $EdgeSUURL)) {
        New-Item -Path $EdgeSUURL | Out-Null
    }
    # Create a single URL startup page
    $HOMEURL = 'https://google.com'
    Set-ItemProperty -Path $EdgeSUURL -Name '1' -Value $HomeURL
}

function Set-GitConfig {
    #--- Configure Git ---
    git config --global user.name 'Chris Skaling'
    git config --global user.email 'Chris.Skaling@gmail.com'
    git config --global core.symlinks true
    git config --global core.autocrlf true
    git config --global color.status auto
    git config --global color.diff auto
    git config --global color.branch auto
    git config --global color.interactive auto
    git config --global color.ui true
    git config --global color.pager true
    git config --global color.showbranch auto
    git config --global alias.co checkout
    git config --global alias.br branch
    git config --global alias.ci commit
    git config --global alias.st status
    git config --global alias.ft fetch
    git config --global alias.ps push
    git config --global alias.ph push
    git config --global alias.pl pull
    # Make a folder for my GitHub repos and make SymbolicLinks to it
    if (-not(Test-Path 'C:\GitHub')) { New-Item -Path 'C:\GitHub' -ItemType Directory }
    if (-not(Test-Path (Join-Path $env:USERPROFILE 'GitHub'))) { New-Item -Path (Join-Path $env:USERPROFILE 'GitHub') -ItemType SymbolicLink -Value 'C:\GitHub' }
    if ((Test-Path 'D:\') -and -not(Test-Path 'D:\GitHub')) { New-Item -Path 'D:\GitHub' -ItemType SymbolicLink -Value 'C:\GitHub' }
}

function Install-AMDChipSetDrivers {
    if (Test-Path "C:\AMDChipsetComplete.txt") {
        Write-Host "AMD Install Already Ran"
    }
    else {
        Start-Process -FilePath "$UtilDownloadPath\amd-chipsetdriver.exe" -ArgumentList "/S"
        Write-Output "Chipset Install Completed, writing completed file to C:" | Out-File "C:\AMDChipsetComplete.txt"
        write-host "sleeping for 30 seconds"
        Start-Sleep 30
    }
}
Start-SophiaScript
Install-ChocoPackagesWithArgs
Install-LatestNvidiaDriver -clean
Install-AMDChipSetDrivers
Set-GitConfig
New-CustomTerminal
Install-AudioDriver
Install-MacriumBackup
Start-WindowsOptimization
Enable-MicrosoftUpdate
Install-WindowsUpdate -acceptEula -getUpdatesFromMS
Start-WinImageBackup
Start-WindowsCleanup
Set-TestTweaks
Set-PerformanceTweaks

if (Test-PendingReboot) {
    Write-Host "Finished, Computer needs a reboot!"
}

Write-Host -ForegroundColor:Green "Install and configuration complete!"
##