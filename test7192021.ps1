

$ManualDownloadInstall = @{
    'amd-chipsetdriver.exe'     = 'https://ftp.nluug.nl/pub/games/PC/guru3d/amd/[Guru3D.com]-amd-chipset-drivers.exe';
    'audio-driver.zip'          = 'https://dlcdnets.asus.com/pub/ASUS/mb/SocketAM4/ROG_CROSSHAIR_VIII_DARK_HERO/Realtek_Audio_Driver_V6.0.8960.1_WIN10_64-bit.zip';
    'l-connect.zip'             = 'https://lian-li.com/downloads/L-connect.zip';
    'device-cleanup-cmd.zip'    = 'https://www.uwe-sieber.de/files/devicecleanupcmd.zip';
    'benchmate.exe'             = 'https://s3.eu-central-1.wasabisys.com/benchmate/downloads/bm-0.10.7.2-offline.exe';
    'MacriumV8-Latest.zip'      = 'https://skalingclouds.blob.core.windows.net/zenboxsetupfiles/Macrium_v8_x64.exe';
    'mobros.exe'                = 'https://skalingclouds.blob.core.windows.net/zenboxsetupfiles/MoBros.exe'
}
# Releases based github packages to download and install. I include Keeweb and the Hack font I love so dearly
$GithubReleasesPackages = @{
    'farag2/Windows-10-Sophia-Script' = 'Sophia.Script.v*.*.*.zip'
    'Maassoft/ColorControl'           = 'ColorControl.zip';
    'lostindark/DriverStoreExplorer'  = 'DriverStoreExplorer.v*.*.*.zip';
    'krlvm/BeautySearch'              = 'BeautySearch.exe';
    'sandboxie-plus/Sandboxie'        = 'Sandboxie-Plus-x64.exe'
    'stnkl/EverythingToolbar'         = 'EverythingToolbar-*.*.*.msi';
    'Hofknecht/SystemTrayMenu'        = 'SystemTrayMenu-*.*.*.*.zip';
    'Klocman/Bulk-Crap-Uninstaller'   = 'BCUninstaller_*.*_setup.exe';
    'svenmauch/WinSlap'               = 'WinSlap.exe';
    'AlexanderPro/SmartSystemMenu'    = 'SmartSystemMenu_v*.*.*.zip';
    'CXWorld/CapFrameX'               = 'CapFrameX_v*.*.*_Portable.zip'
}


#Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('http://boxstarter.org/bootstrapper.ps1')); get-boxstarter -Force
$UtilBinPath = "C:\ZenBoxSetup\UtilBin"
$UtilDownloadPath = "C:\ZenboxSetup\Downloads"

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
        $DownloadPath = (join-path $UtilDownloadPath $_.Name)
        if ($_.name -like $GithubReleasesPackages[$software]) {
            if ( -not (Test-Path $_.name)) {
                try {
                    Write-Output "Downloading $($_.name)..."
                    Invoke-WebRequest $_.'browser_download_url' -OutFile $DownloadPath
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
            Invoke-WebRequest $ManualDownloadInstall[$software] -OutFile $DownloadPath -UseBasicParsing
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