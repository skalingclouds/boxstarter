$UtilBinPath = "C:\ZenBoxSetup\UtilBin"
$UtilDownloadPath = "C:\ZenboxSetup\Downloads"
$GithubReleasesPackages = @{
    'farag2/Windows-10-Sophia-Script' = 'Sophia.Script.v*.*.*.zip';
    #'Maassoft/ColorControl'           = 'ColorControl.zip';
    #'lostindark/DriverStoreExplorer'  = 'DriverStoreExplorer.v*.*.*.zip';
    #'krlvm/BeautySearch'              = 'BeautySearch.exe';
    #'sandboxie-plus/Sandboxie'        = 'Sandboxie-Plus-x64.exe'
    #'stnkl/EverythingToolbar'         = 'EverythingToolbar-*.*.*.msi';
    #'Hofknecht/SystemTrayMenu'        = 'SystemTrayMenu-*.*.*.*.zip';
    #'Klocman/Bulk-Crap-Uninstaller'   = 'BCUninstaller_*.*_setup.exe';
    #'svenmauch/WinSlap'               = 'WinSlap.exe';
    #'AlexanderPro/SmartSystemMenu'    = 'SmartSystemMenu_v*.*.*.zip';
    #'CXWorld/CapFrameX'               = 'CapFrameX_v*.*.*_Portable.zip'
}

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
        if ($_.Name -like $GithubReleasesPackages[$software]) {
            if (!(Test-Path (Join-Path $UtilBinPath $_.Name))) {
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
    Expand-Archive -Path (Join-Path $UtilDownloadPath $_.Name) -DestinationPath (Join-Path $UtilBinPath ($_.Name).split('.')[0]) -Force }
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
    }
}
Start-SophiaScript
