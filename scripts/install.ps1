<#
.SYNOPSIS
    Installs the BTXS™ command-line tool for Windows.
.DESCRIPTION
    This script downloads the latest Windows binary for BTXS from GitHub,
    installs it to the user's home directory (~/.btxs), and adds the
    installation directory to the user's PATH.
.EXAMPLE
    To run from the web (ensure Execution Policy is set appropriately):
    iwr https://raw.githubusercontent.com/BlackTechX011/BTXS/main/scripts/install.ps1 | iex
.NOTES
    Author: BlackTechX011
    License: BTXS EULA (https://github.com/BlackTechX011/BTXS/blob/main/LICENSE.md)
#>

# Stop script on any error
$ErrorActionPreference = 'Stop'

# --- Configuration ---
$Repo = "BlackTechX011/BTXS"
$InstallDir = Join-Path $HOME ".btxs"
$ExeName = "btxs.exe"

# --- Main Logic ---
try {
    Write-Host "Starting BTXS™ installation for Windows..." -ForegroundColor Cyan

    # 1. Detect Architecture
    if ($env:PROCESSOR_ARCHITECTURE -ne "AMD64") {
        throw "Unsupported architecture: $($env:PROCESSOR_ARCHITECTURE). BTXS currently supports AMD64 (64-bit) on Windows."
    }
    $Arch = "amd64"
    $Os = "windows"
    $BinaryName = "btxs-$Os-$Arch.exe"
    Write-Host "Detected System: $Os-$Arch. Target binary: $BinaryName" -ForegroundColor Cyan

    # 2. Get the download URL for the latest release
    $ApiUrl = "https://api.github.com/repos/$Repo/releases/latest"
    Write-Host "Fetching latest release information from GitHub..." -ForegroundColor Cyan
    
    $latestRelease = Invoke-RestMethod -Uri $ApiUrl
    $asset = $latestRelease.assets | Where-Object { $_.name -eq $BinaryName }

    if (-not $asset) {
        throw "Could not find a download URL for '$BinaryName'. The release may be missing."
    }
    
    $DownloadUrl = $asset.browser_download_url
    Write-Host "Download URL: $DownloadUrl" -ForegroundColor Cyan

    # 3. Download and Install
    $InstallPath = Join-Path $InstallDir $ExeName
    Write-Host "Installing to $InstallPath..." -ForegroundColor Cyan
    
    # Ensure the installation directory exists
    if (-not (Test-Path -Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir | Out-Null
    }

    Invoke-WebRequest -Uri $DownloadUrl -OutFile $InstallPath
    
    # 4. Add to PATH (permanently for the current user)
    Write-Host "Adding installation directory to your PATH..." -ForegroundColor Cyan
    $UserPath = [System.Environment]::GetEnvironmentVariable('Path', 'User')
    
    if (-not ($UserPath -split ';' -contains $InstallDir)) {
        $NewPath = "$UserPath;$InstallDir"
        [System.Environment]::SetEnvironmentVariable('Path', $NewPath, 'User')
        
        # Also update the current session's PATH
        $env:PATH += ";$InstallDir"
        
        Write-Host "Updated user PATH. Please restart your terminal for the changes to take full effect." -ForegroundColor Yellow
    } else {
        Write-Host "PATH is already configured." -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "BTXS™ was installed successfully!" -ForegroundColor Green
    Write-Host "You can now run 'btxs' from a new terminal window." -ForegroundColor Green

}
catch {
    Write-Host "An error occurred during installation:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
