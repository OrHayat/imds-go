#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$GO_MIN_VERSION = "1.22"
$GIT_TOWN_MIN_VERSION = "22.0"

function Compare-Version {
    param([string]$Current, [string]$Minimum)
    $c = [version]$Current
    $m = [version]$Minimum
    return $c -ge $m
}

function Install-Go {
    $installed = Get-Command go -ErrorAction SilentlyContinue
    if ($installed) {
        $version = (go version) -replace '.*go(\d+\.\d+).*', '$1'
        if (Compare-Version $version $GO_MIN_VERSION) {
            Write-Host "[OK] Go $version" -ForegroundColor Green
            return
        }
        Write-Host "[UPGRADE] Go $version found, need >= $GO_MIN_VERSION" -ForegroundColor Yellow
    } else {
        Write-Host "[MISSING] Go not found" -ForegroundColor Yellow
    }
    Write-Host "Installing Go via winget..." -ForegroundColor Cyan
    winget install GoLang.Go --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to install Go. Install manually from https://go.dev/dl/" -ForegroundColor Red
        exit 1
    }
    Write-Host "[OK] Go installed. Restart your terminal to update PATH." -ForegroundColor Green
}

function Install-GitTown {
    $installed = Get-Command git-town -ErrorAction SilentlyContinue
    if ($installed) {
        $versionOutput = git-town --version 2>&1
        $version = ($versionOutput -replace '.*?(\d+\.\d+).*', '$1')
        if (Compare-Version $version $GIT_TOWN_MIN_VERSION) {
            Write-Host "[OK] git-town $version" -ForegroundColor Green
            return
        }
        Write-Host "[UPGRADE] git-town $version found, need >= $GIT_TOWN_MIN_VERSION" -ForegroundColor Yellow
    } else {
        Write-Host "[MISSING] git-town not found" -ForegroundColor Yellow
    }
    Write-Host "Installing git-town via go install..." -ForegroundColor Cyan
    go install github.com/git-town/git-town/v22@v22.7.1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to install git-town." -ForegroundColor Red
        exit 1
    }
    Write-Host "[OK] git-town installed" -ForegroundColor Green
}

Write-Host "=== imds-go dev setup (Windows) ===" -ForegroundColor Cyan
Write-Host ""
Install-Go
Install-GitTown
Write-Host ""
Write-Host "Setup complete." -ForegroundColor Green
