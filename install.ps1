<#
.SYNOPSIS
    Installs NetShot (Python version) on Windows: virtual environment, Playwright, Chromium.

.DESCRIPTION
    Creates .venv in the application folder (your global Python is not touched), installs
    requirements.txt, downloads Chromium for Playwright, then checks that everything imports.
    Running it again updates the installation. Nothing is installed outside the application
    folder, except Chromium in %LOCALAPPDATA%\ms-playwright (Playwright's own location).

.PARAMETER Proxy
    HTTP proxy for pip and the Chromium download, e.g. http://proxy.company.local:8080
    (default: the HTTPS_PROXY / HTTP_PROXY variables already set, if any).

.PARAMETER Recreate
    Delete .venv and start again from scratch.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File install.ps1
    powershell -ExecutionPolicy Bypass -File install.ps1 -Proxy http://proxy.company.local:8080
#>
param(
    [string]$Proxy = "",
    [switch]$Recreate
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$MinVersion = [version]"3.9"

function Step($text) { Write-Host "`n==> $text" -ForegroundColor Cyan }
function Fail($text) { Write-Host "`nERREUR : $text" -ForegroundColor Red; exit 1 }

# Runs a native command and stops on a non-zero exit code
function Run([string]$exe, [string[]]$arguments) {
    & $exe @arguments
    if ($LASTEXITCODE -ne 0) { Fail "échec de : $exe $($arguments -join ' ')" }
}

if ($Proxy) {
    $env:HTTPS_PROXY = $Proxy
    $env:HTTP_PROXY = $Proxy
    Write-Host "Proxy : $Proxy"
}

# --- 1. Python ------------------------------------------------------------------------
Step "Recherche de Python $MinVersion ou plus récent"
$python = $null
foreach ($candidate in @(@("py", "-3"), @("python"), @("python3"))) {
    $exe = $candidate[0]
    $pre = @($candidate | Select-Object -Skip 1)
    if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
    try {
        $out = & $exe @pre -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
    } catch { continue }
    # The Microsoft Store alias prints nothing (or opens the Store) when Python is not installed
    if ($LASTEXITCODE -eq 0 -and $out -match '^\d+\.\d+$' -and [version]$out -ge $MinVersion) {
        $python = @{ exe = $exe; pre = $pre; version = $out }
        break
    }
}
if (-not $python) {
    Fail "Python $MinVersion+ introuvable. Installe-le depuis https://www.python.org/downloads/ (cocher « Add python.exe to PATH ») ou avec : winget install Python.Python.3.12"
}
Write-Host "Python $($python.version) ($($python.exe) $($python.pre -join ' '))"

# --- 2. Virtual environment -----------------------------------------------------------------
$venv = Join-Path $PSScriptRoot ".venv"
$venvPython = Join-Path $venv "Scripts\python.exe"
if ($Recreate -and (Test-Path $venv)) {
    Step "Suppression de l'ancien environnement .venv"
    Remove-Item -Recurse -Force $venv
}
if (-not (Test-Path $venvPython)) {
    Step "Création de l'environnement virtuel .venv"
    Run $python.exe ($python.pre + @("-m", "venv", $venv))
} else {
    Step "Environnement .venv existant : mise à jour"
}

# --- 3. Python packages ----------------------------------------------------------------------
Step "Installation des dépendances (requirements.txt)"
Run $venvPython @("-m", "pip", "install", "--disable-pip-version-check", "--upgrade", "pip")
Run $venvPython @("-m", "pip", "install", "--disable-pip-version-check", "-r", "requirements.txt")

# --- 4. Chromium for Playwright ----------------------------------------------------------------
Step "Téléchargement de Chromium pour Playwright (environ 150 Mo, une seule fois)"
Run $venvPython @("-m", "playwright", "install", "chromium")

# --- 5. Checks ---------------------------------------------------------------------------------
Step "Vérification"
Run $venvPython @("-c", "import tkinter, playwright.async_api, core.scan, core.gui; print('imports OK')")
Run $venvPython @("netshot.py", "--list-ua") | Out-Null

# Small launchers so the app runs with the environment without activating it
Set-Content -Encoding ASCII -Path (Join-Path $PSScriptRoot "netshot.cmd") -Value @(
    "@echo off", '"%~dp0.venv\Scripts\python.exe" "%~dp0netshot.py" %*')
Set-Content -Encoding ASCII -Path (Join-Path $PSScriptRoot "netshot_gui.cmd") -Value @(
    "@echo off", 'start "" "%~dp0.venv\Scripts\pythonw.exe" "%~dp0netshot_gui.py" %*')

Write-Host "`nInstallation terminée." -ForegroundColor Green
Write-Host "  Interface graphique : double-clic sur netshot_gui.cmd"
Write-Host "  Ligne de commande   : .\netshot.cmd 192.168.1.0/24   (ou .\netshot.cmd --help)"
