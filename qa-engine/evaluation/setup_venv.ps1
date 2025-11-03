# PowerShell script to set up Python 3.11 virtual environment for qafacteval
# Make sure Python 3.11 is installed first!

Write-Host "Setting up Python 3.11 virtual environment for qafacteval..." -ForegroundColor Green

# Check if Python 3.11 is available
$python311 = Get-Command python3.11 -ErrorAction SilentlyContinue
if (-not $python311) {
    Write-Host "ERROR: Python 3.11 not found!" -ForegroundColor Red
    Write-Host "Please install Python 3.11 first:" -ForegroundColor Yellow
    Write-Host "  https://www.python.org/downloads/release/python-3119/" -ForegroundColor Cyan
    Write-Host "  Make sure to check 'Add Python 3.11 to PATH' during installation" -ForegroundColor Yellow
    exit 1
}

Write-Host "✓ Python 3.11 found: $($python311.Source)" -ForegroundColor Green
Write-Host "Python version:" -ForegroundColor Cyan
& python3.11 --version

# Create virtual environment
Write-Host "`nCreating virtual environment..." -ForegroundColor Yellow
if (Test-Path "venv") {
    Write-Host "Virtual environment already exists. Removing old one..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force venv
}

python3.11 -m venv venv

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to create virtual environment" -ForegroundColor Red
    exit 1
}

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
& .\venv\Scripts\Activate.ps1

# Upgrade pip
Write-Host "`nUpgrading pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip

# Install requirements
Write-Host "`nInstalling requirements (this may take a while)..." -ForegroundColor Yellow
pip install -r requirements.txt

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n✓ Setup complete!" -ForegroundColor Green
    Write-Host "`nTo use this environment in the future:" -ForegroundColor Cyan
    Write-Host "  1. Navigate to this directory" -ForegroundColor White
    Write-Host "  2. Run: .\venv\Scripts\Activate.ps1" -ForegroundColor White
    Write-Host "  3. Run your scripts: python multi-eval.py --id 1" -ForegroundColor White
} else {
    Write-Host "`nERROR: Failed to install requirements" -ForegroundColor Red
    exit 1
}

