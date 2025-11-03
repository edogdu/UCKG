# Installing Python 3.10/3.11 for qafacteval Compatibility

## Why Python 3.10/3.11?
The `qafacteval` package requires old dependencies (spacy 2.2.4) that are incompatible with Python 3.12, which removed the `distutils` module.

## Step 1: Download Python 3.11

1. Go to: https://www.python.org/downloads/release/python-3119/
2. Scroll down to "Files" section
3. Download: **Windows installer (64-bit)** (e.g., `python-3.11.9-amd64.exe`)

   OR use Python 3.10:
   - https://www.python.org/downloads/release/python-31012/
   - Download: **Windows installer (64-bit)**

## Step 2: Install Python 3.11

1. Run the installer
2. ✅ **IMPORTANT**: Check "Add Python 3.11 to PATH" at the bottom
3. Click "Install Now" (or "Customize installation" → Next → Next)
4. Wait for installation to complete

## Step 3: Verify Installation

Open PowerShell and run:
```powershell
python3.11 --version
```
Should show: `Python 3.11.9` (or similar)

## Step 4: Create Virtual Environment

Navigate to your evaluation directory and create a venv:

```powershell
cd S:\UCKG2.0\UCKG\qa-engine\evaluation
python3.11 -m venv venv
```

## Step 5: Activate Virtual Environment

```powershell
.\venv\Scripts\Activate.ps1
```

If you get an execution policy error, run:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then activate again:
```powershell
.\venv\Scripts\Activate.ps1
```

## Step 6: Install Requirements

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Step 7: Verify Installation

```powershell
python -c "from qafacteval import QAFactEval; print('✓ QAFactEval installed successfully')"
```

## Using the Virtual Environment

Every time you want to use this environment:

1. Navigate to: `S:\UCKG2.0\UCKG\qa-engine\evaluation`
2. Activate: `.\venv\Scripts\Activate.ps1`
3. Run your scripts: `python multi-eval.py --id 1`

The virtual environment keeps Python 3.11 separate from your system Python 3.12.

