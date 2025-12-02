# 𖣐 CustosEye 𖣐

CustosEye is a local-first system monitoring tool that watches your processes, network connections, and file integrity. Everything runs on your machine - no cloud, no telemetry, no external connections. It uses a trust scoring engine to evaluate processes and presents everything through a web dashboard.

---

## What It Does

CustosEye continuously monitors three things:

**Process monitoring** - Tracks all running processes, their parent relationships, memory usage, command lines, and network connections. Each process gets evaluated by a trust scoring engine that looks at where it came from, whether it's signed, what it's doing, and how often you've seen it before.

**Network monitoring** - Scans active network connections to see what's listening on ports and what outbound connections processes are making.

**File integrity monitoring** - Watches specific files you care about and alerts you when they change. Supports two modes: SHA-256 hashing for exact change detection, or mtime+size for lighter monitoring. Can show you what changed with a diff viewer that works on text files, Office documents, and PDFs.

All of this data flows into a web dashboard that you access locally. The dashboard has authentication (login with optional 2FA), real-time event feeds, process trees, and export capabilities.

---

## Quick Start

### Prerequisites

- Python 3.11 (specifically 3.11.9 is tested)
- Windows 10 or 11

### Setup

```bash
# Create and activate a virtual environment
python -m venv .venv
# If that doesn't work due to the IDE can't find the right python version, try:
py -3.11 -m venv .venv
.venv\Scripts\activate

# Install dependencies
python -m pip install -U pip
python -m pip install -r requirements.txt

# Generate environment file with secrets (auto-creates .env)
python setup_env.py

# Run CustosEye
python -m app.console
```

The dashboard will open automatically in a windowed application or in your browser at `http://127.0.0.1:8765/`. If it doesn't open automatically, visit that URL in your browser.

**Viewing static HTML files (for GitHub Pages):**
If you want to preview the static HTML files (like index.html, privacy.html, etc.) without running the full application:

```bash
python -m http.server 8765
```

Then visit `http://127.0.0.1:8765/` in your browser to see the static pages.

**Important:** The static HTML server uses the same port (8765) as the CustosEye application. Make sure CustosEye is not running when you use the static server, or you'll get a port conflict. If you need both, use a different port for the static server (e.g., `python -m http.server 8000`).

**Command-line options:**
```bash
python -m app.console --no-open    # Don't open dashboard automatically
python -m app.console --tray       # Run with system tray icon
python -m app.console --browser   # Open dashboard in browser instead of windowed application
```

**Note:** By default, CustosEye opens the dashboard in a windowed application (if pywebview is available). Use `--browser` to open it in your default browser instead. Press `Ctrl+C` in the terminal to shut down the application.

**Regenerating secrets:**
If you need to regenerate the `.env` file (deletes existing one first):
```bash
del .env  # Windows
python setup_env.py
```

---

## Testing

The project includes a pytest test suite. Run all tests with:

```bash
python -m pytest tests/ -q
```

The test suite covers:
- Trust scoring engine logic and edge cases
- Helper functions (entropy, hex detection, etc.)
- API endpoints (events, process tree, integrity)
- Diff computation and formatting
- EXE smoke test (verifies the built executable starts correctly)

**Code quality checks:**
```bash
# Format test files
python -m black tests

# Format all source code
python -m black app agent algorithm dashboard

# Check formatting without changing files
python -m black --check app agent algorithm dashboard tests

# Lint and auto-fix
python -m ruff check app agent algorithm dashboard tests --fix

# Lint without fixing
python -m ruff check app agent algorithm dashboard tests

# Type checking
python -m mypy app agent algorithm dashboard

# Run tests
python -m pytest -q
```

---

## Building the Executable

### Using PyInstaller

Build a standalone Windows executable:

```powershell
pyinstaller --noconfirm --onefile --name CustosEye.exe --console `
  --icon dashboard\static\assets\favicon.ico `
  --add-data "data;data" `
  --add-data "dashboard\static;dashboard\static" `
  --add-data "dashboard\templates;dashboard\templates" `
  app\console.py
```

The executable will be in the `dist/` folder. You'll also need to copy the `data/` directory alongside the exe for it to work properly.

### Using the Installer (Inno Setup)

To create a proper Windows installer:

1. Build the executable first (see above)
2. Make sure you have Inno Setup installed
3. Run the installer script:

```powershell
iscc installer.iss
```

Or with a specific version:

```powershell
iscc /DAppVersion="1.0.0" installer.iss
```

The installer will be created in `installer_output/` as `CustosEye-Setup.exe`. It includes:
- The main executable
- Data directory with default configs
- Assets (icons, etc.)
- Optional desktop shortcut
- Uninstaller

**Testing the installer:**
1. Build the executable first (see PyInstaller section above)
2. Run the Inno Setup script:
   ```powershell
   iscc installer.iss
   ```
3. Install from the generated setup file in `installer_output/CustosEye-Setup.exe`
4. Verify CustosEye launches and the dashboard works
5. Test uninstallation

**Quick test commands:**
```powershell
# Build the executable
pyinstaller --noconfirm --onefile --name CustosEye.exe --console --icon dashboard\static\assets\favicon.ico --add-data "data;data" --add-data "dashboard\static;dashboard\static" --add-data "dashboard\templates;dashboard\templates" app\console.py

# Build the installer
iscc installer.iss

# Run tests
python -m pytest -q
```

---

## Dashboard Features

### Live Events Tab

Real-time stream of all security events. Filter by level (Info, Warning, Critical), search by process name or path, pause/resume the feed, and export to CSV, JSON, JSONL, or XLSX.

### Process Tree Tab

Hierarchical view of all running processes showing parent-child relationships. Each process shows its trust verdict (trusted, caution, suspicious, malicious, unknown) and class (system, service, dev_tool, game, utility, etc.). Search and expand/collapse nodes.

### Integrity Tab

Manage files you want to monitor for changes. Add files with either SHA-256 or mtime+size rules. View diffs when changes are detected. The diff viewer shows what changed in text files, Office documents, and PDFs without uploading anything - all analysis happens locally.

### About Tab

Version information, build details, buffer size, and runtime stats.

---

## Trust Scoring (CSC v2)

The trust engine evaluates processes using multiple signals:

- **Path context** - System directories are trusted, temp/downloads are suspicious
- **Code signing** - Valid signatures boost trust, especially from known publishers
- **Name heuristics** - High entropy names, hex-like strings, misspellings of system processes reduce trust
- **File characteristics** - Very new or tiny binaries outside system dirs are flagged
- **Network behavior** - Listening on ports (especially risky ones) is suspicious
- **Parent context** - Processes launched by script interpreters get penalized
- **Elevation/service** - Elevated processes or services from user directories are highly suspicious
- **Prevalence** - Processes seen frequently on your machine earn trust over time (with time decay)

The engine produces categorical verdicts (trusted, caution, suspicious, malicious, unknown) with confidence scores and human-readable reasons.

---

## Rules Engine

The rules engine (`data/rules.json`) applies severity levels and contextual reasons to events. Rules are evaluated in order - first match wins. Rules can match on:
- Source type (process, network, integrity)
- Process names or executable paths
- Listening ports
- Remote connections
- And more

Rules hot-reload automatically when you edit the file. The engine also deduplicates events within a short window to reduce noise while preserving important state changes.

---

## Configuration Files

All configuration lives in the `data/` directory:

| File | Purpose |
|------|---------|
| `rules.json` | Detection rules that assign severity levels to events |
| `csc_weights.json` | Trust scoring weights and thresholds |
| `integrity_targets.json` | Files being monitored for changes |
| `trust_db.json` | Local prevalence database (auto-generated) |
| `name_trust.json` | Fast-path trust verdicts for known process names |
| `self_suppress.json` | Filters to hide CustosEye's own processes |

---

## Project Structure

```
app/              Main entry point (console.py)
dashboard/        Flask web server and API
  templates/      HTML templates (including auth pages)
  static/         CSS, JavaScript, icons
agent/            Monitoring agents
  monitor.py      Process monitoring
  network_scan.py Network connection scanning
  integrity_check.py File integrity checking
  rules_engine.py Rules evaluation
algorithm/        Trust scoring engine
  csc_engine.py   CSC v2 trust classifier
data/             Configuration JSON files
tests/            Pytest test suite
```

---

## Security

- Dashboard serves only on `127.0.0.1` (localhost)
- No external network calls or telemetry
- All data stored locally in `data/` directory
- Authentication required to access dashboard (login with optional 2FA)
- Session secrets auto-generated per installation
- Exports are manual and local only

---

## Troubleshooting

**Port already in use:** Another application is using port 8765. Close it or change the port in the configuration.

**Dashboard won't open:** Manually visit `http://127.0.0.1:8765/` in your browser.

**Antivirus warnings:** The executable isn't code-signed yet. If you trust the source, add an exception.

**Tests failing:** Make sure you're using Python 3.11 and all dependencies are installed. Try regenerating the `.env` file.

**Issues or questions:** Check the GitHub issues page or submit a new issue.

---

## 𖦹 License ꩜

GPL-3.0 - See LICENSE.md for full license text.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
