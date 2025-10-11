# CustosEye – Phase 1 MVP

**Goal:** working Windows `.exe` that monitors processes, checks file integrity, applies simple rules, and shows a minimal dashboard.

## Quick start (Windows 11, Python 3.11.9)

```powershell
# Clone and install
pip install -e .
pip install black ruff mypy pytest pyinstaller

# Run console only
python -m app.console --console

# Run with dashboard (http://127.0.0.1:8765)
python -m app.console