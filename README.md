# CustosEye

Local-first system visibility with a lightweight rules engine, smart trust scoring, and a polished web dashboard. No cloud, no drama.. just signal.

## What it does

- Watches processes, network, and file integrity on your machine.
- Scores trust per process (0–100) with explainable reasons (CSCTrustEngine).
- Shows live events in a clean web UI at `http://127.0.0.1:8765/` with filters, search, and export.
- Builds a collapsible Process Tree (PPID→PID) with trust labels.
- Hot-reloads your rules when `data/rules.json` changes.

The console now just prints a welcome banner and the dashboard URL.

---

## Quick start

```bash
# 1. Create a virtual environment
python -m venv .venv
. .venv/Scripts/activate

# 2. Install dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install waitress pystray pillow

# 3. Run
python -m app.console
# Console shows:
# Welcome to CustosEye – Your Third Eye
# Dashboard running at http://127.0.0.1:8765/
```

Options:
```bash
python -m app.console --console   # run without opening browser
python -m app.console --no-open   # dashboard only
python -m app.console --tray      # system tray icon
```

---

## The Dashboard

- Live feed with Info/Warning/Critical filters, search, pause, refresh, export.
- Process Tree tab with expand/collapse, trust pills, search, export (JSON/XLSX), copy.
- About tab shows version, build, and buffer info.

### API endpoints
- `/api/events`
- `/api/export`
- `/api/proctree`
- `/api/about`
- Favicons: `/favicon.ico`, `/favicon-32x32.png`, `/apple-touch-icon.png`
- `/api/integrity/targets` (GET, POST, DELETE)
- `/api/integrity/hash` (POST)
- `/api/integrity/browse` (POST, Windows only)

---

## Trust scoring

Explainable, local, and tunable (see `data/csc_weights.json`).

Uses multiple signals:
- Prevalence & decay
- Path context
- Name entropy
- Signer validity
- Network posture
- Parent process behavior

Produces:
```json
{
  "trust": 0..100,
  "label": "high|medium|low",
  "reasons": [...]
}
```

---

## Rules engine

- Config: `data/rules.json`
- Hot-reloads automatically
- Applies `level` and `reason` to events

---

## Project structure

```
app/           main console + setup
dashboard/     Flask app & web UI
agent/         process, network, integrity monitors
algorithm/     CSCTrustEngine & scoring logic
data/          JSON config files
assets/        favicon files
tests/         pytest suite
```

---

## Development

```bash
python -m black --check app agent algorithm dashboard tests
python -m ruff check app agent algorithm dashboard tests
python -m mypy app agent algorithm dashboard
python -m pytest -q
```

- Integrity tab: pick files to watch (Windows Browse or paste path), choose rule
  (`sha256` or `mtime+size`), preview “Hash Now”, save/remove targets. Targets are written to
  `data/integrity_targets.json` and hot-reloaded by the Integrity checker.

---

## Building the EXE (Windows)

```powershell
pyinstaller --noconfirm --onefile --name CustosEye.exe --console `
  --icon assets/favicon.ico `
  --add-data "data;data" `
  --add-data "assets;assets" `
  app/console.py
```

GitHub Actions also handles this build automatically and uploads artifacts:
`CustosEye.exe`, `VERSION.txt`, and a ZIP with assets.

---

## Configuration

- Rules: `data/rules.json`
- Weights: `data/csc_weights.json`
- Integrity targets: `data/integrity_targets.json`
- Trust DB: `data/trust_db.json`

---

## Security

- Local-only (`127.0.0.1`)
- No external calls
- Exports are manual and stay local

---

## Troubleshooting

- **Icon missing:** ensure favicon files exist and are bundled.
- **No events:** some network events without PID/name are ignored.
- **Missing assets:** confirm PyInstaller `--add-data` paths.
- **Port conflict:** default is `127.0.0.1:8765`.

---

## Roadmap

- WebSocket updates
- Rule suppressions
- Inline trust details
- Trust DB import/export

---

## License

MIT — do cool things, don’t sue me.