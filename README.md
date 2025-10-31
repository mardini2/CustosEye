# 𖦹 CustosEye ꩜

CustosEye is a local-first visibility and integrity monitor with a lightweight rules engine, contextual trust scoring (CSC v2), and a clean web dashboard.  
No cloud, no telemetry everything runs locally 👁

---

## Overview

CustosEye continuously monitors processes, network activity, and file integrity, then classifies each event using an explainable trust model.  
The dashboard presents this data in real time with filters, search, and export options.

**Core features**
- Local-only monitoring for process, network, and file changes.
- Categorical trust scoring via `CSCTrustEngine` (Trusted / Caution / Suspicious / Malicious).
- Real-time dashboard at [http://127.0.0.1:8765](http://127.0.0.1:8765) with live filters and export.
- Integrity watcher that supports SHA-256 or `mtime+size` modes.
- Automatic rule and configuration reloads on file changes.

---

## Quick start

```bash
# (Optional) Create and activate a venv
python -m venv .venv
. .venv/Scripts/activate

# Install all dependencies
python -m pip install -U pip
python -m pip install -r requirements.txt

# 3. Launch
python -m app.console
# Console output:
# CustosEye running at http://127.0.0.1:8765/
```

**Command-line options**
```bash
python -m app.console --console    # run headless (no browser)
python -m app.console --no-open    # dashboard only
python -m app.console --tray       # run with system tray icon
```

---

## Dashboard

### Tabs
- **Live feed:** filter by level (Info / Warning / Critical), pause/resume, search, export JSON.
- **Process Tree:** PPID→PID hierarchy with trust badges, search, expand/collapse, export.
- **Integrity:** manage watched files, hash instantly, or browse and register new targets.
- **About:** version, build, buffer size, and runtime information.

### API endpoints
| Endpoint | Description |
|-----------|-------------|
| `/api/events` | Live event stream |
| `/api/export` | Export feed as JSON |
| `/api/proctree` | Current process tree |
| `/api/about` | Version and build info |
| `/api/integrity/targets` | List, add, or remove integrity targets |
| `/api/integrity/hash` | Compute hash for a given file |
| `/api/integrity/browse` | Browse files (Windows only) |

---

## Trust Scoring (CSC v2)

`algorithm/csc_engine.py` implements **CSCTrustEngine**, a contextual trust classifier.

Each event is evaluated on:
- Path context (system vs. user/temp)
- Signing status and publisher cues
- Name entropy and suspicious tokens
- Network posture (listening ports, remote endpoints)
- Parent process behavior
- Elevation and service context
- Prevalence with time-decay scoring

It produces:
```json
{
  "version": "csc-v2",
  "verdict": "trusted | caution | suspicious | malicious | unknown",
  "cls": "system | service | dev_tool | game | utility | unknown",
  "confidence": 0.0–1.0,
  "reasons": ["..."],
  "signals": { "key": "value" }
}
```

---

## Rules Engine

- Config file: `data/rules.json`
- Hot-reloads automatically.
- Applies severity (`level`) and contextual `reason` to each event.
- Coalesces duplicate events within a short window to reduce spam while preserving “worsened” ones.

---

## Project Layout

```
app/           main console + entrypoint
dashboard/     Flask dashboard and API
agent/         system monitors (process, network, integrity)
algorithm/     CSCTrustEngine & scoring logic
data/          configuration JSON files
assets/        icons and favicon resources
tests/         pytest suite
```

---

## Development and Testing

Formatting, linting, typing, and test coverage can be verified before committing:

```bash
python -m black tests
python -m black app agent algorithm dashboard
python -m black --check app agent algorithm dashboard tests
python -m ruff check app agent algorithm dashboard tests --fix
python -m ruff check app agent algorithm dashboard tests
python -m mypy app agent algorithm dashboard
python -m pytest -q
```

### Automated test suite
Located under `tests/`:
- **Algorithm tests:** verify trust scoring, classification, decay, and boundary logic.
- **Helper tests:** validate utility functions and entropy calculations.
- **EXE smoke test:** ensures the PyInstaller build starts and exits cleanly.

---

## Building the EXE (Windows)

```powershell
pyinstaller --noconfirm --onefile --name CustosEye.exe --console `
  --icon assets/favicon.ico `
  --add-data "data;data" `
  --add-data "assets;assets" `
  app/console.py
```

Artifacts:  
`CustosEye.exe`, `VERSION.txt`, and `CustosEye-Windows.zip` (portable bundle).

GitHub Actions automatically runs this build, embeds version and commit hash, and updates integrity suppressions.

---

## Configuration

| Purpose | File |
|----------|------|
| Detection rules | `data/rules.json` |
| Trust weights | `data/csc_weights.json` |
| Integrity targets | `data/integrity_targets.json` |
| Trust database | `data/trust_db.json` |

---

## Security

- Serves only on `127.0.0.1`
- No external calls or telemetry
- Exports are manual and local
- All rule and trust data stored under `data/`

---

## Troubleshooting

| Please submit whatever the problem is into the issues tab in github |

| Port conflict | Default port `8765` can be changed via CLI or config |

---

## Roadmap

- WebSocket-based live updates
- Rule suppression and exemptions
- Inline trust details in dashboard
- Trust DB import/export

---

## License

MIT — do cool things, don’t sue me man 𒅒

Use, modify, and share freely. Attribution appreciated.
