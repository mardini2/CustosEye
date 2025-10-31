# CustosEye for Windows

**Local system visibility. No cloud, no accounts — just insight.**

## How to Run
1. Download `CustosEye.zip`.
2. Unzip it anywhere (for example, Desktop).
3. Double-click `CustosEye.exe`.
4. Your browser will open the dashboard at `http://127.0.0.1:8765/`.

## Notes
- Works on Windows 10 and 11
- No installation required
- All data stays local on your machine

---

## Dashboard Overview

### Live Events
- Shows process, network, and integrity events as they happen.
- Use the level filter (Info / Warning / Critical) and the search box to narrow results.
- You can export the current view as CSV, JSON, JSONL, or XLSX.

### Process Trust Labels
Every process gets a **verdict** and **class**:
- **Verdict:** `trusted`, `caution`, `suspicious`, `malicious`, or `unknown`
- **Class:** broad family hints (for example, `system`, `popular_app`, `service`, `dev_tool`)

These labels combine basic context (where the file lives, whether it's signed, launch context)
and simple, local prevalence signals. They’re guides to help you prioritize what to look at.

---

## Integrity Tab (File Change Watch)

Use this to watch important files (configs, scripts, docs) for unexpected changes.

### Add a File
1. Click **Add Target** and choose a file path.
2. Pick a **rule**:
   - **`sha256`** — Strong: alerts if *any* byte changes.
   - **`mtime+size`** — Light: alerts only if the file’s modified-time and size change.

> First time you add a file, CustosEye records a **baseline** (the reference state).

### Run a Check
- Click **Hash / Check** to compare the current file to the baseline.
- The **Result** column will show:
  - **`OK`** — Matches the baseline.
  - **`OK (baseline set)`** — First run established the baseline.
  - **`CHANGED`** — The file differs from the baseline.
  - **`ERR: …`** — The file couldn’t be read (moved, locked, or permission issues).

### View Changes (Privacy-preserving)
- Click **View changes** on a changed file to see:
  - Which **regions** changed (byte ranges).
  - A tiny **preview** of the changed bytes (hex + safe ASCII).
  - An **approximate % of file changed**.

For Office files (Word/Excel/PowerPoint), you’ll also see which internal parts
were added/removed/modified (for example, a slide or embedded image). We **never**
upload your files; this analysis runs locally and shows only minimal summaries.

### Tips
- Add critical configs or scripts with `sha256` for maximum assurance.
- For large media or frequently edited documents, `mtime+size` can be less noisy.
- You can remove a target anytime; it doesn’t touch your file.

---

## Troubleshooting
- **Dashboard didn’t open?** Visit `http://127.0.0.1:8765/` manually.
- **Port in use?** Another app may be using the default port. Close it and relaunch.
- **Antivirus popup?** No code signing yet, this can reduce this. Simply allow the app if you trust it.

## Uninstall
- Close the app and delete the unzipped folder. No drivers, no services, no registry keys are installed.