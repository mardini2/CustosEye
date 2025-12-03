# How to Use CustosEye

This guide covers how to use CustosEye once it's running. For installation and setup, see the main README.

---

## Getting Started

### Running the Portable Version

If you downloaded `CustosEye.zip`:

1. **Unzip the file** anywhere you want (Desktop, Documents, etc.)
2. **Open the unzipped folder**
3. **Double-click `CustosEye.exe`**
4. Your browser should automatically open to the dashboard at `http://127.0.0.1:8765/`

If the browser doesn't open automatically, manually visit `http://127.0.0.1:8765/` in your browser.

**Note:** The first time you run it, Windows Defender or your antivirus might show a warning because the executable isn't code-signed. This is normal - if you trust the source, allow it to run.

---

## First Launch

When you first run CustosEye, the dashboard opens at `http://127.0.0.1:8765/`. You'll see a login page.

**Creating your first account:**
1. Click "Sign up" on the login page
2. Choose a username and password
3. The first account you create becomes an admin account
4. You can enable 2FA later if you want extra security

**Logging in:**
- Enter your username and password
- If you enabled 2FA, you'll be prompted for a code from your authenticator app
- Sessions expire when you close your browser (for security)

---

## Live Events Tab

This is where you see everything happening on your system in real time.

**Understanding event levels:**
- **Info** - Normal activity, just informational
- **Warning** - Something worth paying attention to
- **Critical** - Potentially serious issues that need investigation

**Using filters:**
- Click the level chips (Info, Warning, Critical) to show or hide those events
- Use the search box to find specific processes, paths, or keywords
- Click "Pause" to freeze the feed while you investigate something

**Exporting data:**
- Click "Export" to download the current filtered view
- Choose format: CSV, JSON, JSONL, or XLSX
- Only exports what's currently visible based on your filters

**What you'll see:**
- Process events show the process name, path, trust verdict, and why it was flagged
- Network events show connections and listening ports
- Integrity events show file changes and verification results

---

## Process Tree Tab

This shows all running processes organized by parent-child relationships. It's useful for understanding what launched what.

**Reading the tree:**
- Top level shows processes with no parent (or system processes)
- Click the arrow next to a process to expand and see its children
- Each process shows its trust verdict badge and class label

**Trust verdicts:**
- **Trusted** - Looks legitimate based on location, signature, and history
- **Caution** - Neutral, nothing obviously wrong but not fully trusted
- **Suspicious** - Has some red flags worth investigating
- **Malicious** - Multiple strong indicators of malicious behavior
- **Unknown** - Not enough information to evaluate (often non-process events)

**Process classes:**
- **system** - Windows system processes
- **service** - Windows services
- **popular_app** - Well-known applications (Chrome, Firefox, etc.)
- **dev_tool** - Development tools
- **game** - Game executables
- **utility** - Utility programs
- **unknown** - Couldn't be classified

**Using the tree:**
- Search box filters processes by name or path
- Click "Expand All" to see everything at once
- Click "Collapse All" to start fresh
- Export the tree as JSON if you need it for analysis

---

## Integrity Tab

Use this to monitor important files for unauthorized changes. This is especially useful for configuration files, scripts, or documents you want to protect.

### Adding Files to Monitor

1. Click "Add Target"
2. Browse to the file you want to monitor (or type the path)
3. Choose a monitoring rule:
   - **SHA-256** - Detects any byte-level change. Use this for critical files where any modification matters
   - **mtime+size** - Only alerts if the file's modification time and size change. Use this for files that change frequently but you want to know about major edits

4. Click "Add" - the file is now being monitored

**First-time setup:**
When you first add a file, CustosEye establishes a baseline. This is the "known good" state that future checks compare against.

### Checking Files

Click "Hash / Check" next to any file to manually trigger a check. The Result column shows:

- **OK** - File matches the baseline, no changes detected
- **OK (baseline set)** - First check completed, baseline established
- **CHANGED** - File differs from the baseline
- **ERR: [message]** - Couldn't read the file (moved, deleted, locked, or permission issue)

**Automatic checking:**
Files are automatically checked every 30 seconds. You'll see events in the Live Events tab when changes are detected.

### Viewing What Changed

When a file shows "CHANGED", click "View changes" to see what actually changed.

**For text files:**
- Shows which lines changed
- Highlights additions (green) and deletions (red)
- Shows a preview of the changed content

**For Office documents (Word, Excel, PowerPoint):**
- Shows which internal parts changed (slides, paragraphs, embedded images, etc.)
- Indicates formatting changes (color, bold, italic, etc.)
- Shows approximate percentage of file that changed

**For PDFs:**
- Shows which pages changed
- Highlights text additions and deletions
- Shows formatting changes

**Privacy:**
All diff analysis happens locally on your machine. Nothing is uploaded anywhere. The diff viewer only shows summaries and small previews, not the full file contents.

### Managing Monitored Files

- **Remove** - Stops monitoring a file (doesn't delete the file itself)
- **Hash / Check** - Manually trigger a check
- **View changes** - See what changed (only available for changed files)

**Tips:**
- Use SHA-256 for critical configs, scripts, or sensitive documents
- Use mtime+size for large files or documents you edit frequently
- You can monitor as many files as you want
- Removing a file from monitoring doesn't affect the file itself

---

## About Tab

Shows system information:
- CustosEye version
- Build information
- Event buffer size and usage
- Runtime statistics

Useful for troubleshooting or verifying you're running the expected version.

---

## Understanding Trust Scores

The trust scoring engine evaluates every process using multiple factors. Here's what influences the verdict:

**Trust boosters:**
- Running from Windows system directories
- Valid code signature from known publisher (Microsoft, Google, etc.)
- Seen frequently on your machine before
- Normal outbound network connections

**Trust reducers:**
- Running from temp or downloads folders
- High entropy (random-looking) names
- Listening on risky ports (22, 3389, 4444, etc.)
- Launched by script interpreters (PowerShell, cmd, etc.)
- Elevated privileges but running from user directories
- Never seen before on this machine

**The verdict is a guide, not a verdict:**
Trust scores help you prioritize what to investigate. A "suspicious" verdict doesn't mean something is definitely malicious - it means there are enough red flags to warrant a closer look. Similarly, "trusted" doesn't mean you should ignore it completely if you see unusual behavior.

---

## Tips for Effective Monitoring

**Start with the defaults:**
The default rules and trust weights work well for most systems. Don't change them unless you understand what you're doing.

**Use filters:**
The Live Events tab can get noisy. Use level filters to focus on what matters - start with Critical and Warning events.

**Check the Process Tree regularly:**
Understanding what's normally running helps you spot anomalies. If you see a new process you don't recognize, check its trust verdict and where it came from.

**Monitor important files:**
Add critical configuration files, scripts, or documents to the Integrity tab. SHA-256 mode catches everything, but mtime+size is fine for files that change legitimately.

**Export for analysis:**
If you see something interesting, export the events before they scroll out of the buffer. The JSON format preserves all the details.

**Don't ignore the reasons:**
Each event shows why it was flagged. Read the reasons to understand what triggered the alert.

---

## Troubleshooting

**Dashboard is slow:**
The event buffer has a maximum size (default 10,000 events). If it's full, older events are automatically removed. Try filtering to reduce what's displayed.

**Too many false positives:**
- Adjust the rules in `data/rules.json` to be less aggressive
- Add trusted process names to `data/name_trust.json` for fast-path trust
- The trust engine learns over time - processes you see frequently will become more trusted

**Missing events:**
- Check that the monitoring agents are running (they start automatically)
- Verify the event buffer isn't full
- Check the About tab for runtime stats

**Can't add files to Integrity:**
- Make sure the file path is correct and accessible
- Check file permissions - you need read access
- Some system files may be locked by Windows

**Authentication issues:**
- Sessions expire when you close the browser
- If you forgot your password, you'll need to reset it (or delete `data/users.json` and create a new account if you're the only user)
- 2FA codes expire quickly - make sure your device clock is accurate

---

## Advanced Usage

**Custom rules:**
Edit `data/rules.json` to add custom detection rules. Rules are evaluated in order, so put specific rules before general ones. The file hot-reloads automatically.

**Trust weights:**
Edit `data/csc_weights.json` to adjust how the trust engine scores processes. This is advanced - make sure you understand the impact before changing values.

**Name-based trust:**
Add entries to `data/name_trust.json` to give specific process names fast-path trust verdicts. Format: `{"processname.exe": ["verdict", "class", confidence]}`

**Self-suppression:**
Edit `data/self_suppress.json` to filter out CustosEye's own processes from the event feed.

---

## Getting Help

If something isn't working:
1. Check the About tab for version and runtime info
2. Look at the Live Events tab for error messages
3. Check the console window for detailed logs
4. Review the troubleshooting section above
5. Check GitHub issues for known problems
6. Submit a new issue with details about what's happening

---

## Uninstalling

**Portable version (CustosEye.exe):**
Just delete the folder. No registry entries, no services, no drivers. Everything is self-contained.

**Installed version:**
Use Windows Settings > Apps to uninstall, or run the uninstaller from the Start Menu. This removes the program files but leaves your `data/` directory intact (so you don't lose your configuration). Delete the `data/` folder manually if you want to remove everything.
