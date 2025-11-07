# ruff: noqa: E501
"""
goal: evaluate process trustworthiness and return categorical verdicts (malicious, suspicious, caution, trusted, unknown)
with confidence scores and human-readable reasons. small, fast, and runs entirely locally without cloud dependencies.

what this engine does
this engine takes a process event and analyzes it using multiple signals to determine if the process is trustworthy.
it returns a verdict (categorical label), a class (what kind of process it is), a confidence score, reasons for the decision,
and raw signals for debugging. the engine learns over time by tracking how often processes are seen on this specific machine.

how it decides when processing data
the engine builds an internal score S starting at zero, then adds or subtracts points based on various factors:

1. path context: processes in system directories get a trust boost, processes in temp/downloads get penalized
2. code signing: valid signatures increase trust, especially from known publishers like Microsoft, Google, etc.
3. name heuristics: suspicious-looking names (high entropy, hex-like strings, misspellings of system processes) reduce trust
4. file characteristics: very new or tiny binaries outside system directories are flagged
5. network behavior: listening on ports (especially risky ones like 22, 3389, 4444) is suspicious, but outbound connections are normal
6. parent context: processes launched by script interpreters (PowerShell, cmd, wscript) get a small penalty
7. elevation and service status: elevated processes or services running from user directories are highly suspicious
8. local prevalence: processes seen frequently on this machine earn trust over time, with older sightings gradually fading away

algorithm explanation in plain language
the engine works like a scoring system. imagine starting with a neutral score of zero. then it looks at eight different
aspects of the process and adjusts the score up (more trustworthy) or down (less trustworthy). for example, if a process
has a valid Microsoft signature and is in the Windows system directory, the score goes way up. if it has a random-looking
name, is in a temp folder, and is listening on port 4444, the score goes way down.

once all the adjustments are made, the final score S is compared against threshold boundaries (cut points). if S is very
negative (below -2.0), the verdict is "malicious". if it is moderately negative (between -2.0 and -0.5), it is "suspicious".
if it is slightly negative or neutral (between -0.5 and 0.5), it is "caution". if it is positive but not too high (0.5 to 1.6),
it is "trusted". if it is very positive (above 1.6), it is also "trusted" but with high confidence.

the engine also learns over time. every time it sees a process, it records the hash and executable name in a tiny local database.
when evaluating a process, it checks how many times it has seen this exact hash or this executable name before, but with a twist:
older sightings count less than recent ones. this means if you used Chrome yesterday it still counts as common, but if you used
some random tool six months ago, the engine has mostly forgotten about it. this time-decay prevents the database from growing
forever and ensures the engine adapts to changes in your system over time.

the confidence score reflects how sure the engine is about the verdict. verdicts near the boundaries (like a score right at -0.5)
get lower confidence because the process could easily fall into a different category. verdicts far from boundaries (like a score
of -5.0 for malicious) get higher confidence because there is no ambiguity.

inputs it expects (event dict)
• source="process" or not (non-process returns unknown quickly)
• name, exe, sha256
• parent_name/parent_exe
• signer_valid, signer_subject
• is_service, elevation
• listening_ports, remote_addrs|remote_endpoints
• file_ctime, file_size_mb

outputs you get (always)
{
  "version": "csc-v2",
  "verdict": "...",
  "cls": "...",
  "confidence": float 0..1,
  "reasons": [str, ...],   # short, readable
  "signals": { ... }       # raw flags and numbers for UI and tests
}

config and data
• weights JSON is optional. every knob has a sane default so the engine runs out of the box.
• tiny JSON DB tracks decayed sightings. writes are best-effort so the pipeline never breaks.
"""

from __future__ import annotations  # lets us use string annotations before classes are defined

import json  # for loading weights config and saving/loading the prevalence database
import math  # for calculating entropy and doing math operations
import os  # for checking paths and getting basenames
import time  # for getting current timestamp for time-decay calculations
from numbers import Real  # type hint for numeric types (used in isinstance checks)
from pathlib import Path  # for creating directories when saving the database
from typing import Any  # type hint for flexible dictionary values

# tiny utilities


def _now() -> float:
    # return current time as epoch seconds, used for decay calculations and tracking when we last saw something
    return time.time()


def _safe_lower(x: Any) -> str:
    # convert a value to lowercase string safely, return empty string if it is None
    return str(x).lower() if x is not None else ""


def _basename(p: str) -> str:
    # extract just the filename from a path, but never crash even if the path is weird or invalid
    try:
        return os.path.basename(p)  # try to get the basename normally
    except Exception:  # if anything goes wrong
        return p  # just return the original string


def _to_float(x: Any) -> float | None:
    # try to convert something to a float, return None if it cannot be converted
    if isinstance(x, Real):  # if it is already a number
        return float(x)  # convert to float
    if isinstance(x, str):  # if it is a string
        try:
            return float(x)  # try to parse it as a float
        except ValueError:  # if parsing fails
            return None  # return None
    return None  # for anything else, return None


def _shannon_entropy(s: str) -> float:
    # calculate how random-looking a string is, higher entropy means more random
    if not s:  # if the string is empty
        return 0.0  # entropy is zero
    from collections import Counter  # import Counter to count character frequencies

    counts = Counter(s)  # count how many times each character appears
    n = float(len(s))  # total number of characters as a float
    ent = 0.0  # start with zero entropy
    for c in counts.values():  # loop through each character count
        p = c / n  # calculate the probability of this character
        ent -= p * math.log(p, 2.0)  # add to entropy using Shannon's formula (log base 2)
    return ent  # return the final entropy value


def _looks_hexish(s: str) -> bool:
    # check if a string looks like it is made of hexadecimal characters (like random hashes)
    if not s or len(s) < 8:  # if string is empty or too short
        return False  # cannot be hexish
    hex_chars = set("0123456789abcdef")  # valid hex characters
    s2 = s.lower()  # convert to lowercase for easier checking
    alnum = [ch for ch in s2 if ch.isalnum()]  # get only alphanumeric characters
    if len(alnum) < 8:  # if there are not enough alphanumeric chars
        return False  # cannot be hexish
    return sum(1 for ch in alnum if ch in hex_chars) / len(alnum) >= 0.9  # return true if 90 percent or more are hex chars


def _safe_int(v: Any) -> int:
    # convert something to an integer, return -1 if it cannot be converted
    try:
        return int(v)  # try to convert to int
    except Exception:  # if conversion fails
        return -1  # return -1 as a sentinel value


# CSC v2 core


class CSCTrustEngine:
    """
    CSC v2 (categorical): returns a verdict, class, and confidence instead of a 0–100 score.

    Output schema (always present):
        {
          "version": "csc-v2",
          "verdict": "trusted" | "caution" | "suspicious" | "malicious" | "unknown",
          "cls":     "system"  | "popular_app" | "game" | "dev_tool" | "service" |
                     "script"  | "utility" | "embedded" | "unknown",
          "confidence": float in [0.0, 1.0],
          "reasons": [str, ...],       # short human messages
          "signals": { str: Any, ... } # raw helpful flags/values for UI/debug
        }

    Notes:
    - We still keep a tiny local DB to model prevalence with time decay (per-hash, per-basename).
    - We use weight config for knobs, risky/common ports, path hints, and allow/deny vendor cues.
    """

    def __init__(self, weights_path: str, db_path: str) -> None:
        # store the paths to the weights config file and the prevalence database file
        self.weights_path = weights_path  # where to find the weights JSON config
        self.db_path = db_path  # where to save/load the prevalence database
        # load the weights config, with sensible defaults if the file does not exist
        self.weights = self._load_weights()  # dictionary of all the scoring parameters
        # load the tiny database that tracks how often we have seen processes
        self.db = self._load_db()  # dictionary with hash_stats and exe_stats

    # config / db

    def _load_weights(self) -> dict[str, Any]:
        # start with default values for every configurable parameter, so the engine works even without a config file
        defaults: dict[str, Any] = {
            # these are the score thresholds that determine which verdict category a process gets
            # categorical thresholds live as logit-like cut points on an internal score S
            # we map S -> verdict using these boundaries (ordered low->high)
            "cut_malicious": -2.0,  # if score S is less than -2.0, verdict is malicious
            "cut_suspicious": -0.5,  # if score S is between -2.0 and -0.5, verdict is suspicious
            "cut_caution": 0.5,  # if score S is between -0.5 and 0.5, verdict is caution
            "cut_trusted": 1.6,  # if score S is between 0.5 and 1.6, verdict is trusted; above 1.6 is also trusted with higher confidence
            # path groups (we check if these substrings appear in the executable path, case-insensitive)
            "system_paths": ["\\windows\\system32", "/windows/system32"],  # paths that indicate system executables
            "program_files_paths": ["\\program files", "\\program files (x86)"],  # paths that indicate installed programs
            "temp_paths": [
                "\\appdata\\local\\temp",  # temporary file locations
                "/appdata/local/temp",
                "\\temp\\",
                "/tmp/",
                "\\users\\public\\",  # public user directory
            ],
            "downloads_paths": ["\\downloads\\", "/downloads/"],  # download directories
            # name heuristics (looking for suspicious patterns in process names)
            "susp_name_tokens": [
                "svhost",  # suspicious tokens that often appear in malware names
                "svch0st",
                "updater",
                "update",
                "patch",
                "fix",
                "agent",
                "service",
                "driver",
                "protect",
                "defender",
                "winlogin",
                "security",
            ],
            "misspell_tokens": [
                ["svchost", "svhost"],  # pairs of [correct spelling, misspelling] to catch typos of system processes
                ["explorer", "exploer"],
                ["chrome", "chr0me"],
                ["system", "syst3m"],
                ["microsoft", "micros0ft"],
            ],
            "entropy_name_thresh": 3.8,  # if process name entropy is above this, it is suspicious
            "hexish_name_len": 14,  # minimum length for a name to be considered hex-like
            # signing and vendor hints
            "prefer_signed_bonus": 0.8,  # score boost for having a valid code signature
            "unsigned_system_penalty": 0.9,  # score penalty for unsigned binaries in system directories
            "publisher_buckets": {  # mapping of publisher names to process classes for classification
                "microsoft": "system",
                "google": "popular_app",
                "mozilla": "popular_app",
                "valve": "game",
                "epic": "game",
                "unity": "game",
                "adobe": "popular_app",
                "jetbrains": "dev_tool",
                "oracle": "popular_app",
                "nvidia": "driver",
                "amd": "driver",
            },
            # file age/size
            "file_age_days_fresh": 3.0,  # files newer than this are considered "fresh"
            "tiny_binary_mb": 0.15,  # binaries smaller than this are considered unusually small
            # network posture
            "risky_ports": [22, 3389, 4444, 5900, 135, 139, 445],  # ports that are commonly used for attacks
            "common_ports": [80, 443, 53, 123, 587, 993],  # ports that are commonly used for legitimate purposes
            "listen_penalty": 0.6,  # score penalty for listening on any port
            "risky_listen_extra": 1.1,  # extra penalty for listening on risky ports
            "many_listens_extra": 0.4,  # extra penalty for listening on many ports (3 or more)
            "remote_bump": 0.2,  # small score boost for having outbound connections (normal for apps)
            "remote_many_extra": 0.5,  # extra boost for many outbound connections
            "remote_many_count": 10,  # threshold for "many" remote connections
            # parent/launcher context
            "susp_launchers": [
                "powershell.exe",  # script interpreters and tools commonly used by malware
                "pwsh.exe",
                "cmd.exe",
                "wscript.exe",
                "cscript.exe",
                "mshta.exe",
                "regsvr32.exe",
                "rundll32.exe",
                "wmic.exe",
            ],
            "susp_launcher_penalty": 0.7,  # score penalty for being launched by a suspicious tool
            # elevation/service context
            "elev_from_user_penalty": 0.9,  # score penalty for elevated processes running from user/temp paths
            "service_userdir_penalty": 0.9,  # score penalty for services running from user/temp paths
            # prevalence with time-decay
            "prevalence_halflife_days": 14.0,  # how many days until a sighting counts half as much (time decay)
            "hash_seen_thresh": 4.0,  # how many times a hash must be seen to get the prevalence bonus
            "exe_seen_thresh": 8.0,  # how many times an executable name must be seen to get the prevalence bonus
            "prevalence_hash_bonus": 0.8,  # score boost for seeing the same hash many times
            "prevalence_exe_bonus": 0.4,  # score boost for seeing the same executable name many times
            "unknown_hash_penalty": 0.4,  # score penalty for hashes we have never seen before
            # class mapping thresholds (soft rules to pick a "cls" label)
            "class_rules": {
                # these are evaluated in order; first hit wins
                "system": {"if_system_dir": True, "if_signed": True},  # if in system dir and signed, classify as system
                "service": {"if_service": True},  # if it is a service, classify as service
                "dev_tool": {"if_parent_is_dev_shell": True},  # if launched by dev shell, classify as dev_tool
                "game": {"if_publisher_any": ["valve", "epic", "unity"]},  # if publisher is game company, classify as game
                "popular_app": {"if_publisher_any": ["google", "mozilla", "adobe", "oracle"]},  # if publisher is well-known, classify as popular_app
            },
        }
        try:
            with open(self.weights_path, encoding="utf-8") as f:  # try to load the weights config file
                overrides = json.load(f) or {}  # parse JSON, use empty dict if file is empty
            if isinstance(overrides, dict):  # make sure we got a dictionary
                # merge simple dicts; nested dicts use a shallow update for simplicity
                for k, v in overrides.items():  # loop through each key-value pair in the overrides
                    if isinstance(v, dict) and isinstance(defaults.get(k), dict):  # if both override and default are dicts
                        defaults[k].update(v)  # merge the nested dictionaries (shallow update)
                    else:  # if it is not a nested dict
                        defaults[k] = v  # just replace the default value
        except Exception:  # if anything goes wrong (file missing, invalid JSON, etc)
            # if anything goes wrong we just stick with defaults
            pass  # ignore errors and use defaults
        return defaults  # return the final weights dictionary

    def _load_db(self) -> dict[str, Any]:
        # load the prevalence database that tracks how often we have seen processes
        # schema stays tiny and straightforward to avoid migrations
        # {
        #   "version": 2,
        #   "hash_stats": { sha256: {"seen": int, "last_seen": ts} },
        #   "exe_stats":  { basename: {"seen": int, "last_seen": ts} }
        # }
        empty = {"version": 2, "hash_stats": {}, "exe_stats": {}}  # empty database structure
        if not os.path.exists(self.db_path):  # if the database file does not exist
            return empty  # return an empty database
        try:
            with open(self.db_path, encoding="utf-8") as f:  # try to open the database file
                data = json.load(f)  # parse the JSON
                if isinstance(data, dict):  # make sure we got a dictionary
                    data.setdefault("version", 2)  # ensure version field exists
                    data.setdefault("hash_stats", {})  # ensure hash_stats exists
                    data.setdefault("exe_stats", {})  # ensure exe_stats exists
                    return data  # return the loaded data
        except Exception:  # if anything goes wrong (corrupt JSON, etc)
            # corrupt or unreadable DB → start clean
            pass  # ignore errors
        return empty  # return empty database if loading failed

    def _save_db(self) -> None:
        # save the prevalence database to disk, but never fail if this does not work
        # persistence is best-effort; failures must never break the pipeline
        try:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)  # create the directory if it does not exist
            with open(self.db_path, "w", encoding="utf-8") as f:  # open the file for writing
                json.dump(self.db, f, indent=2)  # write the database as formatted JSON
        except Exception:  # if anything goes wrong (permissions, disk full, etc)
            pass  # silently fail, do not break the scoring pipeline

    # small helpers

    def _days_since(self, ts: float) -> float:
        # calculate how many days ago a timestamp was, return huge number if timestamp is missing or zero
        if not ts:  # if timestamp is zero or None
            return 1e9  # return a huge number (effectively "never")
        return max(0.0, (_now() - float(ts)) / 86400.0)  # calculate days since timestamp (86400 seconds per day)

    def _decayed_seen(self, seen: int, last_seen: float, halflife_days: float) -> float:
        # calculate how many "effective" times we have seen something, with old sightings counting less
        # standard exponential decay so old sightings fade out naturally
        if seen <= 0:  # if we have never seen it
            return 0.0  # effective count is zero
        days = self._days_since(last_seen)  # calculate days since we last saw it
        if halflife_days <= 0:  # if halflife is invalid
            return float(seen)  # just return the raw count
        return float(seen) * (0.5 ** (days / float(halflife_days)))  # apply exponential decay: count halves every halflife_days

    # main API

    def evaluate(self, event: dict[str, Any]) -> dict[str, Any]:
        # main entry point: evaluate a process event and return verdict, class, confidence, reasons, and signals
        # non-process events get a neutral "unknown" verdict right away
        if event.get("source") != "process":  # if this is not a process event
            return {  # return immediately with unknown verdict
                "version": "csc-v2",
                "verdict": "unknown",  # we do not know how to evaluate non-process events
                "cls": "unknown",
                "confidence": 0.35,  # low confidence since we cannot evaluate it
                "reasons": ["not a process event"],  # explain why it is unknown
                "signals": {},  # no signals for non-process events
            }

        w = self.weights  # shorthand for the weights config, makes code more readable
        reasons: list[str] = []  # list of human-readable messages explaining the verdict
        signals: dict[str, Any] = {}  # raw data and flags for debugging and UI display

        # normalize inputs we care about (convert to lowercase, handle missing values)
        name = _safe_lower(event.get("name"))  # process name in lowercase
        exe = _safe_lower(event.get("exe"))  # executable path in lowercase
        sha256 = _safe_lower(event.get("sha256"))  # file hash in lowercase
        base = _basename(exe)  # just the filename without the path
        parent_name = _safe_lower(event.get("parent_name") or event.get("parent"))  # parent process name
        parent_exe = _safe_lower(event.get("parent_exe"))  # parent executable path
        is_service = bool(event.get("is_service"))  # whether this is a Windows service
        elevation = bool(event.get("elevation"))  # whether this process has elevated privileges
        signer_valid = bool(event.get("signer_valid"))  # whether the code signature is valid
        signer_subject = _safe_lower(event.get("signer_subject") or "")  # certificate subject (publisher name)
        ports = event.get("listening_ports") or []  # ports this process is listening on
        remotes = event.get("remote_addrs") or event.get("remote_endpoints") or []  # remote connections
        if isinstance(remotes, dict):  # if remotes is a dictionary (keyed by protocol)
            # flatten proto-keyed dicts into a single list
            try:
                flat = []  # build a flat list
                for v in remotes.values():  # loop through each protocol's connection list
                    flat.extend(v)  # add all connections from this protocol
                remotes = flat  # replace dict with flat list
            except Exception:  # if anything goes wrong
                remotes = []  # just use empty list

        file_ctime = float(event.get("file_ctime") or 0.0)  # file creation time (epoch seconds)
        file_size_mb = _to_float(event.get("file_size_mb"))  # file size in megabytes

        # compute an internal score S (unbounded real number)
        # we start at zero, then add or subtract points based on various factors
        S = 0.0  # initialize score at zero (neutral)

        # 1) path context (system vs program files vs temp/downloads)
        in_system = bool(exe and any(seg in exe for seg in w["system_paths"]))  # check if path contains system directory
        in_pf = bool(exe and any(seg in exe for seg in w["program_files_paths"]))  # check if path contains Program Files
        in_userish = bool(
            exe and any(seg in exe for seg in (w["temp_paths"] + w["downloads_paths"]))  # check if path is in temp or downloads
        )

        signals["in_system_dir"] = in_system  # save path context to signals for debugging
        signals["in_program_files"] = in_pf
        signals["in_user_or_downloads"] = in_userish

        if in_system:  # if executable is in system directory
            S += 0.9  # big boost for system paths (usually trustworthy)
            reasons.append("executable under system directory")  # add explanation
        elif in_pf:  # else if in Program Files
            S += 0.4  # smaller boost for installed programs
            reasons.append("executable under Program Files")  # add explanation
        if in_userish:  # if in temp or downloads (can overlap with above)
            S -= 1.0  # penalty for running from user/temp/downloads (often malicious)
            reasons.append("executable under user/temp/downloads path")  # add explanation

        # 2) code signing (strong safety cue when valid, especially with known publishers)
        if signer_valid:  # if the executable has a valid code signature
            S += float(w["prefer_signed_bonus"])  # add trust boost for signed code
            reasons.append("valid code signature")  # add explanation
            signals["publisher"] = signer_subject  # save publisher name for debugging
            # light class cue: vendor buckets map to rough families (games, dev, popular)
            for vendor, bucket in w["publisher_buckets"].items():  # loop through known publishers
                if vendor in signer_subject:  # if publisher name is in the certificate subject
                    signals.setdefault("publisher_bucket_hits", []).append(bucket)  # record which class this publisher maps to
        else:  # if not signed
            if in_system:  # and it is in system directory
                S -= float(w["unsigned_system_penalty"])  # big penalty (system files should be signed)
                reasons.append("unsigned binary located in system directory")  # add explanation

        # 3) name-based oddities (entropy / hexish / misspells / suspicious tokens)
        if name:  # if we have a process name
            ent = _shannon_entropy(name)  # calculate how random the name looks
            if ent >= float(w["entropy_name_thresh"]):  # if entropy is above threshold
                S -= 0.4  # penalty for random-looking names
                reasons.append("name has high entropy")  # add explanation
            if len(name) >= int(w["hexish_name_len"]) and _looks_hexish(name):  # if name is long and hex-like
                S -= 0.5  # penalty for hex-looking names (often packed malware)
                reasons.append("name looks hex/packed-like")  # add explanation
            if any(tok in name for tok in w["susp_name_tokens"]):  # if name contains suspicious tokens
                S -= 0.5  # penalty for suspicious name tokens
                reasons.append("suspicious name token")  # add explanation
            for canonical, miss in w["misspell_tokens"]:  # loop through known misspellings
                if miss in name and canonical not in name:  # if name contains misspelling but not correct spelling
                    S -= 0.3  # penalty for misspelled system process names (often malware)
                    reasons.append(f"name looks like a misspelling of '{canonical}'")  # add explanation

        # 4) file age/size (fresh and tiny outside system dirs tends to be risky)
        if file_ctime and exe:  # if we have file creation time and path
            age_days = self._days_since(file_ctime)  # calculate how many days old the file is
            signals["file_age_days"] = age_days  # save age for debugging
            if age_days <= float(w["file_age_days_fresh"]) and not in_system:  # if file is very new and not in system dir
                S -= 0.5  # penalty for very new binaries outside system (often malware)
                reasons.append("very new binary outside system directory")  # add explanation
        if file_size_mb is not None:  # if we have file size information
            signals["file_size_mb"] = file_size_mb  # save size for debugging
            if file_size_mb <= float(w["tiny_binary_mb"]):  # if file is unusually small
                S -= 0.5  # penalty for tiny binaries (sometimes malware packers)
                reasons.append("binary size is unusually small")  # add explanation

        # 5) network posture (listening and especially on risky ports is a red flag)
        risky = set(int(p) for p in w["risky_ports"])  # convert risky ports list to set for fast lookup
        listen_ports = [p for p in ports if _safe_int(p) >= 0]  # filter out invalid ports
        if listen_ports:  # if process is listening on any ports
            S -= float(w["listen_penalty"])  # penalty for listening (servers are more risky)
            reasons.append("process is listening on a port")  # add explanation
            if any(_safe_int(p) in risky for p in listen_ports):  # if any listening port is risky
                S -= float(w["risky_listen_extra"])  # extra penalty for risky ports
                reasons.append("listening on a risky port")  # add explanation
            if len(listen_ports) >= 3:  # if listening on many ports
                S -= float(w["many_listens_extra"])  # extra penalty for multiple listeners
                reasons.append("listening on multiple ports")  # add explanation

        remote_count = 0  # initialize remote connection count
        try:
            remote_count = len(remotes)  # count remote connections
        except Exception:  # if counting fails
            remote_count = 0  # default to zero
        if remote_count > 0:  # if there are outbound connections
            S += float(w["remote_bump"])  # small boost (outbound is normal for apps, not necessarily evil)
            reasons.append("has remote connections")  # add explanation
            if remote_count >= int(w["remote_many_count"]):  # if many connections
                S += float(w["remote_many_extra"])  # extra boost (legitimate apps often have many connections)
                reasons.append("many remote connections")  # add explanation
        signals["listening_ports"] = listen_ports  # save ports for debugging
        signals["remote_count"] = remote_count  # save count for debugging

        # 6) parent / launcher context (script shells / LOLBINs reduce trust a notch)
        if parent_name or parent_exe:  # if we know the parent process
            parent_base = _basename(parent_exe) if parent_exe else parent_name  # get parent executable name
            if parent_base and parent_base in w["susp_launchers"]:  # if parent is a suspicious launcher
                S -= float(w["susp_launcher_penalty"])  # penalty for being launched by script interpreters
                reasons.append(f"launched by suspicious tool ({parent_base})")  # add explanation
                signals["parent"] = parent_base  # save parent for debugging

        # 7) elevation/service in user locations (classic "service from user dir" smell)
        if elevation and in_userish:  # if process is elevated and running from user/temp path
            S -= float(w["elev_from_user_penalty"])  # big penalty (elevated malware often runs from temp)
            reasons.append("elevated binary from user/temp path")  # add explanation
        if is_service and in_userish:  # if process is a service running from user/temp path
            S -= float(w["service_userdir_penalty"])  # big penalty (services should not be in user dirs)
            reasons.append("service binary resides in user/temp path")  # add explanation

        # 8) prevalence with time-decay (things seen often here earn trust gradually)
        halflife = float(w["prevalence_halflife_days"])  # get the half-life for time decay

        if sha256:  # if we have a file hash
            hs = self.db["hash_stats"].get(sha256, {"seen": 0, "last_seen": 0.0})  # get previous stats for this hash
            seen_prev = int(hs.get("seen", 0) or 0)  # how many times we have seen this hash before
            last_seen = _to_float(hs.get("last_seen")) or 0.0  # when we last saw it
            # exclude current sighting from effective-seen (we are evaluating it right now)
            eff = self._decayed_seen(max(seen_prev - 1, 0), last_seen, halflife)  # calculate decayed count
            signals["hash_eff_seen"] = eff  # save for debugging
            if eff >= float(w["hash_seen_thresh"]):  # if we have seen this hash many times before
                S += float(w["prevalence_hash_bonus"])  # boost for common hash (trust through familiarity)
                reasons.append("hash is common on this machine (time-decayed)")  # add explanation
            else:  # if we have not seen it much
                S -= float(w["unknown_hash_penalty"])  # penalty for unknown hash (first time seeing it)
                reasons.append("hash is rare/unknown on this machine")  # add explanation

        if base:  # if we have an executable name
            es = self.db["exe_stats"].get(base.lower(), {"seen": 0, "last_seen": 0.0})  # get previous stats for this name
            seen_prev2 = int(es.get("seen", 0) or 0)  # how many times we have seen this name before
            last_seen2 = _to_float(es.get("last_seen")) or 0.0  # when we last saw it
            # exclude current sighting from effective-seen (we are evaluating it right now)
            eff2 = self._decayed_seen(max(seen_prev2 - 1, 0), last_seen2, halflife)  # calculate decayed count
            signals["exe_eff_seen"] = eff2  # save for debugging
            if eff2 >= float(w["exe_seen_thresh"]):  # if we have seen this name many times before
                S += float(w["prevalence_exe_bonus"])  # smaller boost for common name (less reliable than hash)
                reasons.append("executable name seen often here (time-decayed)")  # add explanation

        # classify "cls" (family) before we choose verdict, because reasons may reference it
        cls = self._classify(signals, signer_subject, is_service, parent_exe or parent_name)  # determine process class

        # convert internal S into a categorical verdict and a confidence
        verdict, confidence = self._to_verdict_and_confidence(S, w)  # map score to verdict and calculate confidence

        # record the sighting *after* scoring so decay uses pre-update stats (important for consistency)
        try:
            now_ts = _now()  # get current timestamp
            if sha256:  # if we have a hash
                h2 = self.db["hash_stats"].setdefault(sha256, {"seen": 0, "last_seen": 0.0})  # get or create hash entry
                h2["seen"] = int(h2.get("seen", 0)) + 1  # increment seen count
                h2["last_seen"] = now_ts  # update last seen timestamp
            if base:  # if we have an executable name
                e2 = self.db["exe_stats"].setdefault(base.lower(), {"seen": 0, "last_seen": 0.0})  # get or create name entry
                e2["seen"] = int(e2.get("seen", 0)) + 1  # increment seen count
                e2["last_seen"] = now_ts  # update last seen timestamp
        except Exception:  # if database update fails
            # never fail scoring on telemetry bookkeeping
            pass  # just continue, do not break the scoring

        # persist DB at the end; never fail the flow if this throws
        self._save_db()  # save database to disk (best-effort)

        # return the v2 shape expected by the updated dashboard
        return {
            "version": "csc-v2",  # version identifier
            "verdict": verdict,  # categorical verdict (malicious, suspicious, caution, trusted, unknown)
            "cls": cls,  # process class (system, popular_app, game, etc)
            "confidence": confidence,  # how confident we are (0.0 to 1.0)
            "reasons": reasons,  # list of human-readable explanations
            "signals": signals,  # raw data for debugging and UI
        }

    # helpers: class + verdict mapping

    def _classify(
        self, signals: dict[str, Any], publisher: str, is_service: bool, parent_path: str
    ) -> str:
        # determine what kind of process this is (system, game, dev tool, etc) based on signals
        # this maps to a coarse "family" label that the UI can badge nicely
        w = self.weights  # get weights for class rules

        # quick booleans for readability
        in_system = bool(signals.get("in_system_dir"))  # check if process is in system directory
        parent_base = _basename(_safe_lower(parent_path)) if parent_path else ""  # get parent executable name
        parent_is_dev_shell = parent_base in {"powershell.exe", "pwsh.exe", "cmd.exe"}  # check if launched by dev shell

        # evaluate rule buckets in order; first match wins
        rules: dict[str, dict[str, Any]] = dict(w.get("class_rules", {}))  # get classification rules from weights
        for label, rule in rules.items():  # loop through rules in order
            # simple checks; each key is optional and treated as AND within the rule
            if rule.get("if_system_dir") and not in_system:  # if rule requires system dir but process is not in system
                continue  # skip this rule, try next one
            if rule.get("if_signed") and not publisher:  # if rule requires signature but process is not signed
                continue  # skip this rule, try next one
            vend_list = [v for v in rule.get("if_publisher_any", [])]  # get list of allowed publishers
            if vend_list and not any(v in publisher for v in vend_list):  # if rule requires specific publisher but not found
                continue  # skip this rule, try next one
            if rule.get("if_service") and not is_service:  # if rule requires service but process is not a service
                continue  # skip this rule, try next one
            if rule.get("if_parent_is_dev_shell") and not parent_is_dev_shell:  # if rule requires dev shell parent but not found
                continue  # skip this rule, try next one
            return label  # all conditions matched, return this label (first matching bucket wins)

        # fallbacks if no rule matched
        if is_service:  # if it is a service but no rule matched
            return "service"  # classify as service
        if parent_is_dev_shell:  # if launched by dev shell but no rule matched
            return "dev_tool"  # classify as dev tool
        if signals.get("in_program_files"):  # if in Program Files but no rule matched
            return "utility"  # classify as utility
        return "unknown"  # default fallback

    def _to_verdict_and_confidence(self, S: float, w: dict[str, Any]) -> tuple[str, float]:
        # convert the internal score S into a categorical verdict and confidence level
        # map internal score S to categorical verdict using cut points
        # confidence uses a smooth linear interpolation around the chosen region
        if S < float(w["cut_malicious"]):  # if score is below malicious threshold
            verdict = "malicious"  # verdict is malicious
            # farther below the cut → higher confidence (very negative scores are clearly malicious)
            confidence = min(1.0, 0.6 + (float(w["cut_malicious"]) - S) / 4.0)  # calculate confidence based on distance from threshold
        elif S < float(w["cut_suspicious"]):  # else if score is below suspicious threshold
            verdict = "suspicious"  # verdict is suspicious
            confidence = 0.55 + (float(w["cut_suspicious"]) - S) / 6.0  # calculate confidence (closer to threshold = lower confidence)
        elif S < float(w["cut_caution"]):  # else if score is below caution threshold
            verdict = "caution"  # verdict is caution
            confidence = 0.45 + (S - float(w["cut_suspicious"])) / 6.0  # calculate confidence in caution range
        elif S < float(w["cut_trusted"]):  # else if score is below trusted threshold
            verdict = "trusted"  # verdict is trusted
            confidence = 0.55 + (S - float(w["cut_caution"])) / 6.0  # calculate confidence in trusted range
        else:  # else score is above trusted threshold
            verdict = "trusted"  # verdict is still trusted (high trust)
            confidence = min(1.0, 0.8 + (S - float(w["cut_trusted"])) / 4.0)  # higher confidence for very positive scores

        # clamp confidence strictly to [0,1] to keep UI sane (ensure it is always between 0 and 1)
        confidence = max(0.0, min(1.0, float(confidence)))  # make sure confidence is in valid range
        return verdict, confidence  # return both verdict and confidence