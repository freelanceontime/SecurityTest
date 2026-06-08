#!/usr/bin/env python3
"""
selfImprovementtest.py  –  AI-Assisted Android Security Test Runner
======================================================================
Feeds MASTG tests from Prompt.md to Claude Code one-by-one, captures
structured results, refines prompts automatically after each run, and
outputs Jira-ready Markdown reports.

Assumed environment
  • Kali Linux (ADB + Frida + jadx + objection installed)
  • Android device connected via USB, frida-server running on-device
  • APK decompiled to a local folder (e.g. with jadx or apktool)
  • Claude Code CLI installed  →  `claude` is in PATH

Self-update source
  https://github.com/freelanceontime/SecurityTest/blob/main/selfImprovedtests.py
"""

import sys, os, re, json, platform, subprocess, hashlib, shutil
import urllib.request, urllib.error, datetime, time
from pathlib import Path

sys.dont_write_bytecode = True

# ── Version & paths ──────────────────────────────────────────────────────────
__version__   = "1.0.0"
SCRIPT_PATH   = Path(__file__).resolve()
SCRIPT_DIR    = SCRIPT_PATH.parent
PROMPT_MD     = SCRIPT_DIR / "Prompt.md"
STATE_FILE    = SCRIPT_DIR / "session_state.json"
IMPROVEMENTS  = SCRIPT_DIR / "prompt_improvements.json"
RESULTS_DIR   = SCRIPT_DIR / "test_results"
REPORTS_DIR   = SCRIPT_DIR / "reports"

GITHUB_RAW = (
    "https://raw.githubusercontent.com/"
    "freelanceontime/SecurityTest/main/selfImprovedtests.py"
)

# ── MASVS section → L1 / L2 ──────────────────────────────────────────────────
SECTION_LEVEL = {
    "Storage Tests":                 "L1",
    "Cryptography tests":            "L1",
    "Authentication":                "L1",
    "Network":                       "L1",
    "Platform":                      "L1",
    "CODE QUALITY & BUILD SETTINGS": "L1",
    "RESILIENCE":                    "L2",
}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info", "N/A", "SKIP", "UNKNOWN"]

# ── ANSI helpers ──────────────────────────────────────────────────────────────
IS_WIN = platform.system() == "Windows"
_B = "\033[1m"; _R  = "\033[0m";  _HL  = "\033[7m"
_G = "\033[32m"; _Y = "\033[33m"; _C   = "\033[36m"
_RE= "\033[31m"; _D = "\033[2m";  _MAG = "\033[35m"

def _enable_ansi() -> None:
    if IS_WIN:
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass

def _clear() -> None:
    os.system("cls" if IS_WIN else "clear")

def _box(title: str, w: int = 72) -> None:
    print(f"{_B}{'=' * w}{_R}")
    print(f"{_B}  {title}{_R}")
    print(f"{_B}{'=' * w}{_R}")

def _hr(w: int = 72) -> str:
    return "─" * w

# ─────────────────────────────────────────────────────────────────────────────
# 1.  PROMPT.MD PARSER
# ─────────────────────────────────────────────────────────────────────────────
_SKIP_RE = re.compile(
    r"^(using |start the |note:|example |see also|for |check the|"
    r"this |if |when |open a |run the |try |call |send |type |look |install |view )",
    re.IGNORECASE,
)
_CONTENT_LIMIT = 2500   # max chars of original Prompt.md description per test

def parse_prompt_md(filepath: Path) -> list[dict]:
    """
    Extract {section, level, name, content} for every # test under each ## section.
    content = text between consecutive # headings (first 2500 chars).
    """
    results, seen = [], set()
    cur_section = cur_name = None
    buf: list[str] = []

    def flush() -> None:
        if cur_name and cur_section and cur_name not in seen:
            seen.add(cur_name)
            results.append({
                "section": cur_section,
                "level":   SECTION_LEVEL.get(cur_section, "L1"),
                "name":    cur_name,
                "content": "\n".join(buf).strip()[:_CONTENT_LIMIT],
                "status":  "pending",
                "result":  None,
            })

    with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line = raw.rstrip()
            if line.startswith("## "):
                flush()
                cur_section = line[3:].strip()
                cur_name = None; buf = []
            elif line.startswith("# ") and cur_section:
                flush()
                name = line[2:].strip()
                if name and len(name) > 10 and name[0].isupper() and not _SKIP_RE.match(name):
                    cur_name = name; buf = []
                else:
                    cur_name = None
            elif cur_name:
                buf.append(line)
    flush()
    return results

# ─────────────────────────────────────────────────────────────────────────────
# 2.  SELF-UPDATE
# ─────────────────────────────────────────────────────────────────────────────
def check_for_update() -> None:
    print(f"  {_D}Checking for updates…{_R}", end="", flush=True)
    try:
        with urllib.request.urlopen(GITHUB_RAW, timeout=6) as r:
            remote = r.read()
    except Exception as e:
        print(f"\r  {_D}[~] Update check skipped: {e}{_R}")
        return

    local_hash  = hashlib.sha256(SCRIPT_PATH.read_bytes()).hexdigest()
    remote_hash = hashlib.sha256(remote).hexdigest()

    if local_hash == remote_hash:
        print(f"\r  {_G}[✓] Script is up to date (v{__version__}){_R}")
        return

    print(f"\r  {_Y}{_B}[!] A newer version is available on GitHub!{_R}")
    ans = input("      Download and apply now? [y/N]: ").strip().lower()
    if ans in ("y", "yes"):
        backup = SCRIPT_PATH.with_suffix(".py.bak")
        shutil.copy2(SCRIPT_PATH, backup)
        SCRIPT_PATH.write_bytes(remote)
        print(f"  {_G}[✓] Updated. Old version backed up to {backup.name}")
        print(f"      Please restart the script.{_R}")
        sys.exit(0)

# ─────────────────────────────────────────────────────────────────────────────
# 3.  PROMPT-IMPROVEMENT STORE  (persists across sessions)
# ─────────────────────────────────────────────────────────────────────────────
def load_improvements() -> dict:
    if IMPROVEMENTS.exists():
        try:
            with open(IMPROVEMENTS, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_improvements(store: dict) -> None:
    with open(IMPROVEMENTS, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2, ensure_ascii=False)

def get_improvement(store: dict, name: str) -> dict:
    return store.get(name, {
        "current_prompt": None, "false_positives": [],
        "known_commands": [], "history": [], "run_count": 0,
    })

def update_improvement(store: dict, name: str, result: dict, improved_prompt: str) -> None:
    entry = get_improvement(store, name)
    entry["run_count"] = entry.get("run_count", 0) + 1
    if improved_prompt:
        entry["history"].append({
            "date":   datetime.datetime.now().isoformat(),
            "prompt": improved_prompt,
        })
        entry["current_prompt"] = improved_prompt
    for fp in result.get("false_positives", []):
        if fp and fp not in entry["false_positives"]:
            entry["false_positives"].append(fp)
    for cmd in result.get("commands_used", []):
        if cmd and cmd not in entry["known_commands"]:
            entry["known_commands"].append(cmd)
    store[name] = entry

# ─────────────────────────────────────────────────────────────────────────────
# 4.  SESSION STATE
# ─────────────────────────────────────────────────────────────────────────────
def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_state(state: dict) -> None:
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)

def new_session(tests: list, app_name: str, pkg_name: str,
                apk_path: str, decomp_path: str, level_filter: str) -> dict:
    return {
        "session_id":       datetime.datetime.now().strftime("%Y%m%d_%H%M%S"),
        "app_name":         app_name,
        "package_name":     pkg_name,
        "apk_path":         apk_path,
        "decompiled_path":  decomp_path,
        "level_filter":     level_filter,
        "created_at":       datetime.datetime.now().isoformat(),
        "last_run":         None,
        "tests":            tests,
        "pending_jira":     False,
        "last_report_path": None,
    }

# ─────────────────────────────────────────────────────────────────────────────
# 5.  PROMPT BUILDER
# ─────────────────────────────────────────────────────────────────────────────
_ENVIRONMENT_CONTEXT = """\
## ENVIRONMENT
- OS: Kali Linux
- ADB device: Android phone/emulator connected via USB
  Verify connection : adb devices
  List packages     : adb shell pm list packages
- Frida server running on device
  Verify            : frida-ps -U | head -20
- Tools available   : adb, frida, frida-ps, objection, jadx, apktool,
                      apksigner, openssl, grep, strings, semgrep, sqlite3,
                      burpsuite / mitmproxy (for network interception)
"""

def build_prompt(test: dict, session: dict, improvement: dict) -> str:
    tests   = session["tests"]
    idx     = next((i for i, t in enumerate(tests) if t["name"] == test["name"]), 0)
    total   = len(tests)
    run_cnt = improvement.get("run_count", 0)

    # Pick guidance: refined prompt from previous run beats raw Prompt.md text
    if improvement.get("current_prompt"):
        guidance     = improvement["current_prompt"]
        guidance_src = "(refined from previous run – use this as primary guidance)"
    else:
        guidance     = test.get("content") or "No guidance available – use MASTG methodology."
        guidance_src = "(from Prompt.md)"

    # Accumulated notes from prior runs
    extras = ""
    fps = improvement.get("false_positives", [])
    if fps:
        extras += "\n### ⚠ Known False Positives – skip these\n"
        for fp in fps[:10]:
            extras += f"- {fp}\n"
    cmds = improvement.get("known_commands", [])
    if cmds:
        extras += "\n### Commands that found issues in previous runs\n"
        for cmd in cmds[:10]:
            extras += f"- `{cmd}`\n"

    return f"""\
You are an expert Android application security tester performing OWASP MASTG tests.

{_ENVIRONMENT_CONTEXT}
## APP UNDER TEST
- Name            : {session.get("app_name", "Unknown")}
- Package         : {session.get("package_name") or "[find with: adb shell pm list packages | grep <name>]"}
- APK file        : {session.get("apk_path") or "[not provided]"}
- Decompiled path : {session.get("decompiled_path") or "[not provided – navigate to it]"}

## CURRENT TEST  ({idx + 1} of {total})
Name    : {test["name"]}
Section : {test["section"]}
Level   : {test["level"]}  {"(Standard Security)" if test["level"] == "L1" else "(Defense-in-Depth)"}
{"Prior runs : " + str(run_cnt) if run_cnt else "First time running this test"}

## TEST GUIDANCE  {guidance_src}
{guidance}
{extras}
## INSTRUCTIONS
1. Perform this security test thoroughly using the tools available.
2. Run actual commands (adb, frida, grep, strings, apksigner, etc.) and show their output.
3. Evidence must include file paths, line numbers, or command output – no assumptions.
4. Flag any findings that are library/framework code (not app code) as low-priority.
5. Note any false positives explicitly so future runs can skip them.
6. When done, output the result block below EXACTLY – do not alter the delimiters.

===TEST_RESULT_START===
STATUS: PASS|FAIL|INFO|SKIP
SEVERITY: Critical|High|Medium|Low|Info|N/A
FINDINGS:
- <finding 1 with evidence, or "None">
COMMANDS_USED:
- <exact command and brief output summary>
NOTES:
<context, caveats, observations>
FALSE_POSITIVES:
- <false positive you identified, or "None">
JIRA_TICKET_SUMMARY:
<one-line Jira summary; blank if PASS>
JIRA_TICKET_DESCRIPTION:
<full Jira description with steps to reproduce; blank if PASS>
JIRA_TICKET_RECOMMENDATION:
<what the developer must do to fix this; blank if PASS>
===TEST_RESULT_END===

Now suggest an improved version of the TEST GUIDANCE section for the next run:
===PROMPT_IMPROVEMENT_START===
<rewrite only the guidance – incorporate what you learned, useful commands, etc.>
===PROMPT_IMPROVEMENT_END===

Finally, mark this test as done by printing this exact line:
TEST_COMPLETED: {test["name"]}
"""

# ─────────────────────────────────────────────────────────────────────────────
# 6.  CLAUDE RUNNER
# ─────────────────────────────────────────────────────────────────────────────
def run_claude(prompt: str, cwd: str | None = None, timeout: int = 600) -> tuple[bool, str]:
    """
    Run  claude -p <prompt>  in a subprocess.
    Streams output to console in real-time and returns the full text.
    """
    w = 70
    print(f"\n  {_C}┌{'─' * w}┐{_R}")
    print(f"  {_C}│{'  Claude output':^{w}}│{_R}")
    print(f"  {_C}├{'─' * w}┤{_R}")

    try:
        proc = subprocess.Popen(
            ["claude", "-p", prompt],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=cwd or str(SCRIPT_DIR),
        )

        lines: list[str] = []
        for raw in proc.stdout:
            lines.append(raw)
            clean = raw.rstrip()
            # Show non-delimiter lines so the user can follow progress
            if clean and not clean.startswith("===") and not clean.startswith("TEST_COMPLETED"):
                print(f"  {_D}│ {clean[:w - 2]:<{w - 2}} │{_R}")

        proc.wait()
        full = "".join(lines)
        print(f"  {_C}└{'─' * w}┘{_R}\n")
        return True, full

    except subprocess.TimeoutExpired:
        proc.kill()
        full = "".join(lines) if "lines" in dir() else ""
        return False, full or f"[ERROR] claude timed out after {timeout}s"
    except FileNotFoundError:
        return False, "[ERROR] 'claude' not found – install Claude Code CLI and ensure it is in PATH."
    except Exception as exc:
        return False, f"[ERROR] {exc}"

# ─────────────────────────────────────────────────────────────────────────────
# 7.  RESULT PARSER
# ─────────────────────────────────────────────────────────────────────────────
def parse_result(output: str, test_name: str) -> dict:
    r: dict = {
        "status": "UNKNOWN", "severity": "Info",
        "findings": [], "commands_used": [], "notes": "",
        "false_positives": [], "jira_summary": "",
        "jira_description": "", "jira_recommendation": "",
        "completed": False, "improved_prompt": "",
        "raw_output": output,
    }

    r["completed"] = f"TEST_COMPLETED: {test_name}" in output

    m = re.search(r"===TEST_RESULT_START===(.*?)===TEST_RESULT_END===", output, re.DOTALL)
    if m:
        blk = m.group(1)

        def _field(key: str) -> str:
            pat = rf"{re.escape(key)}:\s*\n?(.*?)(?=\n[A-Z_]{{3,}}:|===|$)"
            mm  = re.search(pat, blk, re.DOTALL | re.IGNORECASE)
            return mm.group(1).strip() if mm else ""

        sm = re.search(r"STATUS:\s*(PASS|FAIL|INFO|SKIP)", blk, re.IGNORECASE)
        if sm: r["status"] = sm.group(1).upper()

        vm = re.search(r"SEVERITY:\s*(Critical|High|Medium|Low|Info|N/A)", blk, re.IGNORECASE)
        if vm: r["severity"] = vm.group(1).title()

        def _bullets(raw: str) -> list[str]:
            return [
                l.lstrip("-•*# \t").strip() for l in raw.splitlines()
                if l.strip() and l.strip().lower() not in ("none", "-", "n/a")
            ]

        r["findings"]            = _bullets(_field("FINDINGS"))
        r["commands_used"]       = _bullets(_field("COMMANDS_USED"))
        r["notes"]               = _field("NOTES")
        r["false_positives"]     = _bullets(_field("FALSE_POSITIVES"))
        r["jira_summary"]        = _field("JIRA_TICKET_SUMMARY")
        r["jira_description"]    = _field("JIRA_TICKET_DESCRIPTION")
        r["jira_recommendation"] = _field("JIRA_TICKET_RECOMMENDATION")

    pm = re.search(
        r"===PROMPT_IMPROVEMENT_START===(.*?)===PROMPT_IMPROVEMENT_END===",
        output, re.DOTALL)
    if pm: r["improved_prompt"] = pm.group(1).strip()

    return r

# ─────────────────────────────────────────────────────────────────────────────
# 8.  PER-TEST RESULT FILE
# ─────────────────────────────────────────────────────────────────────────────
def save_result_file(test: dict, result: dict, session_id: str) -> Path:
    dest = RESULTS_DIR / session_id
    dest.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^a-zA-Z0-9_-]", "_", test["name"])[:60]
    path = dest / f"{slug}.md"

    lines = [
        f"# {test['name']}",
        f"**Section:** {test['section']}  |  **Level:** {test['level']}",
        f"**Status:** `{result['status']}`  |  **Severity:** `{result['severity']}`",
        f"**Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
    ]
    if result["findings"]:
        lines += ["## Findings", ""] + [f"- {f}" for f in result["findings"]] + [""]
    if result["commands_used"]:
        lines += ["## Commands Used", ""]
        for cmd in result["commands_used"]:
            lines += [f"```bash\n{cmd}\n```"]
        lines.append("")
    if result["notes"]:
        lines += ["## Notes", "", result["notes"], ""]
    if result["false_positives"]:
        lines += ["## False Positives", ""] + [f"- {fp}" for fp in result["false_positives"]] + [""]
    if result["jira_summary"]:
        lines += [
            "## Jira Ticket",
            f"**Summary:** {result['jira_summary']}", "",
            "**Description:**", result["jira_description"], "",
            "**Recommendation:**", result["jira_recommendation"], "",
        ]
    if result.get("improved_prompt"):
        lines += [
            "## Improved Prompt (next run)",
            "", "```", result["improved_prompt"], "```", "",
        ]
    if result.get("raw_output"):
        lines += [
            "## Raw Output", "",
            "<details><summary>Click to expand</summary>", "",
            "```", result["raw_output"][:6000], "```",
            "", "</details>",
        ]

    path.write_text("\n".join(lines), encoding="utf-8")
    return path

# ─────────────────────────────────────────────────────────────────────────────
# 9.  JIRA REPORT GENERATOR
# ─────────────────────────────────────────────────────────────────────────────
def generate_report(session: dict) -> str:
    app    = session.get("app_name", "Unknown App")
    pkg    = session.get("package_name", "")
    dt     = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    tests  = session["tests"]

    done    = [t for t in tests if t.get("status") == "completed" and t.get("result")]
    passed  = [t for t in done  if t["result"].get("status") == "PASS"]
    skipped = [t for t in tests if t.get("status") == "skipped"]
    issues  = [t for t in done  if t["result"].get("status") not in ("PASS", "SKIP")]

    by_sev: dict[str, list] = {s: [] for s in SEVERITY_ORDER}
    for t in issues:
        sev = t["result"].get("severity", "Info")
        by_sev.setdefault(sev, []).append(t)

    lines: list[str] = [
        f"# Security Report: {app}",
        f"**Package:** `{pkg}`" if pkg else "",
        f"**Date:** {dt}",
        f"**Test Level:** {session.get('level_filter', 'N/A')}",
        "",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Tests run | {len(done)} |",
        f"| Issues found | {len(issues)} |",
        f"| Passed | {len(passed)} |",
        f"| Skipped | {len(skipped)} |",
        "",
        "---",
        "",
    ]

    ticket = 1
    for sev in SEVERITY_ORDER:
        grp = by_sev.get(sev, [])
        if not grp:
            continue
        sev_emoji = {
            "Critical": "🔴", "High": "🟠", "Medium": "🟡",
            "Low": "🔵", "Info": "⚪",
        }.get(sev, "•")
        lines.append(f"## {sev_emoji} {sev} Severity Issues\n")

        for t in grp:
            r = t["result"]
            lines += [
                f"### [SEC-{ticket:03d}] {t['name']}",
                f"> **Section:** {t['section']}  |  **Level:** {t['level']}  |  **Severity:** {r['severity']}",
                "",
            ]
            if r.get("jira_summary"):
                lines += [f"**Summary:** {r['jira_summary']}", ""]
            if r.get("findings"):
                lines += ["**Findings:**"] + [f"- {f}" for f in r["findings"]] + [""]
            if r.get("jira_description"):
                lines += ["**Steps to Reproduce / Evidence:**", "", r["jira_description"], ""]
            if r.get("jira_recommendation"):
                lines += ["**Recommendation:**", "", r["jira_recommendation"], ""]
            if r.get("commands_used"):
                lines += ["**Commands used:**"]
                for cmd in r["commands_used"]:
                    lines += [f"```bash\n{cmd}\n```"]
                lines.append("")
            lines += ["---", ""]
            ticket += 1

    if passed:
        lines += ["## ✅ Passed Tests", ""]
        for t in passed:
            lines.append(f"- [x] **{t['name']}** ({t['section']})")
        lines.append("")

    if skipped:
        lines += ["## ⏭ Skipped Tests", ""]
        for t in skipped:
            lines.append(f"- [ ] {t['name']} ({t['section']})")
        lines.append("")

    return "\n".join(l for l in lines if l is not None)

# ─────────────────────────────────────────────────────────────────────────────
# 10. CHECKLIST DISPLAY
# ─────────────────────────────────────────────────────────────────────────────
_ICONS = {
    "completed_pass":  f"{_G}[✓]{_R}",
    "completed_fail":  f"{_RE}[✗]{_R}",
    "completed_info":  f"{_Y}[i]{_R}",
    "completed_skip":  f"{_D}[-]{_R}",
    "running":         f"{_Y}[→]{_R}",
    "pending":         "[ ]",
    "skipped":         f"{_D}[~]{_R}",
}

def show_checklist(session: dict) -> None:
    tests    = session["tests"]
    done_cnt = sum(1 for t in tests if t.get("status") == "completed")
    _clear()
    print()
    _box(f"TEST CHECKLIST  –  {session.get('app_name','?')}  [{session.get('level_filter','')}]")
    print(f"  Progress: {_G}{_B}{done_cnt}{_R} / {len(tests)} completed\n")

    prev_sec = None
    for t in tests:
        if t["section"] != prev_sec:
            lc = _Y if t["level"] == "L2" else _C
            print(f"\n  {lc}{_B}[{t['level']}] {t['section']}{_R}")
            prev_sec = t["section"]

        st = t.get("status", "pending")
        r  = t.get("result") or {}
        rs = (r.get("status") or "").lower()

        if st == "completed":
            key  = f"completed_{rs}" if rs in ("pass","fail","info","skip") else "completed_fail"
            icon = _ICONS.get(key, _ICONS["completed_fail"])
            sev  = r.get("severity", "")
            sev_tag = f" {_Y}[{sev}]{_R}" if sev not in ("N/A","Info","") and rs != "pass" else ""
            print(f"  {icon} {t['name']}{sev_tag}")
        else:
            icon = _ICONS.get(st, "[ ]")
            print(f"  {icon} {t['name']}")

    print(f"\n  {_B}{_hr()}{_R}")

# ─────────────────────────────────────────────────────────────────────────────
# 11. PENDING-JIRA WARNING
# ─────────────────────────────────────────────────────────────────────────────
def check_pending_jira(state: dict) -> bool:
    """Return True if safe to proceed."""
    if not state.get("pending_jira"):
        return True
    rp = state.get("last_report_path", "N/A")
    print(f"\n  {'=' * 70}")
    print(f"  {_Y}{_B}[!] PENDING JIRA UPLOAD FROM LAST SESSION{_R}")
    print(f"  {'=' * 70}")
    print(f"  Report not yet uploaded to Jira:")
    print(f"  {_C}{rp}{_R}\n")
    print("  1  Upload now (confirm when done to clear flag)")
    print("  2  Skip and start next run anyway")
    print("  Q  Quit")
    print()
    ch = input("  Choice (1/2/Q): ").strip().upper()
    if ch == "Q":
        return False
    if ch == "1":
        print(f"\n  Open the report and upload it to Jira, then press Enter…")
        input()
    state["pending_jira"] = False
    save_state(state)
    return True

# ─────────────────────────────────────────────────────────────────────────────
# 12. INTERACTIVE TEST SELECTION  (curses on Linux, msvcrt fallback on Windows)
# ─────────────────────────────────────────────────────────────────────────────
try:
    import curses as _curses
    _HAS_CURSES = True
except ImportError:
    _HAS_CURSES = False

if IS_WIN:
    import msvcrt

_PAGE = 22

def _getch() -> str:
    if IS_WIN:
        import msvcrt
        key = msvcrt.getch()
        if key in (b"\xe0", b"\x00"):
            ext = msvcrt.getch()
            return {b"H":"UP",b"P":"DOWN",b"I":"PGUP",b"Q":"PGDN"}.get(ext, "?")
        if key == b"\r":   return "ENTER"
        if key == b" ":    return "SPACE"
        if key == b"\x1b": return "ESC"
        return key.decode("latin-1", errors="replace").upper()
    else:
        import tty, termios
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = os.read(fd, 1)
            if ch == b"\x1b":
                ch2 = os.read(fd, 1)
                if ch2 == b"[":
                    ch3 = os.read(fd, 1)
                    return {b"A":"UP",b"B":"DOWN",b"5":"PGUP",b"6":"PGDN"}.get(ch3,"?")
                return "ESC"
            if ch in (b"\r", b"\n"): return "ENTER"
            if ch == b" ":           return "SPACE"
            return ch.decode("latin-1", errors="replace").upper()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)

def _draw_select(items: list, selected: set, current: int,
                 title: str, ws: int, we: int) -> None:
    _clear()
    w = 72
    print(f"{_B}{'=' * w}{_R}")
    print(f"{_B}  {title}{_R}")
    print(f"{_B}{'=' * w}{_R}")
    print(f"  Selected: {_G}{_B}{len(selected)}{_R}/{len(items)}   "
          f"Pos: {current + 1}/{len(items)}")
    print(f"  {'─' * (w - 2)}")
    prev = None
    for i in range(ws, we):
        t = items[i]
        if t["section"] != prev:
            lc = _Y if t["level"] == "L2" else _C
            print(f"\n  {lc}{_B}[{t['level']}] {t['section']}{_R}")
            prev = t["section"]
        name   = t["name"][:60]
        raw_cb = "[*]" if i in selected else "[ ]"
        if i == current:
            print(f"{_HL}  >>> {raw_cb} {name:<60}{_R}")
        elif i in selected:
            print(f"      {_G}[*]{_R} {_G}{name}{_R}")
        else:
            print(f"      [ ] {name}")
    if ws > 0:          print(f"\n  {_D}^ {ws} more above  (↑ / PgUp){_R}")
    if we < len(items): print(f"  {_D}v {len(items) - we} more below  (↓ / PgDn){_R}")
    print(f"\n  {'─' * (w - 2)}")
    print(f"  {_B}↑↓{_R}=Nav  {_B}SPACE{_R}=Toggle  {_B}A{_R}=All  "
          f"{_B}N{_R}=None  {_B}ENTER{_R}=Confirm  {_B}Q{_R}=Quit")
    print(f"{_B}{'=' * w}{_R}")

def _plain_select(items: list, presel: set, title: str) -> set | None:
    if not items:
        return set()
    sel, cur = set(presel), 0
    while True:
        ws = max(0, cur - _PAGE // 2)
        we = min(len(items), ws + _PAGE)
        if we == len(items):
            ws = max(0, len(items) - _PAGE)
        _draw_select(items, sel, cur, title, ws, we)
        k = _getch()
        if   k == "UP":    cur = (cur - 1) % len(items)
        elif k == "DOWN":  cur = (cur + 1) % len(items)
        elif k == "PGUP":  cur = max(0, cur - _PAGE)
        elif k == "PGDN":  cur = min(len(items) - 1, cur + _PAGE)
        elif k == "SPACE": sel.symmetric_difference_update({cur})
        elif k == "A":     sel = set(range(len(items)))
        elif k == "N":     sel = set()
        elif k == "ENTER": return sel
        elif k in ("Q","ESC"): return None

def _curses_select(stdscr, items, presel, title):
    _curses.curs_set(0)
    try:
        _curses.start_color()
        _curses.init_pair(1, _curses.COLOR_BLACK,  _curses.COLOR_WHITE)
        _curses.init_pair(2, _curses.COLOR_GREEN,  _curses.COLOR_BLACK)
        _curses.init_pair(3, _curses.COLOR_CYAN,   _curses.COLOR_BLACK)
        _curses.init_pair(4, _curses.COLOR_YELLOW, _curses.COLOR_BLACK)
        hc = True
    except Exception:
        hc = False

    sel, cur = set(presel), 0
    disp: list = []
    prev = None
    for i, t in enumerate(items):
        if t["section"] != prev:
            disp.append(("hdr", t["section"], t["level"]))
            prev = t["section"]
        disp.append(("item", i))

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        pg = max(4, h - 8)
        cur_dr = next((r for r,(dt,*_) in enumerate(disp)
                       if dt == "item" and disp[r][1] == cur), 0)
        ws = max(0, cur_dr - pg // 2)
        we = min(len(disp), ws + pg)
        if we == len(disp):
            ws = max(0, len(disp) - pg)

        row = 0
        stdscr.addstr(row, 0, "=" * min(72, w - 1), _curses.A_BOLD); row += 1
        stdscr.addstr(row, 0, f"  {title}"[:w - 1],  _curses.A_BOLD); row += 1
        stdscr.addstr(row, 0, "=" * min(72, w - 1), _curses.A_BOLD); row += 1
        stdscr.addstr(row, 0, f"  Sel:{len(sel)}/{len(items)}  Pos:{cur+1}/{len(items)}"[:w-1]); row += 1
        stdscr.addstr(row, 0, "-" * min(68, w - 1)); row += 1

        for di in range(ws, we):
            if row >= h - 3:
                break
            dtype = disp[di][0]
            if dtype == "hdr":
                _, sec, lvl = disp[di]
                a = (_curses.color_pair(4 if lvl == "L2" else 3) | _curses.A_BOLD) if hc else _curses.A_BOLD
                stdscr.addstr(row, 0, f"  [{lvl}] {sec}"[:w - 1], a)
            else:
                idx = disp[di][1]
                t   = items[idx]
                cb  = "[*]" if idx in sel else "[ ]"
                ar  = ">>>" if idx == cur else "   "
                txt = f"  {ar} {cb} {t['name']}"[:w - 1]
                a   = (_curses.color_pair(1) | _curses.A_BOLD) if idx == cur and hc \
                      else (_curses.A_REVERSE | _curses.A_BOLD) if idx == cur \
                      else _curses.color_pair(2) if idx in sel and hc else 0
                stdscr.addstr(row, 0, txt, a)
            row += 1

        if ws > 0:         stdscr.addstr(h - 3, w - 11, "^ MORE  ^")
        if we < len(disp): stdscr.addstr(h - 2, w - 11, "v  MORE v")
        stdscr.addstr(h - 2, 0, "-" * min(68, w - 1))
        stdscr.addstr(h - 1, 0, "ARROWS  SPACE=Toggle  A=All  N=None  ENTER=Confirm  Q=Quit"[:w-1])
        stdscr.refresh()

        k = stdscr.getch()
        if   k == _curses.KEY_UP:    cur = (cur - 1) % len(items)
        elif k == _curses.KEY_DOWN:  cur = (cur + 1) % len(items)
        elif k == _curses.KEY_PPAGE: cur = max(0, cur - pg // 2)
        elif k == _curses.KEY_NPAGE: cur = min(len(items) - 1, cur + pg // 2)
        elif k == ord(" "):          sel.symmetric_difference_update({cur})
        elif k in (ord("a"), ord("A")): sel = set(range(len(items)))
        elif k in (ord("n"), ord("N")): sel = set()
        elif k in (ord("\n"), 10, 13):  return sel
        elif k in (ord("q"), ord("Q"), 27): return None

def run_selection_menu(items: list, presel: set, title: str) -> set | None:
    if _HAS_CURSES:
        try:
            return _curses.wrapper(_curses_select, items, presel, title)
        except Exception:
            pass
    return _plain_select(items, presel, title)

def choose_level_filter(total: int) -> str | None:
    print()
    _box("SELECT TEST LEVEL")
    print(f"  Tests available in Prompt.md: {_B}{total}{_R}\n")
    print(f"  {_B}1{_R}  {_C}L1{_R}     Standard Security  – applies to all apps")
    print(f"  {_B}2{_R}  {_Y}L2{_R}     Defense-in-Depth   – Resilience / anti-tamper")
    print(f"  {_B}3{_R}  {_G}Both{_R}   Full suite  (L1 + L2)")
    print(f"  {_B}4{_R}  Custom  Pick tests individually")
    print(f"  {_B}Q{_R}  Quit")
    print()
    while True:
        raw = input("  Choice (1/2/3/4/Q): ").strip().upper()
        if raw in ("1", "L1"):              return "L1"
        if raw in ("2", "L2"):              return "L2"
        if raw in ("3", "BOTH", "B"):       return "BOTH"
        if raw in ("4", "CUSTOM", "C"):     return "CUSTOM"
        if raw in ("Q", "QUIT", ""):        return None
        print("  [!] Enter 1, 2, 3, 4, or Q.")

# ─────────────────────────────────────────────────────────────────────────────
# 13. MAIN TEST LOOP
# ─────────────────────────────────────────────────────────────────────────────
def run_tests(session: dict, improvements: dict) -> None:
    tests = session["tests"]

    for i, test in enumerate(tests):
        if test.get("status") == "completed":
            continue

        test["status"] = "running"
        save_state(session)
        show_checklist(session)

        print(f"\n{_B}{_hr()}{_R}")
        print(f"{_B}  Test {i + 1} / {len(tests)}: {test['name']}{_R}")
        print(f"  Section: {test['section']}  |  Level: {test['level']}")
        print(f"{_B}{_hr()}{_R}")

        imp = get_improvement(improvements, test["name"])
        if imp.get("run_count", 0):
            print(f"  {_C}[~] Refinement available from {imp['run_count']} prior run(s){_R}")

        prompt = build_prompt(test, session, imp)

        # Show a brief prompt preview so the tester knows what Claude will receive
        preview_lines = [l for l in prompt.splitlines() if l.strip()][:8]
        print(f"\n  {_D}Prompt preview:")
        for pl in preview_lines:
            print(f"    {pl[:90]}")
        print(f"    …{_R}\n")

        print(f"  {_C}[*] Sending to Claude (timeout 10 min)…{_R}")
        cwd = session.get("decompiled_path") or str(SCRIPT_DIR)
        success, output = run_claude(prompt, cwd=cwd)

        # ── Handle runner errors ──
        if not success and not output.strip():
            print(f"\n  {_RE}[!] Claude failed to produce output.{_R}")
            print("  R=Retry  S=Skip this test  Q=Save & quit")
            ch = input("  Choice: ").strip().upper()
            if ch == "R":
                test["status"] = "pending"
                continue
            if ch == "Q":
                test["status"] = "pending"
                save_state(session)
                return
            test["status"] = "skipped"
            save_state(session)
            continue

        result = parse_result(output, test["name"])

        # ── Completion marker check ──
        if not result["completed"]:
            print(f"\n  {_Y}[!] TEST_COMPLETED marker not found.{_R}")
            print("  The test may be only partially done.")
            print("  C=Accept as complete  R=Retry  S=Skip")
            ch = input("  Choice (C/R/S): ").strip().upper()
            if ch == "R":
                test["status"] = "pending"
                continue
            if ch == "S":
                test["status"] = "skipped"
                save_state(session)
                continue
            # C → fall through and accept

        # ── Store results ──
        test["result"] = result
        test["status"] = "completed"
        session["last_run"] = datetime.datetime.now().isoformat()
        save_state(session)

        update_improvement(improvements, test["name"],
                           result, result.get("improved_prompt", ""))
        save_improvements(improvements)

        rf = save_result_file(test, result, session["session_id"])

        # ── Print brief summary ──
        st  = result["status"]
        sev = result["severity"]
        st_col = _G if st == "PASS" else _Y if st == "INFO" else _RE
        print(f"\n  Result: {st_col}{_B}{st}{_R}  |  Severity: {sev}")
        if result["findings"]:
            print(f"  Findings ({len(result['findings'])}):")
            for f in result["findings"][:3]:
                print(f"    {_RE}•{_R} {f[:85]}")
            if len(result["findings"]) > 3:
                print(f"    {_D}… {len(result['findings']) - 3} more (see result file){_R}")
        if result.get("improved_prompt"):
            print(f"  {_G}[✓] Prompt improved for next run{_R}")
        print(f"  {_D}Saved: {rf}{_R}")

        if i < len(tests) - 1:
            remaining = sum(1 for t in tests[i+1:] if t.get("status") != "completed")
            print(f"\n  {remaining} test(s) remaining.")
            input("  Press Enter for next test…")

    # ── All done ──
    show_checklist(session)
    print(f"\n  {_G}{_B}All tests completed!{_R}\n")

    report_md = generate_report(session)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", session.get("app_name", "app"))
    rfile = REPORTS_DIR / f"{safe}_{session['session_id']}.md"
    rfile.write_text(report_md, encoding="utf-8")

    session["pending_jira"]     = True
    session["last_report_path"] = str(rfile)
    save_state(session)

    print(f"  {_G}Jira-ready report:{_R}  {_C}{rfile}{_R}")
    print(f"  {_Y}[!] Upload this report to Jira before starting the next test run.{_R}\n")
    print(f"  Individual results are in:  {_C}{RESULTS_DIR / session['session_id']}{_R}\n")

# ─────────────────────────────────────────────────────────────────────────────
# 14. ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    _enable_ansi()
    _clear()

    print(f"\n{_B}{'=' * 72}{_R}")
    print(f"{_B}  selfImprovementtest.py  v{__version__}{_R}")
    print(f"{_B}  AI-Assisted Android Security Testing  –  OWASP MASTG{_R}")
    print(f"{_B}  Platform: Kali Linux  |  ADB + Frida  |  Claude Code CLI{_R}")
    print(f"{_B}{'=' * 72}{_R}\n")

    check_for_update()

    state        = load_state()
    improvements = load_improvements()

    # Pending Jira warning
    if not check_pending_jira(state):
        print("[*] Exiting.\n")
        sys.exit(0)

    # Resume existing session?
    session: dict | None = None
    pending = [t for t in state.get("tests", [])
               if t.get("status") not in ("completed", "skipped")]
    if state.get("tests") and pending:
        done  = sum(1 for t in state["tests"] if t.get("status") == "completed")
        total = len(state["tests"])
        print(f"  {_Y}[?] Resumable session found:{_R}  "
              f"{state.get('app_name','?')}  ({done}/{total} done)")
        print()
        print("  1  Resume existing session")
        print("  2  Start a new session")
        print("  Q  Quit")
        print()
        ch = input("  Choice (1/2/Q): ").strip().upper()
        if ch == "Q":
            sys.exit(0)
        if ch == "1":
            session = state

    if session is None:
        # ── New session setup ──
        print()
        _box("NEW TEST SESSION")
        print()
        app_name    = input("  App name (used in report filename): ").strip() or "UnknownApp"
        pkg_name    = input("  Package name  (e.g. com.example.app): ").strip()
        apk_path    = input("  APK file path (optional, Enter to skip): ").strip()
        decomp_path = input("  Decompiled APK folder  (e.g. /root/Desktop/AppName/): ").strip()
        print()

        if not PROMPT_MD.exists():
            print(f"  [!] Prompt.md not found at:  {PROMPT_MD}")
            print(f"  Place Prompt.md in the same folder as this script.")
            sys.exit(1)

        print(f"  {_D}Parsing Prompt.md…{_R}", end="", flush=True)
        all_tests = parse_prompt_md(PROMPT_MD)
        l1 = sum(1 for t in all_tests if t["level"] == "L1")
        l2 = sum(1 for t in all_tests if t["level"] == "L2")
        print(f"\r  {_G}[✓]{_R} {len(all_tests)} tests loaded  "
              f"({_C}L1: {l1}{_R}  {_Y}L2: {l2}{_R})")

        level_filter = choose_level_filter(len(all_tests))
        if level_filter is None:
            print("[*] Exiting.\n")
            sys.exit(0)

        if level_filter == "L1":
            presel = {i for i, t in enumerate(all_tests) if t["level"] == "L1"}
        elif level_filter == "L2":
            presel = {i for i, t in enumerate(all_tests) if t["level"] == "L2"}
        elif level_filter == "BOTH":
            presel = set(range(len(all_tests)))
        else:
            presel = set()

        title  = (f"SELECT TESTS [{level_filter}]  –  "
                  "SPACE=toggle  ENTER=confirm  A=all  N=none  Q=quit")
        sel_idx = run_selection_menu(all_tests, presel, title)

        if not sel_idx:
            print("\n[*] No tests selected. Exiting.\n")
            sys.exit(0)

        selected = [all_tests[i] for i in sorted(sel_idx)]
        session  = new_session(selected, app_name, pkg_name,
                               apk_path, decomp_path, level_filter)
        save_state(session)

    # ── Show checklist, confirm, run ──
    show_checklist(session)
    done = sum(1 for t in session["tests"] if t.get("status") == "completed")
    remaining = len(session["tests"]) - done
    print(f"  {remaining} tests will be sent to Claude one-by-one.")
    print(f"  {_Y}Ensure 'claude' is in PATH and your ADB device is connected.{_R}")
    if session.get("decompiled_path"):
        print(f"  Claude will run with CWD: {_C}{session['decompiled_path']}{_R}")
    print()
    ans = input("  Start testing? [Y/n]: ").strip().lower()
    if ans in ("n", "no", "q"):
        print("[*] Exiting. Session saved.\n")
        sys.exit(0)

    run_tests(session, improvements)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Interrupted – session progress saved.\n")
        sys.exit(0)
