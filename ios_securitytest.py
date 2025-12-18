#!/usr/bin/env python3
"""
ios_securitytest.py (enhanced)
macOS iOS MASVS-oriented assessment helper (static-first) with interactive test selection.

Highlights
- Unzips .ipa and locates Payload/*.app, frameworks, dylibs
- Extracts Info.plist metadata
- Extracts entitlements and code signing details
- Runs otool / nm / lipo / strings scans
- Scans bundle files for common insecure configurations, secrets, endpoints, jailbreak artifacts
- Generates <bundle_id>.report.html + <bundle_id>.report.json

Optional safe dynamic introspection (read-only):
- --dynamic: lightweight Frida introspection (enumerate modules), no bypass logic.

Requirements (macOS):
- Xcode Command Line Tools (otool, nm, codesign, plutil, strings)
Optional:
- lipo, swift-demangle, frida-tools, objection (for manual follow-on)
- sshpass OR pexpect (for SSH device analysis)
  - sshpass: brew install hudochenkov/sshpass/sshpass
  - pexpect: pip3 install pexpect

Usage
  python3 ios_securitytest.py -f App.ipa
  python3 ios_securitytest.py -f App.ipa -s
  python3 ios_securitytest.py -f App.ipa -d
  python3 ios_securitytest.py -f App.ipa -ssh 192.168.1.100
  python3 ios_securitytest.py -f App.ipa -ssh 192.168.1.100 --ssh-password mypass
  python3 ios_securitytest.py -f App.ipa -ssh 192.168.1.100 --ssh-manual

This script accelerates triage; MASVS compliance still needs human validation.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import pathlib
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Literal, Optional, Set, Tuple

APPLE_BANNER = r"""
          .:'
      __ :'__
   .'`  `-'  ``'.
  :             :
  :             :
   :           :
    `.__.-.__.'
"""

RUN_INTRO = [
    "ios_securitytest.py (enhanced)",
    "macOS iOS MASVS-oriented assessment helper (static-first) with interactive test selection.",
    "Highlights: unzip IPA, extract metadata/entitlements, run otool/nm/strings, scan for insecure configs,",
    "generate <bundle_id>.report.html + <bundle_id>.report.json",
    "Optional: --dynamic (Frida read-only), --ssh (device triage)",
]

Status = Literal["PASS", "FAIL", "WARN", "INFO"]

# --------------------------- 
# Utilities
# --------------------------- 

def run(cmd: List[str], timeout: int = 60, cwd: Optional[str] = None) -> Tuple[int, str]:
    try:
        # Use text=False to get bytes, then decode with error handling for binary output
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, cwd=cwd)
        # Decode with 'replace' to handle binary data gracefully
        output = p.stdout.decode('utf-8', errors='replace') if p.stdout else ""
        return p.returncode, output
    except FileNotFoundError:
        return 127, f"Missing tool: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"Timeout running: {' '.join(cmd)}"

def which(tool: str) -> Optional[str]:
    return shutil.which(tool)

def safe_mkdir(p: str):
    os.makedirs(p, exist_ok=True)

def read_file_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def rel(path: str, base: str) -> str:
    try:
        return os.path.relpath(path, base)
    except Exception:
        return path

def is_macho(path: str) -> bool:
    try:
        b = read_file_bytes(path)[:4]
        return b in (
            b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"
        )
    except Exception:
        return False

def plutil_to_plist(plist_path: str) -> Dict:
    rc, out = run(["plutil", "-convert", "xml1", "-o", "-", plist_path], timeout=30)
    if rc == 0 and out.strip().startswith("<?xml"):
        return plistlib.loads(out.encode("utf-8"))
    with open(plist_path, "rb") as f:
        return plistlib.load(f)

def dir_size(path: str) -> int:
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            fp = os.path.join(root, f)
            try:
                total += os.path.getsize(fp)
            except Exception:
                pass
    return total

def recursive_file_find(base: str, exts: Tuple[str, ...]) -> List[str]:
    res = []
    for root, _, files in os.walk(base):
        for f in files:
            if f.lower().endswith(exts):
                res.append(os.path.join(root, f))
    return res

def strings_dump(path: str, timeout: int = 120) -> List[str]:
    rc, out = run(["/usr/bin/strings", "-a", path], timeout=timeout)
    if rc != 0:
        return []
    return [l.rstrip("\n") for l in out.splitlines()]

def strings_grep_lines(lines: List[str], patterns: List[str], max_hits: int = 60) -> List[str]:
    hits: List[str] = []
    for line in lines:
        l = line.strip()
        if not l:
            continue
        for pat in patterns:
            if re.search(pat, l, flags=re.IGNORECASE):
                hits.append(l)
                if len(hits) >= max_hits:
                    return hits
                break
    return hits

def strings_grep_lines_with_matches(lines: List[str], patterns: List[str], max_hits: int = 60) -> List[tuple]:
    """Returns list of (line, matched_pattern) tuples"""
    hits: List[tuple] = []
    for line in lines:
        l = line.strip()
        if not l:
            continue
        for pat in patterns:
            match = re.search(pat, l, flags=re.IGNORECASE)
            if match:
                hits.append((l, match.group(0)))
                if len(hits) >= max_hits:
                    return hits
                break
    return hits

def list_bundle_binaries(app_dir: str, main_bin: str) -> List[str]:
    targets = [main_bin]
    targets += recursive_file_find(app_dir, (".dylib",))
    # frameworks: binary with same name as framework dir
    for fw in recursive_file_find(app_dir, (".framework",)):
        if os.path.isdir(fw):
            name = os.path.splitext(os.path.basename(fw))[0]
            candidate = os.path.join(fw, name)
            if os.path.isfile(candidate) and is_macho(candidate):
                targets.append(candidate)
    # remove duplicates
    seen = set()
    out = []
    for t in targets:
        if os.path.isfile(t) and t not in seen:
            seen.add(t)
            out.append(t)
    return out

# ---------------------------
# SSH Device Utilities
# ---------------------------

def clean_ssh_output(output: str) -> str:
    """
    Clean SSH output by removing SSH warnings, password prompts, and other noise.
    Returns only the actual command output.
    """
    if not output:
        return ""

    lines = output.splitlines()
    cleaned_lines = []

    for line in lines:
        line_lower = line.lower()

        # Skip SSH warning messages and prompts
        if any(skip in line_lower for skip in [
            "warning: permanently added",
            "password for root@",
            "password:",
            "pseudo-terminal will not be allocated",
            "killed by signal",
            "connection to",
            "connection closed",
        ]):
            continue

        # Skip pexpect error messages
        if "<class 'pexpect" in line or "TIMEOUT'>" in line:
            continue

        # Keep non-empty lines that don't look like shell prompts
        stripped = line.strip()
        if stripped and not stripped.endswith("# ") and not stripped.endswith("#"):
            cleaned_lines.append(line)

    return "\n".join(cleaned_lines)

def ssh_run(device_ip: str, cmd: str, password: str = "alpine", timeout: int = 30, manual: bool = False) -> Tuple[int, str]:
    """
    Run a command on the iOS device via SSH.
    Uses sshpass if available, otherwise falls back to pexpect for automatic password entry.
    If manual=True, prompts user for password interactively.
    Automatically cleans SSH warnings and prompts from output.
    """
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
               "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=5", f"root@{device_ip}", cmd]

    # If manual mode, skip automation and prompt user
    if manual:
        print(f"    [*] Running SSH command (you'll be prompted for password): {cmd[:50]}...")
        rc, out = run(ssh_cmd, timeout=timeout)
        return (rc, clean_ssh_output(out))

    # Try with sshpass first (cleanest method)
    if which("sshpass"):
        ssh_cmd = ["sshpass", "-p", password] + ssh_cmd
        rc, out = run(ssh_cmd, timeout=timeout)
        return (rc, clean_ssh_output(out))

    # Fallback to pexpect for automatic password entry
    try:
        import pexpect

        # Build the full SSH command as a string for pexpect
        ssh_cmd_str = " ".join(f'"{arg}"' if " " in arg else arg for arg in ssh_cmd)

        # Use pexpect.run with events for password handling - simpler and more reliable
        try:
            # Define what to send when we see the password prompt
            events = {
                r'(?i)password:': password + '\n',
            }

            # Run the command and capture all output
            output = pexpect.run(
                ssh_cmd_str,
                events=events,
                timeout=timeout,
                encoding='utf-8',
                withexitstatus=True
            )

            # pexpect.run returns (output, exit_status) when withexitstatus=True
            if isinstance(output, tuple):
                all_output, exitstatus = output
            else:
                all_output = output
                exitstatus = 0

            # Debug: Print raw output before cleaning
            if os.environ.get('SSH_DEBUG'):
                print(f"    [RAW OUTPUT] length={len(all_output)}, content={repr(all_output[:500])}")

            # Clean the output
            cleaned = clean_ssh_output(all_output)

            # More debug
            if os.environ.get('SSH_DEBUG'):
                print(f"    [CLEANED OUTPUT] length={len(cleaned)}, content={repr(cleaned[:500])}")

            return (exitstatus if exitstatus is not None else 0, cleaned)

        except pexpect.TIMEOUT:
            return (1, "SSH command timed out")
        except pexpect.ExceptionPexpect as e:
            return (1, f"SSH pexpect error: {str(e)}")

    except ImportError:
        # pexpect not available, fallback to regular ssh (will prompt for password)
        rc, out = run(ssh_cmd, timeout=timeout)
        return (rc, clean_ssh_output(out))
    except Exception as e:
        return (1, f"SSH error: {str(e)}")

def ssh_check_connectivity(device_ip: str, password: str = "alpine", manual: bool = False) -> bool:
    """Check if the device is reachable via SSH."""
    rc, _ = ssh_run(device_ip, "echo test", password=password, timeout=5, manual=manual)
    return rc == 0

def ssh_diagnostic_check(device_ip: str, expected_bundle_id: str, password: str = "alpine", manual: bool = False) -> Dict[str, any]:
    """
    Run diagnostic checks to locate app and verify bundle ID.
    Returns dict with: {found: bool, actual_bundle_id: str, app_path: str, data_path: str, suggestions: list}
    """
    print(f"\n{'='*60}")
    print(f"SSH DIAGNOSTIC PRE-CHECK")
    print(f"{'='*60}")
    print(f"Expected Bundle ID: {expected_bundle_id}")
    print()

    result = {
        "found": False,
        "actual_bundle_id": None,
        "app_path": None,
        "data_path": None,
        "suggestions": []
    }

    # 1. Use grep to find the bundle ID (much simpler and more reliable)
    print("[1/4] Searching for app using grep...")
    # -a flag treats binary files as text
    cmd = f"grep -ra '{expected_bundle_id}' /var/mobile/Containers/Data/Application/ 2>/dev/null | head -1"

    rc, out = ssh_run(device_ip, cmd, password=password, timeout=30, manual=manual)

    if rc == 0 and out.strip():
        match_line = out.strip().splitlines()[0]
        if '/Containers/Data/Application/' in match_line:
            parts = match_line.split('/Containers/Data/Application/')
            if len(parts) > 1:
                container_uuid = parts[1].split('/')[0].split(':')[0]
                result["found"] = True
                result["actual_bundle_id"] = expected_bundle_id
                result["data_path"] = f"/var/mobile/Containers/Data/Application/{container_uuid}"
                print(f"  ✓ FOUND: {expected_bundle_id} -> {container_uuid}")

    if not result["found"]:
        print(f"  ✗ Not found: {expected_bundle_id}")

        # Try searching with just the app name
        print("\n[2/4] Searching for similar bundle IDs...")
        # Extract app name from bundle ID (e.g., "staging" from "com.blatchfordmobility.universalapp.staging")
        search_terms = expected_bundle_id.split('.')
        for term in reversed(search_terms[-2:]):  # Try last two components
            # -a flag treats binary files as text
            cmd = f"grep -ra '{term}' /var/mobile/Containers/Data/Application/ 2>/dev/null | grep -i 'bundle' | head -3"
            rc, out = ssh_run(device_ip, cmd, password=password, timeout=20, manual=manual)
            if rc == 0 and out.strip():
                print(f"  ? Found references to '{term}':")
                for line in out.strip().splitlines()[:3]:
                    print(f"    {line[:100]}")
                break

    # 3. Search for app bundle using grep
    print("\n[3/4] Searching for app bundle...")
    search_bundle = result.get("actual_bundle_id") or expected_bundle_id

    # -a flag treats binary files as text
    cmd = f"grep -ram1 '{search_bundle}' /var/containers/Bundle/Application 2>/dev/null | grep '\\.app/' | head -10"
    rc, out = ssh_run(device_ip, cmd, password=password, timeout=20, manual=manual)

    app_match = extract_app_bundle_path_from_output(out) if rc == 0 else None
    if not app_match and (rc == 124 or (out.strip().startswith("Timeout running:") if out else False)):
        app_match = ssh_find_app_path(device_ip, search_bundle, password, manual)

    if app_match:
        result["app_path"] = app_match
        print(f"  ✓ App bundle: {result['app_path']}")
    else:
        if not result.get("app_path"):
            print(f"  ✗ App bundle not found for: {search_bundle}")

    # 4. Summary
    print(f"\n[4/4] Diagnostic Summary")
    print(f"{'='*60}")
    if result["found"]:
        print(f"✓ App is installed")
        print(f"  Bundle ID: {result['actual_bundle_id']}")
        print(f"  App Bundle: {result['app_path'] or 'Not found'}")
        print(f"  Data Container: {result['data_path']}")
    else:
        print(f"✗ App NOT found with bundle ID: {expected_bundle_id}")
        if result["suggestions"]:
            print(f"\n  Possible matches found:")
            for suggestion in result["suggestions"]:
                print(f"    - {suggestion}")
            print(f"\n  💡 TIP: Update your IPA's bundle ID or use one of the above")
        else:
            print(f"\n  💡 TIP: Ensure the app is installed on the device")
            print(f"  💡 Run on device: ls /var/mobile/Containers/Data/Application/*/")

    print(f"{'='*60}\n")
    return result

# Cache for jailbreak type detection (device_ip -> jailbreak_type)
_jailbreak_type_cache = {}

def ssh_detect_jailbreak_type(device_ip: str, password: str = "alpine", manual: bool = False) -> str:
    """
    Detect jailbreak type: 'rootless', 'rootful', or 'none'.

    Rootless jailbreaks (palera1n, Dopamine, etc.) mount at /var/jb/
    Rootful jailbreaks modify the system partition directly

    Returns cached result if already detected for this device.
    """
    if device_ip in _jailbreak_type_cache:
        return _jailbreak_type_cache[device_ip]

    print(f"    [*] Detecting jailbreak type...")

    # Temporarily enable debug for detection
    old_debug = os.environ.get('SSH_DEBUG')
    os.environ['SSH_DEBUG'] = '1'

    # Method 1: Simple test using ls
    rc, out = ssh_run(device_ip, "ls -d /var/jb 2>&1", password=password, timeout=5, manual=manual)
    result = out.strip()

    # Restore debug setting
    if old_debug is None:
        os.environ.pop('SSH_DEBUG', None)
    else:
        os.environ['SSH_DEBUG'] = old_debug

    # If /var/jb exists, it's rootless
    if rc == 0 and result and '/var/jb' in result and 'cannot access' not in result.lower() and 'no such file' not in result.lower():
        jailbreak_type = 'rootless'
        _jailbreak_type_cache[device_ip] = jailbreak_type
        print(f"    [+] Detected {jailbreak_type} jailbreak")
        return jailbreak_type

    # Method 2: Try with test -d
    rc2, out2 = ssh_run(device_ip, "test -d /var/jb && echo YES || echo NO", password=password, timeout=5, manual=manual)
    result2 = out2.strip().upper()

    if result2 == 'YES':
        jailbreak_type = 'rootless'
        _jailbreak_type_cache[device_ip] = jailbreak_type
        print(f"    [+] Detected {jailbreak_type} jailbreak (via test)")
        return jailbreak_type
    elif result2 == 'NO':
        jailbreak_type = 'rootful'
        _jailbreak_type_cache[device_ip] = jailbreak_type
        print(f"    [+] Detected {jailbreak_type} jailbreak (via test)")
        return jailbreak_type

    # Method 3: Try multiple simple echo commands to verify SSH is working
    rc3, out3 = ssh_run(device_ip, "echo HELLO", password=password, timeout=5, manual=manual)
    result3 = out3.strip()

    if 'HELLO' in result3:
        print(f"    [!] SSH is working but jailbreak detection unclear")
        # SSH works, but we couldn't detect jailbreak type - default to rootful
        jailbreak_type = 'rootful'
        _jailbreak_type_cache[device_ip] = jailbreak_type
        print(f"    [!] Assuming {jailbreak_type} jailbreak (detection failed but SSH works)")
        return jailbreak_type

    # Complete failure
    print(f"    [!] Could not detect jailbreak type - SSH may not be working properly")
    jailbreak_type = 'rootful'
    _jailbreak_type_cache[device_ip] = jailbreak_type
    print(f"    [!] Assuming {jailbreak_type} jailbreak (default)")
    return jailbreak_type

def extract_app_bundle_path_from_output(out: str) -> Optional[str]:
    """
    Extract the first plausible *.app path from grep output, tolerating binary noise.
    """
    for raw_line in out.splitlines():
        if not raw_line.strip():
            continue

        cleaned = raw_line.replace("\x00", "").strip()

        # Drop anything after the first colon (grep output uses colon as separator)
        if ":" in cleaned:
            cleaned = cleaned.split(":", 1)[0]

        # Trim to the first slash in case of leading junk
        slash_idx = cleaned.find("/")
        if slash_idx != -1:
            cleaned = cleaned[slash_idx:]

        if not cleaned.startswith("/"):
            continue

        match = re.search(r"(/[^:\s]*?\.app)", cleaned)
        if match:
            return match.group(1)

    return None

def ssh_find_app_path(device_ip: str, bundle_id: str, password: str = "alpine", manual: bool = False) -> Optional[str]:
    """
    Find the app installation path on the device by bundle identifier.
    Uses direct Info.plist scanning (previous grep-first approach often timed out).
    """
    print(f"    [*] Searching for app bundle containing '{bundle_id}' (Info.plist scan)...")

    # Check standard locations
    search_paths = [
        "/var/containers/Bundle/Application",
        "/var/mobile/Containers/Bundle/Application",
        "/Applications"
    ]

    # Directly scan Info.plist files for the bundle id
    print(f"    [*] Scanning Info.plist files for bundle id...")
    find_cmd = f"find {' '.join(search_paths)} -maxdepth 3 -type f -name Info.plist 2>/dev/null | head -80"
    rc, out = ssh_run(device_ip, find_cmd, password=password, timeout=45, manual=manual)

    if rc == 0 and out.strip():
        for info_path in out.strip().splitlines():
            check_cmd = f"grep -a '{bundle_id}' '{info_path}' 2>/dev/null | head -1"
            rc_check, out_check = ssh_run(device_ip, check_cmd, password=password, timeout=10, manual=manual)
            if rc_check == 0 and out_check.strip():
                app_dir = os.path.dirname(info_path)
                print(f"    [+] Found app bundle via Info.plist: {app_dir}")
                return app_dir

    # Not found - provide helpful debug info
    print(f"    [!] App bundle not found. Troubleshooting:")
    print(f"    [!] 1. Verify the app is installed: Is '{bundle_id}' on the device?")
    print(f"    [!] 2. Try manually: grep -r '{bundle_id}' /var/containers/Bundle/Application/")
    return None

def ssh_find_app_data_path(device_ip: str, bundle_id: str, password: str = "alpine", manual: bool = False) -> Optional[str]:
    """
    Find the app data container path on the device.
    Uses grep to search for bundle ID in any file (much more reliable than plutil).
    """
    print(f"    [*] Searching for data container containing '{bundle_id}'...")

    # Simple and reliable: grep recursively for the bundle ID
    # This works with binary plists, JSON, XML, and any other format
    # -a flag treats binary files as text so we can find matches in .db files, binary plists, etc.
    cmd = f"grep -ra '{bundle_id}' /var/mobile/Containers/Data/Application/ 2>/dev/null | head -1"

    rc, out = ssh_run(device_ip, cmd, password=password, timeout=30, manual=manual)

    if rc == 0 and out.strip():
        # Extract the container UUID from the path
        # Example output: /var/mobile/Containers/Data/Application/UUID/some/file: "bundleId" : "com.example.app"
        match_line = out.strip().splitlines()[0]
        if '/Containers/Data/Application/' in match_line:
            # Extract path up to the container UUID
            parts = match_line.split('/Containers/Data/Application/')
            if len(parts) > 1:
                container_uuid = parts[1].split('/')[0].split(':')[0]
                data_path = f"/var/mobile/Containers/Data/Application/{container_uuid}"
                print(f"    [+] Found data container: {data_path}")
                return data_path

    # Not found - provide helpful debug info
    print(f"    [!] Data container not found")
    print(f"    [!] The app may not have been run yet (no data container created)")
    print(f"    [!] Try manually: grep -r '{bundle_id}' /var/mobile/Containers/Data/Application/")
    return None

# ---------------------------
# Reporting model
# --------------------------- 

@dataclass
class FindingBlock:
    """Enhanced finding with code snippets and clickable file links (matches Android pattern)"""
    title: str                                    # File path or finding title
    subtitle: Optional[str] = None                # Line number, function name, description
    link: Optional[str] = None                    # file:// clickable link with optional line number
    meta: Dict[str, str] = field(default_factory=dict)  # Additional metadata
    code: Optional[str] = None                    # Raw code snippet
    code_language: str = "objc"                   # objc/swift/c/other
    is_collapsible: bool = True                   # Whether code block is collapsible
    open_by_default: bool = False                 # Whether to expand by default
    evidence: List[str] = field(default_factory=list)  # Additional evidence lines

# Legacy Finding class for backward compatibility
@dataclass
class Finding:
    title: str
    evidence: List[str] = field(default_factory=list)
    files: List[str] = field(default_factory=list)

@dataclass
class TestResult:
    """Test result with MASTG alignment and rich findings"""
    name: str                                     # Test name (was id + name, now unified)
    status: Status                                # PASS/FAIL/WARN/INFO
    summary_lines: List[str] = field(default_factory=list)  # Summary text lines
    mastg_ref_html: Optional[str] = None          # Full HTML link to MASTG test(s)
    findings: List[FindingBlock] = field(default_factory=list)  # Detailed findings with code
    tables_html: List[str] = field(default_factory=list)  # Optional HTML tables
    raw_html: Optional[str] = None                # Custom HTML content if needed
    is_dynamic: bool = False                      # Whether this is a dynamic test

    # Legacy fields for backward compatibility
    id: Optional[str] = None                      # Deprecated: use name instead
    summary: Optional[List[str]] = None           # Deprecated: use summary_lines
    mastg_ref: Optional[str] = None               # Deprecated: use mastg_ref_html

def status_cls(s: str) -> str:
    return {"PASS":"pass","FAIL":"fail","WARN":"warn","INFO":"info"}.get(s, "info")

# --------------------------- 
# MASTG and Finding Helpers
# --------------------------- 

def mastg_ref(test_ids: List[str], titles: Optional[List[str]] = None) -> str:
    """
    Generate MASTG reference HTML link(s) for iOS tests.

    Args:
        test_ids: List of MASTG test IDs (e.g., ["MASTG-TEST-0087", "MASTG-TEST-0228"])
        titles: Optional list of titles for each test (if None, uses generic titles)

    Returns:
        HTML string with clickable MASTG links

    Example:
        mastg_ref(["MASTG-TEST-0087"], ["Make Sure That Free Security Features Are Activated"])
    """
    if not test_ids:
        return ""

    # Category mapping for iOS tests
    category_map = {
        "0053": "MASVS-STORAGE", "0054": "MASVS-STORAGE", "0055": "MASVS-STORAGE",
        "0058": "MASVS-STORAGE", "0060": "MASVS-STORAGE", "0215": "MASVS-STORAGE",
        "0296": "MASVS-STORAGE", "0297": "MASVS-STORAGE", "0299": "MASVS-STORAGE",
        "0302": "MASVS-STORAGE",

        "0061": "MASVS-CRYPTO", "0062": "MASVS-CRYPTO", "0063": "MASVS-CRYPTO",
        "0209": "MASVS-CRYPTO", "0210": "MASVS-CRYPTO", "0211": "MASVS-CRYPTO",
        "0212": "MASVS-CRYPTO", "0213": "MASVS-CRYPTO", "0214": "MASVS-CRYPTO",

        "0064": "MASVS-AUTH", "0266": "MASVS-AUTH", "0267": "MASVS-AUTH",
        "0268": "MASVS-AUTH", "0269": "MASVS-AUTH", "0270": "MASVS-AUTH",
        "0271": "MASVS-AUTH",

        "0065": "MASVS-NETWORK", "0066": "MASVS-NETWORK", "0067": "MASVS-NETWORK",
        "0068": "MASVS-NETWORK",

        "0056": "MASVS-PLATFORM", "0057": "MASVS-PLATFORM", "0059": "MASVS-PLATFORM",
        "0069": "MASVS-PLATFORM", "0070": "MASVS-PLATFORM", "0071": "MASVS-PLATFORM",
        "0072": "MASVS-PLATFORM", "0073": "MASVS-PLATFORM", "0074": "MASVS-PLATFORM",
        "0075": "MASVS-PLATFORM", "0076": "MASVS-PLATFORM", "0077": "MASVS-PLATFORM",
        "0078": "MASVS-PLATFORM", "0276": "MASVS-PLATFORM", "0277": "MASVS-PLATFORM",
        "0278": "MASVS-PLATFORM", "0279": "MASVS-PLATFORM", "0280": "MASVS-PLATFORM",
        "0290": "MASVS-PLATFORM",

        "0079": "MASVS-CODE", "0080": "MASVS-CODE", "0081": "MASVS-CODE",
        "0085": "MASVS-CODE", "0087": "MASVS-CODE", "0228": "MASVS-CODE",
        "0229": "MASVS-CODE", "0230": "MASVS-CODE", "0273": "MASVS-CODE",
        "0275": "MASVS-CODE",

        "0082": "MASVS-RESILIENCE", "0083": "MASVS-RESILIENCE", "0084": "MASVS-RESILIENCE",
        "0088": "MASVS-RESILIENCE", "0089": "MASVS-RESILIENCE", "0090": "MASVS-RESILIENCE",
        "0091": "MASVS-RESILIENCE", "0092": "MASVS-RESILIENCE", "0093": "MASVS-RESILIENCE",
        "0094": "MASVS-RESILIENCE", "0240": "MASVS-RESILIENCE", "0241": "MASVS-RESILIENCE",
    }

    links = []
    for i, test_id in enumerate(test_ids):
        # Extract test number from ID (e.g., "MASTG-TEST-0087" -> "0087")
        match = re.search(r'(\d{4})', test_id)
        if not match:
            continue
        test_num = match.group(1)
        category = category_map.get(test_num, "MASVS-RESILIENCE")  # Default category

        url = f"https://mas.owasp.org/MASTG/tests/ios/{category}/{test_id}/"
        title = titles[i] if titles and i < len(titles) else test_id
        links.append(f'<a href="{url}" target="_blank">{html.escape(title)}</a>')

    if not links:
        return ""

    return "<br><div><strong>Reference:</strong> " + " • ".join(links) + "</div>"

# Paths used to persist linked evidence into the final report folder
REPORT_ROOT_DIR: Optional[pathlib.Path] = None
REPORT_FILES_DIR: Optional[pathlib.Path] = None
_REPORT_FILE_CACHE: Set[pathlib.Path] = set()


def configure_report_file_links(out_dir: str) -> None:
    """
    Ensure report hyperlinks point to files that persist alongside the HTML report.
    Creates/clears an output subfolder to store copies of referenced files.
    """
    global REPORT_ROOT_DIR, REPORT_FILES_DIR, _REPORT_FILE_CACHE
    REPORT_ROOT_DIR = pathlib.Path(out_dir).resolve()
    REPORT_FILES_DIR = REPORT_ROOT_DIR / "report_files"
    _REPORT_FILE_CACHE = set()

    try:
        shutil.rmtree(REPORT_FILES_DIR, ignore_errors=True)
    except Exception:
        # Ignore cleanup errors; we'll recreate the folder below
        pass
    REPORT_FILES_DIR.mkdir(parents=True, exist_ok=True)


def _safe_relpath_for_report(rel_path: str) -> pathlib.Path:
    """
    Sanitize the relative path used inside report_files to avoid path traversal.
    """
    p = pathlib.Path(rel_path)
    if p.is_absolute():
        return pathlib.Path(p.name)

    parts = [part for part in p.parts if part not in ("", ".", "..")]
    if not parts:
        parts = [p.name or "file"]

    sanitized = [part.replace(":", "_") for part in parts]
    return pathlib.Path(*sanitized)


def make_file_link(base_path: str, rel_path: str, line_num: Optional[int] = None) -> str:
    """
    Generate clickable link to a file with optional line number.

    Copies the referenced file into <out_dir>/report_files so the HTML report
    retains working hyperlinks even after temporary extraction folders are cleaned.

    Args:
        base_path: Base directory path
        rel_path: Relative file path from base
        line_num: Optional line number

    Returns:
        HTML anchor tag pointing to a persisted file copy

    Example:
        make_file_link("/tmp/app", "ViewControl.swift", 142)
        -> '<a href="report_files/ViewController.swift:142" target="_blank" ...>'
    """
    full_path = pathlib.Path(os.path.join(base_path, rel_path)).resolve()
    link_target = full_path

    if REPORT_FILES_DIR:
        try:
            rel_copy = _safe_relpath_for_report(rel_path)
            copy_dest = REPORT_FILES_DIR / rel_copy
            if copy_dest not in _REPORT_FILE_CACHE:
                copy_dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(full_path, copy_dest)
                _REPORT_FILE_CACHE.add(copy_dest)
            link_target = copy_dest
        except Exception:
            # Fall back to the original location if copy fails
            link_target = full_path

    # Preserve the line number in display text; browsers ignore the trailing colon fragment
    display = f"{rel_path}:{line_num}" if line_num else rel_path

    try:
        if REPORT_ROOT_DIR and link_target.is_absolute():
            href = link_target.relative_to(REPORT_ROOT_DIR).as_posix()
        elif link_target.is_absolute():
            href = link_target.as_uri()
        else:
            href = link_target.as_posix()
    except Exception:
        href = link_target.as_posix() if not link_target.is_absolute() else link_target.as_uri()

    return f'<a href="{html.escape(href)}" target="_blank" rel="noopener noreferrer">{html.escape(display)}</a>'

def extract_snippet_with_context(file_path: str, pattern: str, context_lines: int = 3,
                                  max_matches: int = 10) -> List[Tuple[int, str, str]]:
    """
    Extract code snippets matching pattern with surrounding context.

    Args:
        file_path: Path to file to search
        pattern: Regex pattern to match
        context_lines: Number of lines before/after match to include
        max_matches: Maximum number of matches to return

    Returns:
        List of tuples: (line_number, matched_line, full_snippet_with_context)

    Example:
        results = extract_snippet_with_context("ViewController.swift", r"NSLog\\(")
        for line_num, match, snippet in results:
            print(f"Line {line_num}: {snippet}")
    """
    if not os.path.exists(file_path):
        return []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return []

    results = []
    compiled_pattern = re.compile(pattern, re.IGNORECASE)

    for i, line in enumerate(lines, start=1):
        if compiled_pattern.search(line):
            # Extract context window
            start_idx = max(0, i - context_lines - 1)
            end_idx = min(len(lines), i + context_lines)

            # Build snippet with line numbers
            snippet_lines = []
            for j in range(start_idx, end_idx):
                prefix = "→ " if j == i - 1 else "  "
                snippet_lines.append(f"{prefix}{j+1:4d} | {lines[j].rstrip()}")

            snippet = "\n".join(snippet_lines)
            results.append((i, line.strip(), snippet))

            if len(results) >= max_matches:
                break

    return results

def grep_code(base_path: str, pattern: str, file_exts: Tuple[str, ...] = ('.swift', '.m', '.mm', '.h',
                                                                             '.hpp', '.c', '.cpp', '.plist')) -> List[str]:
    """
    Search for pattern in code files within base_path.

    Args:
        base_path: Root directory to search
        pattern: Regex pattern to search for
        file_exts: Tuple of file extensions to search

    Returns:
        List of file paths containing the pattern
    """
    matching_files = []
    compiled_pattern = re.compile(pattern, re.IGNORECASE)

    for root, _, files in os.walk(base_path):
        for filename in files:
            if not filename.lower().endswith(file_exts):
                continue

            file_path = os.path.join(root, filename)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if compiled_pattern.search(content):
                        matching_files.append(file_path)
            except Exception:
                continue

    return matching_files

HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>iOS Mobile Security Assessment Report</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:20px auto;background:#f5f7fa;color:#111827;max-width:1200px}}
h1{{font-size:28px;margin:0 0 10px 0}}
.header{{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;padding:18px;border-radius:12px;margin-bottom:18px}}
.meta{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-top:12px}}
.card{{background:rgba(255,255,255,.15);border-radius:10px;padding:12px}}
.card code{{word-break:break-all;overflow-wrap:break-word}}
h2{{font-size:18px;margin:22px 0 10px 0}}
details{{background:white;border:1px solid #e5e7eb;border-radius:10px;margin:10px 0;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
summary{{cursor:pointer;display:flex;gap:10px;align-items:center;padding:12px 14px}}
.check-name{{flex:1;font-weight:600}}
.badge{{padding:3px 10px;border-radius:999px;font-weight:700;font-size:12px}}
.pass .badge{{background:#d1fae5;color:#065f46}}
.fail .badge{{background:#fee2e2;color:#991b1b}}
.warn .badge{{background:#fef3c7;color:#92400e}}
.info .badge{{background:#dbeafe;color:#1e40af}}
.content{{padding:12px 14px;border-top:1px solid #f3f4f6;background:#fafbfc;border-radius:0 0 10px 10px}}
ul{{margin:8px 0 8px 20px}}
code,pre{{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}}
pre{{background:#0f172a;color:#e2e8f0;padding:12px;border-radius:8px;overflow:auto}}
.small{{font-size:12px;opacity:.9}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin-top:10px}}
.kpi{{background:white;border:1px solid #e5e7eb;border-radius:12px;padding:10px}}
.kpi .num{{font-size:26px;font-weight:800}}
.kpi .lbl{{font-size:12px;opacity:.8}}
th.sortable {{ background: #f5f5f5; }}
.table-card{{background:white;border:1px solid #e5e7eb;border-radius:12px;padding:12px;margin:14px 0;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
.table-head{{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:8px}}
.table-head h4{{margin:0;font-size:15px}}
.table-search{{padding:6px 10px;border:1px solid #d1d5db;border-radius:8px;min-width:220px}}
.data-table{{width:100%;border-collapse:collapse;font-size:13px}}
.data-table th,.data-table td{{border:1px solid #e5e7eb;padding:8px;text-align:left;vertical-align:top;word-break:break-word}}
.data-table th{{background:#f8fafc;cursor:pointer}}
.data-table tbody tr:nth-child(odd){{background:#ffffff}}
.data-table tbody tr:nth-child(even){{background:#f3f4f6}}
/* Also stripe generic tables (e.g., checksec tables) for readability */
table tbody tr:nth-child(odd){{background:#ffffff}}
table tbody tr:nth-child(even){{background:#f3f4f6}}

/* Dark Mode Toggle Button */
.dark-mode-toggle{{position:fixed;top:20px;right:20px;z-index:1000;background:rgba(255,255,255,0.9);backdrop-filter:blur(10px);border:1px solid rgba(0,0,0,0.1);border-radius:50px;padding:10px 20px;cursor:pointer;font-size:14px;font-weight:600;color:#333;transition:all 0.3s ease;box-shadow:0 4px 12px rgba(0,0,0,0.15);display:flex;align-items:center;gap:8px}}
.dark-mode-toggle:hover{{background:rgba(255,255,255,1);box-shadow:0 6px 16px rgba(0,0,0,0.2);transform:translateY(-2px)}}
.dark-mode-toggle:active{{transform:translateY(0)}}

/* Dark Mode Styles */
[data-theme="dark"] .dark-mode-toggle{{background:rgba(30,41,59,0.9);border:1px solid rgba(255,255,255,0.2);color:#e2e8f0}}
[data-theme="dark"] .dark-mode-toggle:hover{{background:rgba(30,41,59,1)}}
[data-theme="dark"] body{{background:#0f172a;color:#e2e8f0}}
[data-theme="dark"] h1{{color:#f1f5f9}}
[data-theme="dark"] h2{{color:#f1f5f9}}
[data-theme="dark"] .header{{background:linear-gradient(135deg,#312e81 0%,#581c87 100%)}}
[data-theme="dark"] details{{background:#1e293b;border-color:#334155;box-shadow:0 1px 3px rgba(0,0,0,0.3)}}
[data-theme="dark"] summary{{color:#e2e8f0}}
[data-theme="dark"] summary:hover{{background:#293548}}
[data-theme="dark"] .check-name{{color:#cbd5e1}}
[data-theme="dark"] .pass .badge{{background:#065f46;color:#d1fae5}}
[data-theme="dark"] .fail .badge{{background:#991b1b;color:#fee2e2}}
[data-theme="dark"] .warn .badge{{background:#92400e;color:#fef3c7}}
[data-theme="dark"] .info .badge{{background:#1e40af;color:#dbeafe}}
[data-theme="dark"] .content{{border-top-color:#334155;background:#0f172a;color:#e2e8f0}}
[data-theme="dark"] pre{{background:#1e293b;color:#e2e8f0;border:1px solid #334155}}
[data-theme="dark"] code{{background:#1e293b;color:#e2e8f0}}
[data-theme="dark"] .kpi{{background:#1e293b;border-color:#334155}}
[data-theme="dark"] th.sortable {{ background: #293548; color: #e2e8f0; }}
[data-theme="dark"] a{{color:#60a5fa}}
[data-theme="dark"] a:hover{{color:#93c5fd}}
[data-theme="dark"] strong{{color:#f1f5f9}}
[data-theme="dark"] .table-card{{background:#1e293b;border-color:#334155}}
[data-theme="dark"] .data-table th{{background:#1f2937;color:#e2e8f0;border-color:#334155}}
[data-theme="dark"] .data-table td{{border-color:#334155;color:#e2e8f0}}
[data-theme="dark"] .data-table tbody tr:nth-child(odd){{background:#111827}}
[data-theme="dark"] .data-table tbody tr:nth-child(even){{background:#1b2436}}
[data-theme="dark"] table tbody tr:nth-child(odd){{background:#111827}}
[data-theme="dark"] table tbody tr:nth-child(even){{background:#1b2436}}
[data-theme="dark"] .table-search{{background:#0f172a;color:#e2e8f0;border-color:#334155}}
</style>
<script>
function toggleDarkMode(){{const html=document.documentElement;const currentTheme=html.getAttribute('data-theme');const newTheme=currentTheme==='dark'?'light':'dark';html.setAttribute('data-theme',newTheme);localStorage.setItem('theme',newTheme);updateDarkModeButton(newTheme)}}
function updateDarkModeButton(theme){{const button=document.getElementById('darkModeToggle');if(button){{button.textContent=theme==='dark'?'Light Mode':'Dark Mode'}}}} 
function initDarkMode(){{const savedTheme=localStorage.getItem('theme');const prefersDark=window.matchMedia('(prefers-color-scheme: dark)').matches;const theme=savedTheme||(prefersDark?'dark':'light');document.documentElement.setAttribute('data-theme',theme);updateDarkModeButton(theme)}}
document.addEventListener('DOMContentLoaded',initDarkMode);
function sortTable(tableId,colIndex){{const table=document.getElementById(tableId);if(!table||!table.tBodies.length)return;const tbody=table.tBodies[0];const rows=Array.from(tbody.rows);const currentOrder=table.getAttribute('data-sort-order-'+colIndex)||'asc';const newOrder=currentOrder==='asc'?'desc':'asc';rows.sort((a,b)=>{{const aVal=a.cells[colIndex].innerText.trim();const bVal=b.cells[colIndex].innerText.trim();return newOrder==='asc'?aVal.localeCompare(bVal):bVal.localeCompare(aVal);}});rows.forEach(r=>tbody.appendChild(r));table.setAttribute('data-sort-order-'+colIndex,newOrder);const headers=table.querySelectorAll('th .chevron');headers.forEach((h,i)=>{{if(i===colIndex){{h.textContent=newOrder==='asc'?'▲':'▼';}} else if(h){{h.textContent='▼';}}}});}}
function applyFilters(tableId){{const table=document.getElementById(tableId);if(!table||!table.tBodies.length)return;const selects=document.querySelectorAll('.filter-select-'+tableId);Array.from(table.tBodies[0].rows).forEach(row=>{{let show=true;selects.forEach((sel,idx)=>{{const val=sel.value;if(val&&row.cells[idx]&&row.cells[idx].innerText.trim()!==val){{show=false;}}}});row.style.display=show?'':'none';}});}}
function filterTable(tableId,query){{const table=document.getElementById(tableId);if(!table||!table.tBodies.length)return;const q=(query||'').toLowerCase();Array.from(table.tBodies[0].rows).forEach(row=>{{const text=row.innerText.toLowerCase();row.style.display=text.indexOf(q)!==-1?'':'none';}});}}
</script>
</head>
<body>
<button id="darkModeToggle" class="dark-mode-toggle" onclick="toggleDarkMode()">Dark Mode</button>
<div class="header">
  <h1>iOS Mobile Security Assessment Report</h1>
  <div class="meta">
    <div class="card"><div class="small">App</div><div><code>{app_name}</code></div></div>
    <div class="card"><div class="small">Bundle ID</div><div><code>{bundle_id}</code></div></div>
    <div class="card"><div class="small">Version</div><div>{version}</div></div>
    <div class="card"><div class="small">IPA Size</div><div>{ipa_size} MB</div></div>
    <div class="card"><div class="small">IPA SHA256</div><div><code>{ipa_sha256}</code></div></div>
  </div>
{previous_scan_info}
  <div style="border-top: 1px solid rgba(255,255,255,0.3); padding-top: 15px; margin-top: 15px;">
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; font-size: 13px;">
      <div>
        <span style="opacity: 0.9;">Started:</span> <strong>{started}</strong>
      </div>
      <div>
        <span style="opacity: 0.9;">Finished:</span> <strong>{finished}</strong>
      </div>
    </div>
  </div>
</div>

<div class="grid">
  <div class="kpi"><div class="num">{kpi_fail}</div><div class="lbl">FAIL</div></div>
  <div class="kpi"><div class="num">{kpi_warn}</div><div class="lbl">WARN</div></div>
  <div class="kpi"><div class="num">{kpi_info}</div><div class="lbl">INFO</div></div>
  <div class="kpi"><div class="num">{kpi_pass}</div><div class="lbl">PASS</div></div>
</div>

{sections}

</body>
</html>
"""

# --------------------------- 
# IPA handling
# --------------------------- 

def unzip_ipa(ipa_path: str, out_dir: str) -> str:
    safe_mkdir(out_dir)
    rc, _ = run(["/usr/bin/unzip", "-q", ipa_path, "-d", out_dir], timeout=180)
    if rc != 0:
        shutil.unpack_archive(ipa_path, out_dir, "zip")
    return out_dir

def find_app_bundle(unzipped_dir: str) -> str:
    payload = os.path.join(unzipped_dir, "Payload")
    if not os.path.isdir(payload):
        raise RuntimeError("Payload directory not found (invalid IPA?)")
    apps = [os.path.join(payload, d) for d in os.listdir(payload) if d.endswith(".app")]
    if not apps:
        raise RuntimeError("No .app bundle found in Payload/")
    apps.sort(key=lambda p: dir_size(p), reverse=True)
    return apps[0]

def find_main_binary(app_dir: str, info: Dict) -> str:
    exe = info.get("CFBundleExecutable")
    if exe:
        p = os.path.join(app_dir, exe)
        if os.path.exists(p):
            return p
    # heuristic
    for f in os.listdir(app_dir):
        p = os.path.join(app_dir, f)
        if os.path.isfile(p) and is_macho(p):
            return p
    raise RuntimeError("Main Mach-O not found (CFBundleExecutable missing?)")

# --------------------------- 
# Checks (more MASVS-ish coverage)
# --------------------------- 

SENSITIVE_KEYWORDS = [
    "password","passwd","pwd","token","bearer","authorization","apikey","api_key","secret",
    "client_secret","access_token","refresh_token","private_key","BEGIN PRIVATE KEY",
    "aws_access_key_id","aws_secret_access_key","firebase","s3.amazonaws.com",
    "x-api-key","x_auth_token","sessionid","set-cookie"
]

WEAK_CRYPTO_PATTERNS = [
    r"\bMD5\b", r"CC_MD5", r"\bSHA1\b", r"CC_SHA1", r"\bDES\b", r"kCCAlgorithmDES",
    r"\bRC4\b", r"kCCAlgorithmRC4"
]

TLS_PINNING_INDICATORS = [
    r"SecTrustEvaluate", r"SecTrustEvaluateWithError", r"SecTrustSetAnchorCertificates",
    r"pinning", r"publicKeyHash", r"certificatePinner", r"trustkit", r"TrustKit",
    r"evaluateServerTrust", r"NSURLSession: didReceiveChallenge", r"didReceiveChallenge",
    r"Alamofire", r"AFSecurityPolicy"
]

ANTI_DEBUG_INDICATORS = [
    r"\bptrace\b", r"\bsysctl\b", r"KERN_PROC", r"P_TRACED", r"amfid", r"task_for_pid",
    r"csops", r"csops_audittoken"
]

JAILBREAK_ARTIFACTS = [
    "/Applications/Cydia.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/bin/bash",
    "/usr/sbin/sshd",
    "/etc/apt",
    "/private/var/lib/apt/",
    "/private/var/stash",
    "/var/jb",
    "substrate",
    "SubstrateLoader",
    "frida",
    "objection",
]

INSECURE_API_PATTERNS = [
    # Note: Logging and RNG are now covered by binary analysis tests (nm/jtool2)
    # These remaining patterns are for APIs that warrant review but aren't necessarily insecure
    ("NSUserDefaults usage", [r"\bNSUserDefaults\b"]),
    ("UIPasteboard usage", [r"\bUIPasteboard\b"]),
    ("WebView / JS bridge surface", [r"\bevaluateJavaScript\b", r"javaScriptEnabled", r"WKWebView", r"UIWebView",
                                    r"WKScriptMessageHandler", r"addScriptMessageHandler"]),
]

def check_info_plist(info: Dict, info_path: str, base: str) -> List[TestResult]:
    results: List[TestResult] = []
    rel_info_path = rel(info_path, base)

    # URL schemes
    url_types = info.get("CFBundleURLTypes", []) or []
    schemes: List[str] = []
    for ut in url_types:
        for s in (ut.get("CFBundleURLSchemes", []) or []):
            if s:
                schemes.append(str(s))
    
    findings = []
    if schemes:
        # Build evidence showing plist structure
        evidence_lines = ["CFBundleURLTypes:"]
        for idx, ut in enumerate(url_types):
            url_schemes = ut.get("CFBundleURLSchemes", []) or []
            if url_schemes:
                evidence_lines.append(f"  [{idx}]:")
                evidence_lines.append(f"    CFBundleURLSchemes:")
                for scheme in url_schemes:
                    evidence_lines.append(f"      - {scheme}")
                # Optionally show CFBundleURLName if present
                url_name = ut.get("CFBundleURLName")
                if url_name:
                    evidence_lines.append(f"    CFBundleURLName: {url_name}")

        findings.append(FindingBlock(
            title=rel_info_path,
            link=make_file_link(base, rel_info_path),
            evidence=evidence_lines
        ))

    results.append(TestResult(
        id="PLATFORM-URLSCHEMES",
        name="Custom URL Schemes",
        status="INFO" if schemes else "PASS",
        summary=[f"Found {len(schemes)} scheme(s): {', '.join(sorted(set(schemes)))}"] if schemes else
                ["No CFBundleURLTypes schemes found in Info.plist"],
        findings=findings,
        mastg_ref_html=mastg_ref(["MASTG-TEST-0069"], ["Testing Custom URL Schemes"])
    ))

    # Universal links (associated domains) come from entitlements; still note in plist if present
    # ATS
    ats = info.get("NSAppTransportSecurity")
    ats_findings = [FindingBlock(title=rel_info_path, link=make_file_link(base, rel_info_path))]
    if not ats:
        results.append(TestResult(
            id="NETWORK-ATS",
            name="App Transport Security (ATS)",
            status="WARN",
            summary=["NSAppTransportSecurity not present; verify ATS defaults and exceptions"],
            findings=ats_findings,
            mastg_ref_html=mastg_ref(["MASTG-TEST-0065"], ["Testing Data Encryption on the Network"])
        ))
    else:
        allows_arbitrary = bool(ats.get("NSAllowsArbitraryLoads", False))
        allows_media = bool(ats.get("NSAllowsArbitraryLoadsForMedia", False))
        allows_web = bool(ats.get("NSAllowsArbitraryLoadsInWebContent", False))
        exceptions = ats.get("NSExceptionDomains", {}) or {}
        lines = []
        if allows_arbitrary: lines.append("NSAllowsArbitraryLoads=true (global ATS bypass)")
        if allows_media: lines.append("NSAllowsArbitraryLoadsForMedia=true")
        if allows_web: lines.append("NSAllowsArbitraryLoadsInWebContent=true")
        if exceptions: lines.append(f"NSExceptionDomains: {', '.join(sorted(exceptions.keys()))[:240]}")
        if allows_arbitrary:
            st: Status = "FAIL"
        elif allows_media or allows_web or exceptions:
            st = "WARN"
        else:
            st = "PASS"
            lines.append("ATS present with no obvious broad exceptions")

        # Build evidence showing plist structure
        evidence_lines = ["NSAppTransportSecurity:"]
        if allows_arbitrary:
            evidence_lines.append(f"  NSAllowsArbitraryLoads: {allows_arbitrary}")
        if allows_media:
            evidence_lines.append(f"  NSAllowsArbitraryLoadsForMedia: {allows_media}")
        if allows_web:
            evidence_lines.append(f"  NSAllowsArbitraryLoadsInWebContent: {allows_web}")
        if exceptions:
            evidence_lines.append("  NSExceptionDomains:")
            for domain in sorted(exceptions.keys())[:20]:  # Limit to 20 domains
                evidence_lines.append(f"    - {domain}")
                domain_settings = exceptions[domain]
                if isinstance(domain_settings, dict):
                    for key, val in sorted(domain_settings.items())[:5]:  # Limit settings per domain
                        evidence_lines.append(f"        {key}: {val}")
            if len(exceptions) > 20:
                evidence_lines.append(f"    ... and {len(exceptions) - 20} more domain(s)")

        ats_findings = [FindingBlock(title=rel_info_path, link=make_file_link(base, rel_info_path), evidence=evidence_lines)]

        results.append(TestResult(
            id="NETWORK-ATS",
            name="App Transport Security (ATS)",
            status=st,
            summary=lines or ["ATS present"],
            findings=ats_findings,
            mastg_ref_html=mastg_ref(["MASTG-TEST-0065"], ["Testing Data Encryption on the Network"])
        ))

    # UIFileSharing
    ui_fs = bool(info.get("UIFileSharingEnabled", False))
    open_in_place = bool(info.get("LSSupportsOpeningDocumentsInPlace", False))
    if ui_fs or open_in_place:
        # Build evidence showing plist structure
        evidence_lines = []
        if ui_fs:
            evidence_lines.append(f"UIFileSharingEnabled: {ui_fs}")
        if open_in_place:
            evidence_lines.append(f"LSSupportsOpeningDocumentsInPlace: {open_in_place}")

        results.append(TestResult(
            id="STORAGE-FILESHARING",
            name="iTunes File Sharing / Document Sharing",
            status="WARN",
            summary=[
                f"UIFileSharingEnabled={ui_fs}",
                f"LSSupportsOpeningDocumentsInPlace={open_in_place}",
                "Review for unintended exposure of sensitive files via Finder/iTunes."
            ],
            findings=[FindingBlock(title=rel_info_path, link=make_file_link(base, rel_info_path), evidence=evidence_lines)],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0060"], ["Testing Local Storage for Sensitive Data"])
        ))
    else:
        results.append(TestResult(
            id="STORAGE-FILESHARING",
            name="iTunes File Sharing / Document Sharing",
            status="PASS",
            summary=["UIFileSharingEnabled not enabled and no 'open in place' support declared"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0060"], ["Testing Local Storage for Sensitive Data"])
        ))

    # Background modes (info)
    bg = info.get("UIBackgroundModes", []) or []
    if bg:
        # Build evidence showing plist structure
        evidence_lines = ["UIBackgroundModes:"]
        for mode in bg:
            evidence_lines.append(f"  - {mode}")

        results.append(TestResult(
            id="PLATFORM-BGMODES",
            name="Background Modes",
            status="INFO",
            summary=[f"Declared: {', '.join(map(str, bg))}"],
            findings=[FindingBlock(title=rel_info_path, link=make_file_link(base, rel_info_path), evidence=evidence_lines)],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0070"], ["Testing App Permissions"])
        ))
    else:
        results.append(TestResult(
            id="PLATFORM-BGMODES",
            name="Background Modes",
            status="PASS",
            summary=["No background modes declared"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0070"], ["Testing App Permissions"])
        ))

    # Query schemes
    qschemes = info.get("LSApplicationQueriesSchemes", []) or []
    if qschemes:
        # Build evidence showing plist structure
        evidence_lines = ["LSApplicationQueriesSchemes:"]
        for scheme in sorted(set(map(str, qschemes)))[:120]:
            evidence_lines.append(f"  - {scheme}")
        if len(qschemes) > 120:
            evidence_lines.append(f"  ... and {len(qschemes) - 120} more scheme(s)")

        results.append(TestResult(
            id="PRIVACY-APPQUERIES",
            name="LSApplicationQueriesSchemes (installed app probing)",
            status="INFO",
            summary=[f"Found {len(qschemes)} scheme(s) (review necessity)"],
            findings=[FindingBlock(title=rel_info_path, link=make_file_link(base, rel_info_path), evidence=evidence_lines)],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0070"], ["Testing App Permissions"])
        ))
    else:
        results.append(TestResult(
            id="PRIVACY-APPQUERIES",
            name="LSApplicationQueriesSchemes (installed app probing)",
            status="PASS",
            summary=["No LSApplicationQueriesSchemes declared"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0070"], ["Testing App Permissions"])
        ))

    # Minimum iOS Version Check
    min_ios_version = info.get("MinimumOSVersion") or info.get("LSMinimumSystemVersion")
    if min_ios_version:
        # Parse version string (e.g., "17.0", "18.0", "16.4")
        try:
            version_parts = str(min_ios_version).split('.')
            major_version = int(version_parts[0])
            minor_version = int(version_parts[1]) if len(version_parts) > 1 else 0

            version_float = float(f"{major_version}.{minor_version}")
            target_version = 18.0

            # Build evidence showing plist structure
            evidence_lines = []
            if info.get("MinimumOSVersion"):
                evidence_lines.append(f"MinimumOSVersion: {min_ios_version}")
            if info.get("LSMinimumSystemVersion"):
                evidence_lines.append(f"LSMinimumSystemVersion: {min_ios_version}")

            if version_float < target_version:
                status = "FAIL"
                summary = [
                    f"App targets iOS {min_ios_version} (below recommended minimum of iOS {int(target_version)})",
                ]
                evidence_lines.append("")
                evidence_lines.append(f"⚠ Current: iOS {min_ios_version}")
                evidence_lines.append(f"✓ Recommended: iOS {int(target_version)}.0+")
            else:
                status = "PASS"
                summary = [f"App targets iOS {min_ios_version} (meets recommended minimum)"]
                evidence_lines.append(f"✓ Meets recommended minimum of iOS {int(target_version)}.0+")

            results.append(TestResult(
                id="PLATFORM-MINIOS",
                name="Minimum iOS Version",
                status=status,
                summary=summary,
                findings=[FindingBlock(
                    title=rel_info_path,
                    link=make_file_link(base, rel_info_path),
                    evidence=evidence_lines
                )],
                mastg_ref_html=mastg_ref(["MASTG-TEST-0104"], ["Testing the App Update Mechanism"])
            ))
        except (ValueError, IndexError):
            # Invalid version format
            results.append(TestResult(
                id="PLATFORM-MINIOS",
                name="Minimum iOS Version",
                status="WARN",
                summary=[f"Could not parse MinimumOSVersion: {min_ios_version}"],
                findings=[FindingBlock(
                    title=rel_info_path,
                    link=make_file_link(base, rel_info_path),
                    evidence=[f"MinimumOSVersion: {min_ios_version}", "Unable to parse version format"]
                )],
                mastg_ref_html=mastg_ref(["MASTG-TEST-0104"], ["Testing the App Update Mechanism"])
            ))
    else:
        # No minimum version specified
        results.append(TestResult(
            id="PLATFORM-MINIOS",
            name="Minimum iOS Version",
            status="WARN",
            summary=["MinimumOSVersion not found in Info.plist", "App may run on outdated iOS versions with security vulnerabilities"],
            findings=[FindingBlock(
                title=rel_info_path,
                link=make_file_link(base, rel_info_path),
                evidence=["MinimumOSVersion: Not specified", "LSMinimumSystemVersion: Not specified"]
            )],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0104"], ["Testing the App Update Mechanism"])
        ))

    # Privacy Permission Descriptions (NSUsageDescription keys)
    # All permission keys that iOS requires usage descriptions for
    PRIVACY_KEYS = {
        "NSCameraUsageDescription": "Camera",
        "NSPhotoLibraryUsageDescription": "Photo Library (Read)",
        "NSPhotoLibraryAddUsageDescription": "Photo Library (Write)",
        "NSLocationWhenInUseUsageDescription": "Location (When In Use)",
        "NSLocationAlwaysUsageDescription": "Location (Always)",
        "NSLocationAlwaysAndWhenInUseUsageDescription": "Location (Always and When In Use)",
        "NSMicrophoneUsageDescription": "Microphone",
        "NSContactsUsageDescription": "Contacts",
        "NSCalendarsUsageDescription": "Calendars",
        "NSRemindersUsageDescription": "Reminders",
        "NSMotionUsageDescription": "Motion & Fitness",
        "NSHealthShareUsageDescription": "Health (Read)",
        "NSHealthUpdateUsageDescription": "Health (Write)",
        "NSBluetoothAlwaysUsageDescription": "Bluetooth",
        "NSBluetoothPeripheralUsageDescription": "Bluetooth Peripheral",
        "NSAppleMusicUsageDescription": "Apple Music",
        "NSSpeechRecognitionUsageDescription": "Speech Recognition",
        "NSSiriUsageDescription": "Siri",
        "NSFaceIDUsageDescription": "Face ID",
        "NSHomeKitUsageDescription": "HomeKit",
        "NSNFCReaderUsageDescription": "NFC",
        "NSVideoSubscriberAccountUsageDescription": "TV Provider",
        "NSLocalNetworkUsageDescription": "Local Network",
        "NSUserTrackingUsageDescription": "Tracking (ATT)",
        "NSIdentityUsageDescription": "Identity",
        "NSMediaLibraryUsageDescription": "Media Library",
        "NSAppleEventsUsageDescription": "AppleEvents",
        "NSSystemExtensionUsageDescription": "System Extension",
        "NSFileProviderDomainUsageDescription": "File Provider",
        "NSDesktopFolderUsageDescription": "Desktop Folder",
        "NSDocumentsFolderUsageDescription": "Documents Folder",
        "NSDownloadsFolderUsageDescription": "Downloads Folder",
        "NSNetworkVolumesUsageDescription": "Network Volumes",
        "NSRemovableVolumesUsageDescription": "Removable Volumes",
    }

    found_permissions = []
    missing_descriptions = []
    weak_descriptions = []

    # Weak/generic descriptions that should be flagged
    WEAK_PATTERNS = [
        "this app needs", "we need", "required", "necessary",
        "app needs access", "needs permission", "for functionality"
    ]

    for key, permission_name in PRIVACY_KEYS.items():
        if key in info:
            description = str(info[key]).strip()
            found_permissions.append((key, permission_name, description))

            # Check for weak/generic descriptions
            if len(description) < 20 or any(weak.lower() in description.lower() for weak in WEAK_PATTERNS):
                weak_descriptions.append((permission_name, description))

    privacy_findings = []

    if found_permissions:
        # Build evidence for found permissions
        evidence_lines = ["Privacy Permissions Requested:"]
        evidence_lines.append("")

        for key, perm_name, desc in found_permissions:
            evidence_lines.append(f"{perm_name}:")
            evidence_lines.append(f"  Key: {key}")
            evidence_lines.append(f"  Description: \"{desc}\"")
            if any(perm_name == wp[0] for wp in weak_descriptions):
                evidence_lines.append("  ⚠ WARNING: Description may be too generic or weak")
            evidence_lines.append("")

        privacy_findings.append(FindingBlock(
            title=rel_info_path,
            link=make_file_link(base, rel_info_path),
            evidence=evidence_lines
        ))

        if weak_descriptions:
            weak_evidence = ["Permissions with weak/generic descriptions:"]
            weak_evidence.append("")
            for perm_name, desc in weak_descriptions:
                weak_evidence.append(f"• {perm_name}:")
                weak_evidence.append(f"  \"{desc}\"")
                weak_evidence.append("")
            weak_evidence.append("Best Practice: Descriptions should:")
            weak_evidence.append("• Clearly explain WHY the permission is needed")
            weak_evidence.append("• Be specific to the feature requiring it")
            weak_evidence.append("• Be user-friendly and transparent")
            weak_evidence.append("• Avoid generic phrases like 'this app needs' or 'required'")

            privacy_findings.append(FindingBlock(
                title="Weak Permission Descriptions Detected",
                evidence=weak_evidence,
                open_by_default=True
            ))

        status = "WARN" if weak_descriptions else "INFO"
        summary = [
            f"Found {len(found_permissions)} privacy permission(s) declared",
        ]
        if weak_descriptions:
            summary.append(f"⚠ {len(weak_descriptions)} permission(s) have weak/generic descriptions")
        else:
            summary.append("✓ All descriptions appear reasonably detailed")

        results.append(TestResult(
            id="PRIVACY-PERMISSIONS",
            name="Privacy Permission Descriptions",
            status=status,
            summary=summary,
            findings=privacy_findings,
            mastg_ref_html=mastg_ref(["MASTG-TEST-0070"], ["Testing App Permissions"])
        ))
    else:
        # No privacy permissions requested
        results.append(TestResult(
            id="PRIVACY-PERMISSIONS",
            name="Privacy Permission Descriptions",
            status="PASS",
            summary=["No privacy-sensitive permissions requested in Info.plist"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0070"], ["Testing App Permissions"])
        ))

    return results

def check_codesign_details(main_bin: str) -> TestResult:
    rc, out = run(["/usr/bin/codesign", "-dvv", main_bin], timeout=30)
    if rc != 0:
        return TestResult(
            id="RESILIENCE-CODESIGN",
            name="Code Signing Details",
            status="WARN",
            summary=["Unable to read codesign details"],
            findings=[Finding(title="codesign -dvv output", evidence=out.splitlines()[:120])],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0229"], ["Verifying that the App is Properly Signed"])
        )
    lines = out.splitlines()

    # Parse key signing information
    identifier = None
    team_id = None
    authorities = []
    sealed_resources = None
    runtime_version = None
    signature_flags = None

    for l in lines:
        if "Identifier=" in l:
            identifier = l.split("=", 1)[1].strip() if "=" in l else None
        elif "TeamIdentifier=" in l or (l.startswith("TeamIdentifier") and "=" in l):
            team_id = l.split("=", 1)[1].strip() if "=" in l else None
        elif "Authority=" in l:
            authority = l.split("=", 1)[1].strip() if "=" in l else None
            if authority:
                authorities.append(authority)
        elif "Sealed Resources" in l:
            sealed_resources = l.strip()
        elif "Runtime Version" in l or "runtime" in l.lower():
            runtime_version = l.strip()
        elif "Signature size=" in l or "flags=" in l:
            signature_flags = l.strip()

    # Build summary
    summary_lines = []
    status: Status = "INFO"

    if identifier:
        summary_lines.append(f"Bundle ID: {identifier}")

    if team_id:
        summary_lines.append(f"Team ID: {team_id}")
    else:
        summary_lines.append("Team ID: Not found (ad-hoc signed?)")
        status = "WARN"

    if authorities:
        summary_lines.append(f"Signed by: {authorities[0]}")
        if "iPhone Distribution" in authorities[0]:
            summary_lines.append("Certificate Type: App Store/Ad Hoc Distribution")
        elif "iPhone Developer" in authorities[0] or "Apple Development" in authorities[0]:
            summary_lines.append("Certificate Type: Development (should not be in production)")
            if status == "INFO":
                status = "WARN"
        elif "Apple Distribution" in authorities[0]:
            summary_lines.append("Certificate Type: Distribution")
    else:
        summary_lines.append("Certificate: Not found or ad-hoc signed")
        status = "WARN"

    # Build evidence
    evidence_lines = []
    if identifier:
        evidence_lines.append(f"Identifier: {identifier}")
    if team_id:
        evidence_lines.append(f"TeamIdentifier: {team_id}")

    if authorities:
        evidence_lines.append("")
        evidence_lines.append("Certificate Chain:")
        for i, auth in enumerate(authorities):
            evidence_lines.append(f"  [{i}] {auth}")

    findings = []
    if evidence_lines:
        findings.append(Finding(title="Code Signing Details", evidence=evidence_lines))

    return TestResult(
        id="RESILIENCE-CODESIGN",
        name="Code Signing Details",
        status=status,
        summary=summary_lines,
        findings=findings,
        mastg_ref_html=mastg_ref(["MASTG-TEST-0229"], ["Verifying that the App is Properly Signed"])
    )

def check_provisioning_profile(app_dir: str, base: str) -> TestResult:
    """
    Parse and analyze embedded.mobileprovision file.

    MASTG References:
    - MASTG-TEST-0229: Verifying that the App is Properly Signed
    - MASTG-TEST-0230: Make Sure the App is Properly Signed
    """
    from datetime import datetime

    profile_path = os.path.join(app_dir, "embedded.mobileprovision")

    if not os.path.exists(profile_path):
        return TestResult(
            id="CODESIGN-PROFILE",
            name="Provisioning Profile Analysis",
            status="INFO",
            summary=["No embedded.mobileprovision found (may be App Store build or enterprise distribution)"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0229", "MASTG-TEST-0230"],
                                     ["Verifying that the App is Properly Signed"])
        )

    # Decode provisioning profile using security cms
    rc, plist_xml = run(["/usr/bin/security", "cms", "-D", "-i", profile_path], timeout=30)

    if rc != 0 or not plist_xml.strip():
        return TestResult(
            id="CODESIGN-PROFILE",
            name="Provisioning Profile Analysis",
            status="WARN",
            summary=["Failed to decode embedded.mobileprovision"],
            findings=[FindingBlock(
                title=rel(profile_path, base),
                link=make_file_link(base, rel(profile_path, base)),
                evidence=["Unable to decode provisioning profile with 'security cms -D'"]
            )],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0229", "MASTG-TEST-0230"],
                                     ["Verifying that the App is Properly Signed"])
        )

    # Parse the plist
    try:
        profile_data = plistlib.loads(plist_xml.encode("utf-8"))
    except Exception as e:
        return TestResult(
            id="CODESIGN-PROFILE",
            name="Provisioning Profile Analysis",
            status="WARN",
            summary=[f"Failed to parse provisioning profile: {str(e)}"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0229", "MASTG-TEST-0230"],
                                     ["Verifying that the App is Properly Signed"])
        )

    # Extract key information
    profile_name = profile_data.get("Name", "Unknown")
    creation_date = profile_data.get("CreationDate")
    expiration_date = profile_data.get("ExpirationDate")
    team_name = profile_data.get("TeamName", "Unknown")
    team_ids = profile_data.get("TeamIdentifier", [])
    app_id_name = profile_data.get("AppIDName", "Unknown")
    platform = profile_data.get("Platform", [])
    provisioned_devices = profile_data.get("ProvisionedDevices", [])
    entitlements = profile_data.get("Entitlements", {})

    # Determine profile type
    profile_type = "Unknown"
    if provisioned_devices:
        if len(provisioned_devices) == 1:
            profile_type = "Development (1 device)"
        else:
            profile_type = f"Ad Hoc or Development ({len(provisioned_devices)} devices)"
    else:
        # No devices = App Store or Enterprise
        if entitlements.get("get-task-allow"):
            profile_type = "Development (Xcode managed)"
        else:
            profile_type = "App Store or Enterprise Distribution"

    # Check expiration
    status: Status = "INFO"
    is_expired = False
    days_until_expiry = None

    if expiration_date:
        now = datetime.now(expiration_date.tzinfo) if expiration_date.tzinfo else datetime.now()
        if now > expiration_date:
            is_expired = True
            status = "FAIL"
        else:
            days_until_expiry = (expiration_date - now).days
            if days_until_expiry < 30:
                status = "WARN"

    # Build summary
    summary_lines = [
        f"Profile: {profile_name}",
        f"Type: {profile_type}",
    ]

    if team_name and team_name != "Unknown":
        summary_lines.append(f"Team: {team_name}")

    if team_ids:
        summary_lines.append(f"Team ID: {', '.join(team_ids)}")

    if is_expired:
        summary_lines.append(f"❌ EXPIRED: {expiration_date.strftime('%Y-%m-%d')}")
    elif days_until_expiry is not None:
        if days_until_expiry < 30:
            summary_lines.append(f"⚠ Expires in {days_until_expiry} days: {expiration_date.strftime('%Y-%m-%d')}")
        else:
            summary_lines.append(f"✓ Valid until: {expiration_date.strftime('%Y-%m-%d')} ({days_until_expiry} days)")

    # Build evidence
    evidence_lines = [
        f"Profile Name: {profile_name}",
        f"Type: {profile_type}",
        f"App ID Name: {app_id_name}",
        ""
    ]

    if team_name and team_name != "Unknown":
        evidence_lines.append(f"Team Name: {team_name}")

    if team_ids:
        evidence_lines.append(f"Team Identifier(s): {', '.join(team_ids)}")

    if platform:
        evidence_lines.append(f"Platform: {', '.join(platform)}")

    evidence_lines.append("")

    if creation_date:
        evidence_lines.append(f"Created: {creation_date.strftime('%Y-%m-%d %H:%M:%S')}")

    if expiration_date:
        if is_expired:
            evidence_lines.append(f"❌ EXPIRED: {expiration_date.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            evidence_lines.append(f"Expires: {expiration_date.strftime('%Y-%m-%d %H:%M:%S')} ({days_until_expiry} days remaining)")

    evidence_lines.append("")

    # Provisioned devices
    if provisioned_devices:
        evidence_lines.append(f"Provisioned Devices: {len(provisioned_devices)}")
        if len(provisioned_devices) <= 10:
            for i, device_udid in enumerate(provisioned_devices, 1):
                evidence_lines.append(f"  [{i}] {device_udid}")
        else:
            for i, device_udid in enumerate(provisioned_devices[:5], 1):
                evidence_lines.append(f"  [{i}] {device_udid}")
            evidence_lines.append(f"  ... and {len(provisioned_devices) - 5} more device(s)")

        evidence_lines.append("")
        evidence_lines.append("⚠ WARNING: Provisioned devices indicate this is NOT an App Store build")
        evidence_lines.append("  • Development/Ad Hoc profiles should not be used in production")
        evidence_lines.append("  • Device UDIDs may be considered sensitive information")
    else:
        evidence_lines.append("Provisioned Devices: None")
        evidence_lines.append("✓ This appears to be an App Store or Enterprise distribution profile")

    evidence_lines.append("")

    # Key entitlements from profile
    if entitlements:
        evidence_lines.append("Key Entitlements from Profile:")

        # Check for development entitlements
        get_task_allow = entitlements.get("get-task-allow", False)
        if get_task_allow:
            evidence_lines.append("  • get-task-allow: true ⚠ (allows debugging - should be false in production)")

        app_id = entitlements.get("application-identifier", "")
        if app_id:
            evidence_lines.append(f"  • application-identifier: {app_id}")

        team_id_ent = entitlements.get("com.apple.developer.team-identifier", "")
        if team_id_ent:
            evidence_lines.append(f"  • team-identifier: {team_id_ent}")

        aps_env = entitlements.get("aps-environment")
        if aps_env:
            evidence_lines.append(f"  • aps-environment: {aps_env}")

    # Findings
    findings = [
        FindingBlock(
            title=rel(profile_path, base),
            link=make_file_link(base, rel(profile_path, base)),
            evidence=evidence_lines,
            open_by_default=True
        )
    ]

    return TestResult(
        id="CODESIGN-PROFILE",
        name="Provisioning Profile Analysis",
        status=status,
        summary=summary_lines,
        findings=findings,
        mastg_ref_html=mastg_ref(["MASTG-TEST-0229", "MASTG-TEST-0230"],
                                 ["Verifying that the App is Properly Signed"])
    )

def check_entitlements(main_bin: str) -> TestResult:
    rc, out = run(["/usr/bin/codesign", "-d", "--entitlements", ":-", main_bin], timeout=30)
    if rc != 0:
        return TestResult(
            id="PLATFORM-ENTITLEMENTS",
            name="Entitlements Review",
            status="WARN",
            summary=["Unable to extract entitlements via codesign"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0070"], ["Testing App Permissions"])
        )
    # isolate XML if needed
    m = re.search(r"(<?xml.*</plist>)", out, flags=re.DOTALL)
    xml = m.group(1) if m else out
    try:
        ent = plistlib.loads(xml.encode("utf-8"))
    except Exception:
        ent = {}

    findings: List[Finding] = []
    summary: List[str] = []
    status: Status = "PASS"

    def add_kv(key: str):
        if key in ent:
            value = ent.get(key)
            evidence_lines = [f"{key}:"]

            # Format the value based on type
            if isinstance(value, list):
                for item in value[:100]:  # Limit to 100 items
                    evidence_lines.append(f"  - {item}")
                if len(value) > 100:
                    evidence_lines.append(f"  ... and {len(value) - 100} more item(s)")
            elif isinstance(value, dict):
                for k, v in list(value.items())[:50]:  # Limit to 50 items
                    evidence_lines.append(f"  {k}: {v}")
                if len(value) > 50:
                    evidence_lines.append(f"  ... and {len(value) - 50} more item(s)")
            elif isinstance(value, bool):
                evidence_lines.append(f"  {value}")
            else:
                evidence_lines.append(f"  {str(value)[:4000]}")

            findings.append(Finding(title=key, evidence=evidence_lines))

    # get-task-allow
    gta = ent.get("get-task-allow")
    if gta is True:
        status = "FAIL"
        summary.append("get-task-allow=true (debuggable/attachable build)")
        add_kv("get-task-allow")
    else:
        summary.append("get-task-allow is not true")

    # keychain groups (info)
    if "keychain-access-groups" in ent:
        summary.append(f"keychain-access-groups count: {len(ent.get('keychain-access-groups') or [])}")
        add_kv("keychain-access-groups")

    # associated domains (universal links)
    if "com.apple.developer.associated-domains" in ent:
        summary.append("Associated domains present (universal links / applinks)")
        add_kv("com.apple.developer.associated-domains")

    # iCloud
    for k in ["com.apple.developer.icloud-services",
              "com.apple.developer.icloud-container-identifiers",
              "com.apple.developer.ubiquity-container-identifiers"]:
        if k in ent:
            summary.append("iCloud entitlement present (review data sync scope)")
            add_kv(k)

    # App Groups
    if "com.apple.security.application-groups" in ent:
        summary.append("App Groups entitlement present (shared container; review stored data + ACLs)")
        add_kv("com.apple.security.application-groups")

    # aps
    if "aps-environment" in ent:
        summary.append(f"aps-environment: {ent.get('aps-environment')}")
        add_kv("aps-environment")

    if not findings and status == "PASS":
        return TestResult(
            id="PLATFORM-ENTITLEMENTS",
            name="Entitlements Review",
            status="PASS",
            summary=["No high-risk entitlements detected in static triage"],
            findings=[FindingBlock(title=os.path.basename(main_bin), link=make_file_link(os.path.dirname(main_bin), os.path.basename(main_bin)))],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0070"], ["Testing App Permissions"])
        )

    return TestResult(
        id="PLATFORM-ENTITLEMENTS",
        name="Entitlements Review",
        status="INFO" if status == "PASS" else status,
        summary=summary,
        findings=findings,
        mastg_ref_html=mastg_ref(["MASTG-TEST-0070"], ["Testing App Permissions"])
    )

def check_privacy_manifest(app_dir: str, base: str) -> TestResult:
    """
    Check for Privacy Manifest files (PrivacyInfo.xcprivacy) required by iOS 17+.

    Apple requires privacy manifests for apps using certain "required reason" APIs:
    - File timestamp APIs
    - System boot time APIs
    - Disk space APIs
    - Active keyboard APIs
    - User defaults APIs

    MASTG References:
    - MASTG-TEST-0074: Testing App Permissions
    - MASTG-TEST-0070: Testing App Permissions
    """

    # Search for PrivacyInfo.xcprivacy files in app bundle and frameworks
    privacy_manifests = []

    # Check main app bundle
    main_manifest = os.path.join(app_dir, "PrivacyInfo.xcprivacy")
    if os.path.exists(main_manifest):
        privacy_manifests.append(("App Bundle", main_manifest))

    # Check Frameworks directory
    frameworks_dir = os.path.join(app_dir, "Frameworks")
    if os.path.exists(frameworks_dir):
        for item in os.listdir(frameworks_dir):
            item_path = os.path.join(frameworks_dir, item)
            if os.path.isdir(item_path):
                framework_manifest = os.path.join(item_path, "PrivacyInfo.xcprivacy")
                if os.path.exists(framework_manifest):
                    privacy_manifests.append((item, framework_manifest))

    findings = []

    if not privacy_manifests:
        return TestResult(
            id="PRIVACY-MANIFEST",
            name="Privacy Manifest (iOS 17+)",
            status="INFO",
            summary=[
                "No PrivacyInfo.xcprivacy files found",
                "Required if app uses certain APIs (file timestamps, system boot time, disk space, etc.)",
                "See: https://developer.apple.com/documentation/bundleresources/privacy_manifest_files"
            ],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0074", "MASTG-TEST-0070"],
                                     ["Testing App Permissions"])
        )

    # Parse each manifest
    for location, manifest_path in privacy_manifests:
        try:
            with open(manifest_path, 'rb') as f:
                manifest_data = plistlib.load(f)

            evidence_lines = [f"Privacy Manifest Location: {location}"]
            evidence_lines.append("")

            # NSPrivacyTracking
            privacy_tracking = manifest_data.get("NSPrivacyTracking", False)
            evidence_lines.append(f"NSPrivacyTracking: {privacy_tracking}")
            if privacy_tracking:
                evidence_lines.append("  ⚠ App declares that it tracks users")

            # NSPrivacyTrackingDomains
            tracking_domains = manifest_data.get("NSPrivacyTrackingDomains", [])
            if tracking_domains:
                evidence_lines.append(f"NSPrivacyTrackingDomains: {len(tracking_domains)} domain(s)")
                for domain in tracking_domains[:10]:
                    evidence_lines.append(f"  • {domain}")
                if len(tracking_domains) > 10:
                    evidence_lines.append(f"  ... and {len(tracking_domains) - 10} more")
            else:
                evidence_lines.append("NSPrivacyTrackingDomains: None")

            evidence_lines.append("")

            # NSPrivacyCollectedDataTypes
            collected_data = manifest_data.get("NSPrivacyCollectedDataTypes", [])
            if collected_data:
                evidence_lines.append(f"NSPrivacyCollectedDataTypes: {len(collected_data)} type(s)")
                for data_type in collected_data:
                    type_identifier = data_type.get("NSPrivacyCollectedDataType", "Unknown")
                    linked = data_type.get("NSPrivacyCollectedDataTypeLinked", False)
                    tracking = data_type.get("NSPrivacyCollectedDataTypeTracking", False)
                    purposes = data_type.get("NSPrivacyCollectedDataTypePurposes", [])

                    evidence_lines.append(f"  • {type_identifier}")
                    evidence_lines.append(f"    Linked to user: {linked}")
                    evidence_lines.append(f"    Used for tracking: {tracking}")
                    if purposes:
                        evidence_lines.append(f"    Purposes: {', '.join(purposes)}")
            else:
                evidence_lines.append("NSPrivacyCollectedDataTypes: None declared")

            evidence_lines.append("")

            # NSPrivacyAccessedAPITypes (Required Reason APIs)
            accessed_apis = manifest_data.get("NSPrivacyAccessedAPITypes", [])
            if accessed_apis:
                evidence_lines.append(f"NSPrivacyAccessedAPITypes: {len(accessed_apis)} API category(ies)")
                evidence_lines.append("")
                evidence_lines.append("Required Reason APIs declared:")

                for api in accessed_apis:
                    api_type = api.get("NSPrivacyAccessedAPIType", "Unknown")
                    reasons = api.get("NSPrivacyAccessedAPITypeReasons", [])

                    # Decode API type
                    api_name = {
                        "NSPrivacyAccessedAPICategoryFileTimestamp": "File Timestamp APIs",
                        "NSPrivacyAccessedAPICategorySystemBootTime": "System Boot Time APIs",
                        "NSPrivacyAccessedAPICategoryDiskSpace": "Disk Space APIs",
                        "NSPrivacyAccessedAPICategoryActiveKeyboards": "Active Keyboards APIs",
                        "NSPrivacyAccessedAPICategoryUserDefaults": "User Defaults APIs"
                    }.get(api_type, api_type)

                    evidence_lines.append(f"  • {api_name}")
                    if reasons:
                        evidence_lines.append(f"    Reason codes: {', '.join(reasons)}")
                    else:
                        evidence_lines.append("    ⚠ No reason codes provided!")
                    evidence_lines.append("")
            else:
                evidence_lines.append("NSPrivacyAccessedAPITypes: None declared")
                evidence_lines.append("⚠ If app uses required reason APIs, they must be declared")

            findings.append(FindingBlock(
                title=rel(manifest_path, base),
                link=make_file_link(base, rel(manifest_path, base)),
                evidence=evidence_lines,
                open_by_default=True
            ))

        except Exception as e:
            findings.append(FindingBlock(
                title=f"Error parsing {location} manifest",
                evidence=[f"Path: {rel(manifest_path, base)}", f"Error: {str(e)}"]
            ))

    summary = [
        f"Found {len(privacy_manifests)} Privacy Manifest file(s)",
        "✓ Privacy manifests help comply with iOS 17+ privacy requirements"
    ]

    return TestResult(
        id="PRIVACY-MANIFEST",
        name="Privacy Manifest (iOS 17+)",
        status="INFO",
        summary=summary,
        findings=findings,
        mastg_ref_html=mastg_ref(["MASTG-TEST-0074", "MASTG-TEST-0070"],
                                 ["Testing App Permissions"])
    )

def check_macho_hardening(main_bin: str) -> TestResult:
    """
    Binary analysis for Mach-O header, encryption status, and hardened runtime.
    Note: PIE, stack canaries, and ARC are checked separately in checksec test.

    MASTG References:
    - MASTG-TEST-0087: Make Sure That Free Security Features Are Activated
    - MASTG-TEST-0229: Verifying that the App is Properly Signed
    """
    summary_lines: List[str] = []
    findings: List[FindingBlock] = []
    status: Status = "PASS"

    # 1. Get Mach-O header output
    rc, hv_output = run(["/usr/bin/otool", "-hv", main_bin], timeout=30)

    # 2. Check Binary Encryption (cryptid)
    rc3, lc_output = run(["/usr/bin/otool", "-l", main_bin], timeout=60)
    cryptid = None
    encrypted = False

    if rc3 == 0:
        m = re.search(r"LC_ENCRYPTION_INFO_64.*?cryptid\s+(\d+)", lc_output, flags=re.DOTALL)
        if not m:
            m = re.search(r"LC_ENCRYPTION_INFO.*?cryptid\s+(\d+)", lc_output, flags=re.DOTALL)
        if m:
            cryptid = m.group(1)
            encrypted = (cryptid == "1")

    if cryptid is not None:
        if encrypted:
            summary_lines.append(f"✓ Binary Encryption: Enabled (cryptid={cryptid})")
        else:
            if status == "PASS":
                status = "WARN"
            summary_lines.append(f"⚠ Binary Encryption: Disabled (cryptid={cryptid}) - App Store binaries should be encrypted")
    else:
        summary_lines.append("? Binary Encryption: Unable to determine (no LC_ENCRYPTION_INFO)")

    # 3. Check Hardened Runtime
    rc4, codesign_output = run(["/usr/bin/codesign", "-dvv", main_bin], timeout=30)
    runtime_hardened = False
    if rc4 == 0:
        # Check for Hardened Runtime flags
        if "runtime" in codesign_output.lower():
            runtime_hardened = True
            summary_lines.append("✓ Hardened Runtime: Enabled")
        else:
            summary_lines.append("⚠ Hardened Runtime: Not detected (check codesign flags)")

    # Build detailed findings with otool output
    if rc == 0 and hv_output:
        findings.append(FindingBlock(
            title="otool -hv output (Mach-O header)",
            subtitle="Binary format and protection flags",
            code=hv_output[:1500],  # Limit output size
            code_language="c",
            open_by_default=False
        ))

    if rc3 == 0 and lc_output:
        # Extract relevant load commands
        encryption_section = ""
        for line in lc_output.splitlines():
            if "LC_ENCRYPTION" in line or "cryptid" in line or (encryption_section and line.strip()):
                encryption_section += line + "\n"
                if "cryptid" in line:
                    encryption_section += "\n"
                    break

        if encryption_section:
            findings.append(FindingBlock(
                title="Binary Encryption Status",
                subtitle=f"cryptid={cryptid} ({'encrypted' if encrypted else 'not encrypted'})",
                code=encryption_section.strip(),
                code_language="c",
                open_by_default=True
            ))

    # Add summary finding with remediation
    protection_summary = f"""
Binary Protection Summary for: {os.path.basename(main_bin)}

Security Features:
  • Binary Encryption (cryptid): {f'{"✓ Enabled" if encrypted else "⚠ Disabled"} ({cryptid})' if cryptid else '? Unknown'}
  • Hardened Runtime: {'✓ Enabled' if runtime_hardened else '⚠ Not detected'}

Note: PIE, Stack Canaries, and ARC are checked in the checksec test.

Recommendations:
  {" - Binary encryption indicates App Store distribution; decryption suggests analysis on jailbroken device" if cryptid == "0" else ""}
  {" - Consider enabling Hardened Runtime for additional protections" if not runtime_hardened else ""}
"""

    findings.append(FindingBlock(
        title="Binary Hardening Analysis",
        subtitle=f"Status: {status}",
        evidence=[line for line in protection_summary.strip().split('\n') if line.strip()],
        open_by_default=True
    ))

    findings.insert(0, FindingBlock(title=os.path.basename(main_bin), link=make_file_link(os.path.dirname(main_bin), os.path.basename(main_bin))))

    return TestResult(
        name="Binary Hardening (MachO Header / Encryption / Runtime)",
        status=status,
        summary_lines=summary_lines,
        mastg_ref_html=mastg_ref(
            ["MASTG-TEST-0087", "MASTG-TEST-0229"],
            ["Make Sure That Free Security Features Are Activated",
             "Verifying that the App is Properly Signed"]
        ),
        findings=findings
    )

def check_keychain_security(app_dir: str, base: str) -> TestResult:
    """
    Comprehensive Keychain security analysis.

    MASTG References:
    - MASTG-TEST-0062: Testing the Memory for Sensitive Data (Keychain)
    - MASTG-TEST-0215: Determining Whether Sensitive Data Is Stored Securely on the Device
    """
    summary_lines: List[str] = []
    findings: List[FindingBlock] = []
    status: Status = "PASS"

    # Keychain API patterns to detect
    keychain_patterns = {
        'SecItemAdd': (r'\bSecItemAdd\b', 'Adding items to Keychain', 'INFO'),
        'SecItemUpdate': (r'\bSecItemUpdate\b', 'Updating Keychain items', 'INFO'),
        'SecItemCopyMatching': (r'\bSecItemCopyMatching\b', 'Querying Keychain', 'INFO'),
        'SecItemDelete': (r'\bSecItemDelete\b', 'Deleting Keychain items', 'INFO'),

        # Accessibility attributes - CRITICAL for security
        'kSecAttrAccessibleAlways': (r'kSecAttrAccessibleAlways\b', 'INSECURE: Always accessible (even when locked)', 'FAIL'),
        'kSecAttrAccessibleAlwaysThisDeviceOnly': (r'kSecAttrAccessibleAlwaysThisDeviceOnly\b', 'INSECURE: Always accessible, device-only', 'FAIL'),
        'kSecAttrAccessibleWhenUnlocked': (r'kSecAttrAccessibleWhenUnlocked\b', 'Secure: Accessible when unlocked', 'PASS'),
        'kSecAttrAccessibleWhenUnlockedThisDeviceOnly': (r'kSecAttrAccessibleWhenUnlockedThisDeviceOnly\b', 'Secure: Accessible when unlocked, device-only', 'PASS'),
        'kSecAttrAccessibleAfterFirstUnlock': (r'kSecAttrAccessibleAfterFirstUnlock\b', 'Moderate: After first unlock', 'WARN'),
        'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly': (r'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly\b', 'Moderate: After first unlock, device-only', 'WARN'),
        'kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly': (r'kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly\b', 'Secure: When passcode set', 'PASS'),

        # Keychain access groups
        'kSecAttrAccessGroup': (r'kSecAttrAccessGroup\b', 'Keychain access group (sharing)', 'INFO'),

        # Synchronization (iCloud Keychain)
        'kSecAttrSynchronizable': (r'kSecAttrSynchronizable\b', 'Keychain iCloud sync', 'INFO'),
    }

    # Track findings by category
    api_usage = {}
    accessibility_attrs = {}
    insecure_found = False
    secure_found = False

    # Search for patterns in source files
    for pattern_name, (pattern, description, severity) in keychain_patterns.items():
        matching_files = grep_code(app_dir, pattern)

        if matching_files:
            api_usage[pattern_name] = len(matching_files)

            # Track security-relevant attributes
            if 'kSecAttrAccessible' in pattern_name:
                accessibility_attrs[pattern_name] = {
                    'count': len(matching_files),
                    'description': description,
                    'severity': severity,
                    'files': matching_files[:5]  # Limit to first 5
                }

                if severity == 'FAIL':
                    insecure_found = True
                    if status == "PASS":
                        status = "FAIL"
                elif severity == 'WARN':
                    if status == "PASS":
                        status = "WARN"
                elif severity == 'PASS':
                    secure_found = True

    # Build summary
    keychain_api_count = sum(1 for k in api_usage.keys() if k.startswith('SecItem'))

    if keychain_api_count > 0:
        summary_lines.append(f"Keychain API usage detected: {keychain_api_count} different API(s) used")
    else:
        summary_lines.append("No Keychain API usage detected")
        status = "INFO"

    # Summarize accessibility attributes
    if accessibility_attrs:
        summary_lines.append(f"Found {len(accessibility_attrs)} accessibility attribute(s)")

        for attr_name, attr_data in accessibility_attrs.items():
            severity_icon = {"FAIL": "✗", "WARN": "⚠", "PASS": "✓", "INFO": "•"}[attr_data['severity']]
            summary_lines.append(f"{severity_icon} {attr_name}: {attr_data['count']} usage(s) - {attr_data['description']}")
    else:
        summary_lines.append("⚠ No kSecAttrAccessible attributes found (default accessibility unknown)")
        if status == "PASS":
            status = "WARN"

    # Build detailed findings for insecure usage
    if insecure_found:
        insecure_attrs = {k: v for k, v in accessibility_attrs.items() if v['severity'] == 'FAIL'}

        for attr_name, attr_data in insecure_attrs.items():
            for file_path in attr_data['files']:
                rel_path = rel(file_path, base)

                # Extract code snippets
                snippets = extract_snippet_with_context(file_path, keychain_patterns[attr_name][0], context_lines=4, max_matches=3)

                for line_num, matched_line, snippet in snippets:
                    findings.append(FindingBlock(
                        title=os.path.basename(file_path),
                        subtitle=f"Line {line_num}: {attr_name}",
                        link=make_file_link(base, rel_path, line_num),
                        code=snippet,
                        code_language="swift" if file_path.endswith('.swift') else "objc",
                        open_by_default=True,
                        evidence=[
                            f"🔴 INSECURE: {attr_data['description']}",
                            "Risk: Data accessible even when device is locked",
                            f"Recommendation: Use kSecAttrAccessibleWhenUnlocked or kSecAttrAccessibleAfterFirstUnlock"
                        ]
                    ))

    # Add findings for secure usage (informational)
    if secure_found and not insecure_found:
        secure_attrs = {k: v for k, v in accessibility_attrs.items() if v['severity'] == 'PASS'}

        secure_summary = "Secure Keychain accessibility attributes detected:\n\n"
        for attr_name, attr_data in secure_attrs.items():
            secure_summary += f"✓ {attr_name}: {attr_data['count']} usage(s)\n"
            secure_summary += f"  {attr_data['description']}\n\n"

        findings.append(FindingBlock(
            title="Secure Keychain Configuration",
            subtitle="No insecure accessibility attributes found",
            evidence=[line.strip() for line in secure_summary.split('\n') if line.strip()],
            open_by_default=False
        ))

    # Check for potential hardcoded keychain keys
    hardcoded_key_patterns = [
        (r'keychain.*key.*=.*["\'][\\w]{8,}["\']', 'Potential hardcoded keychain key'),
        (r'kSecAttrAccount.*=.*@?"["\\w\-\.\@]+@', 'Hardcoded keychain account identifier'),
        (r'kSecAttrService.*=.*@?"["\\w\-\.]+"["\']', 'Hardcoded keychain service identifier'),
    ]

    for pattern, description in hardcoded_key_patterns:
        matching_files = grep_code(app_dir, pattern)
        if matching_files:
            summary_lines.append(f"⚠ {description}: {len(matching_files)} file(s)")
            if status == "PASS":
                status = "WARN"

    # Add recommendation if no Keychain usage found
    if keychain_api_count == 0:
        findings.append(FindingBlock(
            title="No Keychain Usage Detected",
            subtitle="Verify how sensitive data is stored",
            evidence=[
                "No Keychain API calls detected in source code.",
                "",
                "Considerations:",
                "• Sensitive data (passwords, tokens, keys) should use iOS Keychain",
                "• UserDefaults/NSUserDefaults are NOT secure for sensitive data",
                "• Core Data/SQLite should be encrypted for sensitive data",
                "• Check for alternative storage mechanisms"
            ],
            open_by_default=True
        ))

    return TestResult(
        name="Keychain Security Configuration",
        status=status,
        summary_lines=summary_lines,
        mastg_ref_html=mastg_ref(
            ["MASTG-TEST-0062", "MASTG-TEST-0215"],
            ["Testing the Memory for Sensitive Data",
             "Determining Whether Sensitive Data Is Stored Securely"]
        ),
        findings=findings
    )

def check_weak_crypto_and_rng(main_bin: str) -> TestResult:
    """
    Detect usage of weak cryptography and insecure random number generation through binary symbol analysis (nm/jtool2).

    MASTG References:
    - MASTG-TEST-0061: Testing for Weak Cryptography
    """

    # Check if jtool2 is available for enhanced analysis
    rc_jtool2, _ = run(["which", "jtool2"], timeout=5)
    has_jtool2 = (rc_jtool2 == 0)

    # Use nm to get undefined symbols (imported functions)
    rc_nm_u, nm_u_output = run(["/usr/bin/nm", "-u", main_bin], timeout=30)

    # Also get defined symbols for comprehensive analysis
    rc_nm_def, nm_def_output = run(["/usr/bin/nm", "-gU", main_bin], timeout=30)

    if rc_nm_u != 0 and rc_nm_def != 0:
        return TestResult(
            id="CRYPTO-SYMBOLS",
            name="Weak Crypto & Insecure RNG (Binary Analysis)",
            status="WARN",
            summary=["Unable to analyze binary symbols (nm failed)"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0061"], ["Testing for Weak Cryptography"])
        )

    # Combine both symbol outputs
    nm_output = nm_u_output + "\n" + (nm_def_output if rc_nm_def == 0 else "")

    # Define weak/insecure symbols to check
    WEAK_CRYPTO_SYMBOLS = {
        # Weak hash functions
        "_CC_MD5": ("MD5 Hash", "FAIL", "Cryptographically broken - use SHA-256 or higher"),
        "_CC_SHA1": ("SHA-1 Hash", "FAIL", "Weak collision resistance - use SHA-256 or higher"),

        # Weak encryption algorithms
        "_CCCrypt": ("CommonCrypto (check algorithm)", "INFO", "Verify using AES-256, not DES/3DES/RC4"),
        "_kCCAlgorithmDES": ("DES Encryption", "FAIL", "Broken cipher - use AES-256"),
        "_kCCAlgorithm3DES": ("3DES Encryption", "FAIL", "Deprecated - use AES-256"),
        "_kCCAlgorithmRC4": ("RC4 Stream Cipher", "FAIL", "Broken cipher - use AES-256-GCM"),
        "_kCCAlgorithmRC2": ("RC2 Cipher", "FAIL", "Weak cipher - use AES-256"),

        # ECB mode (weak)
        "_kCCOptionECBMode": ("ECB Mode", "FAIL", "No IV, reveals patterns - use CBC or GCM mode"),

        # Good crypto (for comparison)
        "_kCCAlgorithmAES": ("AES Encryption", "PASS", "Good if using AES-256 with proper mode"),
        "_CC_SHA256": ("SHA-256 Hash", "PASS", "Secure hash function"),
        "_CC_SHA512": ("SHA-512 Hash", "PASS", "Secure hash function"),
    }

    INSECURE_RNG_SYMBOLS = {
        # Bad RNGs
        "_rand": ("rand()", "FAIL", "Predictable - use SecRandomCopyBytes or arc4random_buf"),
        "_srand": ("srand()", "FAIL", "Predictable seed - use SecRandomCopyBytes"),
        "_random": ("random()", "FAIL", "Predictable - use SecRandomCopyBytes"),
        "_srandom": ("srandom()", "FAIL", "Predictable seed - use SecRandomCopyBytes"),
        "_arc4random": ("arc4random()", "WARN", "Acceptable for non-crypto use, but use SecRandomCopyBytes for cryptographic keys/tokens"),
        "_arc4random_uniform": ("arc4random_uniform()", "WARN", "Acceptable for non-crypto use, but use SecRandomCopyBytes for cryptographic keys/tokens"),

        # Good RNGs (for comparison)
        "_SecRandomCopyBytes": ("SecRandomCopyBytes", "PASS", "Cryptographically secure RNG"),
        "_CCRandomGenerateBytes": ("CCRandomGenerateBytes", "PASS", "Cryptographically secure RNG"),
    }

    findings = []
    status: Status = "PASS"
    issues_found = []
    good_practices = []

    # Check for weak crypto symbols
    crypto_evidence = ["Cryptography Symbols Found:", ""]
    crypto_found = False
    for symbol, (name, severity, desc) in WEAK_CRYPTO_SYMBOLS.items():
        if symbol in nm_output:
            crypto_found = True
            symbol_marker = "❌" if severity == "FAIL" else ("⚠" if severity == "WARN" else "✓")
            crypto_evidence.append(f"{symbol_marker} {name}")
            crypto_evidence.append(f"   Symbol: {symbol}")
            crypto_evidence.append(f"   {desc}")
            crypto_evidence.append("")

            if severity == "FAIL":
                status = "FAIL"
                issues_found.append(f"Weak crypto: {name}")
            elif severity == "WARN" and status == "PASS":
                status = "WARN"
            elif severity == "PASS":
                good_practices.append(name)

    if crypto_found:
        findings.append(FindingBlock(
            title="Cryptography Symbol Analysis",
            evidence=crypto_evidence,
            open_by_default=(status == "FAIL")
        ))

    # Check for insecure RNG symbols
    rng_evidence = ["Random Number Generation Symbols Found:", ""]
    rng_found = False
    for symbol, (name, severity, desc) in INSECURE_RNG_SYMBOLS.items():
        if symbol in nm_output:
            rng_found = True
            symbol_marker = "❌" if severity == "FAIL" else ("⚠" if severity == "WARN" else "✓")
            rng_evidence.append(f"{symbol_marker} {name}")
            rng_evidence.append(f"   Symbol: {symbol}")
            rng_evidence.append(f"   {desc}")
            rng_evidence.append("")

            if severity == "FAIL":
                if status != "FAIL":
                    status = "FAIL"
                issues_found.append(f"Insecure RNG: {name}")
            elif severity == "WARN" and status == "PASS":
                status = "WARN"
                issues_found.append(f"Weak RNG: {name}")
            elif severity == "PASS":
                good_practices.append(name)

    if rng_found:
        findings.append(FindingBlock(
            title="Random Number Generation Analysis",
            evidence=rng_evidence,
            open_by_default=(status == "FAIL" or status == "WARN")
        ))

    # Build summary
    summary_lines = []
    if issues_found:
        summary_lines.append(f"❌ Found {len(issues_found)} security issue(s):")
        for issue in issues_found[:5]:
            summary_lines.append(f"  • {issue}")
        if len(issues_found) > 5:
            summary_lines.append(f"  ... and {len(issues_found) - 5} more")
    else:
        summary_lines.append("✓ No obvious weak crypto or insecure RNG symbols detected")

    if good_practices:
        summary_lines.append(f"✓ Detected {len(good_practices)} secure practice(s): {', '.join(good_practices[:3])}")

    # Optional: Use jtool2 for more detailed disassembly confirmation
    if has_jtool2 and issues_found:
        rc_jtool, jtool_output = run(["jtool2", "-d", "__TEXT,__text", main_bin], timeout=60)
        if rc_jtool == 0:
            # Look for calls to problematic crypto/RNG functions
            call_analysis = ["jtool2 Disassembly Analysis:", ""]
            found_calls = False

            # Check weak crypto symbols
            for symbol, (name, severity, _) in WEAK_CRYPTO_SYMBOLS.items():
                if symbol in nm_output and severity == "FAIL":
                    # Look for "bl <symbol>" or "call <symbol>" in disassembly
                    pattern = rf'\b(bl|call)\s+{re.escape(symbol)}'
                    if re.search(pattern, jtool_output):
                        call_analysis.append(f"⚠ Found direct call to {name}")
                        found_calls = True

            # Check insecure RNG symbols
            for symbol, (name, severity, _) in INSECURE_RNG_SYMBOLS.items():
                if symbol in nm_output and severity == "FAIL":
                    pattern = rf'\b(bl|call)\s+{re.escape(symbol)}'
                    if re.search(pattern, jtool_output):
                        call_analysis.append(f"⚠ Found direct call to {name}")
                        found_calls = True

            if found_calls:
                call_analysis.append("")
                call_analysis.append("Note: These are confirmed function calls from disassembly, not just symbol references")
                findings.append(FindingBlock(
                    title="Disassembly Confirmation (jtool2)",
                    evidence=call_analysis,
                    open_by_default=True
                ))

    # Add recommendations
    if status == "FAIL" or status == "WARN":
        rec_evidence = [
            "Security Recommendations:",
            "",
            "Cryptography:",
            "  ✓ Use: AES-256-GCM for encryption",
            "  ✓ Use: SHA-256 or SHA-512 for hashing",
            "  ✓ Use: CBC or GCM mode (never ECB)",
            "  ❌ Avoid: MD5, SHA-1, DES, 3DES, RC4",
            "",
            "Random Number Generation:",
            "  ✓ Use: SecRandomCopyBytes (Security framework)",
            "  ✓ Use: CCRandomGenerateBytes (CommonCrypto)",
            "  ⚠ Acceptable: arc4random_buf (non-crypto only)",
            "  ❌ Avoid: rand(), random(), srand() (predictable)",
            "",
            "References:",
            "  • MASTG-TEST-0061: Testing for Weak Cryptography",
            "  • Apple CryptoKit (iOS 13+) for modern crypto APIs",
            "  • CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
            "  • CWE-338: Use of Cryptographically Weak PRNG",
        ]
        findings.append(FindingBlock(
            title="Remediation Guidance",
            evidence=rec_evidence,
            open_by_default=False
        ))

    return TestResult(
        id="CRYPTO-SYMBOLS",
        name="Weak Crypto & Insecure RNG (Binary Analysis)",
        status=status,
        summary=summary_lines,
        findings=findings,
        mastg_ref_html=mastg_ref(["MASTG-TEST-0061"], ["Testing for Weak Cryptography"])
    )

def check_insecure_apis_symbols(main_bin: str) -> TestResult:
    """
    Detect usage of insecure APIs through binary symbol analysis (nm/jtool2).
    More reliable than strings-based detection as it finds actual function calls.

    MASTG References:
    - MASTG-TEST-0081: Testing for Sensitive Data in Logs
    - MASTG-TEST-0061: Testing for Weak Cryptography (RNG)
    """

    # Check if jtool2 is available for enhanced analysis
    rc_jtool2, _ = run(["which", "jtool2"], timeout=5)
    has_jtool2 = (rc_jtool2 == 0)

    # Use nm to get undefined symbols (imported functions)
    rc_nm, nm_output = run(["/usr/bin/nm", "-u", main_bin], timeout=30)

    if rc_nm != 0:
        return TestResult(
            id="CODE-INSECUREAPIS",
            name="Insecure API Usage (Binary Analysis)",
            status="WARN",
            summary=["Unable to analyze binary symbols (nm failed)"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0081", "MASTG-TEST-0061"])
        )

    # Also get defined symbols for comprehensive analysis
    rc_nm_def, nm_def_output = run(["/usr/bin/nm", "-gU", main_bin], timeout=30)
    all_symbols = nm_output + "\n" + (nm_def_output if rc_nm_def == 0 else "")

    # Define insecure APIs to detect with severity levels
    INSECURE_APIS = {
        # Memory management vulnerabilities
        "_malloc": ("malloc()", "WARN", "Manual memory management - prefer ARC/Swift automatic memory"),
        "_calloc": ("calloc()", "WARN", "Manual memory management - prefer ARC/Swift automatic memory"),
        "_realloc": ("realloc()", "WARN", "Manual memory management - prefer ARC/Swift automatic memory"),
        "_free": ("free()", "WARN", "Manual memory management - prefer ARC/Swift automatic memory"),
        "_alloca": ("alloca()", "FAIL", "Stack allocation risk - use heap allocation or fixed buffers"),

        # Buffer operations (unsafe)
        "_strcpy": ("strcpy()", "FAIL", "Buffer overflow risk - use strncpy/strlcpy or NSString"),
        "_strcat": ("strcat()", "FAIL", "Buffer overflow risk - use strncat/strlcat or NSString"),
        "_sprintf": ("sprintf()", "FAIL", "Buffer overflow risk - use snprintf or NSString stringWithFormat"),
        "_vsprintf": ("vsprintf()", "FAIL", "Buffer overflow risk - use vsnprintf"),
        "_gets": ("gets()", "FAIL", "Extremely unsafe - use fgets or NSFileHandle"),
        "_scanf": ("scanf()", "WARN", "Input validation risk - use NSScanner or controlled parsing"),

        # Logging (data leakage)
        "_NSLog": ("NSLog()", "WARN", "Logs to system - may leak sensitive data. Use os_log with privacy annotations or disable in production"),
        "_printf": ("printf()", "WARN", "Console logging - may leak data. Use os_log or disable in production"),
        "_fprintf": ("fprintf()", "WARN", "File/stream logging - may leak data"),
        "_puts": ("puts()", "WARN", "Console output - may leak data"),
        "_NSLogv": ("NSLogv()", "WARN", "NSLog variant - same data leakage concerns"),

        # Random number generation (weak)
        "_rand": ("rand()", "FAIL", "Predictable PRNG - use SecRandomCopyBytes for crypto, arc4random_buf for non-crypto"),
        "_random": ("random()", "FAIL", "Predictable PRNG - use SecRandomCopyBytes"),
        "_srand": ("srand()", "FAIL", "Predictable seed - do not use"),
        "_srandom": ("srandom()", "FAIL", "Predictable seed - do not use"),
        "_drand48": ("drand48()", "FAIL", "Predictable PRNG - use SecRandomCopyBytes"),

        # Command execution
        "_system": ("system()", "FAIL", "Command injection risk - avoid shell execution or sanitize input"),
        "_popen": ("popen()", "FAIL", "Command injection risk - avoid or use NSTask with argument array"),
        "_exec": ("exec()", "FAIL", "Command execution - validate all inputs"),
        "_execl": ("execl()", "FAIL", "Command execution - validate all inputs"),
        "_execv": ("execv()", "FAIL", "Command execution - validate all inputs"),

        # Temporary files (predictable)
        "_tmpnam": ("tmpnam()", "FAIL", "Race condition risk - use mkstemp or NSTemporaryDirectory with unique names"),
        "_tempnam": ("tempnam()", "FAIL", "Race condition risk - use mkstemp"),
        "_mktemp": ("mktemp()", "FAIL", "Race condition risk - use mkstemp"),

        # Information disclosure
        "_getenv": ("getenv()", "WARN", "Environment variables may leak info - validate and sanitize"),
        "_getpass": ("getpass()", "WARN", "Password in memory - use secure input methods"),
    }

    # Good APIs (for comparison)
    SECURE_ALTERNATIVES = {
        "_SecRandomCopyBytes": "SecRandomCopyBytes (secure RNG)",
        "_CCRandomGenerateBytes": "CCRandomGenerateBytes (secure RNG)",
        "_arc4random_buf": "arc4random_buf (good for non-crypto RNG)",
        "_snprintf": "snprintf (safe string formatting)",
        "_strlcpy": "strlcpy (safe string copy)",
        "_strlcat": "strlcat (safe string concatenation)",
        "_mkstemp": "mkstemp (safe temp file creation)",
    }

    findings = []
    tables_html: List[str] = []
    issues_found = []
    warnings_found = []
    good_practices = []
    status: Status = "PASS"
    table_rows: List[List[str]] = []

    # Analyze for insecure APIs
    api_categories = {
        "Memory Management": [],
        "Buffer Operations": [],
        "Logging & Data Leakage": [],
        "Weak RNG": [],
        "Command Execution": [],
        "Temporary Files": [],
        "Information Disclosure": [],
    }

    for symbol, (name, severity, desc) in INSECURE_APIS.items():
        if symbol in all_symbols:
            # Categorize the finding
            if "malloc" in name or "alloca" in name or "free" in name:
                category = "Memory Management"
            elif "strcpy" in name or "sprintf" in name or "gets" in name or "scanf" in name:
                category = "Buffer Operations"
            elif "NSLog" in name or "printf" in name or "puts" in name:
                category = "Logging & Data Leakage"
            elif "rand" in name or "drand" in name:
                category = "Weak RNG"
            elif "system" in name or "exec" in name or "popen" in name:
                category = "Command Execution"
            elif "tmp" in name or "temp" in name or "mktemp" in name:
                category = "Temporary Files"
            else:
                category = "Information Disclosure"

            marker = "❌" if severity == "FAIL" else "⚠"
            api_categories[category].append((marker, name, symbol, desc, severity))

            if severity == "FAIL":
                status = "FAIL"
                issues_found.append(name)
            elif severity == "WARN":
                if status == "PASS":
                    status = "WARN"
                warnings_found.append(name)
            table_rows.append([category, name, severity, symbol, desc])

    # Build findings by category
    for category, apis in api_categories.items():
        if apis:
            evidence = [f"{category}:", ""]
            for marker, name, symbol, desc, severity in apis:
                evidence.append(f"{marker} {name}")
                evidence.append(f"   Symbol: {symbol}")
                evidence.append(f"   Risk: {desc}")
                evidence.append("")

            findings.append(FindingBlock(
                title=category,
                evidence=evidence,
                open_by_default=(any(sev == "FAIL" for _, _, _, _, sev in apis))
            ))

    # Check for secure alternatives
    for symbol, name in SECURE_ALTERNATIVES.items():
        if symbol in all_symbols:
            good_practices.append(name)

    if good_practices:
        alt_evidence = [
            "Secure APIs Detected (Good Practices):",
            ""
        ]
        for api in good_practices:
            alt_evidence.append(f"✓ {api}")

        findings.append(FindingBlock(
            title="Secure Alternatives Found",
            evidence=alt_evidence,
            open_by_default=False
        ))

    # Optional: Use jtool2 for more detailed analysis if available
    if has_jtool2 and issues_found:
        rc_jtool, jtool_output = run(["jtool2", "-d", "__TEXT,__text", main_bin], timeout=60)
        if rc_jtool == 0:
            # Look for calls to problematic functions
            call_analysis = ["jtool2 Disassembly Analysis:", ""]
            found_calls = False

            for symbol, (name, severity, _) in INSECURE_APIS.items():
                if symbol in all_symbols and severity == "FAIL":
                    # Look for "bl <symbol>" or "call <symbol>" in disassembly
                    pattern = rf'\b(bl|call)\s+{re.escape(symbol)}'
                    if re.search(pattern, jtool_output):
                        call_analysis.append(f"⚠ Found direct call to {name}")
                        found_calls = True

            if found_calls:
                call_analysis.append("")
                call_analysis.append("Note: These are confirmed function calls, not just references")
                findings.append(FindingBlock(
                    title="Disassembly Confirmation",
                    evidence=call_analysis,
                    open_by_default=True
                ))

    # Build summary (show full list, no truncation)
    summary_lines = []
    if issues_found or warnings_found:
        if issues_found:
            summary_lines.append("❌ Critical API issues: " + ", ".join(sorted(set(issues_found))))
        if warnings_found:
            summary_lines.append("⚠ Warning-level APIs: " + ", ".join(sorted(set(warnings_found))))
    else:
        summary_lines.append("✓ No critical insecure API usage detected via symbol analysis")

    if good_practices:
        summary_lines.append("✓ Secure APIs detected: " + ", ".join(sorted(set(good_practices))))

    # Add remediation guidance
    if status == "FAIL" or status == "WARN":
        rec_evidence = [
            "Security Recommendations:",
            "",
            "Buffer Safety:",
            "  ✓ Use: strncpy/strlcpy, snprintf, NSString methods",
            "  ❌ Avoid: strcpy, sprintf, gets, strcat",
            "",
            "Memory Management:",
            "  ✓ Use: ARC (Automatic Reference Counting)",
            "  ✓ Use: Swift automatic memory management",
            "  ⚠ Review: Manual malloc/free usage for leaks/corruption",
            "",
            "Logging:",
            "  ✓ Use: os_log with privacy annotations (iOS 10+)",
            "  ✓ Disable verbose logging in production builds",
            "  ❌ Avoid: NSLog for sensitive data",
            "",
            "Random Numbers:",
            "  ✓ Crypto: SecRandomCopyBytes, CCRandomGenerateBytes",
            "  ✓ Non-crypto: arc4random_buf, arc4random_uniform",
            "  ❌ Never: rand(), random(), srand()",
            "",
            "References:",
            "  • MASTG-TEST-0081: Sensitive Data in Logs",
            "  • MASTG-TEST-0061: Weak Cryptography",
            "  • CWE-120: Buffer Overflow",
            "  • CWE-338: Weak PRNG",
        ]
        findings.append(FindingBlock(
            title="Remediation Guidance",
            evidence=rec_evidence,
            open_by_default=False
        ))

    # Add filterable table with all hits
    if table_rows:
        tables_html.append(render_filterable_table(
            f"insecureApis-{uuid.uuid4().hex[:6]}",
            ["Category", "API", "Severity", "Symbol", "Notes"],
            table_rows,
            "Insecure / review APIs (symbol scan)"
        ))

    return TestResult(
        id="CODE-INSECUREAPIS",
        name="Insecure API Usage (Binary Analysis)",
        status=status,
        summary=summary_lines,
        findings=findings,
        tables_html=tables_html,
        mastg_ref_html=mastg_ref(["MASTG-TEST-0081", "MASTG-TEST-0061"],
                                 ["Testing for Sensitive Data in Logs", "Testing for Weak Cryptography"])
    )

def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0

    entropy = 0.0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * (p_x.__log__() if hasattr(p_x, '__log__') else __import__('math').log2(p_x))

    return entropy

def check_hardcoded_secrets_binary(main_bin: str) -> TestResult:
    """
    Detect hardcoded secrets through binary analysis using entropy detection and pattern matching.
    Uses strings extraction, entropy calculation, and optionally jtool2 for confirmation.

    MASTG References:
    - MASTG-TEST-0057: Searching for Hardcoded Secrets
    """

    # Check if jtool2 is available
    rc_jtool2, _ = run(["which", "jtool2"], timeout=5)
    has_jtool2 = (rc_jtool2 == 0)

    # Extract strings from binary (minimum length 8 for secrets)
    rc_strings, strings_output = run(["/usr/bin/strings", "-n", "8", main_bin], timeout=60)

    if rc_strings != 0:
        return TestResult(
            id="STORAGE-SECRETS-BINARY",
            name="Hardcoded Secrets (Binary Analysis)",
            status="WARN",
            summary=["Unable to extract strings from binary"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0057"], ["Searching for Hardcoded Secrets"])
        )

    strings_list = [s.strip() for s in strings_output.split('\n') if len(s.strip()) >= 8]

    # Define secret patterns (regex-based detection)
    SECRET_PATTERNS = [
        # API Keys and tokens
        (r'\b[A-Za-z0-9]{32,}\b', "Long alphanumeric string (potential API key/token)", 32),
        (r'\b[A-Z0-9]{20,}\b', "Long uppercase alphanumeric (potential token)", 20),
        (r'(?i)(api[_-]?key|apikey|api[_-]?secret)["\s:=]+([A-Za-z0-9_\-]{16,})', "API key pattern", 16),
        (r'(?i)(access[_-]?token|accesstoken)["\s:=]+([A-Za-z0-9_\-]{16,})', "Access token pattern", 16),
        (r'(?i)(secret[_-]?key|secretkey)["\s:=]+([A-Za-z0-9_\-]{16,})', "Secret key pattern", 16),
        (r'(?i)(private[_-]?key|privatekey)["\s:=]+([A-Za-z0-9_\-]{16,})', "Private key pattern", 16),

        # AWS
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID", 20),
        (r'(?i)aws.{0,20}["\s:=]+([A-Za-z0-9/+=]{40})', "AWS Secret Access Key", 40),

        # Base64 encoded (high entropy indicators)
        (r'[A-Za-z0-9+/]{40,}={0,2}', "Base64 string (potential encoded secret)", 40),

        # Slack tokens
        (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}', "Slack token", 40),

        # GitHub tokens
        (r'gh[pousr]_[A-Za-z0-9]{36,}', "GitHub token", 40),

        # Generic Bearer tokens
        (r'(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*', "Bearer token", 20),

        # JWT tokens (3 base64 parts separated by dots)
        (r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', "JWT token", 40),

        # Generic passwords in config-like strings
        (r'(?i)(password|passwd|pwd)["\s:=]+([^\s"]{8,})', "Password in configuration", 8),
    ]

    # High entropy thresholds
    ENTROPY_THRESHOLD_HIGH = 4.5  # Very high entropy (likely random/encoded)
    ENTROPY_THRESHOLD_MEDIUM = 4.0  # Medium-high entropy
    MIN_LENGTH_FOR_ENTROPY = 16  # Only check entropy for strings >= 16 chars

    # False positive filters
    FALSE_POSITIVE_PATTERNS = [
        r'^[A-F0-9]{32,}$',  # Likely hash/UUID (all hex)
        r'^0+$|^1+$|^[01]+$',  # Repeated 0s or 1s
        r'^[A-Za-z]+$',  # Only letters (not a secret)
        r'^\d+$',  # Only digits
        r'^[\/\-_\.]+$',  # Only special chars
        r'(?i)^(true|false|yes|no|null|undefined)$',  # Boolean values
        r'(?i)^(http|https|ftp|file)://',  # URLs
        r'\.framework$|\.app$|\.dylib$',  # Framework/app names
        r'^com\.[a-z]+\.[a-z]+',  # Bundle identifiers
        r'^\$\{[A-Z_]+\}$',  # Template variables
        r'^ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',  # Base64 alphabet
        r'^[/\\]Users[/\\]',  # File paths (Unix/Windows)
        r'^[/\\][a-zA-Z]+[/\\]',  # Unix paths
        r'[/\\](src|build|package|include|lib|bin|dist)[/\\]',  # Build/source paths
        r'\.conan[/\\]',  # Conan package manager paths
        r'buildAgent[/\\]work',  # CI/CD build agent paths
        r':\s*(Unknown|Error|Warning|Failed)',  # Log messages
        r'%[sd@]',  # Format string placeholders
        r'<[a-z]+\s+class=',  # HTML tags
        r'&[a-z]+;',  # HTML entities
        r'^[G6B]+$',  # Repeated G, 6, B characters (binary artifacts)
        r'Activity:\s*Unknown',  # Activity log patterns
        r'democratic|technology|background|management|javascript|conditions',  # Common HTML/web content words
    ]

    # Common English words and patterns to exclude
    COMMON_WORDS = {
        'application', 'description', 'information', 'configuration',
        'copyright', 'reserved', 'permission', 'foundation', 'identifier',
        'ViewController', 'AppDelegate', 'Foundation', 'CoreData',
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',  # Base64 alphabet
    }

    high_entropy_secrets = []
    pattern_based_secrets = []
    findings = []
    tables_html: List[str] = []
    status: Status = "PASS"

    # Pattern-based detection
    for pattern, description, min_len in SECRET_PATTERNS:
        matches = []
        for s in strings_list:
            if len(s) < min_len:
                continue

            match = re.search(pattern, s)
            if match:
                # Filter false positives
                is_false_positive = False
                matched_text = match.group(0)

                # Check both matched text and full string context
                for fp_pattern in FALSE_POSITIVE_PATTERNS:
                    if re.search(fp_pattern, matched_text) or re.search(fp_pattern, s):
                        is_false_positive = True
                        break

                # Check if it's a common word
                if matched_text.lower() in COMMON_WORDS:
                    is_false_positive = True

                # Additional specific filters
                if not is_false_positive:
                    # Filter base64 alphabet string
                    if matched_text == "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/":
                        is_false_positive = True
                    # Filter file path hashes
                    elif '/package/' in s or '/.conan/' in s or 'buildAgent' in s:
                        is_false_positive = True
                    # Filter log/debug messages with format specifiers
                    elif '%s' in s or '%d' in s or '%@' in s:
                        is_false_positive = True

                if not is_false_positive and matched_text not in [m[0] for m in matches]:
                    matches.append((matched_text, s))

        if matches:
            pattern_based_secrets.append((description, matches))  # Keep all matches for accurate counting

    # Entropy-based detection for high-entropy strings
    for s in strings_list:
        if len(s) < MIN_LENGTH_FOR_ENTROPY:
            continue

        # Skip if obviously not a secret
        is_false_positive = False
        for fp_pattern in FALSE_POSITIVE_PATTERNS:
            if re.search(fp_pattern, s):
                is_false_positive = True
                break

        if is_false_positive:
            continue

        # Skip common words
        if s.lower() in COMMON_WORDS:
            continue

        # Additional specific entropy filters
        # Skip strings that are mostly repeated characters
        unique_chars = len(set(s))
        if unique_chars < 5:  # Less than 5 unique characters
            continue

        # Skip strings with suspicious patterns
        if any([
            s.startswith('/') and ('/' in s[1:]),  # Looks like a path
            s.count('/') > 3,  # Multiple slashes (likely path)
            s.count('\\') > 3,  # Multiple backslashes (likely Windows path)
            'buildAgent' in s,  # CI/CD paths
            '.conan' in s,  # Package manager
            'package/' in s,  # Package paths
            s.startswith('Copyright') or 'copyright' in s.lower(),  # Copyright text
            '<' in s and '>' in s,  # HTML/XML
            '%s' in s or '%d' in s or '%@' in s,  # Format strings
        ]):
            continue

        # Calculate entropy
        try:
            import math
            entropy = 0.0
            if s:
                for x in range(256):
                    p_x = float(s.count(chr(x))) / len(s)
                    if p_x > 0:
                        entropy += - p_x * math.log2(p_x)

            if entropy >= ENTROPY_THRESHOLD_HIGH:
                # Very high entropy - likely secret
                high_entropy_secrets.append((s, entropy, "Very High"))
            elif entropy >= ENTROPY_THRESHOLD_MEDIUM and len(s) >= 24:
                # Medium-high entropy with good length
                high_entropy_secrets.append((s, entropy, "High"))
        except:
            pass

    # Sort high entropy findings by entropy (highest first), limit to 100 for performance
    high_entropy_secrets = sorted(high_entropy_secrets, key=lambda x: x[1], reverse=True)[:100]

    # Build tables so every hit is visible and filterable
    if pattern_based_secrets:
        pattern_rows = []
        for description, matches in pattern_based_secrets:
            for matched_text, full_string in matches:
                pattern_rows.append([description, matched_text, full_string])
        tables_html.append(render_filterable_table(
            f"secretPattern-{uuid.uuid4().hex[:6]}",
            ["Pattern", "Matched", "Context"],
            pattern_rows,
            f"Pattern-based secrets ({len(pattern_rows)} hits)"
        ))
        status = "FAIL"

    if high_entropy_secrets:
        entropy_rows = [
            [level, f"{entropy_val:.2f}", str(len(secret)), secret]
            for secret, entropy_val, level in high_entropy_secrets
        ]
        tables_html.append(render_filterable_table(
            f"secretEntropy-{uuid.uuid4().hex[:6]}",
            ["Level", "Entropy", "Length", "String"],
            entropy_rows,
            f"High-entropy strings ({len(high_entropy_secrets)} hits)"
        ))

        if status == "PASS":
            status = "WARN"

    if pattern_based_secrets or high_entropy_secrets:
        findings.append(FindingBlock(
            title="Evidence tables",
            evidence=[
                "All detected strings are listed in the interactive tables above.",
                "Use the column sort and search box to triage, export, or confirm each hit.",
            ],
            open_by_default=False
        ))

    # Optional: Use jtool2 for string section analysis
    if has_jtool2 and (pattern_based_secrets or high_entropy_secrets):
        rc_jtool, jtool_output = run(["jtool2", "-l", main_bin], timeout=30)
        if rc_jtool == 0:
            # Check for __cstring section size (where string literals live)
            cstring_match = re.search(r'__cstring\s+([0-9a-fx]+)\s+([0-9a-fx]+)', jtool_output)
            if cstring_match:
                size_hex = cstring_match.group(2)
                try:
                    size_bytes = int(size_hex, 16)
                    size_kb = size_bytes / 1024

                    jtool_evidence = [
                        "jtool2 Binary Analysis:",
                        "",
                        f"__cstring section size: {size_kb:.2f} KB ({size_bytes} bytes)",
                        "",
                        "Large __cstring sections may indicate embedded configuration or secrets.",
                        "Review the strings found above for sensitive data."
                    ]

                    findings.append(FindingBlock(
                        title="Binary String Section Analysis (jtool2)",
                        evidence=jtool_evidence,
                        open_by_default=False
                    ))
                except:
                    pass

    total_pattern_hits = sum(len(m) for _, m in pattern_based_secrets)
    summary_lines = []
    if pattern_based_secrets or high_entropy_secrets:
        if pattern_based_secrets:
            summary_lines.append(f"⚠ Found {total_pattern_hits} pattern-based secret hit(s)")
        if high_entropy_secrets:
            summary_lines.append(f"⚠ Found {len(high_entropy_secrets)} high-entropy string(s) (potential encoded secrets)")
        summary_lines.append("MASTG expects no hardcoded secrets in production binaries")
    else:
        summary_lines.append("✓ No obvious hardcoded secrets detected via binary analysis")

    return TestResult(
        id="STORAGE-SECRETS-BINARY",
        name="Hardcoded Secrets (Binary Analysis)",
        status=status,
        summary_lines=summary_lines,
        findings=findings,
        tables_html=tables_html,
        mastg_ref_html=mastg_ref(["MASTG-TEST-0057"], ["Searching for Hardcoded Secrets"])
    )

def check_app_extensions(app_dir: str, base: str) -> TestResult:
    """
    Analyze app extensions (PlugIns/*.appex) for security concerns.

    MASTG References:
    - MASTG-TEST-0070: Testing App Permissions
    """

    plugins_dir = os.path.join(app_dir, "PlugIns")

    if not os.path.exists(plugins_dir):
        return TestResult(
            id="PLATFORM-EXTENSIONS",
            name="App Extensions Analysis",
            status="PASS",
            summary=["No app extensions found (no PlugIns directory)"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0070"], ["Testing App Permissions"])
        )

    # Find all .appex bundles
    extensions = []
    for item in os.listdir(plugins_dir):
        if item.endswith(".appex"):
            ext_path = os.path.join(plugins_dir, item)
            if os.path.isdir(ext_path):
                extensions.append((item, ext_path))

    if not extensions:
        return TestResult(
            id="PLATFORM-EXTENSIONS",
            name="App Extensions Analysis",
            status="PASS",
            summary=["PlugIns directory exists but no .appex extensions found"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0070"], ["Testing App Permissions"])
        )

    findings = []
    status: Status = "INFO"
    concerns = []

    for ext_name, ext_path in extensions:
        # Parse Info.plist
        info_path = os.path.join(ext_path, "Info.plist")
        if not os.path.exists(info_path):
            findings.append(FindingBlock(
                title=f"Extension: {ext_name}",
                evidence=[f"Path: {rel(ext_path, base)}", "⚠ No Info.plist found"]
            ))
            continue

        try:
            ext_info = plutil_to_plist(info_path)
        except Exception as e:
            findings.append(FindingBlock(
                title=f"Extension: {ext_name}",
                evidence=[f"Path: {rel(ext_path, base)}", f"⚠ Failed to parse Info.plist: {e}"]
            ))
            continue

        # Extract extension point
        ns_extension = ext_info.get("NSExtension", {})
        extension_point = ns_extension.get("NSExtensionPointIdentifier", "Unknown")
        extension_name = ext_info.get("CFBundleDisplayName") or ext_info.get("CFBundleName", ext_name)

        # Parse entitlements
        ext_binary = None
        for item in os.listdir(ext_path):
            item_path = os.path.join(ext_path, item)
            if os.path.isfile(item_path) and os.access(item_path, os.X_OK):
                # Check if it's a Mach-O binary
                try:
                    with open(item_path, 'rb') as f:
                        magic = f.read(4)
                        if magic in [b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xca\xfe\xba\xbe']:
                            ext_binary = item_path
                            break
                except:
                    pass

        entitlements = {}
        if ext_binary:
            rc, ent_xml = run(["/usr/bin/codesign", "-d", "--entitlements", ":-", ext_binary], timeout=30)
            if rc == 0 and ent_xml.strip():
                try:
                    entitlements = plistlib.loads(ent_xml.encode("utf-8"))
                except:
                    pass

        # Build evidence
        evidence_lines = [
            f"Extension Name: {extension_name}",
            f"Extension Type: {extension_point}",
            f"Path: {rel(ext_path, base)}",
            ""
        ]

        # Categorize extension type and security implications
        extension_types = {
            "com.apple.widget-extension": ("Today Widget", "WARN", "Can display data on lock screen"),
            "com.apple.share-services": ("Share Extension", "INFO", "Processes shared data from other apps"),
            "com.apple.keyboard-service": ("Custom Keyboard", "WARN", "Full access to user input - high privacy risk"),
            "com.apple.services": ("Action Extension", "INFO", "Processes data from other apps"),
            "com.apple.photo-editing": ("Photo Editing Extension", "INFO", "Access to photos"),
            "com.apple.Safari.content-blocker": ("Content Blocker", "INFO", "Safari extension"),
            "com.apple.authentication-services-credential-provider-ui": ("Password AutoFill", "WARN", "Access to credentials"),
            "com.apple.intents-service": ("Siri Intents", "INFO", "Voice assistant integration"),
            "com.apple.intents-ui-service": ("Siri Intents UI", "INFO", "Voice assistant UI"),
            "com.apple.usernotifications.content-extension": ("Notification Content", "INFO", "Custom notification UI"),
            "com.apple.usernotifications.service": ("Notification Service", "INFO", "Modify notifications"),
        }

        ext_desc, ext_severity, ext_note = extension_types.get(
            extension_point,
            ("Unknown Extension Type", "INFO", "Review security implications")
        )

        evidence_lines.append(f"Category: {ext_desc}")
        evidence_lines.append(f"Security Note: {ext_note}")

        if ext_severity == "WARN":
            if status != "FAIL":
                status = "WARN"
            concerns.append(f"{extension_name} ({ext_desc})")

        evidence_lines.append("")

        # Check app groups (data sharing)
        app_groups = entitlements.get("com.apple.security.application-groups", [])
        if app_groups:
            evidence_lines.append(f"App Groups (Shared Containers): {len(app_groups)}")
            for group in app_groups:
                evidence_lines.append(f"  • {group}")
            evidence_lines.append("⚠ Extension shares data with main app via app groups")
            evidence_lines.append("")

        # Check keychain access groups
        keychain_groups = entitlements.get("keychain-access-groups", [])
        if keychain_groups:
            evidence_lines.append(f"Keychain Access Groups: {len(keychain_groups)}")
            for group in keychain_groups:
                evidence_lines.append(f"  • {group}")
            evidence_lines.append("ℹ Extension can access shared keychain items")
            evidence_lines.append("")

        # Check for full network access (custom keyboards)
        requests_open_access = ns_extension.get("RequestsOpenAccess", False)
        if requests_open_access:
            evidence_lines.append("⚠ RequestsOpenAccess: true")
            evidence_lines.append("  CRITICAL: Custom keyboard has full network access!")
            evidence_lines.append("  Can send user input to external servers")
            status = "FAIL"
            concerns.append(f"{extension_name} requests open access (network)")
            evidence_lines.append("")

        # Check data protection entitlement
        data_protection = entitlements.get("com.apple.developer.default-data-protection")
        if data_protection:
            evidence_lines.append(f"Data Protection: {data_protection}")
        else:
            evidence_lines.append("Data Protection: Not specified (uses default)")

        findings.append(FindingBlock(
            title=f"Extension: {extension_name}",
            link=make_file_link(base, rel(ext_path, base)),
            evidence=evidence_lines,
            open_by_default=(ext_severity == "WARN" or requests_open_access)
        ))

    # Build summary
    summary_lines = [f"Found {len(extensions)} app extension(s)"]

    if concerns:
        summary_lines.append(f"⚠ {len(concerns)} extension(s) require security review:")
        for concern in concerns[:3]:
            summary_lines.append(f"  • {concern}")
        if len(concerns) > 3:
            summary_lines.append(f"  ... and {len(concerns) - 3} more")
    else:
        summary_lines.append("ℹ Review extension permissions and data sharing")

    return TestResult(
        id="PLATFORM-EXTENSIONS",
        name="App Extensions Analysis",
        status=status,
        summary=summary_lines,
        findings=findings,
        mastg_ref_html=mastg_ref(["MASTG-TEST-0070"], ["Testing App Permissions"])
    )

def check_sql_injection_patterns(main_bin: str) -> TestResult:
    """
    Detect potentially unsafe SQL query patterns in binary strings.

    References:
    - OWASP MASVS-CODE: Input validation & SQL injection
    """
    sql_ref_html = (
        "<div><strong>Reference:</strong> "
        '<a href="https://mas.owasp.org/MASVS/controls/MASVS-CODE-2/" target="_blank" rel="noopener noreferrer">'
        "MASVS-CODE-2 (Injection resilience)</a> • "
        '<a href="https://owasp.org/www-community/attacks/SQL_Injection" target="_blank" rel="noopener noreferrer">'
        "OWASP SQL Injection</a></div>"
    )

    # Extract strings from binary
    strings_output = strings_dump(main_bin, timeout=60)

    if not strings_output:
        return TestResult(
            id="CODE-SQLINJECTION",
            name="SQL Injection Pattern Detection",
            status="WARN",
            summary=["Unable to extract strings from binary"],
            mastg_ref_html=sql_ref_html
        )

    # Patterns indicating potentially unsafe SQL construction
    # These patterns look for actual SQL query construction, not just keywords in strings
    UNSAFE_SQL_PATTERNS = [
        # Look for SQL structure with formatting
        (r'SELECT\s+\*?\s+FROM\s+.*%[@sd]', "String formatting in SELECT...FROM query", "FAIL"),
        (r'INSERT\s+INTO\s+.*%[@ sd]', "String formatting in INSERT INTO query", "FAIL"),
        (r'UPDATE\s+\w+\s+SET\s+.*%[@sd]', "String formatting in UPDATE...SET query", "FAIL"),
        (r'DELETE\s+FROM\s+.*%[@ sd]', "String formatting in DELETE FROM query", "FAIL"),
        (r'WHERE\s+\w+\s*=\s*["\']?%@', "String formatting in WHERE clause", "FAIL"),

        # String building methods with SQL keywords
        (r'stringWithFormat:@"SELECT.*FROM', "NSString stringWithFormat with SELECT FROM", "FAIL"),
        (r'stringWithFormat:@"INSERT.*INTO', "NSString stringWithFormat with INSERT INTO", "FAIL"),
        (r'stringWithFormat:@"UPDATE.*SET', "NSString stringWithFormat with UPDATE SET", "FAIL"),
        (r'stringWithFormat:@"DELETE.*FROM', "NSString stringWithFormat with DELETE FROM", "FAIL"),

        # Swift string interpolation with SQL structure
        (r'\\\(.*\)\s*SELECT\s+.*FROM', "String interpolation in SELECT FROM (Swift)", "FAIL"),
        (r'\\\(.*\)\s*INSERT\s+INTO', "String interpolation in INSERT INTO (Swift)", "FAIL"),

        # String concatenation with SQL
        (r'\+\s*@"SELECT\s+.*FROM', "String concatenation with SELECT FROM", "FAIL"),
        (r'appendString.*@"SELECT\s+FROM', "appendString with SELECT FROM", "FAIL"),
    ]

    # Patterns to EXCLUDE (false positives - log messages, error strings)
    FALSE_POSITIVE_PATTERNS = [
        r'[Ff]ailed',
        r'[Ee]rror',
        r'[Ss]uccess',
        r'[Cc]ompleted',
        r'[Uu]nable to',
        r'[Cc]ould not',
        r'[Cc]annot',
        r'[Ll]ogging',
        r'[Dd]ebug',
        r'[Ww]arning',
        r'subscription',
        r'resource',
        r'path',
        r'location',
    ]

    # Patterns for safe SQL usage (parameterized queries)
    SAFE_SQL_PATTERNS = [
        r'\?',  # Placeholder in prepared statements
        r'sqlite3_bind',  # SQLite parameter binding
        r'bindParameter',
        r'NSPredicate',  # Core Data predicate (safe)
    ]

    findings = []
    unsafe_matches = []
    safe_indicators = []

    # Check for unsafe patterns
    for pattern, description, severity in UNSAFE_SQL_PATTERNS:
        matches = []
        for s in strings_output:
            if re.search(pattern, s, re.IGNORECASE):
                # Filter out false positives (log messages)
                is_false_positive = False
                for fp_pattern in FALSE_POSITIVE_PATTERNS:
                    if re.search(fp_pattern, s):
                        is_false_positive = True
                        break

                if not is_false_positive:
                    matches.append(s)

        if matches:
            unsafe_matches.append((description, matches[:10]))  # Limit to 10 examples

    # Check for safe patterns
    for pattern in SAFE_SQL_PATTERNS:
        if any(re.search(pattern, s, re.IGNORECASE) for s in strings_output):
            safe_indicators.append(pattern)

    status: Status = "PASS"

    if unsafe_matches:
        status = "FAIL"

        for description, matches in unsafe_matches:
            evidence_lines = [
                f"Pattern: {description}",
                f"Found {len(matches)} potential occurrence(s)",
                "",
                "Examples:"
            ]

            for i, match in enumerate(matches[:5], 1):
                # Truncate long strings
                display_match = match[:200] + "..." if len(match) > 200 else match
                evidence_lines.append(f"  [{i}] {display_match}")

            if len(matches) > 5:
                evidence_lines.append(f"  ... and {len(matches) - 5} more")

            evidence_lines.append("")
            evidence_lines.append("⚠ SECURITY RISK: SQL Injection")
            evidence_lines.append("  • Attackers can manipulate SQL queries")
            evidence_lines.append("  • Can lead to data theft, modification, or deletion")
            evidence_lines.append("  • Use parameterized queries instead")

            findings.append(FindingBlock(
                title=f"Unsafe SQL Pattern: {description}",
                evidence=evidence_lines,
                open_by_default=True
            ))

        # Add remediation guidance
        remediation = [
            "SQL Injection Prevention:",
            "",
            "❌ UNSAFE - String Formatting:",
            '  NSString *query = [NSString stringWithFormat:@"SELECT * FROM users WHERE name=\'%@\'", userName];',
            '  // Vulnerable to SQL injection!',
            "",
            "✓ SAFE - Parameterized Queries (SQLite):",
            '  sqlite3_stmt *statement;',
            '  sqlite3_prepare_v2(db, "SELECT * FROM users WHERE name=?", -1, &statement, NULL);',
            '  sqlite3_bind_text(statement, 1, [userName UTF8String], -1, SQLITE_TRANSIENT);',
            "",
            "✓ SAFE - Core Data NSPredicate:",
            '  NSPredicate *predicate = [NSPredicate predicateWithFormat:@"name == %@", userName];',
            '  // Core Data handles escaping automatically',
            "",
            "✓ SAFE - FMDB (with parameters):",
            '  [db executeQuery:@"SELECT * FROM users WHERE name=?", userName];',
            "",
            "References:",
            "  • OWASP: SQL Injection Prevention",
            "  • OWASP MASVS-CODE: Input validation & injection",
        ]

        findings.append(FindingBlock(
            title="Remediation: Safe SQL Practices",
            evidence=remediation,
            open_by_default=False
        ))

    # Check for safe patterns
    if safe_indicators and not unsafe_matches:
        safe_map = {
            r'\?': "Found '?' placeholders (typical for prepared statements / sqlite3_bind usage)",
            r'sqlite3_bind': "Found sqlite3_bind* symbols (binding parameters safely)",
            r'bindParameter': "Found bindParameter usage (likely parameter binding)",
            r'NSPredicate': "Found NSPredicate (Core Data parameterization)",
        }
        evidence_lines = ["✓ Detected safe SQL indicators:", ""]
        for indicator in safe_indicators:
            desc = safe_map.get(indicator, f"Indicator: {indicator}")
            evidence_lines.append(f"  • {desc}")

        evidence_lines.append("")
        evidence_lines.append(
            "Inference: binary strings show parameter placeholders; verify at source that values are bound "
            "with sqlite3_bind* / NSPredicate rather than string interpolation."
        )

        findings.append(FindingBlock(
            title="Safe SQL Usage Detected",
            evidence=evidence_lines,
            open_by_default=False
        ))

    # Build summary
    summary_lines = []
    if unsafe_matches:
        summary_lines.append(f"❌ Found {len(unsafe_matches)} unsafe SQL pattern type(s)")
        summary_lines.append("CRITICAL: High risk of SQL injection vulnerabilities")
        summary_lines.append("Use parameterized queries (sqlite3_bind, NSPredicate)")
    else:
        summary_lines.append("✓ No obvious unsafe SQL patterns detected")
        if safe_indicators:
            summary_lines.append(f"✓ Detected {len(safe_indicators)} safe SQL indicator(s)")

    return TestResult(
        id="CODE-SQLINJECTION",
        name="SQL Injection Pattern Detection",
        status=status,
        summary=summary_lines,
        findings=findings,
        mastg_ref_html=sql_ref_html
    )

def check_webview_security(app_dir: str, base: str) -> TestResult:
    """
    Comprehensive WebView security analysis for iOS.

    MASTG References:
    - MASTG-TEST-0076: Testing iOS WebViews
    - MASTG-TEST-0077: Determining Whether Native Methods Are Exposed Through WebViews
    - MASTG-TEST-0078: Testing WebView Protocol Handlers
    """
    summary_lines: List[str] = []
    findings: List[FindingBlock] = []
    status: Status = "PASS"

    # WebView type detection patterns
    webview_types = {
        'WKWebView': (r'\bWKWebView\b', 'Modern WebView (recommended)', 'PASS'),
        'UIWebView': (r'\bUIWebView\b', 'Deprecated WebView (iOS 12+)', 'FAIL'),
        'SFSafariViewController': (r'\bSFSafariViewController\b', 'Safari View Controller', 'PASS'),
    }

    # Security-sensitive WebView APIs
    webview_apis = {
        # JavaScript execution
        'evaluateJavaScript': (r'\bevaluateJavaScript\b', 'JavaScript execution', 'WARN'),
        'stringByEvaluatingJavaScript': (r'\bstringByEvaluatingJavaScript\b', 'JavaScript execution (deprecated)', 'WARN'),

        # JavaScript bridges (message handlers)
        'addScriptMessageHandler': (r'\baddScriptMessageHandler\b', 'JavaScript bridge to native', 'WARN'),
        'WKScriptMessageHandler': (r'\bWKScriptMessageHandler\b', 'JavaScript message handler protocol', 'WARN'),

        # Configuration
        'javaScriptEnabled': (r'javaScriptEnabled\s*=\s*true', 'JavaScript enabled', 'INFO'),
        'javaScriptCanOpenWindowsAutomatically': (r'javaScriptCanOpenWindowsAutomatically', 'JavaScript window opening', 'WARN'),

        # File access
        'allowFileAccessFromFileURLs': (r'allowFileAccessFromFileURLs', 'File access from file URLs', 'FAIL'),
        'allowUniversalAccessFromFileURLs': (r'allowUniversalAccessFromFileURLs', 'Universal file access', 'FAIL'),
        'loadFileURL': (r'\bloadFileURL\b', 'Loading file:// URLs', 'WARN'),

        # URL loading
        'loadHTMLString': (r'\bloadHTMLString\b', 'Loading HTML strings', 'INFO'),
        'load.*URLRequest': (r'load\s*\(\s*URLRequest', 'Loading URL requests', 'INFO'),

        # Custom URL schemes
        'WKURLSchemeHandler': (r'\bWKURLSchemeHandler\b', 'Custom URL scheme handler', 'WARN'),
        'setURLSchemeHandler': (r'\bsetURLSchemeHandler\b', 'Registering URL scheme handler', 'WARN'),
    }

    # Track usage
    webview_usage = {}
    api_usage = {}
    deprecated_found = False
    insecure_config_found = False

    # Detect WebView types
    for wv_type, (pattern, description, severity) in webview_types.items():
        matching_files = grep_code(app_dir, pattern)

        if matching_files:
            webview_usage[wv_type] = {
                'count': len(matching_files),
                'description': description,
                'severity': severity,
                'files': matching_files[:5]
            }

            if severity == 'FAIL':
                deprecated_found = True
                status = "FAIL"

    # Detect API usage
    for api_name, (pattern, description, severity) in webview_apis.items():
        matching_files = grep_code(app_dir, pattern)

        if matching_files:
            api_usage[api_name] = {
                'count': len(matching_files),
                'description': description,
                'severity': severity,
                'files': matching_files[:5]
            }

            if severity == 'FAIL':
                insecure_config_found = True
                if status == "PASS":
                    status = "FAIL"
            elif severity == 'WARN' and status == "PASS":
                status = "WARN"

    # Build summary
    if webview_usage:
        summary_lines.append(f"WebView usage detected: {len(webview_usage)} type(s)")

        for wv_type, wv_data in webview_usage.items():
            severity_icon = {"FAIL": "✗", "WARN": "⚠", "PASS": "✓", "INFO": "•"}[wv_data['severity']]
            summary_lines.append(f"{severity_icon} {wv_type}: {wv_data['count']} usage(s) - {wv_data['description']}")
    else:
        summary_lines.append("No WebView usage detected")
        status = "INFO"

    # Summarize critical APIs
    if api_usage:
        critical_apis = {k: v for k, v in api_usage.items() if v['severity'] in ['FAIL', 'WARN']}
        if critical_apis:
            summary_lines.append(f"Security-sensitive APIs: {len(critical_apis)} detected")

    # Build findings for deprecated UIWebView
    if deprecated_found:
        for file_path in webview_usage.get('UIWebView', {}).get('files', []):
            rel_path = rel(file_path, base)
            snippets = extract_snippet_with_context(file_path, webview_types['UIWebView'][0], context_lines=3, max_matches=2)

            for line_num, matched_line, snippet in snippets:
                findings.append(FindingBlock(
                    title=os.path.basename(file_path),
                    subtitle=f"Line {line_num}: UIWebView (Deprecated)",
                    link=make_file_link(base, rel_path, line_num),
                    code=snippet,
                    code_language="swift" if file_path.endswith('.swift') else "objc",
                    open_by_default=True,
                    evidence=[
                        "🔴 DEPRECATED: UIWebView is deprecated since iOS 12",
                        "Risk: Security vulnerabilities, no longer receives security updates",
                        "App Store may reject apps using UIWebView",
                        "Recommendation: Migrate to WKWebView immediately"
                    ]
                ))

    # Build findings for insecure file access
    if insecure_config_found:
        insecure_apis = {k: v for k, v in api_usage.items() if v['severity'] == 'FAIL'}

        for api_name, api_data in insecure_apis.items():
            for file_path in api_data['files']:
                rel_path = rel(file_path, base)
                snippets = extract_snippet_with_context(file_path, webview_apis[api_name][0], context_lines=4, max_matches=2)

                for line_num, matched_line, snippet in snippets:
                    findings.append(FindingBlock(
                        title=os.path.basename(file_path),
                        subtitle=f"Line {line_num}: {api_name}",
                        link=make_file_link(base, rel_path, line_num),
                        code=snippet,
                        code_language="swift" if file_path.endswith('.swift') else "objc",
                        open_by_default=True,
                        evidence=[
                            f"🔴 INSECURE: {api_data['description']}",
                            "Risk: Local file access, XSS, arbitrary file reading",
                            "Recommendation: Disable file access or use strict content security policies"
                        ]
                    ))

    # Build findings for JavaScript bridges (WARN level)
    js_bridge_apis = {k: v for k, v in api_usage.items() if 'ScriptMessage' in k or k == 'evaluateJavaScript'}
    if js_bridge_apis:
        bridge_summary = "JavaScript Bridge APIs detected:\n\n"
        for api_name, api_data in js_bridge_apis.items():
            bridge_summary += f"⚠ {api_name}: {api_data['count']} usage(s)\n"
            bridge_summary += f"  {api_data['description']}\n\n"

        bridge_summary += "\nSecurity Considerations:\n"
        bridge_summary += "• Validate all messages from JavaScript\n"
        bridge_summary += "• Sanitize data before passing to native code\n"
        bridge_summary += "• Avoid exposing sensitive native methods\n"
        bridge_summary += "• Implement proper authentication/authorization\n"

        # Find one example to show
        for api_name in ['addScriptMessageHandler', 'evaluateJavaScript']:
            if api_name in js_bridge_apis:
                file_path = js_bridge_apis[api_name]['files'][0]
                rel_path = rel(file_path, base)
                snippets = extract_snippet_with_context(file_path, webview_apis[api_name][0], context_lines=4, max_matches=1)

                if snippets:
                    line_num, matched_line, snippet = snippets[0]
                    findings.append(FindingBlock(
                        title=f"JavaScript Bridge Example: {api_name}",
                        subtitle=f"{os.path.basename(file_path)}:{line_num}",
                        link=make_file_link(base, rel_path, line_num),
                        code=snippet,
                        code_language="swift" if file_path.endswith('.swift') else "objc",
                        open_by_default=False,
                        evidence=[line.strip() for line in bridge_summary.split('\n') if line.strip()]
                    ))
                    break

    # Add recommendations if WebView usage found but no major issues
    if webview_usage and status == "PASS":
        findings.append(FindingBlock(
            title="WebView Security Best Practices",
            subtitle="Verify these additional security measures",
            evidence=[
                "✓ Using modern WKWebView (good!)",
                "",
                "Additional security checklist:",
                "• Validate all URLs before loading (whitelist allowed domains)",
                "• Implement WKNavigationDelegate for request filtering",
                "• Use Content Security Policy (CSP) headers",
                "• Disable JavaScript if not needed",
                "• Sanitize user input in HTML/JavaScript",
                "• Avoid loading untrusted remote content",
                "• Implement certificate pinning for HTTPS connections",
                "• Clear WebView cache/cookies on logout"
            ],
            open_by_default=False
        ))

    # Add info if no WebView usage
    if not webview_usage:
        findings.append(FindingBlock(
            title="No WebView Usage Detected",
            subtitle="App does not appear to use WebViews",
            evidence=[
                "No WKWebView or UIWebView usage detected in source code.",
                "",
                "Note: This is based on static analysis of available source files.",
                "WebViews in compiled frameworks/libraries may not be detected."
            ],
            open_by_default=False
        ))

    return TestResult(
        name="WebView Security Configuration",
        status=status,
        summary_lines=summary_lines,
        mastg_ref_html=mastg_ref(
            ["MASTG-TEST-0076", "MASTG-TEST-0077", "MASTG-TEST-0078"],
            ["Testing iOS WebViews",
             "Determining Whether Native Methods Are Exposed Through WebViews",
             "Testing WebView Protocol Handlers"]
        ),
        findings=findings
    )

def check_certificate_pinning(app_dir: str, base: str) -> TestResult:
    """
    Comprehensive certificate pinning detection and analysis.

    MASTG References:
    - MASTG-TEST-0068: Testing Custom Certificate Stores and Certificate Pinning
    - MASTG-TEST-0065: Testing Data Encryption on the Network
    """
    summary_lines: List[str] = []
    findings: List[FindingBlock] = []
    status: Status = "WARN"  # Default to WARN since pinning should be implemented

    # Certificate pinning patterns (iOS-specific)
    pinning_patterns = {
        # TrustKit framework (popular pinning library)
        'TrustKit': (r'\bTrustKit\b', 'TrustKit certificate pinning framework', 'PASS'),
        'TSKPinningValidator': (r'\bTSKPinningValidator\b', 'TrustKit pinning validator', 'PASS'),
        'TSKConfiguration': (r'\bTSKConfiguration\b', 'TrustKit configuration', 'PASS'),

        # URLSession challenge handling
        'URLAuthenticationChallenge': (r'\bURLAuthenticationChallenge\b', 'URLSession authentication challenge', 'INFO'),
        'didReceiveChallenge': (r'didReceiveChallenge', 'Challenge handler method', 'INFO'),
        'serverTrust': (r'serverTrust', 'Server trust evaluation', 'INFO'),

        # SecTrust APIs (manual pinning)
        'SecTrustEvaluate': (r'\bSecTrustEvaluate\b', 'Certificate trust evaluation', 'INFO'),
        'SecTrustCopyPublicKey': (r'\bSecTrustCopyPublicKey\b', 'Public key extraction', 'PASS'),
        'SecCertificateCopyData': (r'\bSecCertificateCopyData\b', 'Certificate data extraction', 'INFO'),
        'SecPolicyCopyProperties': (r'\bSecPolicyCopyProperties\b', 'Policy properties check', 'INFO'),

        # ATS (App Transport Security) - related
        'NSPinnedDomains': (r'NSPinnedDomains', 'ATS pinned domains', 'PASS'),
        'NSIncludesSubdomains': (r'NSIncludesSubdomains', 'ATS subdomain inclusion', 'INFO'),

        # Generic pinning keywords
        'publicKeyHash': (r'publicKeyHash', 'Public key hash pinning', 'PASS'),
        'certificatePin': (r'certificatePin', 'Certificate pinning implementation', 'PASS'),
        'pinnedCertificates': (r'pinnedCertificates', 'Pinned certificates array', 'PASS'),
        'validateCertificate': (r'validateCertificate', 'Custom certificate validation', 'INFO'),

        # SSL/TLS delegate bypass patterns (INSECURE)
        'continueWithoutCredential': (r'continueWithoutCredential', 'INSECURE: Bypassing certificate validation', 'FAIL'),
        'kSecTrustResultProceed': (r'kSecTrustResultProceed', 'Proceeding with untrusted cert', 'WARN'),
    }

    # Track findings by category
    pinning_found = False
    trustkit_found = False
    manual_pinning_found = False
    challenge_handling_found = False
    insecure_bypass_found = False

    api_usage = {}

    # Search for patterns
    for pattern_name, (pattern, description, severity) in pinning_patterns.items():
        matching_files = grep_code(app_dir, pattern)

        if matching_files:
            api_usage[pattern_name] = {
                'count': len(matching_files),
                'description': description,
                'severity': severity,
                'files': matching_files[:5]
            }

            if 'TrustKit' in pattern_name:
                trustkit_found = True
                pinning_found = True
            elif severity == 'PASS' and 'pin' in pattern_name.lower():
                manual_pinning_found = True
                pinning_found = True
            elif severity == 'INFO' and ('Challenge' in pattern_name or 'SecTrust' in pattern_name):
                challenge_handling_found = True
            elif severity == 'FAIL':
                insecure_bypass_found = True

    # Determine status
    if insecure_bypass_found:
        status = "FAIL"
    elif pinning_found:
        status = "PASS"
    elif challenge_handling_found:
        status = "INFO"  # Challenge handling present but pinning not confirmed
    else:
        status = "WARN"  # No pinning detected

    # Build summary
    if pinning_found:
        summary_lines.append(f"✓ Certificate pinning detected: {len([k for k, v in api_usage.items() if v['severity'] == 'PASS'])} implementation(s)")

        if trustkit_found:
            summary_lines.append("  • TrustKit framework detected (recommended)")
        if manual_pinning_found:
            summary_lines.append("  • Manual pinning implementation detected")
    else:
        summary_lines.append("✗ No certificate pinning detected")

    if challenge_handling_found:
        summary_lines.append(f"• URLSession challenge handling detected ({len([k for k in api_usage if 'Challenge' in k or 'Trust' in k])} API(s))")

    if insecure_bypass_found:
        summary_lines.append("🔴 INSECURE: Certificate validation bypass detected!")

    # Build findings for TrustKit usage
    if trustkit_found:
        trustkit_apis = {k: v for k, v in api_usage.items() if 'TrustKit' in k or 'TSK' in k}

        trustkit_summary = "TrustKit Certificate Pinning Framework:\n\n"
        for api_name, api_data in trustkit_apis.items():
            trustkit_summary += f"✓ {api_name}: {api_data['count']} usage(s)\n"

        trustkit_summary += "\nTrustKit provides:\n"
        trustkit_summary += "• Public key and certificate pinning\n"
        trustkit_summary += "• Backup pin support\n"
        trustkit_summary += "• Pinning configuration via Info.plist\n"
        trustkit_summary += "• Automatic reporting of pin validation failures\n"

        # Find example usage
        for api_name in ['TrustKit', 'TSKConfiguration', 'TSKPinningValidator']:
            if api_name in trustkit_apis:
                file_path = trustkit_apis[api_name]['files'][0]
                rel_path = rel(file_path, base)
                snippets = extract_snippet_with_context(file_path, pinning_patterns[api_name][0], context_lines=4, max_matches=1)

                if snippets:
                    line_num, matched_line, snippet = snippets[0]
                    findings.append(FindingBlock(
                        title=f"TrustKit Implementation: {api_name}",
                        subtitle=f"{os.path.basename(file_path)}:{line_num}",
                        link=make_file_link(base, rel_path, line_num),
                        code=snippet,
                        code_language="swift" if file_path.endswith('.swift') else "objc",
                        open_by_default=True,
                        evidence=[line.strip() for line in trustkit_summary.split('\n') if line.strip()]
                    ))
                    break

    # Build findings for manual pinning implementations
    if manual_pinning_found and not trustkit_found:
        manual_apis = {k: v for k, v in api_usage.items() if v['severity'] == 'PASS' and 'TrustKit' not in k}

        for api_name, api_data in manual_apis.items():
            file_path = api_data['files'][0]
            rel_path = rel(file_path, base)
            snippets = extract_snippet_with_context(file_path, pinning_patterns[api_name][0], context_lines=4, max_matches=1)

            if snippets:
                line_num, matched_line, snippet = snippets[0]
                findings.append(FindingBlock(
                    title=f"Manual Pinning: {api_name}",
                    subtitle=f"{os.path.basename(file_path)}:{line_num}",
                    link=make_file_link(base, rel_path, line_num),
                    code=snippet,
                    code_language="swift" if file_path.endswith('.swift') else "objc",
                    open_by_default=True,
                    evidence=[
                        f"✓ {api_data['description']}",
                        "",
                        "Verify implementation:",
                        "• Pins are validated against known good hashes",
                        "• Backup pins are configured",
                        "• Pin expiration is handled",
                        "• Pinning failures block connections"
                    ]
                ))

    # Build findings for insecure bypasses
    if insecure_bypass_found:
        bypass_apis = {k: v for k, v in api_usage.items() if v['severity'] == 'FAIL'}

        for api_name, api_data in bypass_apis.items():
            for file_path in api_data['files'][:3]:
                rel_path = rel(file_path, base)
                snippets = extract_snippet_with_context(file_path, pinning_patterns[api_name][0], context_lines=4, max_matches=2)

                for line_num, matched_line, snippet in snippets:
                    findings.append(FindingBlock(
                        title=os.path.basename(file_path),
                        subtitle=f"Line {line_num}: {api_name}",
                        link=make_file_link(base, rel_path, line_num),
                        code=snippet,
                        code_language="swift" if file_path.endswith('.swift') else "objc",
                        open_by_default=True,
                        evidence=[
                            f"🔴 CRITICAL: {api_data['description']}",
                            "Risk: Man-in-the-middle attacks, certificate validation bypass",
                            "This allows ALL certificates to be accepted, including attacker-controlled certs",
                            "Recommendation: Remove bypass and implement proper certificate pinning"
                        ]
                    ))

    # Add recommendations if challenge handling found but no pinning
    if challenge_handling_found and not pinning_found:
        findings.append(FindingBlock(
            title="URLSession Challenge Handling Detected",
            subtitle="Certificate pinning not confirmed",
            evidence=[
                "URLSession challenge handling methods detected:",
                "",
                "Detected APIs:"] + 
                [f"  • {k}: {v['count']} usage(s)" for k, v in api_usage.items() if 'Challenge' in k or 'Trust' in k] + 
                ["",
                 "⚠ Challenge handling alone does NOT guarantee pinning",
                 "",
                 "Verify that challenge handler:",
                 "• Extracts server certificate/public key",
                 "• Compares against known good pins",
                 "• Rejects connections on pin mismatch",
                 "• Does NOT use continueWithoutCredential"
                ],
            open_by_default=True
        ))

    # Add warning if no pinning at all
    if not pinning_found and not challenge_handling_found:
        findings.append(FindingBlock(
            title="No Certificate Pinning Detected",
            subtitle="App may be vulnerable to MITM attacks",
            evidence=[
                "❌ No certificate pinning implementation detected",
                "",
                "Risks without pinning:",
                "• Man-in-the-middle attacks using rogue certificates",
                "• Compromised or fraudulent Certificate Authorities",
                "• Network-level SSL interception",
                "",
                "Recommended solutions:",
                "1. Use TrustKit framework (easiest, well-tested)",
                "2. Implement public key pinning via URLSession delegates",
                "3. Use NSPinnedDomains in ATS configuration",
                "",
                "OWASP MASTG recommends pinning for:",
                "• Authentication endpoints",
                "• Payment/financial transactions",
                "• Sensitive user data transmission"
            ],
            open_by_default=True
        ))

    # Check Info.plist for ATS pinning configuration
    info_plist_path = os.path.join(app_dir, "Info.plist")
    if os.path.exists(info_plist_path):
        try:
            with open(info_plist_path, 'rb') as f:
                plist_data = plistlib.load(f)
                ats = plist_data.get("NSAppTransportSecurity", {})
                pinned_domains = ats.get("NSPinnedDomains", {})

                if pinned_domains:
                    summary_lines.append(f"✓ ATS NSPinnedDomains configured: {len(pinned_domains)} domain(s)")
                    pinning_found = True
                    if status == "WARN":
                        status = "PASS"

                    # Build evidence showing plist structure
                    evidence_lines = ["NSAppTransportSecurity:", "  NSPinnedDomains:"]
                    for domain in pinned_domains.keys():
                        evidence_lines.append(f"    - {domain}")
                        domain_config = pinned_domains[domain]
                        if isinstance(domain_config, dict):
                            for key, val in sorted(domain_config.items())[:10]:  # Limit settings per domain
                                evidence_lines.append(f"        {key}: {val}")

                    findings.append(FindingBlock(
                        title="ATS Certificate Pinning Configuration",
                        subtitle=f"Info.plist: NSPinnedDomains ({len(pinned_domains)} domains)",
                        evidence=evidence_lines,
                        open_by_default=True
                    ))
        except Exception:
            pass

    return TestResult(
        name="Certificate Pinning Implementation",
        status=status,
        summary_lines=summary_lines,
        mastg_ref_html=mastg_ref(
            ["MASTG-TEST-0068", "MASTG-TEST-0065"],
            ["Testing Custom Certificate Stores and Certificate Pinning",
             "Testing Data Encryption on the Network"]
        ),
        findings=findings
    )

def check_url_and_keyboard_security(info: Dict, main_bin: str, info_path: str, base: str) -> TestResult:
    """
    Check URL scheme validation and third-party keyboard restrictions with deep code analysis.

    MASTG References:
    - MASTG-TEST-0069: Testing Custom URL Schemes
    - MASTG-TEST-0059: Finding Sensitive Data in the Keyboard Cache
    """

    findings = []
    tables_html: List[str] = []
    issues = []
    status: Status = "PASS"

    # Get URL schemes from Info.plist
    url_types = info.get("CFBundleURLTypes", []) or []
    schemes = []
    for ut in url_types:
        for s in (ut.get("CFBundleURLSchemes", []) or []):
            if s:
                schemes.append(str(s))

    # Deep analysis using multiple techniques
    strings_output = strings_dump(main_bin, timeout=60)

    # 1. Find URL handler methods using nm/symbols
    url_handler_methods = []
    rc_nm, nm_output = run(["/usr/bin/nm", "-gU", main_bin], timeout=30)
    if rc_nm == 0:
        url_handler_patterns = [
            r'openURL',
            r'handleURL',
            r'handleDeepLink',
            r'processURL',
            r'parseURL',
            r'handleUniversalLink',
        ]
        for line in nm_output.splitlines():
            for pattern in url_handler_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Extract method name
                    parts = line.split()
                    if len(parts) >= 3:
                        symbol = parts[2]
                        url_handler_methods.append(symbol)
                    break

    # 2. Look for validation indicators in strings
    validation_indicators = {
        'Strong': [],
        'Medium': [],
        'Weak': [],
    }

    if strings_output:
        # Strong validation indicators
        strong_patterns = [
            (r'NSRegularExpression', "Regex validation"),
            (r'predicateWithFormat', "NSPredicate validation"),
            (r'componentsSeparatedBy.*scheme', "URL scheme parsing"),
            (r'allowedSchemes', "Allowlist checking"),
            (r'validURL', "URL validation function"),
            (r'sanitize', "Input sanitization"),
        ]

        # Medium validation indicators
        medium_patterns = [
            (r'hasPrefix:', "Prefix checking"),
            (r'hasSuffix:', "Suffix checking"),
            (r'rangeOfString:', "String search"),
            (r'containsString:', "Contains check"),
            (r'isEqualToString:', "Equality check"),
        ]

        # Weak/concerning patterns
        weak_patterns = [
            (r'absoluteString', "Raw URL string access (no validation)"),
            (r'stringByAppendingString', "String concatenation (injection risk)"),
            (r'stringWithFormat.*%@', "String formatting (injection risk)"),
        ]

        for pattern, desc in strong_patterns:
            if any(re.search(pattern, s, re.IGNORECASE) for s in strings_output):
                validation_indicators['Strong'].append(desc)

        for pattern, desc in medium_patterns:
            if any(re.search(pattern, s, re.IGNORECASE) for s in strings_output):
                validation_indicators['Medium'].append(desc)

        for pattern, desc in weak_patterns:
            if any(re.search(pattern, s, re.IGNORECASE) for s in strings_output):
                validation_indicators['Weak'].append(desc)

    # 3. Try to use jtool2 for deeper analysis (if available)
    jtool2_analysis = []
    rc_jtool, jtool_check = run(["which", "jtool2"], timeout=5)
    has_jtool2 = (rc_jtool == 0 and jtool_check.strip())

    if has_jtool2 and url_handler_methods:
        # Try to disassemble first URL handler method
        first_handler = url_handler_methods[0]
        rc_dis, dis_output = run(["jtool2", "-d", "__TEXT,__text", main_bin], timeout=30)

        if rc_dis == 0:
            # Look for validation patterns in disassembly near the handler
            # This is a simplified check - full analysis would be more complex
            if "cmp" in dis_output and ("test" in dis_output or "jz" in dis_output):
                jtool2_analysis.append("✓ Found comparison/branching instructions (suggests validation logic)")

            if "NSRegularExpression" in dis_output or "predicateWithFormat" in dis_output:
                jtool2_analysis.append("✓ Found regex/predicate calls in code")

    # 4. Analyze symbols for dangerous functions
    dangerous_functions = []
    if rc_nm == 0:
        unsafe_patterns = [
            (r'_system', "system() - command injection risk"),
            (r'_exec', "exec() - command injection risk"),
            (r'_popen', "popen() - command injection risk"),
            (r'_dlopen', "dlopen() - dynamic loading risk"),
            (r'_NSClassFromString', "NSClassFromString - dynamic instantiation"),
        ]

        for pattern, desc in unsafe_patterns:
            if re.search(pattern, nm_output):
                dangerous_functions.append(desc)

    # Consolidated evidence table
    has_strong = len(validation_indicators['Strong']) > 0
    has_medium = len(validation_indicators['Medium']) > 0
    has_weak = len(validation_indicators['Weak']) > 0

    evidence_rows: List[List[str]] = []

    if schemes:
        for scheme in sorted(set(schemes)):
            evidence_rows.append(["URL Scheme", f"{scheme}://", "Declared in Info.plist"])
    else:
        evidence_rows.append(["URL Scheme", "None", "No CFBundleURLTypes entries"])

    if url_handler_methods:
        for method in url_handler_methods:
            demangled = method
            if method.startswith("_$"):
                demangled = method.replace("_$s", "").replace("_", " ")
            evidence_rows.append(["URL Handler", demangled, "Symbol present in binary"])
    elif schemes:
        evidence_rows.append(["URL Handler", "None found", "Symbols may be stripped; verify at runtime"])

    for indicator in validation_indicators['Strong']:
        evidence_rows.append(["Validation (strong)", indicator, "Detected in binary strings"])
        status = "INFO"

    for indicator in validation_indicators['Medium']:
        evidence_rows.append(["Validation (medium)", indicator, "Basic string checks - verify robustness"])
        if status == "PASS":
            status = "WARN"

    for indicator in validation_indicators['Weak']:
        evidence_rows.append(["Validation (weak)", indicator, "May be unsafe for untrusted input"])
        status = "WARN"

    if schemes and not (has_strong or has_medium or has_weak):
        evidence_rows.append(["Validation", "None detected", "High risk: add allowlists/regex checks"])
        status = "FAIL"
        issues.append("No URL validation detected")

    if dangerous_functions:
        for func in dangerous_functions:
            evidence_rows.append(["Dangerous function", func, "Do not call with URL-controlled data"])
        status = "FAIL"
        issues.append("Dangerous functions detected")

    if jtool2_analysis:
        for entry in jtool2_analysis:
            evidence_rows.append(["Disassembly", entry, "jtool2 scan"])

    # Check keyboard restrictions
    secure_text_indicators = [
        r'isSecureTextEntry',
        r'secureTextEntry',
        r'UITextContentType',
        r'textContentType'
    ]

    has_secure_text = False
    if strings_output:
        for pattern in secure_text_indicators:
            if any(re.search(pattern, s) for s in strings_output):
                has_secure_text = True
                break

    if has_secure_text:
        evidence_rows.append(["Keyboard security", "Secure text keywords found", "Verify correct usage at runtime"])
    else:
        evidence_rows.append(["Keyboard security", "No secure text indicators", "Manually test sensitive fields"])

    if evidence_rows:
        tables_html.append(render_filterable_table(
            f"urlKeyboard-{uuid.uuid4().hex[:6]}",
            ["Type", "Detail", "Notes"],
            evidence_rows,
            "URL Scheme / Keyboard Evidence"
        ))

    if schemes:
        findings.append(FindingBlock(
            title="Info.plist reference",
            link=make_file_link(base, rel(info_path, base)),
            evidence=[f"{len(schemes)} scheme(s) declared in Info.plist"],
            open_by_default=False
        ))

    # Short guidance (keep concise)
    findings.append(FindingBlock(
        title="Manual checks to validate",
        evidence=[
            "URL: Hook application:openURL:options: and fuzz inputs (symbols listed in table).",
            "Keyboard: Open sensitive fields and confirm system keyboard + isSecureTextEntry.",
            "Prefer Universal Links (https) and strict allowlists for schemes/parameters."
        ],
        open_by_default=False
    ))

    # Summary
    summary_lines = []
    if schemes:
        summary_lines.append(f"Found {len(schemes)} custom URL scheme(s)")

        # Build detailed summary based on analysis
        if url_handler_methods:
            summary_lines.append(f"✓ Identified {len(url_handler_methods)} URL handler method(s) in binary")

        if validation_indicators['Strong']:
            summary_lines.append(f"✓ Strong validation detected: {', '.join(validation_indicators['Strong'][:2])}")
        elif validation_indicators['Medium']:
            summary_lines.append(f"⚠ Basic validation detected: {', '.join(validation_indicators['Medium'][:2])}")
        else:
            summary_lines.append("❌ NO validation indicators found - CRITICAL RISK")

        if dangerous_functions:
            summary_lines.append(f"❌ {len(dangerous_functions)} dangerous function(s) detected (system, exec, etc.)")

        if jtool2_analysis:
            summary_lines.append(f"🔍 Disassembly analysis: {len(jtool2_analysis)} finding(s)")
    else:
        summary_lines.append("No custom URL schemes declared")

    if has_secure_text:
        summary_lines.append("ℹ Secure text keywords found - verify correct usage at runtime")
    else:
        summary_lines.append("⚠ No secure text indicators - test keyboard behavior manually")

    return TestResult(
        id="PLATFORM-URLKEYBOARD",
        name="URL Scheme & Keyboard Security",
        status=status,
        summary_lines=summary_lines,
        findings=findings,
        tables_html=tables_html,
        mastg_ref_html=mastg_ref(["MASTG-TEST-0069", "MASTG-TEST-0059"],
                                 ["Testing Custom URL Schemes", "Keyboard Cache Security"])
    )

def check_xpc_services(app_dir: str, base: str) -> TestResult:
    """
    Analyze XPC services for security issues.

    MASTG References:
    - MASTG-TEST-0070: Testing App Permissions
    """

    # Check for XPCServices directory
    xpc_dir = os.path.join(app_dir, "XPCServices")

    if not os.path.exists(xpc_dir):
        return TestResult(
            id="PLATFORM-XPC",
            name="XPC Services Analysis",
            status="PASS",
            summary=["No XPC services found (no XPCServices directory)"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0070"], ["Testing App Permissions"])
        )

    # Find all .xpc bundles
    xpc_services = []
    for item in os.listdir(xpc_dir):
        if item.endswith(".xpc"):
            xpc_path = os.path.join(xpc_dir, item)
            if os.path.isdir(xpc_path):
                xpc_services.append((item, xpc_path))

    if not xpc_services:
        return TestResult(
            id="PLATFORM-XPC",
            name="XPC Services Analysis",
            status="PASS",
            summary=["XPCServices directory exists but no .xpc services found"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0070"], ["Testing App Permissions"])
        )

    findings = []
    status: Status = "INFO"

    for xpc_name, xpc_path in xpc_services:
        # Parse Info.plist
        info_path = os.path.join(xpc_path, "Contents", "Info.plist")
        if not os.path.exists(info_path):
            # Try without Contents directory
            info_path = os.path.join(xpc_path, "Info.plist")

        if not os.path.exists(info_path):
            findings.append(FindingBlock(
                title=f"XPC Service: {xpc_name}",
                evidence=[f"Path: {rel(xpc_path, base)}", "⚠ No Info.plist found"]
            ))
            continue

        try:
            xpc_info = plutil_to_plist(info_path)
        except Exception as e:
            findings.append(FindingBlock(
                title=f"XPC Service: {xpc_name}",
                evidence=[f"Path: {rel(xpc_path, base)}", f"⚠ Failed to parse Info.plist: {e}"]
            ))
            continue

        service_name = xpc_info.get("CFBundleDisplayName") or xpc_info.get("CFBundleName", xpc_name)

        # Get XPC service type
        xpc_service_type = xpc_info.get("XPCService", {})
        service_type = xpc_service_type.get("ServiceType", "Unknown")
        run_loop_type = xpc_service_type.get("RunLoopType", "Unknown")

        evidence_lines = [
            f"Service Name: {service_name}",
            f"Path: {rel(xpc_path, base)}",
            "",
            f"Service Type: {service_type}",
            f"Run Loop Type: {run_loop_type}",
            ""
        ]

        # Check service type security implications
        if service_type == "Application":
            evidence_lines.append("Type: Application Service")
            evidence_lines.append("  • Runs in the app's security context")
            evidence_lines.append("  • Standard privilege level")
        elif service_type == "System":
            evidence_lines.append("Type: System Service")
            evidence_lines.append("  ⚠ Runs with system privileges - ensure proper validation!")
            status = "WARN"

        evidence_lines.append("")

        # Check for entitlements
        xpc_binary = None
        contents_dir = os.path.join(xpc_path, "Contents", "MacOS")
        if os.path.exists(contents_dir):
            for item in os.listdir(contents_dir):
                item_path = os.path.join(contents_dir, item)
                if os.path.isfile(item_path) and os.access(item_path, os.X_OK):
                    xpc_binary = item_path
                    break

        if xpc_binary:
            rc, ent_xml = run(["/usr/bin/codesign", "-d", "--entitlements", ":-", xpc_binary], timeout=30)
            if rc == 0 and ent_xml.strip():
                try:
                    entitlements = plistlib.loads(ent_xml.encode("utf-8"))

                    evidence_lines.append("Entitlements:")
                    for key in sorted(entitlements.keys())[:10]:
                        value = entitlements[key]
                        evidence_lines.append(f"  • {key}: {value}")

                    if len(entitlements) > 10:
                        evidence_lines.append(f"  ... and {len(entitlements) - 10} more")
                except:
                    pass

        evidence_lines.append("")
        evidence_lines.append("Security Considerations:")
        evidence_lines.append("  • XPC services have separate security boundaries")
        evidence_lines.append("  • Validate all messages from clients")
        evidence_lines.append("  • Use NSSecureCoding for object serialization")
        evidence_lines.append("  • Implement proper authorization checks")
        evidence_lines.append("  • Minimize exposed API surface")

        findings.append(FindingBlock(
            title=f"XPC Service: {service_name}",
            link=make_file_link(base, rel(xpc_path, base)),
            evidence=evidence_lines,
            open_by_default=False
        ))

    summary_lines = [
        f"Found {len(xpc_services)} XPC service(s)",
        "ℹ Review XPC service security boundaries and message validation"
    ]

    return TestResult(
        id="PLATFORM-XPC",
        name="XPC Services Analysis",
        status=status,
        summary=summary_lines,
        findings=findings,
        mastg_ref_html=mastg_ref(["MASTG-TEST-0070"], ["Testing App Permissions"])
    )

def check_biometric_authentication(app_dir: str, base: str) -> TestResult:
    """
    Comprehensive biometric authentication security analysis.

    MASTG References:
    - MASTG-TEST-0064: Testing Local Authentication
    - MASTG-TEST-0266: Testing Biometric Authentication
    - MASTG-TEST-0267: Testing the Biometric Authentication Implementation
    """
    summary_lines: List[str] = []
    findings: List[FindingBlock] = []
    status: Status = "PASS"

    # LocalAuthentication framework patterns
    biometric_patterns = {
        # Framework import
        'LocalAuthentication': (r'import\s+LocalAuthentication', 'LocalAuthentication framework', 'INFO'),
        'LAContext': (r'\bLAContext\b', 'Local Authentication context', 'INFO'),

        # Policies
        'deviceOwnerAuthenticationWithBiometrics': (r'deviceOwnerAuthenticationWithBiometrics', 'Biometrics only (no passcode fallback)', 'WARN'),
        'deviceOwnerAuthentication': (r'\bdeviceOwnerAuthentication\b', 'Biometrics with passcode fallback', 'PASS'),

        # Evaluation
        'evaluatePolicy': (r'evaluatePolicy', 'Policy evaluation method', 'INFO'),
        'canEvaluatePolicy': (r'canEvaluatePolicy', 'Checking biometric availability', 'INFO'),

        # Configuration
        'localizedFallbackTitle': (r'localizedFallbackTitle', 'Fallback button configuration', 'INFO'),
        'localizedReason': (r'localizedReason', 'Biometric prompt reason', 'INFO'),

        # Keychain integration
        'SecAccessControlCreateWithFlags': (r'SecAccessControlCreateWithFlags', 'Keychain access control', 'PASS'),
        'kSecAttrAccessControl': (r'kSecAttrAccessControl', 'Biometric-protected Keychain item', 'PASS'),
        'biometryAny': (r'biometryAny', 'Any biometry type allowed', 'INFO'),
        'biometryCurrentSet': (r'biometryCurrentSet', 'Current biometry set required', 'PASS'),

        # Error handling
        'LAError': (r'\bLAError\b', 'LocalAuthentication error handling', 'INFO'),
        'authenticationFailed': (r'authenticationFailed', 'Authentication failure handling', 'INFO'),
        'userCancel': (r'userCancel', 'User cancellation handling', 'INFO'),
        'userFallback': (r'userFallback', 'Fallback handling', 'INFO'),

        # Insecure patterns
        'touchIDAuthenticationAllowableReuseDuration': (r'touchIDAuthenticationAllowableReuseDuration\s*=\s*(?!0)', 'Biometric reuse duration (potential bypass)', 'WARN'),
    }

    # Track usage
    biometric_usage_found = False
    secure_implementation = False
    potential_issues = []

    api_usage = {}

    # Search for patterns
    for pattern_name, (pattern, description, severity) in biometric_patterns.items():
        matching_files = grep_code(app_dir, pattern)

        if matching_files:
            api_usage[pattern_name] = {
                'count': len(matching_files),
                'description': description,
                'severity': severity,
                'files': matching_files[:5]
            }

            if pattern_name in ['LocalAuthentication', 'LAContext', 'evaluatePolicy']:
                biometric_usage_found = True

            if pattern_name in ['deviceOwnerAuthentication', 'SecAccessControlCreateWithFlags', 'biometryCurrentSet']:
                secure_implementation = True

            if severity == 'WARN':
                potential_issues.append(pattern_name)
                if status == "PASS":
                    status = "WARN"

    # Build summary
    if biometric_usage_found:
        summary_lines.append(f"✓ Biometric authentication implemented: {len(api_usage)} API(s) detected")

        # Check for specific implementations
        if 'deviceOwnerAuthenticationWithBiometrics' in api_usage:
            summary_lines.append("  ⚠ Using biometrics-only policy (no passcode fallback)")
        if 'deviceOwnerAuthentication' in api_usage:
            summary_lines.append("  ✓ Using biometrics with passcode fallback (recommended)")

        if secure_implementation:
            summary_lines.append("  ✓ Secure Keychain integration detected")

        if potential_issues:
            summary_lines.append(f"  ⚠ Potential security issues: {len(potential_issues)} detected")
    else:
        summary_lines.append("No biometric authentication detected")
        status = "INFO"

    # Build findings for implementation examples
    if biometric_usage_found:
        # Find evaluatePolicy usage
        if 'evaluatePolicy' in api_usage:
            file_path = api_usage['evaluatePolicy']['files'][0]
            rel_path = rel(file_path, base)
            snippets = extract_snippet_with_context(file_path, biometric_patterns['evaluatePolicy'][0], context_lines=5, max_matches=1)

            if snippets:
                line_num, matched_line, snippet = snippets[0]

                # Determine if secure based on context
                snippet_lower = snippet.lower()
                is_secure = 'deviceownerauthentication' in snippet_lower and 'withbiometrics' not in snippet_lower

                findings.append(FindingBlock(
                    title=f"Biometric Authentication Implementation",
                    subtitle=f"{os.path.basename(file_path)}:{line_num}",
                    link=make_file_link(base, rel_path, line_num),
                    code=snippet,
                    code_language="swift" if file_path.endswith('.swift') else "objc",
                    open_by_default=True,
                    evidence=[
                        f"{'✓' if is_secure else '⚠'} Biometric authentication call detected",
                        "",
                        "Security checklist:",
                        "✓ Use deviceOwnerAuthentication (not deviceOwnerAuthenticationWithBiometrics)",
                        "✓ Invalidate LAContext after authentication",
                        "✓ Handle biometric enrollment changes (biometryCurrentSet)",
                        "✓ Implement proper error handling",
                        "✓ Do NOT allow touchIDAuthenticationAllowableReuseDuration > 0",
                        "✓ Store sensitive data in Keychain with biometric access control"
                    ]
                ))

        # Check for insecure reuse duration
        if 'touchIDAuthenticationAllowableReuseDuration' in api_usage:
            file_path = api_usage['touchIDAuthenticationAllowableReuseDuration']['files'][0]
            rel_path = rel(file_path, base)
            snippets = extract_snippet_with_context(file_path, biometric_patterns['touchIDAuthenticationAllowableReuseDuration'][0], context_lines=3, max_matches=1)

            if snippets:
                line_num, matched_line, snippet = snippets[0]
                findings.append(FindingBlock(
                    title="Insecure Biometric Reuse Duration",
                    subtitle=f"{os.path.basename(file_path)}:{line_num}",
                    link=make_file_link(base, rel_path, line_num),
                    code=snippet,
                    code_language="swift" if file_path.endswith('.swift') else "objc",
                    open_by_default=True,
                    evidence=[
                        "⚠ WARNING: touchIDAuthenticationAllowableReuseDuration set to non-zero",
                        "",
                        "Risk: Allows biometric bypass within reuse window",
                        "• Biometric authentication can be reused without re-prompting",
                        "• Attacker with device access can exploit reuse window",
                        "",
                        "Recommendation: Set to 0 (require authentication every time)"
                    ]
                ))

        # Check for Keychain integration
        if 'SecAccessControlCreateWithFlags' in api_usage:
            file_path = api_usage['SecAccessControlCreateWithFlags']['files'][0]
            rel_path = rel(file_path, base)
            snippets = extract_snippet_with_context(file_path, biometric_patterns['SecAccessControlCreateWithFlags'][0], context_lines=4, max_matches=1)

            if snippets:
                line_num, matched_line, snippet = snippets[0]
                findings.append(FindingBlock(
                    title="Biometric Keychain Integration",
                    subtitle=f"{os.path.basename(file_path)}:{line_num}",
                    link=make_file_link(base, rel_path, line_num),
                    code=snippet,
                    code_language="swift" if file_path.endswith('.swift') else "objc",
                    open_by_default=False,
                    evidence=[
                        "✓ Biometric access control for Keychain items",
                        "",
                        "SecAccessControlCreateWithFlags allows:",
                        "• Protecting Keychain items with biometrics",
                        "• Requiring biometric authentication to access data",
                        "• Invalidating access on biometric enrollment changes",
                        "",
                        "Verify flags include:",
                        "• biometryCurrentSet (invalidate on enrollment change)",
                        "• userPresence (require authentication)"
                    ]
                ))

    else:
        # No biometric usage
        findings.append(FindingBlock(
            title="No Biometric Authentication Detected",
            subtitle="App does not use LocalAuthentication framework",
            evidence=[
                "No LocalAuthentication framework usage detected.",
                "",
                "If app handles sensitive data, consider:",
                "• Implementing biometric authentication for sensitive operations",
                "• Using LAPolicy.deviceOwnerAuthentication (biometrics + passcode)",
                "• Protecting Keychain items with biometric access control",
                "• Handling biometric availability gracefully",
                "",
                "Note: Some apps may use third-party authentication libraries."
            ],
            open_by_default=False
        ))

    return TestResult(
        name="Biometric Authentication Security",
        status=status,
        summary_lines=summary_lines,
        mastg_ref_html=mastg_ref(
            ["MASTG-TEST-0064", "MASTG-TEST-0266", "MASTG-TEST-0267"],
            ["Testing Local Authentication",
             "Testing Biometric Authentication",
             "Testing the Biometric Authentication Implementation"]
        ),
        findings=findings
    )

def check_screenshot_security(app_dir: str, base: str) -> TestResult:
    """
    Screenshot and app switcher security analysis.

    MASTG References:
    - MASTG-TEST-0059: Finding Sensitive Data in the Keyboard Cache
    - MASTG-TEST-0290: Checking for Sensitive Data Disclosure Through the User Interface
    """
    summary_lines: List[str] = []
    findings: List[FindingBlock] = []
    status: Status = "WARN"  # Default to WARN since most apps should implement protection

    # Screenshot protection patterns
    screenshot_patterns = {
        # App lifecycle methods (where protection should be implemented)
        'applicationWillResignActive': (r'applicationWillResignActive', 'App resigning active (screenshot prevention point)', 'INFO'),
        'applicationDidEnterBackground': (r'applicationDidEnterBackground', 'App entering background (screenshot prevention point)', 'INFO'),
        'sceneWillResignActive': (r'sceneWillResignActive', 'Scene resigning active (iOS 13+)', 'INFO'),
        'sceneDidEnterBackground': (r'sceneDidEnterBackground', 'Scene entering background (iOS 13+)', 'INFO'),

        # Protection mechanisms
        'isHidden': (r'\.isHidden\s*=\s*true', 'Hiding sensitive views', 'PASS'),
        'alpha': (r'\.alpha\s*=\s*0', 'Making views transparent', 'PASS'),
        'addSubview.*UIImageView': (r'addSubview.*UIImageView', 'Adding overlay view', 'PASS'),
        'insertSubview': (r'insertSubview', 'Inserting overlay view', 'PASS'),

        # TextField security
        'isSecureTextEntry': (r'isSecureTextEntry\s*=\s*true', 'Secure text entry for passwords', 'PASS'),
        'UITextField': (r'\bUITextField\b', 'Text field usage', 'INFO'),
        'UITextView': (r'\bUITextView\b', 'Text view usage', 'INFO'),

        # Insecure patterns
        'ignoresInteractionEvents': (r'ignoresInteractionEvents.*=.*true', 'Ignoring touch events', 'INFO'),
    }

    # Track usage
    lifecycle_methods_found = []
    protection_mechanisms_found = []
    secure_text_entry_found = False

    api_usage = {}

    # Search for patterns
    for pattern_name, (pattern, description, severity) in screenshot_patterns.items():
        matching_files = grep_code(app_dir, pattern)

        if matching_files:
            api_usage[pattern_name] = {
                'count': len(matching_files),
                'description': description,
                'severity': severity,
                'files': matching_files[:5]
            }

            if pattern_name in ['applicationWillResignActive', 'applicationDidEnterBackground', 'sceneWillResignActive', 'sceneDidEnterBackground']:
                lifecycle_methods_found.append(pattern_name)

            if severity == 'PASS' and 'view' in description.lower():
                protection_mechanisms_found.append(pattern_name)

            if pattern_name == 'isSecureTextEntry':
                secure_text_entry_found = True

    # Determine status
    if lifecycle_methods_found and protection_mechanisms_found:
        status = "PASS"
        summary_lines.append(f"✓ Screenshot protection detected: {len(protection_mechanisms_found)} mechanism(s)")
    elif lifecycle_methods_found:
        status = "WARN"
        summary_lines.append(f"⚠ App lifecycle methods present but no clear protection mechanisms")
    else:
        status = "WARN"
        summary_lines.append("✗ No screenshot protection detected")

    if lifecycle_methods_found:
        summary_lines.append(f"  • Lifecycle methods: {', '.join(lifecycle_methods_found)}")

    if protection_mechanisms_found:
        summary_lines.append(f"  • Protection mechanisms: {', '.join(protection_mechanisms_found)}")

    if secure_text_entry_found:
        summary_lines.append(f"  ✓ Secure text entry used for sensitive fields")

    # Build findings for lifecycle implementations
    for method_name in ['applicationWillResignActive', 'sceneWillResignActive']:
        if method_name in api_usage:
            file_path = api_usage[method_name]['files'][0]
            rel_path = rel(file_path, base)
            snippets = extract_snippet_with_context(file_path, screenshot_patterns[method_name][0], context_lines=6, max_matches=1)

            if snippets:
                line_num, matched_line, snippet = snippets[0]

                # Check if protection is implemented in snippet
                has_protection = any(keyword in snippet.lower() for keyword in ['ishidden', 'alpha', 'addsubview', 'insertsubview', 'overlay'])

                findings.append(FindingBlock(
                    title=f"{'✓' if has_protection else '⚠'} App Lifecycle: {method_name}",
                    subtitle=f"{os.path.basename(file_path)}:{line_num}",
                    link=make_file_link(base, rel_path, line_num),
                    code=snippet,
                    code_language="swift" if file_path.endswith('.swift') else "objc",
                    open_by_default=True,
                    evidence=[
                        f"{'✓ Screenshot protection implemented' if has_protection else '⚠ No screenshot protection detected'}",
                        "",
                        "When app enters background:",
                        "• iOS takes snapshot for app switcher",
                        "• Snapshot may contain sensitive data",
                        "",
                        "Recommended protection:",
                        "• Hide sensitive views: view.isHidden = true",
                        '   passwordField.text = ""',
                        "",
                        "3. Or add overlay:",
                        "   let overlay = UIView(frame: window.bounds)",
                        "   overlay.backgroundColor = .white",
                        "   window.addSubview(overlay)",
                        "",
                        "4. Remove protection in applicationDidBecomeActive:",
                        "   sensitiveView.isHidden = false",
                        "   overlay.removeFromSuperview()",
                        "",
                        "Critical for:",
                        "• Banking/financial apps",
                        "• Healthcare apps",
                        "• Apps with PII/sensitive data"
                    ]
                ))
            break  # Only show one example

    # Check for secure text entry
    if secure_text_entry_found:
        file_path = api_usage['isSecureTextEntry']['files'][0]
        rel_path = rel(file_path, base)
        snippets = extract_snippet_with_context(file_path, screenshot_patterns['isSecureTextEntry'][0], context_lines=3, max_matches=1)

        if snippets:
            line_num, matched_line, snippet = snippets[0]
            findings.append(FindingBlock(
                title="✓ Secure Text Entry",
                subtitle=f"{os.path.basename(file_path)}:{line_num}",
                link=make_file_link(base, rel_path, line_num),
                code=snippet,
                code_language="swift" if file_path.endswith('.swift') else "objc",
                open_by_default=False,
                evidence=[
                    "✓ UITextField configured with isSecureTextEntry",
                    "",
                    "Benefits:",
                    "• Masks password characters",
                    "• Prevents screenshots in text field",
                    "• Disables password manager integration (optional)",
                    "",
                    "Ensure used for:",
                    "• Password fields",
                    "• PIN entry fields",
                    "• Security codes/tokens"
                ]
            ))

    # Add recommendations
    if not lifecycle_methods_found or not protection_mechanisms_found:
        findings.append(FindingBlock(
            title="Screenshot Protection Recommendations",
            subtitle="Implement in app lifecycle methods",
            evidence=[
                "⚠ Screenshot/app switcher protection not clearly implemented",
                "",
                "iOS snapshots the app when entering background:",
                "1. User presses home button",
                "2. User switches apps",
                "3. Notification appears",
                "",
                "Implementation steps:",
                "",
                "1. Implement applicationWillResignActive: (AppDelegate) or",
                "   sceneWillResignActive: (SceneDelegate for iOS 13+)",
                "",
                "2. Hide sensitive content:",
                "   sensitiveView.isHidden = true",
                '   passwordField.text = ""',
                "",
                "3. Or add overlay:",
                "   let overlay = UIView(frame: window.bounds)",
                "   overlay.backgroundColor = .white",
                "   window.addSubview(overlay)",
                "",
                "4. Remove protection in applicationDidBecomeActive:",
                "   sensitiveView.isHidden = false",
                "   overlay.removeFromSuperview()",
                "",
                "Critical for:",
                "• Banking/financial apps",
                "• Healthcare apps",
                "• Apps with PII/sensitive data"
            ],
            open_by_default=True
        ))

    return TestResult(
        name="Screenshot & App Switcher Security",
        status=status,
        summary_lines=summary_lines,
        mastg_ref_html=mastg_ref(
            ["MASTG-TEST-0059", "MASTG-TEST-0290"],
            ["Finding Sensitive Data in the Keyboard Cache",
             "Checking for Sensitive Data Disclosure Through the User Interface"]
        ),
        findings=findings
    )

def check_debug_symbols(main_bin: str) -> TestResult:
    cmd = ["/usr/bin/nm", "-a", main_bin]
    rc, out = run(cmd, timeout=60)

    # Build initial findings with highlighted nm output
    findings = [
        FindingBlock(
            title=f"Command run for {os.path.basename(main_bin)}",
            code=" ".join(cmd),
            code_language="shell"
        )
    ]

    # Show nm output with debug symbols highlighted (limit to 300 lines for performance)
    nm_lines = out.splitlines()[:300]
    highlighted_output = []
    for line in nm_lines:
        # Highlight debug symbols and source file references
        if ' N ' in line or ' n ' in line:
            highlighted_output.append(f"🔴 [DEBUG] {line}")
        elif any(ext in line for ext in ['.swift', '.m', '.mm', '.c', '.cpp', '.h']):
            highlighted_output.append(f"🔴 [SOURCE] {line}")
        else:
            highlighted_output.append(line)

    findings.append(FindingBlock(
        title=f"Raw nm output (first 300 lines, debug symbols highlighted with 🔴)",
        code="\n".join(highlighted_output),
        code_language="text"
    ))

    if rc != 0:
        return TestResult(
            id="RESILIENCE-SYMBOLS",
            name="Debug Symbols / Symbol Stripping",
            status="WARN",
            summary_lines=["Unable to run nm to assess symbols"],
            findings=findings,
            mastg_ref_html=mastg_ref(["MASTG-TEST-0081"], ["Testing for Debugging Code and Verbose Error Logging"])
        )

    # Parse nm output to categorize symbols
    lines = [l for l in out.splitlines() if l.strip() and not l.startswith("nm:")]
    sym_count = len(lines)

    # Symbol type counters
    debug_symbols = []           # N type - debug symbols
    source_file_refs = []        # Contains source file paths
    text_symbols = []            # T/t type - code symbols
    undefined_symbols = []       # U type - external refs
    local_symbols = []           # Lowercase types - local/static

    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue

        # Symbol type is usually the second column (after address)
        # Format: "address type name" or "        U name" for undefined
        symbol_type = parts[1] if len(parts) > 1 and len(parts[1]) == 1 else None

        # Check for debug symbols (N type)
        if symbol_type == 'N' or symbol_type == 'n':
            debug_symbols.append(line.strip())

        # Check for source file references in symbol name
        symbol_name = ' '.join(parts[2:]) if len(parts) > 2 else line
        if any(ext in symbol_name for ext in ['.swift', '.m', '.mm', '.c', '.cpp', '.h']):
            source_file_refs.append(line.strip())

        # Categorize by type
        if symbol_type:
            if symbol_type in ['T', 't']:
                text_symbols.append(symbol_type)
            elif symbol_type == 'U':
                undefined_symbols.append(symbol_type)
            elif symbol_type.islower() and symbol_type != 'n':
                local_symbols.append(symbol_type)

    # Determine status based on actual debug symbols
    status: Status = "PASS"
    summary = []

    summary.append(f"Total Symbols: {sym_count}")

    # Debug symbols should cause FAIL - this is a security issue
    if debug_symbols or source_file_refs:
        status = "FAIL"  # FAIL not WARN - debug symbols must be stripped per MASTG
        if debug_symbols:
            summary.append(f"✗ FAIL: {len(debug_symbols)} DEBUG SYMBOLS FOUND (type 'N') - must be stripped")
        if source_file_refs:
            summary.append(f"✗ FAIL: {len(source_file_refs)} SOURCE FILE PATHS found - leaks project structure")
        summary.append("MASTG requirement: Debug symbols MUST be stripped from release builds")
    else:
        summary.append("✓ No debug symbols detected (properly stripped)")
        summary.append("Note: Symbols for dynamic linking and runtime metadata are normal")

    # Symbol breakdown for info
    summary.append(f"Breakdown: {len(text_symbols)} code, {len(undefined_symbols)} external, {len(local_symbols)} local")

    # Additional context
    if sym_count > 10000 and not debug_symbols and not source_file_refs:
        summary.append(f"INFO: {sym_count} total symbols is high but may be normal for large apps with many classes")

    # Build evidence showing definite debug symbols
    if debug_symbols or source_file_refs:
        evidence_lines = ["Symbol Analysis:", ""]
        evidence_lines.append(f"Total Symbols: {sym_count}")

        if debug_symbols:
            evidence_lines.append("")
            evidence_lines.append(f"🔴 DEBUG SYMBOLS (type 'N') - {len(debug_symbols)} found:")
            evidence_lines.append("These are definite debug symbols that should be stripped:")
            for sym in debug_symbols[:15]:
                evidence_lines.append(f"  🔴 {sym}")
            if len(debug_symbols) > 15:
                evidence_lines.append(f"  ... and {len(debug_symbols) - 15} more debug symbols")

        if source_file_refs:
            evidence_lines.append("")
            evidence_lines.append(f"🔴 SOURCE FILE REFERENCES - {len(source_file_refs)} found:")
            evidence_lines.append("These leak your project structure and should be stripped:")
            for sym in source_file_refs[:15]:
                evidence_lines.append(f"  🔴 {sym}")
            if len(source_file_refs) > 15:
                evidence_lines.append(f"  ... and {len(source_file_refs) - 15} more source references")

        evidence_lines.append("")
        evidence_lines.append("MASTG Requirement: Release builds must strip debug symbols")
        evidence_lines.append("Fix: Set STRIP_INSTALLED_PRODUCT=YES and STRIP_STYLE=non-global in Xcode")

        findings.append(FindingBlock(
            title="Debug Symbol Evidence",
            evidence=evidence_lines,
            open_by_default=True
        ))

    return TestResult(
        id="RESILIENCE-SYMBOLS",
        name="Debug Symbols / Symbol Stripping",
        status=status,
        summary_lines=summary,
        findings=findings,
        mastg_ref_html=mastg_ref(["MASTG-TEST-0081"], ["Testing for Debugging Code and Verbose Error Logging"])
    )

def _render_table_html(table_id: str, col_order: List[str], table_rows: List[List[str]], title: str) -> str:
    """Helper to render a single checksec table."""
    # Build unique filter options per column
    unique_vals = []
    for col_idx in range(len(col_order)):
        vals = sorted({r[col_idx] for r in table_rows})
        unique_vals.append(vals)

    # Assemble HTML with per-column dropdowns
    html_parts = [f'<h4>{title}</h4>']
    html_parts.append('<div style="overflow-x:auto;margin-bottom:20px;">')
    html_parts.append(f'<table id="{table_id}" style="width:100%;min-width:800px;border-collapse:collapse;font-size:13px;"><thead><tr>')

    # Filter row
    for col_idx, vals in enumerate(unique_vals):
        opts = "".join(f'<option value="{html.escape(v)}">{html.escape(v)}</option>' for v in vals)
        html_parts.append(
            f'<th style="padding:6px;border:1px solid #ddd;font-size:12px;">'
            f'<select class="filter-select-{table_id}" onchange="applyFilters(\'{table_id}\')" '
            'style="width:100%;padding:3px;border:1px solid #ccc;border-radius:4px;font-size:11px;">'
            f'<option value="">All</option>{opts}</select></th>'
        )
    html_parts.append('</tr><tr>')

    # Header labels with sort capability
    for idx, h in enumerate(col_order):
        html_parts.append(
            f'<th class="sortable" onclick="sortTable(\'{table_id}\', {idx})" '
            f'style="padding:8px;border:1px solid #ddd;cursor:pointer;font-weight:600;">'
            f'{html.escape(h)} <span class="chevron">▼</span></th>'
        )
    html_parts.append('</tr></thead><tbody>')

    # Data rows
    for r in table_rows:
        html_parts.append('<tr>')
        for i, cell in enumerate(r):
            style = "padding:6px;border:1px solid #ddd;"
            is_bad = 'false' in cell.lower()
            is_good = 'true' in cell.lower()

            # Color-code security issues
            if is_bad and col_order[i] not in ['Authenticode', 'CLR']:
                style += "background:#fee2e2;color:#991b1b;font-weight:600;"
            elif is_good and col_order[i] in ['Encrypted', 'Canary', 'PIE', 'NX Stack', 'ARC', 'GS', 'SafeSEH']:
                style += "background:#d1fae5;color:#065f46;font-weight:600;"
            html_parts.append(f'<td style="{style}">{html.escape(cell)}</td>')
        html_parts.append('</tr>')
    html_parts.append('</tbody></table>')
    html_parts.append('</div>')
    return "".join(html_parts)

def _format_cell_value(text: str, max_len: int = 120) -> str:
    """Render a cell with safe truncation and tooltip for long values."""
    if text is None:
        return ""
    full = str(text)
    safe_full = html.escape(full)
    if len(full) <= max_len:
        return safe_full
    truncated = html.escape(full[:max_len]) + "…"
    return f'<span title="{safe_full}">{truncated}</span>'


def render_filterable_table(table_id: str, headers: List[str], rows: List[List[str]],
                            title: str, searchable: bool = True) -> str:
    """
    Render a generic filterable/sortable table with a search box.
    Relies on global sortTable/filterTable helpers defined in the HTML template.
    """
    safe_id = re.sub(r'[^A-Za-z0-9_-]', '', table_id) or f"tbl_{uuid.uuid4().hex[:6]}"
    parts = [f'<div class="table-card"><div class="table-head"><h4>{html.escape(title)}</h4>']
    if searchable:
        parts.append(
            f'<input class="table-search" type="search" placeholder="Filter rows" '
            f'oninput="filterTable(\'{safe_id}\', this.value)"/>'
        )
    parts.append("</div>")
    parts.append(f'<div style="overflow-x:auto;"><table id="{safe_id}" class="data-table"><thead><tr>')
    for idx, h in enumerate(headers):
        parts.append(
            f'<th onclick="sortTable(\'{safe_id}\', {idx})">'
            f'{html.escape(h)} <span class="chevron">▼</span></th>'
        )
    parts.append("</tr></thead><tbody>")
    for row in rows:
        parts.append("<tr>")
        for cell in row:
            parts.append(f"<td>{_format_cell_value(cell)}</td>")
        parts.append("</tr>")
    parts.append("</tbody></table></div></div>")
    return "".join(parts)

def render_checksec_table(text: str, base: str) -> str:
    """
    Render checksec output into an HTML table with dropdown filters.
    Parses checksec output for iOS (handles both PE32/.NET and MachO64 binaries).

    Format: Type: | field1: value field2: value ... | File: path
    Example: MachO64: | ARC: true Canary: true PIE: false | File: path/to/binary
    """
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines:
        return f"<pre>{html.escape(text)}</pre>"

    macho_rows, pe_rows = [], []

    for ln in lines:
        parts = ln.split('|')
        if len(parts) < 3:
            continue

        bin_type = parts[0].strip().rstrip(':')
        flags_section = parts[1].strip()

        flags = dict(re.findall(r'([A-Z][\w\s]*?):\s*(\S+(?:\s*\(\S+\))?)', flags_section))

        file_match = re.search(r'File:\s*(.+)', parts[2])
        file_path = file_match.group(1).strip() if file_match else parts[2].strip()

        # Convert to relative path
        file_path = rel(file_path, base)

        row_data = {'Type': bin_type, 'flags': flags, 'File': file_path}
        if 'MachO' in bin_type:
            macho_rows.append(row_data)
        elif 'PE' in bin_type:
            pe_rows.append(row_data)

    if not macho_rows and not pe_rows:
        return f"<pre>No native MachO or PE binaries found.\n\n{html.escape(text[:2000])}</pre>"

    all_html = []

    # Render MachO table
    if macho_rows:
        col_order_macho = ['Type', 'ARC', 'Canary', 'NX Stack', 'PIE', 'Code Signature', 'Encrypted',
                           'Fortify', 'Fortified', 'Restrict', 'RPath', 'File']
        
        table_rows_macho = []
        for row_data in macho_rows:
            row = []
            for col in col_order_macho:
                 if col == 'Type':
                    row.append(row_data['Type'])
                 elif col == 'File':
                    row.append(row_data['File'])
                 else:
                    row.append(row_data['flags'].get(col, 'N/A'))
            table_rows_macho.append(row)

        def security_score_macho(r):
            score = 0
            if 'false' in r[2].lower(): score += 100
            if 'false' in r[4].lower(): score += 80
            if 'false' in r[1].lower(): score += 60
            if 'false' in r[3].lower(): score += 50
            if 'false' in r[5].lower(): score += 40
            return score
        
        table_rows_macho.sort(key=security_score_macho, reverse=True)
        all_html.append(_render_table_html('checksecTableMacho', col_order_macho, table_rows_macho, "MachO Binaries"))

    # Render PE table
    if pe_rows:
        col_order_pe = ['Type', 'ASLR', 'DEP', 'GS', 'SafeSEH', 'CFG', 'Authenticode', 'CLR', 'Dynamic Base', 
                        'Force Integrity', 'High Entropy VA', 'Isolation', 'RFG', 'File']

        table_rows_pe = []
        for row_data in pe_rows:
            row = []
            for col in col_order_pe:
                if col == 'Type':
                    row.append(row_data['Type'])
                elif col == 'File':
                    row.append(row_data['File'])
                else:
                    row.append(row_data['flags'].get(col, 'N/A'))
            table_rows_pe.append(row)

        def security_score_pe(r):
            score = 0
            if 'false' in r[3].lower(): score += 100  # No GS
            if 'false' in r[4].lower(): score += 80   # No SafeSEH
            if 'false' in r[2].lower(): score += 60   # No DEP
            if 'false' in r[1].lower(): score += 50   # No ASLR
            return score

        table_rows_pe.sort(key=security_score_pe, reverse=True)
        all_html.append(_render_table_html('checksecTablePE', col_order_pe, table_rows_pe, ".NET (PE) Assemblies"))

    return "".join(all_html)

def check_checksec(app_dir: str, base: str) -> TestResult:
    """
    Run checksec on the iOS app bundle to analyze binary security features.
    Scans the main binary, frameworks, and dylibs.
    """
    # Check if checksec is available
    rc, _ = run(["which", "checksec"], timeout=5)
    if rc != 0:
        return TestResult(
            id="CHECKSEC",
            name="Binary Security Features (checksec)",
            status="INFO",
            summary_lines=["checksec tool not installed - install from https://github.com/slimm609/checksec.sh"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0087"], ["Binary Security Features"])
        )

    # Run checksec on the app directory
    print(f"[*] Running checksec on {app_dir}...")
    rc, out = run(["checksec", "-d", app_dir], timeout=60)

    if rc != 0 or not out.strip():
        return TestResult(
            id="CHECKSEC",
            name="Binary Security Features (checksec)",
            status="WARN",
            summary_lines=["checksec command failed or returned no output"],
            findings=[Finding(title="checksec output", evidence=out[:1000])],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0087"], ["Binary Security Features"])
        )

    # Clean up ANSI codes and non-printable characters
    text = re.sub(r"\x1b\[[0-9;]*m", "", out)
    text = re.sub(r"[^\x20-\x7E\n]", "", text)
    text = re.sub(r'\n\n+', '\n\n', text)

    # Count binaries analyzed
    lines = [l for l in text.splitlines() if l.strip()]

    # Count MachO binaries specifically
    macho_count = sum(1 for l in lines if 'MachO' in l)
    total_count = len(lines)

    # Analyze for security issues in MachO binaries
    issues = []
    macho_lines = [l for l in lines if 'MachO' in l]

    for line in macho_lines:
        if 'Canary: false' in line:
            issues.append("Some binaries lack stack canaries")
            break

    for line in macho_lines:
        if 'PIE: false' in line:
            issues.append("Some binaries are not position-independent (PIE)")
            break

    for line in macho_lines:
        if 'ARC: false' in line:
            issues.append("Some binaries don't use Automatic Reference Counting (ARC)")
            break

    for line in macho_lines:
        if 'NX Stack: false' in line:
            issues.append("Some binaries have NX Stack disabled")
            break

    for line in macho_lines:
        if 'Code Signature: false' in line:
            issues.append("Some binaries lack code signatures")
            break

    status: Status = "PASS"
    summary = [f"Analyzed {total_count} binarie(s) ({macho_count} native MachO)"]
    if issues:
        status = "WARN"
        summary.extend(issues)
    else:
        summary.append("All native binaries have recommended security features enabled")

    # Render as table
    table_html = render_checksec_table(text, base)

    return TestResult(
        id="CHECKSEC",
        name="Binary Security Features (checksec)",
        status=status,
        summary_lines=summary,
        tables_html=[table_html],
        mastg_ref_html=mastg_ref(["MASTG-TEST-0087"], ["Binary Security Features"])
    )

def check_libraries(main_bin: str) -> TestResult:
    rc, out = run(["/usr/bin/otool", "-L", main_bin], timeout=30)
    if rc != 0:
        return TestResult(
            id="RESILIENCE-LIBS",
            name="Linked Libraries (otool -L)",
            status="WARN",
            summary=["Unable to list linked libraries"],
            findings=[Finding(title="otool -L output", evidence=out.splitlines()[:120])],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0086"], ["Testing for Vulnerabilities in Included Libraries"])
        )

    libs = [l.strip() for l in out.splitlines()[1:] if l.strip()]

    # Categorize libraries
    system_frameworks = []
    system_libs = []
    custom_frameworks = []
    other_libs = []
    concerning_libs = []

    for lib in libs:
        lib_lower = lib.lower()
        if "/System/Library/Frameworks/" in lib:
            system_frameworks.append(lib)
        elif "/usr/lib/" in lib or "/System/Library/" in lib:
            system_libs.append(lib)
        elif "@rpath/" in lib or "@executable_path/" in lib or "@loader_path/" in lib:
            custom_frameworks.append(lib)
            # Check for concerning library names
            if any(keyword in lib_lower for keyword in ["openssl", "sqlite", "crypto", "ssl"]):
                concerning_libs.append((lib, "May contain cryptographic implementation - verify version"))
        else:
            other_libs.append(lib)

    # Build summary
    summary_lines = []
    status: Status = "INFO"

    summary_lines.append(f"Total Libraries: {len(libs)}")
    summary_lines.append(f"System Frameworks: {len(system_frameworks)}")
    summary_lines.append(f"System Libraries: {len(system_libs)}")
    summary_lines.append(f"Custom/Bundled Frameworks: {len(custom_frameworks)}")

    if concerning_libs:
        summary_lines.append(f"⚠ Found {len(concerning_libs)} library/libraries requiring review")
        status = "WARN"

    # Build evidence for concerning libs
    findings = []
    if concerning_libs:
        evidence_lines = []
        for lib, reason in concerning_libs:
            evidence_lines.append(f"{lib} - {reason}")
        findings.append(FindingBlock(
            title="Concerning Libraries",
            evidence=evidence_lines,
            open_by_default=True
        ))

    # Show custom frameworks
    if custom_frameworks:
        findings.append(FindingBlock(
            title=f"Custom/Bundled Frameworks ({len(custom_frameworks)})",
            evidence=custom_frameworks,
            open_by_default=False
        ))

    return TestResult(
        id="RESILIENCE-LIBS",
        name="Linked Libraries (otool -L)",
        status=status,
        summary=summary_lines,
        findings=findings,
        mastg_ref_html=mastg_ref(["MASTG-TEST-0086"], ["Testing for Vulnerabilities in Included Libraries"])
    )

def check_bundle_filetypes(app_dir: str, base: str) -> List[TestResult]:
    results: List[TestResult] = []

    # Embedded provisioning profile
    mp = os.path.join(app_dir, "embedded.mobileprovision")
    if os.path.exists(mp):
        # Parse the mobile provision to extract details
        provision_data = {}
        summary_lines = []
        evidence_lines = []
        status: Status = "INFO"

        try:
            # Try to decode using security cms command
            rc, out = run(["/usr/bin/security", "cms", "-D", "-i", mp], timeout=10)
            if rc == 0:
                provision_data = plistlib.loads(out.encode("utf-8"))
        except Exception:
            pass

        # If security command failed, try reading directly (some provisions have plist after header)
        if not provision_data:
            try:
                with open(mp, 'rb') as f:
                    content = f.read()
                    # Find plist start marker
                    start = content.find(b'<?xml')
                    end = content.find(b'</plist>') + 8
                    if start != -1 and end > start:
                        provision_data = plistlib.loads(content[start:end])
            except Exception:
                pass

        if provision_data:
            # Extract key information
            profile_name = provision_data.get("Name", "Unknown")
            team_name = provision_data.get("TeamName", "Unknown")
            team_id = provision_data.get("TeamIdentifier", ["Unknown"])
            if isinstance(team_id, list):
                team_id = team_id[0] if team_id else "Unknown"

            creation_date = provision_data.get("CreationDate", "Unknown")
            expiration_date = provision_data.get("ExpirationDate", "Unknown")
            app_id_name = provision_data.get("AppIDName", "Unknown")

            provisioned_devices = provision_data.get("ProvisionedDevices", [])
            provisions_all = provision_data.get("ProvisionsAllDevices", False)

            entitlements = provision_data.get("Entitlements", {})
            get_task_allow = entitlements.get("get-task-allow", False)
            aps_env = entitlements.get("aps-environment", "")

            # Determine distribution type
            if provisions_all:
                dist_type = "Enterprise/In-House"
                status = "WARN"
                summary_lines.append(f"Distribution: {dist_type} (provisions all devices - review distribution scope)")
            elif provisioned_devices and get_task_allow:
                dist_type = "Development"
                status = "WARN"
                summary_lines.append(f"Distribution: {dist_type} (debuggable build - should not be in production)")
            elif provisioned_devices:
                dist_type = "Ad Hoc"
                summary_lines.append(f"Distribution: {dist_type} (limited to {len(provisioned_devices)} device(s))")
            else:
                dist_type = "Unknown/TestFlight"
                summary_lines.append(f"Distribution: {dist_type}")

            summary_lines.append(f"Team: {team_name} ({team_id})")

            # Check expiration
            if isinstance(expiration_date, str):
                summary_lines.append(f"Expires: {expiration_date}")

            # Build evidence
            evidence_lines.append(f"Name: {profile_name}")
            evidence_lines.append(f"AppIDName: {app_id_name}")
            evidence_lines.append(f"TeamName: {team_name}")
            evidence_lines.append(f"TeamIdentifier: {team_id}")
            evidence_lines.append(f"Distribution Type: {dist_type}")
            evidence_lines.append("")
            evidence_lines.append(f"CreationDate: {creation_date}")
            evidence_lines.append(f"ExpirationDate: {expiration_date}")
            evidence_lines.append("")

            if provisions_all:
                evidence_lines.append(f"ProvisionsAllDevices: {provisions_all}")

            if provisioned_devices:
                evidence_lines.append(f"ProvisionedDevices: {len(provisioned_devices)} device(s)")
                for device in provisioned_devices[:10]:
                    evidence_lines.append(f"  - {device}")
                if len(provisioned_devices) > 10:
                    evidence_lines.append(f"  ... and {len(provisioned_devices) - 10} more device(s)")
                evidence_lines.append("")

            evidence_lines.append("Key Entitlements:")
            evidence_lines.append(f"  get-task-allow: {get_task_allow}")
            if aps_env:
                evidence_lines.append(f"  aps-environment: {aps_env}")
            if entitlements.get("application-identifier"):
                evidence_lines.append(f"  application-identifier: {entitlements.get('application-identifier')}")

            results.append(TestResult(
                id="RESILIENCE-MOBILEPROVISION",
                name="Embedded Mobile Provision (build artefact)",
                status=status,
                summary=summary_lines,
                findings=[FindingBlock(
                    title=rel(mp, base),
                    link=make_file_link(base, rel(mp, base)),
                    evidence=evidence_lines
                )],
                mastg_ref_html=mastg_ref(["MASTG-TEST-0079"], ["Analysis of the Build Settings of the App"])
            ))
        else:
            # Could not parse the provision
            results.append(TestResult(
                id="RESILIENCE-MOBILEPROVISION",
                name="Embedded Mobile Provision (build artefact)",
                status="INFO",
                summary=["embedded.mobileprovision present but could not parse (review distribution channel)"],
                findings=[FindingBlock(title=rel(mp, base), link=make_file_link(base, rel(mp, base)))],
                mastg_ref_html=mastg_ref(["MASTG-TEST-0079"], ["Analysis of the Build Settings of the App"])
            ))
    else:
        results.append(TestResult(
            id="RESILIENCE-MOBILEPROVISION",
            name="Embedded Mobile Provision (build artefact)",
            status="PASS",
            summary=["No embedded.mobileprovision (likely App Store distribution)"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0079"], ["Analysis of the Build Settings of the App"])
        ))

    # Local databases and caches in bundle (should be rare)
    dbs = recursive_file_find(app_dir, (".sqlite", ".db", ".realm"))
    if dbs:
        findings = []
        for p in dbs[:120]:
            rel_path = rel(p, base)
            findings.append(FindingBlock(title=rel_path, link=make_file_link(base, rel_path)))
        results.append(TestResult(
            id="STORAGE-BUNDLEDB",
            name="Databases Bundled in App",
            status="WARN",
            summary=[f"Found {len(dbs)} database file(s) in bundle - MASTG expects no bundled databases with sensitive data"],
            findings=findings,
            mastg_ref_html=mastg_ref(["MASTG-TEST-0060"], ["Testing for Sensitive Data Stored in Local Databases"])
        ))
    else:
        results.append(TestResult(
            id="STORAGE-BUNDLEDB",
            name="Databases Bundled in App",
            status="PASS",
            summary=["No .sqlite/.db/.realm files found inside the app bundle"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0060"], ["Testing for Sensitive Data Stored in Local Databases"])
        ))

    # Potentially sensitive config files
    configs = recursive_file_find(app_dir, (".json", ".plist", ".xml", ".yaml", ".yml", ".txt", ".pem", ".p12", ".cer", ".der"))
    # Heuristic: highlight small-ish configs
    interesting = []
    cert_files = []
    for p in configs:
        try:
            size = os.path.getsize(p)
            if size <= 2 * 1024 * 1024:
                interesting.append(p)
                # Categorize certificate/key files
                if any(ext in p.lower() for ext in [".pem", ".p12", ".cer", ".der", ".key"]):
                    cert_files.append(p)
        except Exception:
            pass

    if interesting:
        findings = []
        status: Status = "WARN" if cert_files else "INFO"
        for p in interesting[:150]:
            rel_path = rel(p, base)
            findings.append(FindingBlock(title=rel_path, link=make_file_link(base, rel_path)))

        summary_lines = [f"Found {len(interesting)} config/cert/key file(s) - MASTG expects no hardcoded credentials or private keys"]
        if cert_files:
            summary_lines.append(f"WARNING: {len(cert_files)} certificate/key file(s) detected")

        results.append(TestResult(
            id="STORAGE-CONFIGFILES",
            name="Config/Key Material Files in Bundle",
            status=status,
            summary=summary_lines,
            findings=findings,
            mastg_ref_html=mastg_ref(["MASTG-TEST-0058"], ["Testing for Sensitive Data in Local Storage"])
        ))
    else:
        results.append(TestResult(
            id="STORAGE-CONFIGFILES",
            name="Config/Key Material Files in Bundle",
            status="PASS",
            summary=["No obvious config/cert/key material file types found in bundle"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0058"], ["Testing for Sensitive Data in Local Storage"])
        ))

    return results

HTTP_IGNORE_DOMAINS = [
    "w3.org",
    "ns.adobe.com",
    "schemas.microsoft.com",
    "schemas.openxmlformats.org",
    "www.apple.com/DTDs",
    "apple.com/DTDs",
    "go.microsoft.com",
    "purl.org",
    "sentry.io",
    "schemas.datacontract.org",
    "www.microsoft.com",
    "www.daltonmaag.com",
    "ocsp.apple.com",
    "crl.apple.com",
    "crl.microsoft.com",
    "www.iec.ch",
    "www.aiim.org"
]

def check_strings_patterns(app_dir: str, main_bin: str, base: str) -> List[TestResult]:
    results: List[TestResult] = []
    bins = list_bundle_binaries(app_dir, main_bin)

    # cache strings per binary to avoid repeated calls
    cache: Dict[str, List[str]] = {}
    def get_lines(p: str) -> List[str]:
        if p not in cache:
            cache[p] = strings_dump(p, timeout=140)
        return cache[p]

    # secrets
    secret_hits = []
    for t in bins:
        hits_with_matches = strings_grep_lines_with_matches(get_lines(t), SENSITIVE_KEYWORDS, max_hits=40)
        if hits_with_matches:
            secret_hits.append((t, hits_with_matches))
    if secret_hits:
        findings = []
        for t, hits_with_matches in secret_hits[:10]:
            # Format evidence with highlighted keywords
            evidence = []
            for line, matched_keyword in hits_with_matches[:25]:
                # Highlight the matched keyword in the line
                evidence.append(f"[{matched_keyword}] {line}")
            findings.append(Finding(title=rel(t, base), evidence=evidence, files=[rel(t, base)]))

        results.append(TestResult(
            id="STORAGE-SECRETS",
            name="Hardcoded Secrets (strings triage)",
            status="WARN",
            summary=[f"Potential secret indicators found in {len(secret_hits)} binary file(s) - MASTG expects no hardcoded secrets (see binary analysis test for entropy detection)"],
            findings=findings,
            mastg_ref_html=mastg_ref(["MASTG-TEST-0057"], ["Searching for Hardcoded Secrets"])
        ))
    else:
        results.append(TestResult(
            id="STORAGE-SECRETS",
            name="Hardcoded Secrets (strings triage)",
            status="PASS",
            summary=["No obvious secret keywords found via strings (see binary analysis test for comprehensive entropy-based detection)"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0057"], ["Searching for Hardcoded Secrets"])
        ))

    # weak crypto
    weak_hits = []
    for t in bins:
        hits = strings_grep_lines(get_lines(t), WEAK_CRYPTO_PATTERNS, max_hits=60)
        if hits:
            weak_hits.append((t, hits))
    if weak_hits:
        findings = [Finding(title=rel(t, base), evidence=sorted(set(h))[:30], files=[rel(t, base)]) for t, h in weak_hits[:10]]
        results.append(TestResult(
            id="CRYPTO-WEAK",
            name="Weak Cryptography (strings triage)",
            status="WARN",
            summary=[f"Weak crypto indicators in {len(weak_hits)} file(s) - MASTG expects AES-256/SHA-256+, not DES/MD5/SHA1 (see binary analysis test for confirmed usage)"],
            findings=findings,
            mastg_ref_html=mastg_ref(["MASTG-TEST-0061"], ["Testing for Weak Cryptography"])
        ))
    else:
        results.append(TestResult(
            id="CRYPTO-WEAK",
            name="Weak Cryptography (strings triage)",
            status="PASS",
            summary=["No obvious weak crypto strings found (see binary analysis test for symbol-level detection)"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0061"], ["Testing for Weak Cryptography"])
        ))

    # TLS pinning indicators (informational — presence isn't bad, absence isn't bad)
    pin_hits = []
    for t in bins:
        hits = strings_grep_lines(get_lines(t), TLS_PINNING_INDICATORS, max_hits=40)
        if hits:
            pin_hits.append((t, hits))
    results.append(TestResult(
        id="NETWORK-PINNING",
        name="TLS/Pinning Indicators (strings triage)",
        status="INFO" if pin_hits else "INFO",
        summary=[f"Found indicators in {len(pin_hits)} file(s) (review implementation quality)"] if pin_hits else
                ["No obvious pinning keywords found (not a guarantee)"],
        findings=[Finding(title=rel(t, base), evidence=sorted(set(h))[:25], files=[rel(t, base)]) for t, h in pin_hits[:8]] if pin_hits else [],
        mastg_ref_html=mastg_ref(["MASTG-TEST-0068"], ["Testing Custom Certificate Stores and Certificate Pinning"])
    ))

    # Anti-debug / anti-tamper indicators (info)
    ad_hits = []
    for t in bins:
        hits = strings_grep_lines(get_lines(t), ANTI_DEBUG_INDICATORS, max_hits=40)
        if hits:
            ad_hits.append((t, hits))
    results.append(TestResult(
        id="RESILIENCE-ANTIDEBUG",
        name="Anti-Debug / Anti-Tamper Indicators (strings triage)",
        status="INFO" if ad_hits else "PASS",
        summary=[f"Indicators in {len(ad_hits)} file(s) (review for false positives)"] if ad_hits else
                ["No obvious anti-debug indicators found"],
        findings=[Finding(title=rel(t, base), evidence=sorted(set(h))[:25], files=[rel(t, base)]) for t, h in ad_hits[:8]] if ad_hits else [],
        mastg_ref_html=mastg_ref(["MASTG-TEST-0082"], ["Testing for Anti-Debugging Detection"])
    ))

    # Jailbreak detection indicators (info)
    jb_hits = []
    for t in bins:
        raw_hits = strings_grep_lines(get_lines(t), [re.escape(x) for x in JAILBREAK_ARTIFACTS], max_hits=60)
        if not raw_hits:
            continue
        # Filter out noisy/HTML-ish lines and truncate length to keep evidence clear
        filtered = []
        for h in raw_hits:
            if len(h) > 160:
                continue
            if "<" in h and ">" in h:
                continue
            filtered.append(h)
        if filtered:
            jb_hits.append((t, filtered))
    results.append(TestResult(
        id="RESILIENCE-JBDETECT",
        name="Jailbreak Detection Indicators (strings triage)",
        status="INFO" if jb_hits else "PASS",
        summary=[f"Indicators in {len(jb_hits)} file(s) (presence indicates checks; validate robustness)"] if jb_hits else
                ["No obvious jailbreak artifact strings found"],
        findings=[Finding(title=rel(t, base), evidence=sorted(set(h))[:30], files=[rel(t, base)]) for t, h in jb_hits[:8]] if jb_hits else [],
        mastg_ref_html=mastg_ref(["MASTG-TEST-0083"], ["Testing for Jailbreak Detection"])
    ))

    # Insecure API indicators
    for label, pats in INSECURE_API_PATTERNS:
        hits = []
        for t in bins:
            hits_with_matches = strings_grep_lines_with_matches(get_lines(t), pats, max_hits=35)
            if hits_with_matches:
                hits.append((t, hits_with_matches))

        mastg_map = {
            "NSUserDefaults usage": mastg_ref(["MASTG-TEST-0058"]),
            "UIPasteboard usage": mastg_ref(["MASTG-TEST-0059"]),
            "WebView / JS bridge surface": mastg_ref(["MASTG-TEST-0076"]),
        }

        # Build findings with highlighted keywords
        findings = []
        if hits:
            for t, hits_with_matches in hits[:8]:
                # Format evidence with highlighted keywords
                evidence = []
                seen = set()
                for line, matched_keyword in hits_with_matches[:25]:
                    if line not in seen:
                        evidence.append(f"[{matched_keyword}] {line}")
                        seen.add(line)
                if evidence:
                    findings.append(Finding(title=rel(t, base), evidence=evidence, files=[rel(t, base)]))

        summary_text = f"Found in {len(hits)} binary file(s) - MASTG expects secure alternatives"
        if "NSUserDefaults" in label:
            summary_text = f"Found NSUserDefaults in {len(hits)} file(s) - Use Keychain for sensitive data, not UserDefaults"
        elif "UIPasteboard" in label:
            summary_text = f"Found UIPasteboard in {len(hits)} file(s) - Pasteboard may leak sensitive data"
        elif "WebView" in label:
            summary_text = f"Found WebView usage in {len(hits)} file(s) - Review JavaScript bridge security"

        results.append(TestResult(
            id=f"CODE-{re.sub(r'[^A-Z0-9]+','',label.upper())[:24]}",
            name=f"Insecure/Review API: {label} (strings triage)",
            status="INFO" if hits else "PASS",
            summary=[summary_text] if hits else ["No indicators found via strings in scanned binaries"],
            findings=findings,
            mastg_ref_html=mastg_map.get(label, mastg_ref(["MASTG-CODE-1"]))
        ))

    # HTTP URLs anywhere in bundle
    http_findings = []
    all_files = [os.path.join(r, f) for r, _, fs in os.walk(app_dir) for f in fs]
    
    for p in all_files:
        try:
            if os.path.getsize(p) > 50 * 1024 * 1024:
                continue
            
            lines = strings_dump(p, timeout=30)
            http_matches = strings_grep_lines(lines, [r"http://"], max_hits=50)
            
            interesting_hits = []
            for hit in http_matches:
                if not any(ignored in hit for ignored in HTTP_IGNORE_DOMAINS):
                    interesting_hits.append(hit)
            
            if interesting_hits:
                http_findings.append(FindingBlock(
                    title=rel(p, base),
                    link=make_file_link(base, rel(p, base)),
                    evidence=interesting_hits
                ))
        except Exception:
            continue

    results.append(TestResult(
        id="NETWORK-HTTP",
        name="Insecure HTTP References",
        status="WARN" if http_findings else "PASS",
        summary=[f"Found 'http://' in {len(http_findings)} file(s) (verify production use)"] if http_findings else
                ["No non-standard 'http://' references found in bundle scan"],
        findings=http_findings,
        mastg_ref_html=mastg_ref(["MASTG-TEST-0065"])
    ))

    return results

# ---------------------------
# Device Runtime Analysis (SSH)
# ---------------------------

def check_device_installed_files(device_ip: str, bundle_id: str, base: str, password: str = "alpine", manual: bool = False, discovered_app_path: Optional[str] = None, discovered_data_path: Optional[str] = None) -> TestResult:
    """
    SSH into jailbroken device and scan installed app for sensitive files, plists, JS, configs.
    Analyzes both app bundle and data container.
    """
    print(f"    [*] Connecting to device {device_ip}...")
    # Check SSH connectivity
    if not ssh_check_connectivity(device_ip, password, manual):
        return TestResult(
            id="DEVICE-FILES",
            name="Installed App File Analysis (SSH)",
            status="WARN",
            summary_lines=[f"Cannot connect to device at {device_ip} via SSH",
                          "Ensure device is jailbroken, reachable, and SSH is enabled (OpenSSH)",
                          "Default password: alpine"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0057"], ["Data Storage"])
        )

    print(f"    [+] Connected to device")
    # Use discovered paths if available, otherwise search
    if discovered_app_path:
        print(f"    [*] Using discovered app bundle: {discovered_app_path}")
        app_path = discovered_app_path
    else:
        print(f"    [*] Searching for app bundle containing '{bundle_id}'...")
        app_path = ssh_find_app_path(device_ip, bundle_id, password, manual)

    if discovered_data_path:
        print(f"    [*] Using discovered data container: {discovered_data_path}")
        data_path = discovered_data_path
    else:
        print(f"    [*] Searching for data container containing '{bundle_id}'...")
        data_path = ssh_find_app_data_path(device_ip, bundle_id, password, manual)

    if not app_path and not data_path:
        return TestResult(
            id="DEVICE-FILES",
            name="Installed App File Analysis (SSH)",
            status="INFO",
            summary_lines=[f"App '{bundle_id}' not found on device at {device_ip}",
                          "Ensure the app is installed on the device"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0057"], ["Data Storage"])
        )

    findings = []
    summary_lines = []

    if app_path:
        summary_lines.append(f"App bundle found: {app_path}")

        # Scan for sensitive file types in app bundle
        sensitive_exts = ["*.plist", "*.js", "*.json", "*.xml", "*.config", "*.conf", "*.env", "*.key", "*.pem", "*.p12", "*.pfx"]

        for ext in sensitive_exts:
            cmd = f"find '{app_path}' -name '{ext}' -type f 2>/dev/null | head -50"
            rc, out = ssh_run(device_ip, cmd, password=password, timeout=30, manual=manual)

            if rc == 0 and out.strip():
                files = out.strip().splitlines()
                # Get file contents for analysis
                evidence_items = []
                for file_path in files[:20]:  # Limit to first 20 files
                    # Get file size
                    size_cmd = f"ls -lh '{file_path}' 2>/dev/null | awk '{{print $5}}'"
                    rc_size, size_out = ssh_run(device_ip, size_cmd, timeout=5)
                    size = size_out.strip() if rc_size == 0 else "?"

                    # Try to read file content (first 1000 chars)
                    read_cmd = f"head -c 1000 '{file_path}' 2>/dev/null"
                    rc_read, content = ssh_run(device_ip, read_cmd, timeout=10)

                    if rc_read == 0 and content.strip():
                        evidence_items.append(f"{file_path} ({size}):")
                        # Check for sensitive patterns in content
                        sensitive_patterns = [
                            r"password", r"secret", r"token", r"api[_-]?key",
                            r"private[_-]?key", r"aws", r"credential"
                        ]
                        for line in content.splitlines()[:10]:
                            for pat in sensitive_patterns:
                                if re.search(pat, line, re.IGNORECASE):
                                    evidence_items.append(f"  [SENSITIVE] {line[:200]}")
                                    break
                    else:
                        evidence_items.append(f"{file_path} ({size})")

                if evidence_items:
                    findings.append(FindingBlock(
                        title=f"App Bundle: {ext} files",
                        evidence=evidence_items,
                        link=""
                    ))

    if data_path:
        summary_lines.append(f"Data container found: {data_path}")

        # Scan data container for sensitive files
        data_scan_patterns = [
            ("*.plist", "Property List files"),
            ("*.db", "Database files"),
            ("*.sqlite", "SQLite databases"),
            ("*.json", "JSON configuration files"),
            ("*.xml", "XML configuration files"),
            ("*.log", "Log files"),
            ("*.txt", "Text files"),
        ]

        for pattern, description in data_scan_patterns:
            cmd = f"find '{data_path}' -name '{pattern}' -type f 2>/dev/null | head -30"
            rc, out = ssh_run(device_ip, cmd, password=password, timeout=30, manual=manual)

            if rc == 0 and out.strip():
                files = out.strip().splitlines()
                evidence_items = []

                for file_path in files[:15]:
                    size_cmd = f"ls -lh '{file_path}' 2>/dev/null | awk '{{print $5}}'"
                    rc_size, size_out = ssh_run(device_ip, size_cmd, timeout=5)
                    size = size_out.strip() if rc_size == 0 else "?"
                    evidence_items.append(f"{file_path} ({size})")

                if evidence_items:
                    findings.append(FindingBlock(
                        title=f"Data Container: {description}",
                        evidence=evidence_items,
                        link=""
                    ))

    if not findings:
        summary_lines.append("No sensitive files found in app bundle or data container")
        status = "PASS"
    else:
        summary_lines.append(f"Found {len(findings)} categories of files requiring review")
        status = "WARN"

    return TestResult(
        id="DEVICE-FILES",
        name="Installed App File Analysis (SSH)",
        status=status,
        summary_lines=summary_lines,
        findings=findings,
        mastg_ref_html=mastg_ref(["MASTG-TEST-0057"], ["Data Storage"])
    )

def check_device_cleartext_dbs(device_ip: str, bundle_id: str, base: str, password: str = "alpine", manual: bool = False, discovered_data_path: Optional[str] = None) -> TestResult:
    """
    SSH into device and check for unencrypted SQLite databases in app data container.
    Tests if databases are encrypted using SQLCipher or similar.
    """
    # Check SSH connectivity
    if not ssh_check_connectivity(device_ip, password, manual):
        return TestResult(
            id="DEVICE-CLEARTEXT-DB",
            name="Cleartext Database Detection (SSH)",
            status="WARN",
            summary_lines=[f"Cannot connect to device at {device_ip} via SSH"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0001"], ["Local Storage"])
        )

    # Use discovered path if available, otherwise search
    if discovered_data_path:
        print(f"    [*] Using discovered data container: {discovered_data_path}")
        data_path = discovered_data_path
    else:
        print(f"    [*] Searching for data container containing '{bundle_id}'...")
        data_path = ssh_find_app_data_path(device_ip, bundle_id, password, manual)

    if not data_path:
        return TestResult(
            id="DEVICE-CLEARTEXT-DB",
            name="Cleartext Database Detection (SSH)",
            status="INFO",
            summary_lines=[f"App data container not found for '{bundle_id}' on device"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0001"], ["Local Storage"])
        )

    # Find SQLite databases
    cmd = f"find '{data_path}' -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null | head -30"
    rc, out = ssh_run(device_ip, cmd, password=password, timeout=30, manual=manual)

    if rc != 0 or not out.strip():
        return TestResult(
            id="DEVICE-CLEARTEXT-DB",
            name="Cleartext Database Detection (SSH)",
            status="PASS",
            summary_lines=["No SQLite databases found in app data container"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0001"], ["Local Storage"])
        )

    db_files = out.strip().splitlines()
    findings = []
    cleartext_count = 0
    encrypted_count = 0
    system_db_count = 0

    # Known system/framework databases that are expected to be cleartext
    # These rely on iOS file-level data protection, not database encryption
    SYSTEM_DBS = {
        'pcs.db',           # CloudKit Private Cloud Storage
        'Records.db',       # CloudKit Records
        'Cache.db',         # Safari/WebKit cache
        'Cookies.binarycookies',  # Safari cookies
        'LocalStorage.sqlite3',    # WebKit local storage
    }

    for db_path in db_files[:20]:
        db_name = os.path.basename(db_path)

        # Skip known system databases
        if db_name in SYSTEM_DBS:
            system_db_count += 1
            continue

        # Check if database is encrypted by reading first 16 bytes
        # SQLite unencrypted: starts with "SQLite format 3"
        # SQLCipher encrypted: starts with random bytes
        check_cmd = f"head -c 16 '{db_path}' 2>/dev/null"
        rc_check, header = ssh_run(device_ip, check_cmd, timeout=10)

        if rc_check != 0:
            continue

        is_cleartext = header.startswith("SQLite format 3")

        # Get database size
        size_cmd = f"ls -lh '{db_path}' 2>/dev/null | awk '{{print $5}}'"
        rc_size, size_out = ssh_run(device_ip, size_cmd, timeout=5)
        size = size_out.strip() if rc_size == 0 else "?"

        # Try to get table names if cleartext
        tables_info = ""
        if is_cleartext:
            cleartext_count += 1
            tables_cmd = f"echo '.tables' | sqlite3 '{db_path}' 2>/dev/null | head -c 500"
            rc_tables, tables_out = ssh_run(device_ip, tables_cmd, timeout=10)
            if rc_tables == 0 and tables_out.strip():
                tables_info = f"\nTables: {tables_out.strip()}"

            # Try to get row count from first table
            if tables_out.strip():
                first_table = tables_out.strip().split()[0]
                count_cmd = f"echo 'SELECT COUNT(*) FROM {first_table};' | sqlite3 '{db_path}' 2>/dev/null"
                rc_count, count_out = ssh_run(device_ip, count_cmd, timeout=10)
                if rc_count == 0 and count_out.strip():
                    tables_info += f"\nSample row count ({first_table}): {count_out.strip()}"

            findings.append(FindingBlock(
                title=f"CLEARTEXT: {os.path.basename(db_path)}",
                evidence=[
                    f"Path: {db_path}",
                    f"Size: {size}",
                    f"Status: ✗ UNENCRYPTED (plaintext SQLite){tables_info}"
                ],
                link=""
            ))
        else:
            encrypted_count += 1
            findings.append(FindingBlock(
                title=f"ENCRYPTED: {os.path.basename(db_path)}",
                evidence=[
                    f"Path: {db_path}",
                    f"Size: {size}",
                    f"Status: ✓ Appears to be encrypted (not standard SQLite header)"
                ],
                link=""
            ))

    summary_lines = [
        f"Found {len(db_files)} database file(s) in data container",
        f"✗ {cleartext_count} CLEARTEXT (unencrypted)",
        f"✓ {encrypted_count} encrypted or non-SQLite",
        f"ℹ {system_db_count} system databases (skipped - CloudKit/Safari)"
    ]

    # Pass if no cleartext app databases, or if only system databases found
    if cleartext_count > 0:
        status = "FAIL"
    elif encrypted_count > 0 or system_db_count > 0:
        status = "PASS"
    else:
        status = "INFO"  # No databases found at all after filtering

    return TestResult(
        id="DEVICE-CLEARTEXT-DB",
        name="Cleartext Database Detection (SSH)",
        status=status,
        summary_lines=summary_lines,
        findings=findings,
        mastg_ref_html=mastg_ref(["MASTG-TEST-0001"], ["Local Storage"])
    )

# ---------------------------
# Optional dynamic (read-only)
# --------------------------- 

def dynamic_introspection_frida(bundle_id: str) -> TestResult:
    if not which("frida-ps") or not which("frida"):
        return TestResult(
            id="DYNAMIC-FRIDA",
            name="Dynamic Introspection (Frida)",
            status="WARN",
            summary=["frida tools not found on PATH; install frida-tools and ensure device is reachable"],
            is_dynamic=True
        )
    rc, ps = run(["frida-ps", "-Uai"], timeout=20)
    if rc != 0:
        return TestResult(
            id="DYNAMIC-FRIDA",
            name="Dynamic Introspection (Frida)",
            status="WARN",
            summary=["Unable to list processes (is frida-server running / device connected?)"],
            findings=[Finding(title="frida-ps output", evidence=ps.splitlines()[:120])],
            is_dynamic=True
        )
    pid = None
    for line in ps.splitlines():
        if bundle_id in line:
            parts = line.split()
            if parts and parts[0].isdigit():
                pid = parts[0]
                break
    if not pid:
        return TestResult(
            id="DYNAMIC-FRIDA",
            name="Dynamic Introspection (Frida)",
            status="INFO",
            summary=["Device reachable; app not currently running/installed or not visible in frida-ps output"],
            findings=[Finding(title="Tip", evidence=["Launch the app once on device, then re-run with --dynamic"] )],
            is_dynamic=True
        )

    js = r"""
    'use strict';
    setImmediate(function() {
      try {
        var mods = Process.enumerateModules();
        send({ev:"modules", count: mods.length, first: mods.slice(0, 15).map(m=>m.name)});
      } catch (e) {
        send({ev:"err", msg: String(e)});
      }
    });
    """
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as tf:
        tf.write(js)
        tmp_js = tf.name
    rc2, out = run(["frida", "-U", "-p", pid, "-l", tmp_js], timeout=12)
    try:
        os.unlink(tmp_js)
    except Exception:
        pass

    status: Status = "INFO" if rc2 == 0 else "WARN"
    return TestResult(
        id="DYNAMIC-FRIDA",
        name="Dynamic Introspection (Frida)",
        status=status,
        summary=[f"Attached to PID {pid} and attempted module enumeration"] if rc2 == 0 else ["Attach failed (see output)"],
        findings=[Finding(title="frida output (truncated)", evidence=out.splitlines()[:120])],
        is_dynamic=True,
        mastg_ref_html=mastg_ref(["MASTG-TEST-0094"], ["Reverse Engineering and Tampering"])
    )

# --------------------------- 
# Test registry + grouping
# --------------------------- 

@dataclass
class TestDef:
    id: str
    name: str
    group: str
    mastg_ref: str
    fn: Callable[..., List[TestResult] | TestResult]

MASVS_GROUPS: Dict[str, str] = {
    "MASVS-STORAGE": "Storage",
    "MASVS-CRYPTO": "Cryptography",
    "MASVS-NETWORK": "Network Communication",
    "MASVS-PLATFORM": "Platform Interaction",
    "MASVS-CODE": "Code Quality",
    "MASVS-RESILIENCE": "Resilience Against Reverse Engineering and Tampering",
    "MASVS-DYNAMIC": "Dynamic (Read-only Introspection)",
    "MASVS-DEVICE": "Device Runtime Analysis (SSH)",
}

def check_device_backup_and_protection(device_ip: str, bundle_id: str, base: str, password: str = "alpine", manual: bool = False, discovered_data_path: Optional[str] = None) -> TestResult:
    """
    Check iOS file backup exclusion and data protection attributes via SSH.

    MASTG References:
    - MASTG-TEST-0060: Testing Local Storage for Sensitive Data
    """

    # Check SSH connectivity
    if not ssh_check_connectivity(device_ip, password, manual):
        return TestResult(
            id="DEVICE-DATAPROTECTION",
            name="Backup Exclusion & Data Protection (SSH)",
            status="WARN",
            summary=[f"Cannot connect to device at {device_ip} via SSH"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0060"], ["Local Storage"])
        )

    # Use discovered path if available
    if discovered_data_path:
        data_path = discovered_data_path
    else:
        data_path = ssh_find_app_data_path(device_ip, bundle_id, password, manual)

    if not data_path:
        return TestResult(
            id="DEVICE-DATAPROTECTION",
            name="Backup Exclusion & Data Protection (SSH)",
            status="INFO",
            summary=[f"App data container not found for '{bundle_id}' on device"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0060"], ["Local Storage"])
        )

    # Find sensitive files (databases, keychain, logs, etc.)
    find_cmd = f"find '{data_path}' -type f \\( -name '*.db' -o -name '*.sqlite' -o -name '*.log' -o -name '*.plist' -o -name '*.json' \\) 2>/dev/null | head -30"
    rc, out = ssh_run(device_ip, find_cmd, password=password, timeout=30, manual=manual)

    if rc != 0 or not out.strip():
        return TestResult(
            id="DEVICE-DATAPROTECTION",
            name="Backup Exclusion & Data Protection (SSH)",
            status="INFO",
            summary=["No sensitive files found or unable to search"],
            mastg_ref_html=mastg_ref(["MASTG-TEST-0060"], ["Local Storage"])
        )

    files = out.strip().splitlines()
    findings = []
    backup_excluded_count = 0
    not_excluded_count = 0

    for file_path in files[:20]:  # Limit to 20 files
        # Check backup exclusion attribute
        backup_cmd = f"xattr -p com.apple.MobileBackup '{file_path}' 2>/dev/null"
        rc_backup, backup_out = ssh_run(device_ip, backup_cmd, timeout=5, manual=manual)

        is_excluded = (rc_backup == 0 and backup_out.strip())

        file_name = os.path.basename(file_path)
        file_dir = os.path.dirname(file_path).replace(data_path, "...")

        evidence_lines = [
            f"File: {file_name}",
            f"Path: {file_dir}/{file_name}",
            ""
        ]

        # Backup status
        if is_excluded:
            backup_excluded_count += 1
            evidence_lines.append("✓ Backup Exclusion: YES")
            evidence_lines.append("  File marked with com.apple.MobileBackup attribute")
            evidence_lines.append("  Will NOT be included in iTunes/iCloud backup")
        else:
            not_excluded_count += 1
            evidence_lines.append("⚠ Backup Exclusion: NO")
            evidence_lines.append("  File WILL be included in backups")

            # Sensitive file types should be excluded
            if any(ext in file_name.lower() for ext in ['.db', '.sqlite', '.log']):
                evidence_lines.append("  ⚠ WARNING: Sensitive file not excluded from backup!")

        evidence_lines.append("")

        # Data protection (approximate - full check requires more privileged access)
        evidence_lines.append("Data Protection:")
        evidence_lines.append("  Note: Full protection class check requires special tools")
        if "Library/Caches" in file_path:
            evidence_lines.append("  ℹ Located in Caches (typically lower protection)")
        elif "Documents" in file_path:
            evidence_lines.append("  ℹ Located in Documents (should have protection)")
        elif "tmp" in file_path.lower():
            evidence_lines.append("  ⚠ Located in tmp (temporary, may lack protection)")

        findings.append(FindingBlock(
            title=f"{file_name}",
            evidence=evidence_lines,
            open_by_default=False
        ))

    # Build summary
    status: Status = "INFO"
    summary_lines = [
        f"Analyzed {len(files[:20])} file(s) in data container",
        f"✓ {backup_excluded_count} file(s) excluded from backup",
        f"⚠ {not_excluded_count} file(s) NOT excluded from backup"
    ]

    if not_excluded_count > backup_excluded_count:
        status = "WARN"
        summary_lines.append("⚠ Many files not excluded - verify if sensitive data is backed up")

    # Add guidance
    guidance = [
        "Backup Exclusion Best Practices:",
        "",
        "Files that SHOULD be excluded from backups:",
        "  • Databases with sensitive user data",
        "  • Log files with potentially sensitive information",
        "  • Cached data that can be regenerated",
        "  • Temporary files",
        "",
        "How to exclude files from backup (Swift):",
        "  var url = URL(fileURLWithPath: filePath)",
        "  var resourceValues = URLResourceValues()",
        "  resourceValues.isExcludedFromBackup = true",
        "  try? url.setResourceValues(resourceValues)",
        "",
        "How to exclude files from backup (Objective-C):",
        "  NSURL *url = [NSURL fileURLWithPath:filePath];",
        "  [url setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:nil];",
        "",
        "Data Protection Classes:",
        "  • NSFileProtectionComplete - Best security",
        "  • NSFileProtectionCompleteUnlessOpen - Good for active files",
        "  • NSFileProtectionCompleteUntilFirstUserAuthentication - Default",
        "  • NSFileProtectionNone - Avoid for sensitive data",
    ]

    findings.insert(0, FindingBlock(
        title="Backup & Data Protection Guidance",
        evidence=guidance,
        open_by_default=False
    ))

    return TestResult(
        id="DEVICE-DATAPROTECTION",
        name="Backup Exclusion & Data Protection (SSH)",
        status=status,
        summary=summary_lines,
        findings=findings,
        mastg_ref_html=mastg_ref(["MASTG-TEST-0060"], ["Local Storage"])
    )

def build_tests() -> List[TestDef]:
    return [
        TestDef("CHECKSEC", "Binary Security Features (checksec)", "MASVS-RESILIENCE",
                "MASTG iOS: Binary Security Features", lambda ctx: check_checksec(ctx["app_dir"], ctx["base"])),
        TestDef("PLIST", "Info.plist Review", "MASVS-PLATFORM",
                "MASTG iOS: Platform Interaction / Configuration", lambda ctx: check_info_plist(ctx["info"], os.path.join(ctx["app_dir"], "Info.plist"), ctx["base"])),
        TestDef("CODESIGN", "Code Signing Details", "MASVS-RESILIENCE",
                "MASTG iOS: Tampering / Code Integrity", lambda ctx: check_codesign_details(ctx["main_bin"])),
        TestDef("PROFILE", "Provisioning Profile Analysis", "MASVS-RESILIENCE",
                "MASTG iOS: Code Signing / Distribution", lambda ctx: check_provisioning_profile(ctx["app_dir"], ctx["base"])),
        TestDef("ENT", "Entitlements Review", "MASVS-PLATFORM",
                "MASTG iOS: App Permissions / Entitlements", lambda ctx: check_entitlements(ctx["main_bin"])),
        TestDef("PRIVMANIFEST", "Privacy Manifest (iOS 17+)", "MASVS-PRIVACY",
                "MASTG iOS: Privacy Requirements", lambda ctx: check_privacy_manifest(ctx["app_dir"], ctx["base"])),
        TestDef("HARDEN", "Binary Hardening", "MASVS-RESILIENCE",
                "MASTG iOS: Resilience / Binary Protections", lambda ctx: check_macho_hardening(ctx["main_bin"])),
        TestDef("CRYPTOSYMS", "Weak Crypto & Insecure RNG", "MASVS-CRYPTO",
                "MASTG iOS: Cryptography / RNG", lambda ctx: check_weak_crypto_and_rng(ctx["main_bin"])),
        TestDef("INSECUREAPIS", "Insecure API Usage (Binary Analysis)", "MASVS-CODE",
                "MASTG iOS: Insecure APIs / Code Quality", lambda ctx: check_insecure_apis_symbols(ctx["main_bin"])),
        TestDef("SECRETS", "Hardcoded Secrets (Binary Analysis)", "MASVS-STORAGE",
                "MASTG iOS: Hardcoded Secrets / Entropy Analysis", lambda ctx: check_hardcoded_secrets_binary(ctx["main_bin"])),
        TestDef("EXTENSIONS", "App Extensions Analysis", "MASVS-PLATFORM",
                "MASTG iOS: App Extensions Security", lambda ctx: check_app_extensions(ctx["app_dir"], ctx["base"])),
        TestDef("SQLINJECTION", "SQL Injection Pattern Detection", "MASVS-CODE",
                "MASTG iOS: SQL Security", lambda ctx: check_sql_injection_patterns(ctx["main_bin"])),
        TestDef("URLKEYBOARD", "URL Scheme & Keyboard Security", "MASVS-PLATFORM",
                "MASTG iOS: URL Validation / Keyboard", lambda ctx: check_url_and_keyboard_security(ctx["info"], ctx["main_bin"], os.path.join(ctx["app_dir"], "Info.plist"), ctx["base"])),
        TestDef("XPC", "XPC Services Analysis", "MASVS-PLATFORM",
                "MASTG iOS: XPC Security", lambda ctx: check_xpc_services(ctx["app_dir"], ctx["base"])),
        TestDef("SYMS", "Debug Symbols / Stripping", "MASVS-RESILIENCE",
                "MASTG iOS: Resilience / Debugging Artifacts", lambda ctx: check_debug_symbols(ctx["main_bin"])),
        TestDef("LIBS", "Linked Libraries", "MASVS-RESILIENCE",
                "MASTG iOS: Resilience / Libraries", lambda ctx: check_libraries(ctx["main_bin"])),
        TestDef("BUNDLE", "Bundle File Scan", "MASVS-STORAGE",
                "MASTG iOS: Data Storage / Bundle Contents", lambda ctx: check_bundle_filetypes(ctx["app_dir"], ctx["base"])),
        TestDef("STRINGS", "Strings Pattern Scan", "MASVS-CODE",
                "MASTG iOS: Static Analysis / Strings", lambda ctx: check_strings_patterns(ctx["app_dir"], ctx["main_bin"], ctx["base"])),
        TestDef("DYNFRIDA", "Dynamic Introspection (Frida)", "MASVS-DYNAMIC",
                "MASTG iOS: Dynamic Analysis", lambda ctx: dynamic_introspection_frida(ctx["bundle_id"])),
        TestDef("DEVICE-FILES", "Installed App File Analysis (SSH)", "MASVS-DEVICE",
                "MASTG iOS: Runtime Data Storage", lambda ctx: check_device_installed_files(ctx.get("device_ip", ""), ctx["bundle_id"], ctx["base"], ctx.get("ssh_password", "alpine"), ctx.get("ssh_manual", False), ctx.get("discovered_app_path"), ctx.get("discovered_data_path"))),
        TestDef("DEVICE-CLEARTEXT-DB", "Cleartext Database Detection (SSH)", "MASVS-DEVICE",
                "MASTG iOS: Database Encryption", lambda ctx: check_device_cleartext_dbs(ctx.get("device_ip", ""), ctx["bundle_id"], ctx["base"], ctx.get("ssh_password", "alpine"), ctx.get("ssh_manual", False), ctx.get("discovered_data_path"))),
        TestDef("DEVICE-BACKUP", "Backup Exclusion & Data Protection (SSH)", "MASVS-DEVICE",
                "MASTG iOS: Backup & File Protection", lambda ctx: check_device_backup_and_protection(ctx.get("device_ip", ""), ctx["bundle_id"], ctx["base"], ctx.get("ssh_password", "alpine"), ctx.get("ssh_manual", False), ctx.get("discovered_data_path"))),
    ]

def parse_previous_report(bundle_id: str, reports_dir: str = '.') -> Optional[Dict]:
    """
    Parse a previous report HTML file for the given bundle ID to extract metadata.

    Returns dict with keys:
        - version: str
        - ipa_size_mb: float
        - scan_started_at: str
        - scan_finished_at: str

    Returns None if no previous report found or parsing fails.
    """
    report_filename = os.path.join(reports_dir, f"{bundle_id}.report.html")

    if not os.path.exists(report_filename):
        return None

    try:
        with open(report_filename, 'r', encoding='utf-8') as f:
            html_content = f.read()

        # Extract metadata from the header
        version_match = re.search(r'<div class="small">Version</div><div>([^<]+)</div>', html_content)
        size_match = re.search(r'<div class="small">IPA Size</div><div>([0-9.]+)\s*MB</div>', html_content)
        started_match = re.search(r'Started:</span>\s*<strong>([^<]+)</strong>', html_content)
        finished_match = re.search(r'Finished:</span>\s*<strong>([^<]+)</strong>', html_content)

        if not all([version_match, started_match, finished_match]):
            return None

        version = version_match.group(1).strip()
        ipa_size_mb = float(size_match.group(1)) if size_match else 0.0
        scan_started_at = started_match.group(1).strip()
        scan_finished_at = finished_match.group(1).strip()

        return {
            'version': version,
            'ipa_size_mb': ipa_size_mb,
            'scan_started_at': scan_started_at,
            'scan_finished_at': scan_finished_at,
        }

    except Exception as e:
        print(f"[!] Warning: Could not parse previous report: {e}")
        return None

def parse_previous_scan_history(bundle_id: str, reports_dir: str = '.') -> List[Dict]:
    """
    Parse all previous scan history from the HTML report.

    Returns: list of dicts with keys:
        - version: str
        - size_mb: float
        - size_diff: str
        - scan_time: str

    Returns empty list if no previous report found or parsing fails.
    """
    report_filename = os.path.join(reports_dir, f"{bundle_id}.report.html")

    if not os.path.exists(report_filename):
        return []

    try:
        with open(report_filename, 'r', encoding='utf-8') as f:
            html_content = f.read()

        history = []

        # Look for all "Previous scan:" entries
        pattern = r'<strong>Previous scan:</strong>\s*version\s+([^\s(]+)\s+\(([0-9.]+)\s*MB,\s*([^)]+)\s+since last scan\)[^<]*<br>\s*<span[^>]*>([^<]+)</span>'

        for match in re.finditer(pattern, html_content, re.DOTALL):
            version = match.group(1).strip()
            size_mb = float(match.group(2))
            size_diff = match.group(3).strip()
            scan_time = match.group(4).strip()

            history.append({
                'version': version,
                'size_mb': size_mb,
                'size_diff': size_diff,
                'scan_time': scan_time,
            })

        return history

    except Exception as e:
        print(f"[!] Warning: Could not parse previous scan history: {e}")
        return []

def format_size_diff(current_mb: float, previous_mb: float) -> str:
    """
    Format size difference with sign and one decimal place.

    Returns: str like "+1.2 MB" or "-0.5 MB" or "no change"
    """
    diff_mb = current_mb - previous_mb

    if diff_mb == 0:
        return "no change"

    sign = "+" if diff_mb > 0 else ""
    return f"{sign}{diff_mb:.1f} MB"

def curses_select_menu(stdscr, items, title="SELECT TESTS"):
    """
    DOS-style menu using arrow keys to navigate and Enter to toggle.
    Returns a set of selected indices.
    """
    import curses
    curses.curs_set(0)  # Hide cursor
    current = 0
    selected = set()

    # Initialize color pairs if supported
    try:
        curses.start_color()
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE)  # Highlighted
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Selected
        has_color = True
    except:
        has_color = False

    while True:
        stdscr.clear()
        height, width = stdscr.getmaxyx()

        # Title
        stdscr.addstr(0, 0, "=" * min(70, width - 1))
        stdscr.addstr(1, 0, title)
        stdscr.addstr(2, 0, "=" * min(70, width - 1))
        stdscr.addstr(3, 0, f"Selected: {len(selected)}/{len(items)}")
        stdscr.addstr(4, 0, "")

        # Display items (with scrolling if needed)
        visible_lines = height - 10
        display_start = max(0, current - (visible_lines // 2))
        display_end = min(len(items), display_start + visible_lines)

        # Adjust display_start if we're near the end
        if display_end == len(items):
            display_start = max(0, len(items) - visible_lines)

        for idx in range(display_start, display_end):
            y = 5 + (idx - display_start)
            if y >= height - 3:
                break

            # Enhanced visual indicators
            status = "[*""" if idx in selected else "[ ]"
            marker = ">>>" if idx == current else "   "
            item_text = f"{marker} {status} [{idx+1:2d}] {items[idx][0]}"

            # Apply visual highlighting for current item
            if idx == current:
                if has_color:
                    stdscr.addstr(y, 0, item_text[:width-1], curses.color_pair(1) | curses.A_BOLD)
                else:
                    stdscr.addstr(y, 0, item_text[:width-1], curses.A_REVERSE | curses.A_BOLD)
            elif idx in selected:
                if has_color:
                    stdscr.addstr(y, 0, item_text[:width-1], curses.color_pair(2))
                else:
                    stdscr.addstr(y, 0, item_text[:width-1])
            else:
                stdscr.addstr(y, 0, item_text[:width-1])

        # Scroll indicator
        if display_start > 0:
            stdscr.addstr(5, width - 10, "^ MORE ^")
        if display_end < len(items):
            stdscr.addstr(height - 4, width - 10, "v MORE v")

        # Instructions
        instr_y = height - 2
        stdscr.addstr(instr_y, 0, "SPACE=Toggle  A=All  N=None  ENTER=Done  Q=Quit")

        stdscr.refresh()

        # Get key input
        key = stdscr.getch()

        if key == curses.KEY_UP:
            current = (current - 1) % len(items)
        elif key == curses.KEY_DOWN:
            current = (current + 1) % len(items)
        elif key == ord(' '):  # Space bar - toggle current item
            if current in selected:
                selected.remove(current)
            else:
                selected.add(current)
        elif key == ord('a') or key == ord('A'):  # Select all
            selected = set(range(len(items)))
        elif key == ord('n') or key == ord('N'):  # Select none
            selected = set()
        elif key == ord('\n') or key == 10:  # Enter - done
            break
        elif key == ord('q') or key == ord('Q'):  # Quit
            return None

    return selected

def interactive_select(tests: List[TestDef], include_dynamic_flag: bool, include_device_flag: bool = False) -> List[TestDef]:
    """Interactive test selection using curses menu"""
    import curses

    # Filter allowed tests
    allowed = []
    for t in tests:
        if t.id == "DYNFRIDA" and not include_dynamic_flag:
            continue
        if t.group == "MASVS-DEVICE" and not include_device_flag:
            continue
        allowed.append(t)

    # Build items for curses menu
    items = [(f"{t.id:<10} {t.group:<16} {t.name}", t) for t in allowed]

    print("\nRun all tests or select specific tests?")
    print("  a - RUN ALL tests")
    print("  s - SELECT specific tests")
    choice = input("Choice [a/s]: ").strip().lower()

    if choice == 's':
        selected_indices = curses.wrapper(curses_select_menu, items, "SELECT TESTS (Use arrows, SPACE to toggle)")
        if selected_indices is None:
            print("[!] Selection cancelled. Exiting.")
            return []

        selected_tests = [allowed[i] for i in sorted(selected_indices)]
        if not selected_tests:
            print("[!] No tests selected. Exiting.")
            return []

        print(f"\n[*] Running {len(selected_tests)} selected test(s)...")
        return selected_tests
    else:
        print(f"\n[*] Running all {len(allowed)} tests...")
        return allowed

# --------------------------- 
# Rendering
# --------------------------- 

def render_html(meta: Dict, grouped_results: Dict[str, List[TestResult]]) -> str:
    # KPIs
    counts = {"FAIL":0,"WARN":0,"INFO":0,"PASS":0}
    for cat in grouped_results.values():
        for tr in cat:
            counts[tr.status] = counts.get(tr.status,0) + 1

    sections: List[str] = []
    for group_key, group_title in MASVS_GROUPS.items():
        blocks = grouped_results.get(group_key, [])
        if not blocks:
            continue
        sections.append(f"<h2>{html.escape(group_key)} — {html.escape(group_title)}</h2>")
        for tr in blocks:
            cls = status_cls(tr.status)
            dyn = " <span class='badge' style='background:#16a34a;color:white'>DYNAMIC</span>" if tr.is_dynamic else ""

            # Handle both old summary and new summary_lines
            if hasattr(tr, 'summary_lines') and tr.summary_lines:
                summary_html = "<ul>" + "".join(f"<li>{html.escape(x)}</li>" for x in tr.summary_lines) + "</ul>"
            elif tr.summary:
                summary_html = "<ul>" + "".join(f"<li>{html.escape(x)}</li>" for x in tr.summary) + "</ul>"
            else:
                summary_html = ""

            findings_html = ""
            if tr.findings:
                parts = []
                for f in tr.findings:
                    # Handle both Finding and FindingBlock
                    if isinstance(f, FindingBlock):
                        title_html = f.link if f.link else html.escape(f.title)
                        subtitle_html = f"<div class='small'>{html.escape(f.subtitle)}</div>" if f.subtitle else ""
                        evidence_html = ""
                        if f.evidence:
                            evidence_html = "<pre>" + html.escape("\n".join(f.evidence)) + "</pre>"
                        code_html = ""
                        if f.code:
                            code_html = f"<pre><code class='language-{f.code_language}'>{html.escape(f.code)}</code></pre>"
                        parts.append(f"<div><strong>{title_html}</strong>{subtitle_html}{evidence_html}{code_html}</div>")
                    else: # Legacy Finding
                        ev = ""
                        if f.evidence:
                            ev = "<pre>" + html.escape("\n".join(f.evidence[:300])) + "</pre>"
                        parts.append(f"<div><strong>{html.escape(f.title)}</strong>{ev}</div>")
                findings_html = "".join(parts)

            # Handle tables_html (for checksec and other tabular data)
            tables_html = ""
            if hasattr(tr, 'tables_html') and tr.tables_html:
                tables_html = "<div style='overflow-x:auto;'>" + "".join(tr.tables_html) + "</div>"

            # Handle both old mastg_ref and new mastg_ref_html
            if hasattr(tr, 'mastg_ref_html') and tr.mastg_ref_html:
                ref_html = tr.mastg_ref_html
            elif tr.mastg_ref:
                ref_html = f"<div class='small'><strong>Reference:</strong> {html.escape(tr.mastg_ref)}</div>"
            else:
                ref_html = ""

            # Handle optional id field
            if tr.id:
                check_name = f"[{html.escape(tr.id)}] {html.escape(tr.name)}{dyn}"
            else:
                check_name = f"{html.escape(tr.name)}{dyn}"

            sections.append(
                f"<details class='{cls}'>"
                f"<summary class='{cls}'><span class='check-name'>{check_name}</span>"
                f"<span class='badge'>{html.escape(tr.status)}</span></summary>"
                f"<div class='content'>{summary_html}{findings_html}{tables_html}{ref_html}</div>"
                f"</details>"
            )

    return HTML_TEMPLATE.format(
        app_name=html.escape(meta.get("app_name","Unknown")),
        bundle_id=html.escape(meta.get("bundle_id","Unknown")),
        version=html.escape(meta.get("version","Unknown")),
        ipa_size=f"{meta.get('ipa_size_mb', 0):.1f}",
        ipa_sha256=html.escape(meta.get("ipa_sha256","")),
        previous_scan_info=meta.get("previous_scan_info", ""),
        started=html.escape(meta.get("started","")),
        finished=html.escape(meta.get("finished","")),
        kpi_fail=counts["FAIL"], kpi_warn=counts["WARN"], kpi_info=counts["INFO"], kpi_pass=counts["PASS"],
        sections="\n".join(sections)
    )

# --------------------------- 
# Preflight
# --------------------------- 

REQUIRED_TOOLS = ["plutil", "otool", "nm", "codesign", "strings"]

def preflight() -> Tuple[bool, List[str]]:
    missing = []
    for t in REQUIRED_TOOLS:
        if which(t):
            continue
        if os.path.exists(f"/usr/bin/{t}"):
            continue
        missing.append(t)
    return (len(missing) == 0), missing

# --------------------------- 
# Main
# --------------------------- 

def main():
    ap = argparse.ArgumentParser(description="iOS IPA MASVS-oriented scanner (static-first)")
    ap.add_argument("-f", "--file", required=True, help="Path to .ipa")
    ap.add_argument("-o", "--out", default=None, help="Output directory (default: ./<ipa_name>_iosscan)")
    ap.add_argument("--keep", action="store_true", help="Keep extracted IPA directory")
    ap.add_argument("-d", "--dynamic", action="store_true", help="Include safe dynamic introspection test(s)")
    ap.add_argument("-s", "--select", action="store_true", help="Interactive test selection")
    ap.add_argument("-ssh", "--ssh", dest="ssh", default=None, help="IP address of jailbroken iOS device for runtime analysis")
    ap.add_argument("--ssh-password", default="alpine", help="SSH password for device (default: alpine)")
    ap.add_argument("--ssh-manual", action="store_true", help="Disable automated SSH (you'll be prompted for password each time)")
    args = ap.parse_args()

    ok, missing = preflight()
    if not ok:
        print("[!] Missing required tools: " + ", ".join(missing))
        print("[!] Install Xcode Command Line Tools: xcode-select --install")
        sys.exit(1)

    ipa_path = os.path.abspath(args.file)
    if not os.path.isfile(ipa_path):
        print(f"[!] IPA not found: {ipa_path}")
        sys.exit(1)

    start = datetime.now()
    out_dir = args.out or (os.path.splitext(os.path.basename(ipa_path))[0] + "_iosscan")
    out_dir = os.path.abspath(out_dir)
    safe_mkdir(out_dir)
    configure_report_file_links(out_dir)

    # Get IPA size
    ipa_size_bytes = os.path.getsize(ipa_path)
    ipa_size_mb = ipa_size_bytes / (1024 * 1024)

    meta = {
        "ipa": ipa_path,
        "ipa_sha256": sha256_file(ipa_path),
        "ipa_size_mb": ipa_size_mb,
        "started": start.strftime("%B %d, %Y, %H:%M:%S"),
    }

    tmp_root = None
    if args.keep:
        # If --keep is used, extract to a permanent dir inside the output folder
        extracted = os.path.join(out_dir, "extracted_ipa")
        safe_mkdir(extracted)
    else:
        # Otherwise, use a temporary directory
        tmp_root = tempfile.mkdtemp(prefix="iosscan_")
        extracted = os.path.join(tmp_root, "ipa")

    try:
        unzip_ipa(ipa_path, extracted)
        app_dir = find_app_bundle(extracted)
        info_path = os.path.join(app_dir, "Info.plist")
        if not os.path.exists(info_path):
            raise RuntimeError("Info.plist not found in app bundle")

        info = plutil_to_plist(info_path)
        main_bin = find_main_binary(app_dir, info)

        meta["app_name"] = info.get("CFBundleDisplayName") or info.get("CFBundleName") or os.path.basename(app_dir)
        meta["bundle_id"] = info.get("CFBundleIdentifier", "Unknown")
        ver = info.get("CFBundleShortVersionString", "?")
        build = info.get("CFBundleVersion", "?")
        meta["version"] = f"{ver} ({build})"
        meta["main_binary"] = rel(main_bin, extracted)

        # Banner + quick intro before running tests
        print(APPLE_BANNER)
        for line in RUN_INTRO:
            print(f"  {line}")
        print(f"\nTarget: {meta['app_name']} ({meta['bundle_id']}) version {meta['version']}")
        print(f"IPA: {meta['ipa']} ({meta['ipa_size_mb']:.1f} MB)")
        print(f"Report output: {out_dir}\n")

        ctx = {
            "base": extracted,
            "app_dir": app_dir,
            "info": info,
            "main_bin": main_bin,
            "bundle_id": meta["bundle_id"],
            "device_ip": args.ssh,
            "ssh_password": args.ssh_password,
            "ssh_manual": args.ssh_manual,
        }

        tests = build_tests()
        if args.select:
            selected = interactive_select(tests, include_dynamic_flag=args.dynamic, include_device_flag=bool(args.ssh))
        else:
            # Filter tests based on flags
            selected = []
            for t in tests:
                # Skip dynamic tests unless --dynamic flag
                if t.id == "DYNFRIDA" and not args.dynamic:
                    continue
                # Skip device tests unless --ssh provided
                if t.group == "MASVS-DEVICE" and not args.ssh:
                    continue
                selected.append(t)

        # Show info about enabled features
        if args.ssh:
            print(f"\n[*] Device SSH analysis enabled for {args.ssh}")
            print(f"[*] SSH password: {args.ssh_password}")

            if args.ssh_manual:
                print(f"[*] Manual SSH mode: You will be prompted to enter the password for each command")
            elif not which("sshpass"):
                try:
                    import pexpect
                    print(f"[!] Using pexpect for automatic SSH authentication")
                    print(f"[!] WARNING: pexpect may have issues capturing SSH output")
                    print(f"[!] RECOMMENDED: Install sshpass for reliable SSH automation:")
                    print(f"[!]   brew install hudochenkov/sshpass/sshpass")
                    print(f"[!] OR use --ssh-manual to enter password manually (more reliable)")
                except ImportError:
                    print(f"[!] Warning: Neither sshpass nor pexpect found - will prompt for passwords")
                    print(f"[!] Install sshpass: 'brew install hudochenkov/sshpass/sshpass'")
            else:
                print(f"[*] Using sshpass for automatic SSH authentication")

            # Run diagnostic pre-check if device tests are selected
            has_device_tests = any(t.group == "MASVS-DEVICE" for t in selected)
            if has_device_tests:
                diagnostic_result = ssh_diagnostic_check(
                    args.ssh,
                    meta["bundle_id"],
                    args.ssh_password,
                    args.ssh_manual
                )
                # Update context with discovered paths if found
                if diagnostic_result["found"]:
                    if diagnostic_result["app_path"]:
                        ctx["discovered_app_path"] = diagnostic_result["app_path"]
                    if diagnostic_result["data_path"]:
                        ctx["discovered_data_path"] = diagnostic_result["data_path"]
                    if diagnostic_result["actual_bundle_id"]:
                        ctx["discovered_bundle_id"] = diagnostic_result["actual_bundle_id"]

            print()

        results: List[TestResult] = []
        total_tests = len(selected)
        for idx, t in enumerate(selected, 1):
            try:
                # Show progress
                print(f"[{idx}/{total_tests}] Running: {t.name}...")
                out = t.fn(ctx)
                if isinstance(out, list):
                    results.extend(out)
                else:
                    results.append(out)
            except Exception as e:
                print(f"[!] Error in {t.name}: {type(e).__name__}: {e}")
                results.append(TestResult(
                    id=f"ERR-{t.id}",
                    name=f"{t.name} (error)",
                    status="WARN",
                    summary=[f"Exception during test: {type(e).__name__}: {e}"],
                    mastg_ref=t.mastg_ref
                ))

        print(f"\n[+] Completed {total_tests} test(s)")

        # Group
        grouped: Dict[str, List[TestResult]] = {k: [] for k in MASVS_GROUPS.keys()}
        for tr in results:
            # Handle both old (id-based) and new (name-based) tests
            if tr.id:
                # Legacy id-based categorization
                if tr.id.startswith(("STORAGE","CRYPTO")):
                    grouped["MASVS-STORAGE" if tr.id.startswith("STORAGE") else "MASVS-CRYPTO"].append(tr)
                elif tr.id.startswith("NETWORK"):
                    grouped["MASVS-NETWORK"].append(tr)
                elif tr.id.startswith(("PLATFORM","PRIVACY")):
                    grouped["MASVS-PLATFORM"].append(tr)
                elif tr.id.startswith("CODE"):
                    grouped["MASVS-CODE"].append(tr)
                elif tr.id.startswith(("RESILIENCE","ERR")):
                    grouped["MASVS-RESILIENCE"].append(tr)
                elif tr.id.startswith(("DYNAMIC",)):
                    grouped["MASVS-DYNAMIC"].append(tr)
                else:
                    grouped["MASVS-CODE"].append(tr)
            else:
                # New name-based categorization
                name_lower = tr.name.lower()
                if any(k in name_lower for k in ["keychain", "storage", "data protection"]):
                    grouped["MASVS-STORAGE"].append(tr)
                elif any(k in name_lower for k in ["crypto", "encryption", "hash"]):
                    grouped["MASVS-CRYPTO"].append(tr)
                elif any(k in name_lower for k in ["network", "certificate", "pinning", "tls", "ssl"]):
                    grouped["MASVS-NETWORK"].append(tr)
                elif any(k in name_lower for k in ["webview", "biometric", "authentication", "screenshot", "platform", "privacy"]):
                    grouped["MASVS-PLATFORM"].append(tr)
                elif any(k in name_lower for k in ["code quality", "binary", "hardening", "arc", "pie", "canary"]):
                    grouped["MASVS-CODE"].append(tr)
                elif any(k in name_lower for k in ["resilience", "error"]):
                    grouped["MASVS-RESILIENCE"].append(tr)
                elif any(k in name_lower for k in ["dynamic"]):
                    grouped["MASVS-DYNAMIC"].append(tr)
                else:
                    grouped["MASVS-CODE"].append(tr)

        finish = datetime.now()
        meta["finished"] = finish.strftime("%B %d, %Y, %H:%M:%S")

        # Check for previous scan
        bundle_id = meta.get("bundle_id", "unknown")
        print("[*] Checking for previous scan report...")
        previous_info = parse_previous_report(bundle_id, reports_dir=out_dir)
        if previous_info:
            print(f"[+] Found previous scan: version {previous_info['version']} ({previous_info['ipa_size_mb']:.1f} MB)")
        else:
            print("[*] No previous scan found for this bundle ID")

        # Generate HTML for previous scan comparison
        previous_scan_info_html = ""
        if previous_info:
            # Parse all previous scan history
            older_scans = parse_previous_scan_history(bundle_id, reports_dir=out_dir)

            # Add the most recent previous scan
            size_diff = format_size_diff(meta["ipa_size_mb"], previous_info["ipa_size_mb"])
            scan_datetime = previous_info['scan_started_at']

            # Add all previous scans
            previous_scan_info_html = '''    <div style="border-top: 1px solid rgba(255,255,255,0.3); padding-top: 15px; margin-top: 15px;">
      <div style="font-size: 12px; opacity: 0.9; margin-bottom: 10px;">
        <strong>Previous scan:</strong> version ''' + html.escape(previous_info["version"]) + f''' ({previous_info["ipa_size_mb"]:.1f} MB, {html.escape(size_diff)} since last scan)<br>
        <span style="opacity: 0.8;">Scanned on {html.escape(scan_datetime)}</span>
      </div>
'''

            # Add older scans from history
            for scan in older_scans:
                previous_scan_info_html += f'''      <div style="font-size: 12px; opacity: 0.9; margin-bottom: 10px;">
        <strong>Previous scan:</strong> version {html.escape(scan['version'])} ({scan['size_mb']:.1f} MB, {html.escape(scan['size_diff'])} since last scan)<br>
        <span style="opacity: 0.8;">{html.escape(scan['scan_time'])}</span>
      </div>
'''
            previous_scan_info_html += '''    </div>
'''
        else:
            previous_scan_info_html = ""

        meta["previous_scan_info"] = previous_scan_info_html

        # Write outputs
        report_json = {
            "meta": meta,
            "selected_tests": [{"id": t.id, "name": t.name, "group": t.group} for t in selected],
            "results": [tr.__dict__ for tr in results],
        }
        bundle_id = meta.get("bundle_id", "unknown")
        with open(os.path.join(out_dir, f"{bundle_id}.report.json"), "w", encoding="utf-8") as f:
            json.dump(report_json, f, indent=2, default=lambda o: o.__dict__)

        html_out = render_html(meta, grouped)
        with open(os.path.join(out_dir, f"{bundle_id}.report.html"), "w", encoding="utf-8") as f:
            f.write(html_out)

        # Artefacts
        artefacts = os.path.join(out_dir, "artefacts")
        safe_mkdir(artefacts)
        shutil.copy2(info_path, os.path.join(artefacts, "Info.plist"))
        rc, ent = run(["/usr/bin/codesign", "-d", "--entitlements", ":-", main_bin], timeout=30)
        if rc == 0:
            with open(os.path.join(artefacts, "entitlements.plist"), "w", encoding="utf-8") as f:
                f.write(ent)
        rc2, cs = run(["/usr/bin/codesign", "-dvv", main_bin], timeout=30)
        if rc2 == 0:
            with open(os.path.join(artefacts, "codesign.txt"), "w", encoding="utf-8") as f:
                f.write(cs)

        print(f"[+] Report written: {os.path.join(out_dir, f'{bundle_id}.report.html')}")
        print(f"[+] JSON written:   {os.path.join(out_dir, f'{bundle_id}.report.json')}")
        print(f"[+] Output dir:     {out_dir}")

    finally:
        # Clean up temp dir if it was used
        if tmp_root:
            shutil.rmtree(tmp_root, ignore_errors=True)

if __name__ == "__main__":
    main()
