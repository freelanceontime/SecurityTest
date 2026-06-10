#!/usr/bin/env python3
from __future__ import annotations  # allow X | Y type hints on Python 3.9
"""
selfImprovementtest.py  –  AI-Assisted Android Security Test Runner
======================================================================
All 131 OWASP MASTG tests are embedded directly in this file.
No external Prompt.md required — this is a fully self-contained script.

Feeds tests to Claude Code one-by-one, captures structured results,
refines prompts automatically after each run, and outputs Jira-ready
Markdown reports.

Assumed environment
  • Kali Linux
  • Android device connected via USB with frida-server running on-device
  • APK decompiled to a local folder (jadx or apktool)
  • App installed on device
  • Claude Code CLI installed  →  `claude` in PATH

Self-update source
  https://github.com/freelanceontime/SecurityTest/blob/main/selfImprovedtests.py
"""
import sys, os, re, json, platform, subprocess, hashlib, shutil, argparse
import urllib.request, urllib.error, datetime
from pathlib import Path

sys.dont_write_bytecode = True

# ── Version & paths ──────────────────────────────────────────────────────────
__version__   = "1.0.0"
SCRIPT_PATH   = Path(__file__).resolve()
SCRIPT_DIR    = SCRIPT_PATH.parent
STATE_FILE    = SCRIPT_DIR / "session_state.json"
IMPROVEMENTS  = SCRIPT_DIR / "prompt_improvements.json"
RESULTS_DIR   = SCRIPT_DIR / "test_results"
REPORTS_DIR   = SCRIPT_DIR / "reports"
APP_RESULTS_DIR = RESULTS_DIR / "by_app"

GITHUB_RAW = (
    "https://raw.githubusercontent.com/"
    "freelanceontime/SecurityTest/main/selfImprovementtest.py"
)

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info", "N/A", "SKIP", "UNKNOWN"]

# ── Ollama remote ─────────────────────────────────────────────────────────────
OLLAMA_HOST = "192.168.1.212"
OLLAMA_PORT = 11434

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

def _term_w() -> int:
    """Return usable inner width for bordered boxes (terminal cols minus borders/indent)."""
    return max(60, shutil.get_terminal_size(fallback=(80, 24)).columns - 4)

def _box(title: str, w: int = 0) -> None:
    w = w or _term_w()
    print(f"{_B}{'=' * w}{_R}")
    print(f"{_B}  {title}{_R}")
    print(f"{_B}{'=' * w}{_R}")

def _hr(w: int = 0) -> str:
    return "─" * (w or _term_w())


def _candidate_cli_paths(binary: str) -> list[str]:
    """Return likely executable paths for CLIs hidden by non-interactive PATHs."""
    candidates: list[str] = []

    home = Path.home()
    candidates.extend([
        str(home / ".local" / "bin" / binary),
        str(home / "bin" / binary),
        f"/usr/local/bin/{binary}",
        f"/opt/homebrew/bin/{binary}",
    ])

    nvm_dir = Path(os.environ.get("NVM_DIR", home / ".nvm"))
    versions = nvm_dir / "versions" / "node"
    if versions.is_dir():
        def _node_version_key(node_dir: Path) -> tuple[int, int, int]:
            nums = re.findall(r"\d+", node_dir.name)
            parts = [int(n) for n in nums[:3]]
            return tuple((parts + [0, 0, 0])[:3])

        for node_dir in sorted(versions.iterdir(), key=_node_version_key, reverse=True):
            candidates.append(str(node_dir / "bin" / binary))

    found = shutil.which(binary)
    if found:
        candidates.append(found)

    seen: set[str] = set()
    return [p for p in candidates if not (p in seen or seen.add(p))]


def _resolve_cli(binary: str) -> str | None:
    """Find an executable CLI even when launched outside the user's login shell."""
    candidates = _candidate_cli_paths(binary)
    if binary == "codex":
        for path in candidates:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                native = _resolve_codex_native(path)
                if native:
                    return native

    for path in _candidate_cli_paths(binary):
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def _resolve_codex_native(codex_entry: str) -> str | None:
    """Return Codex's native binary when codex_entry is the npm Node shim."""
    try:
        entry = Path(codex_entry).resolve()
        package_root = entry.parent.parent
        node_modules = package_root / "node_modules"
        if not node_modules.is_dir():
            return None
        for candidate in node_modules.glob(
            "@openai/codex-*/vendor/*/bin/codex"
        ):
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
    except Exception:
        return None
    return None


def _cli_env(executable: str | None = None) -> dict[str, str]:
    """Build subprocess env with the resolved CLI directory prepended to PATH."""
    env = os.environ.copy()
    if executable:
        exe_dir = str(Path(executable).parent)
        paths = [p for p in env.get("PATH", "").split(os.pathsep) if p and p != exe_dir]
        env["PATH"] = os.pathsep.join([exe_dir] + paths)
    return env


def _clean_terminal_text(value: str | None) -> str:
    """Remove pasted terminal control sequences from saved prompt values."""
    if not isinstance(value, str):
        return ""
    value = re.sub(r"\x1B\[[0-?]*[ -/]*[@-~]", "", value)
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)
    return value.strip()


def _sanitize_session_paths(state: dict) -> dict:
    for key in ("apk_path", "decompiled_path"):
        if key in state:
            state[key] = _clean_terminal_text(state.get(key))
    return state


def _slug(value: str, max_len: int = 80) -> str:
    value = _clean_terminal_text(value).lower()
    value = re.sub(r"[^a-z0-9_.-]+", "_", value).strip("_")
    return (value or "unknown")[:max_len]


def _test_slug(test_name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "_", test_name)[:60]


def _app_key(app_name: str = "", package_name: str = "") -> str:
    return _slug(package_name or app_name)


def _app_results_path(app_name: str = "", package_name: str = "") -> Path:
    return APP_RESULTS_DIR / _app_key(app_name, package_name)


# ── Embedded MASTG test definitions (section, level, name, guidance) ──────────
TESTS = [
    {
        "section": 'Storage Tests',
        "level":   'L1',
        "name":    'Testing Local Storage for Sensitive Data',
        "content": 'Foodscanner-specific local storage checklist from prior runs:\n\n1. Verify environment and package: `adb devices`, `frida-ps -U | head -20`, `adb shell pm list packages | grep com.flipside.devfoodscanner`.\n2. Confirm manifest flags with line numbers: `nl -ba AndroidManifest.xml | sed -n "1,120p"`. Prior evidence: `android:debuggable="true"`, `android:installLocation="preferExternal"`, `android:allowBackup="false"`.\n3. Static app-code searches to rerun: `rg -n "MODE_WORLD_READABLE|MODE_WORLD_WRITABLE|openFileOutput|openFileInput|getExternalStorageDirectory|getExternalStoragePublicDirectory|getExternalFilesDir|getExternalCacheDir|FileOutputStream|EncryptedSharedPreferences|MasterKey|androidx.security.crypto|KeyStore|Cipher" smali/com smali_classes4/com/flipside assets res -g "*"`.\n4. Inspect the known external write code: `nl -ba smali/com/ToolBar/EasyWebCam/EasyWebCam\\$2.smali | sed -n "50,230p"` shows `Environment.getExternalStorageDirectory()` building `/sdcard/AppTest/PicTest_<timestamp>.jpg` and `FileOutputStream`; `nl -ba smali/com/ToolBar/EasyWebCam/EasyWebCam.smali | sed -n "625,660p"` shows `getExternalStoragePublicDirectory(DIRECTORY_PICTURES)`.\n5. Runtime app-private storage: because the build is debuggable, use `run-as` to list and read files: `adb shell run-as com.flipside.devfoodscanner find /data/user/0/com.flipside.devfoodscanner -maxdepth 3 -type f -print`. Confirm `files/PersistedInstallation*.json` for cleartext `Fid`, `AuthToken`, and `RefreshToken`; confirm Unity/Firebase identifiers in `shared_prefs/*.xml`.\n6. Runtime external storage: list files with `adb shell "find /storage/emulated/0/Android/data/com.flipside.devfoodscanner -maxdepth 5 -type f -printf \\"%p %s bytes\\\\n\\" 2>/dev/null | sort | head -200"`. Prior sensitive files: `files/request.txt` contains `from_barcode`, `to_barcode`, and `device_identifier`; `files/data.db` and `files/swaps.db` are Unity/.NET serialized objects, not SQLite, and contain scan/swap history, product names, and barcodes in cleartext; `files/Unity/*/Analytics/ArchivedEvents/*/{s,e}` contain cleartext `userid`, `deviceid`, `identity_token`, and session IDs; `download_cache/*.jpg` contains product image cache.\n7. Sample external file content with `adb shell "for f in /storage/emulated/0/Android/data/com.flipside.devfoodscanner/files/request.txt /storage/emulated/0/Android/data/com.flipside.devfoodscanner/files/messaging.json /storage/emulated/0/Android/data/com.flipside.devfoodscanner/files/terms.json; do echo ---$f; head -c 1200 \\"$f\\"; echo; done"`, `adb shell "for db in /storage/emulated/0/Android/data/com.flipside.devfoodscanner/files/*.db; do echo ---$db; strings \\"$db\\" | head -80; done"`, and `adb shell "grep -RInE \\"deviceid|identity_token|userid|sessionid|token|secret|password\\" /storage/emulated/0/Android/data/com.flipside.devfoodscanner/files/Unity 2>/dev/null | head -80"`.\n8. Packaged assets to inspect: `assets/google-services-desktop.json` exposes Firebase project info, OAuth client IDs, and API key; `assets/bin/Data/boot.config` exposes Unity player connection mode and IP. Treat Firebase API key as project configuration, but still report exposed staging configuration where relevant.\n9. Known false positives to skip or mark low priority: AndroidX Fragment/SavedState/Core SharedPreferences; Firebase datatransport SQLite event queue; AndroidX FileProvider/ContextCompat external path resolution; Firebase Analytics `session_stitching_token` and `sgtm_preview_key` constants; Okio crypto classes; Google/Guava/Crashlytics library `FileOutputStream`, `SecretKeySpec`, and SDK cache/storage code unless it stores live tokens in app data.\n10. Evaluation: fail if sensitive/user-identifying data, tokens, scan history, or camera captures are stored in cleartext in app-private or external storage. External app-specific storage under `/storage/emulated/0/Android/data/<package>` still counts when it contains sensitive data and no encryption is present.',
    },
    {
        "section": 'Storage Tests',
        "level":   'L1',
        "name":    'Testing the Device-Access-Security Policy',
        "content": 'Foodscanner-specific device-access-security policy checklist:\n\n1. Verify environment and package: `adb devices`, `frida-ps -U | head -20`, `adb shell pm list packages | grep com.flipside.devfoodscanner`.\n2. Capture manifest/package evidence with line numbers: `nl -ba AndroidManifest.xml | sed -n "1,90p"` and `aapt dump badging /home/kali/Desktop/FoodScanner_4.0.0_stg.apk | head -20`. Prior evidence: manifest line 2 has `android:installLocation="preferExternal"` / `install-location:\'preferExternal\'`; application line 30 has `android:debuggable="true"`, `android:allowBackup="false"`.\n3. Confirm installed runtime state: `adb shell dumpsys package com.flipside.devfoodscanner | sed -n "/Package \\\\[com.flipside.devfoodscanner\\\\]/,/Queries:/p"` and note `pkgFlags`, `dataDir`, `targetSdk`, granted runtime permissions, and whether the app process is running.\n4. Check current device posture that a policy might enforce: `adb shell "settings get global adb_enabled; settings get secure lockscreen.disabled; settings get secure lockscreen.password_type; getprop ro.crypto.state; getprop ro.crypto.type; getprop ro.debuggable; getprop ro.secure; getprop ro.build.tags; command -v su || true; pidof com.flipside.devfoodscanner || true"`. Prior run showed USB debugging enabled (`1`), `/system/bin/su` present, encrypted file-based storage, and the app still running.\n5. Static policy search to rerun: `rg -n "KeyguardManager|isDeviceSecure|isKeyguardSecure|DevicePolicyManager|Settings\\\\$Secure|Settings\\\\.Secure|ADB_ENABLED|adb_enabled|development_settings_enabled|isEncrypted|ro\\\\.crypto|ro\\\\.secure|ro\\\\.debuggable|RootUtils|com/unitymedved/rootchecker|checkRoot|isRoot|root" smali/com smali_classes4/com/flipside -g "*.smali"`.\n6. Inspect root-checker usage separately: `rg -n "Lcom/unitymedved/rootchecker/RootUtils;|RootUtils;->|checkForBinary|checkSuExists|isDeviceRooted|detectRoot" smali smali_classes* -g "*.smali"`. Prior evidence only found `RootUtils.smali` self-references, so treat the packaged root checker as unused/low-priority unless a caller is found.\n7. For Unity IL2CPP builds, scan native metadata/string tables for policy references: `strings -a lib/arm64-v8a/libil2cpp.so | rg -n "RootUtils|unitymedved|isDeviceSecure|KeyguardManager|DevicePolicyManager|adb_enabled|development_settings_enabled|ro.crypto|ro.secure|ro.debuggable|/system/bin/su|test-keys|Magisk|magisk|root" | head -100`; also scan `global-metadata.dat` if present.\n8. Confirm debug/device-access impact with `adb shell run-as com.flipside.devfoodscanner pwd`, `adb shell run-as com.flipside.devfoodscanner ls -la`, and `adb shell run-as com.flipside.devfoodscanner find . -maxdepth 3 -type f -print | sort | head -100`. Debuggable builds allow app-private data access through ADB and should be reported if this is a release/security test build.\n9. Known false positives to skip or mark low priority: generic `root` variable names in Kotlin/Guava/Okio/Unity GC strings; Firebase Crashlytics `isRooted()` telemetry; bundled `com/unitymedved/rootchecker/RootUtils.smali` unless static or dynamic evidence shows app enforcement; AndroidX/Firebase storage internals unrelated to access policy.\n10. Evaluation: if no written device-access policy is provided, report INFO for policy absence/untestable requirements, but still raise concrete FAIL findings for insecure build/device-access controls such as debug signing, `android:debuggable="true"`, or `installLocation="preferExternal"` when sensitive app data is present or this is expected to be a production-equivalent build.',
    },
    {
        "section": 'Storage Tests',
        "level":   'L1',
        "name":    'Determining Whether Sensitive Data Is Shared with Third Parties via Embedded Services',
        "content": "Overview¶\nStatic Analysis¶\nTo determine whether API calls and functions provided by the third-party library are used according to best practices, review their source code, requested permissions, and check for any known vulnerabilities.\n\nAll data that's sent to third-party services should be anonymized to prevent exposure of PII (Personal Identifiable Information) that would allow the third party to identify the user account. No other data (such as IDs that can be mapped to a user account or session) should be sent to a third party.\n\nDynamic Analysis¶\nCheck all requests to external services for embedded sensitive information. To intercept traffic between the client and server, you can perform dynamic analysis by launching a Machine-in-the-Middle (MITM) attack with  Burp Suite or  ZAP (Zed Attack Proxy). Once you route the traffic through the interception proxy, you can try to sniff the traffic that passes between the app and server. All app requests that aren't sent directly to the server on which the main function is hosted should be checked for sensitive information, such as PII, in a tracker or ad service.",
    },
    {
        "section": 'Storage Tests',
        "level":   'L1',
        "name":    'Determining Whether Sensitive Data Is Shared with Third Parties via Notifications',
        "content": 'Overview¶\nStatic Analysis¶\nSearch for any usage of the NotificationManager class which might be an indication of some form of notification management. If the class is being used, the next step would be to understand how the application is generating the notifications ↗ and which data ends up being shown.\n\nDynamic Analysis¶\nRun the application and start tracing all calls to functions related to the notifications creation, e.g. setContentTitle or setContentText from NotificationCompat.Builder ↗. Observe the trace in the end and evaluate if it contains any sensitive information which another app might have eavesdropped.',
    },
    {
        "section": 'Storage Tests',
        "level":   'L1',
        "name":    'Determining Whether the Keyboard Cache Is Disabled for Text Input Fields',
        "content": 'Static Analysis¶\nIn the layout definition of an activity, you can define TextViews that have XML attributes. If the XML attribute android:inputType is given the value textNoSuggestions, the keyboard cache will not be shown when the input field is selected. The user will have to type everything manually.\n\n\n   <EditText\n        android:id="@+id/KeyBoardCache"\n        android:inputType="textNoSuggestions" />\nThe code for all input fields that take sensitive information should include this XML attribute to disable the keyboard suggestions ↗.\n\nAlternatively, the developer can use the following constants:\n\nXML android:inputType\tCode InputType\tAPI level\ntextPassword ↗\tTYPE_TEXT_VARIATION_PASSWORD ↗\t3\ntextVisiblePassword ↗\tTYPE_TEXT_VARIATION_VISIBLE_PASSWORD ↗\t3\nnumberPassword ↗\tTYPE_NUMBER_VARIATION_PASSWORD ↗\t11\ntextWebPassword ↗\tTYPE_TEXT_VARIATION_WEB_PASSWORD ↗\t11\nCheck the application code to verify that none of the input types are being overwritten. For example, by doing findViewById(R.id.KeyBoardCache).setInputType(InputType.TYPE_CLASS_TEXT) the input type of the input field KeyBoardCache is set to text reenabling the keyboard cache.\n\nFinally, check the minimum required SDK version in the Android Manifest (android:minSdkVersion) since it must support the used constants (for example, Android SDK version 11 is required for textWebPassword). Otherwise, the compiled app would not honor the used input type constants allowing keyboard caching.\n\nDynamic Analysis¶\nStart the app and click in the input fields that take sensitive data. If strings are suggested, the keyboard cache has not been disabled for these fields.\n\n Testing Backups for Sensitive Data\nOverview¶\nStatic Analysis¶\nLocal¶\nCheck the AndroidManifest.xml file for the following flag:\n\n\nandroid:allowBackup="true"\nIf the flag value is true, determine whether the app saves any kind of sensitive data (check the test case "Testing for Sensitive Data in Local Storage").\n\nCloud¶\nRegardless of whether you use key/value backup or auto backup, you must determine the following:\n\nwhich files are sent to the cloud (e.g., SharedPreferences)\nwhether the files contain sensitive information\nwhether sensitive information is encrypted before being sent to the cloud.\nIf you don\'t want to share files with Google Cloud, you can exclude them from Auto Backup ↗. Sensitive information stored at rest on the device should be encrypted before being sent to the cloud.\n\nAuto Backup: You configure Auto Backup via the boolean attribut',
    },
    {
        "section": 'Storage Tests',
        "level":   'L1',
        "name":    'Files Written to External Storage',
        "content": "Overview¶\nThe goal of this test is to retrieve the files written to the external storage ( External Storage) and inspect them regardless of the APIs used to write them. It uses a simple approach based on file retrieval from the device storage ( Host-Device Data Transfer) before and after the app is exercised to identify the files created during the app's execution and to check if they contain sensitive data.\n\nSteps¶\nUse  Installing Apps to install the app.\nUse  Host-Device Data Transfer to get the current list of files in the external storage.\nExercise the app extensively to trigger as many flows as possible and enter sensitive data wherever you can.\nUse  Host-Device Data Transfer to retrieve the list of files in the external storage again.\nCalculate the difference between the two lists.\nObservation¶\nThe output should contain a list of files that were created on the external storage during the app's execution.\n\nEvaluation¶\nThe test case fails if the files found above are not encrypted and leak sensitive data.\n\nFurther Validation Required:\n\nInspect the content of each reported file to determine whether the data is sensitive:\n\nDetermine whether the file contains sensitive information (e.g., personal data, credentials, or tokens).\nDetermine whether the data is stored without encryption.",
    },
    {
        "section": 'Storage Tests',
        "level":   'L1',
        "name":    'Runtime Use of APIs to Access External Storage',
        "content": "Android apps use a variety of APIs to access the external storage ( External Storage). Collecting a comprehensive list of these APIs can be challenging, especially if an app uses a third-party framework, loads code at runtime, or includes native code.\n\nThe most effective approach to testing applications that write to device storage is usually dynamic analysis, and specifically method hooking. You can use it to hook into the relevant APIs such as getExternalStorageDirectory, getExternalStoragePublicDirectory, getExternalFilesDir or FileOutPutStream. You could also use open as a catch-all for file interactions. However, this won't catch all file interactions, such as those that use the MediaStore API and should be done with additional filtering as it can generate a lot of noise.\n\nSteps¶\nUse  Installing Apps to install the app.\nUse  Method Hooking to hook the relevant API calls.\nExercise the app extensively to trigger as many flows as possible and enter sensitive data wherever you can.\nObservation¶\nThe output should contain a list of files that the app wrote to the external storage during execution and the APIs used to write them including function names and backtraces.\n\nEvaluation¶\nThe test case fails if the files found above are not encrypted and leak sensitive data.\n\nFurther Validation Required:\n\nInspect the content of each reported file to determine whether the data is sensitive:\n\nDetermine whether the file contains sensitive information (e.g., personal data, credentials, or tokens).\nDetermine whether the data is stored without encryption.\nUse  Reviewing Decompiled Java Code to inspect the code locations from the backtraces if you want to determine the exact code paths that lead to the file creation and whether they are security-relevant.",
    },
    {
        "section": 'Storage Tests',
        "level":   'L1',
        "name":    'References to APIs and Permissions for Accessing External Storage',
        "content": 'This test uses static analysis to look for uses of APIs allowing an app to write to locations that are shared with other apps ( Testing Local Storage for Sensitive Data) such as the External Storage APIs or the MediaStore API as well as the relevant Android manifest storage-related permissions.\n\nSome APIs used to write to shared storage include getExternalStoragePublicDirectory, getExternalStorageDirectory, getExternalFilesDir, or MediaStore. Permissions include WRITE_EXTERNAL_STORAGE, and MANAGE_EXTERNAL_STORAGE. See  External Storage for more information on these APIs and permissions.\n\nNote\n\nThis static test is great for identifying all code locations where the app is writing data to shared storage. However, it does not provide the actual data being written, and in some cases, the actual path in the device storage where the data is being written. Therefore, it is recommended to combine this test with others that take a dynamic approach, as this will provide a more complete view of the data being written to shared storage.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nUse  Obtaining Information from the AndroidManifest to obtain the AndroidManifest.xml.\nUse  Obtaining App Permissions to obtain the relevant permissions.\nObservation¶\nThe output should contain a list of APIs and storage-related permissions used to write to shared storage and their code locations.\n\nEvaluation¶\nThe test case fails if all of the following apply:\n\nthe app has the proper permissions declared in the Android manifest (e.g. WRITE_EXTERNAL_STORAGE, MANAGE_EXTERNAL_STORAGE, etc.)\nthe app uses APIs that write to shared storage (e.g. getExternalStoragePublicDirectory, getExternalStorageDirectory, getExternalFilesDir, getExternalCacheDir, MediaStore, etc.)\nthe data being written to shared storage is sensitive and not encrypted.\nFurther Validation Required:\n\nInspect each reported code location using  Reviewing Decompiled Java Code to determine whether the data is sensitive:\n\nDetermine whether the data written to shared storage includes sensitive information (e.g., personal data, credentials, or tokens).\nDetermine whether the data is stored without encryption.\nDemos¶\n MASTG-DEMO-0005: App Writing to External Storage via the MediaStore API = https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0005/MASTG-DEMO-0005/\n MASTG-DEMO-0003: App Writing to External Storage without Scoped Storage',
    },
    {
        "section": 'Storage Tests',
        "level":   'L1',
        "name":    'Runtime Use of Logging APIs',
        "content": "On Android platforms, logging APIs like Log, Logger, System.out.print, System.err.print, and java.lang.Throwable#printStackTrace can inadvertently lead to the leakage of sensitive information. Log messages are recorded in logcat, a shared memory buffer, accessible since Android 4.1 (API level 16) only to privileged system applications that declare the READ_LOGS permission. Nonetheless, the vast ecosystem of Android devices includes pre-loaded apps with the READ_LOGS privilege, increasing the risk of sensitive data exposure. Therefore, direct logging to logcat is generally advised against due to its susceptibility to data leaks.\n\nSteps¶\nUse  Installing Apps to install the app.\nUse  Method Hooking to hook the relevant API calls.\nExercise the app extensively to trigger as many flows as possible and enter sensitive data wherever you can.\nObservation¶\nThe output should contain a list of locations where logging APIs are used in the app for the current execution.\n\nEvaluation¶\nThe test case fails if you can find sensitive data being logged using those APIs.\nBest Practices\nhttps://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0002/\ndemo = https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0006/MASTG-DEMO-0006/\n\n#Runtime Storage of Unencrypted Data in the App Sandbox\n\nOverview¶\nThe goal of this test is to retrieve the files written to the internal storage ( Internal Storage) and inspect them regardless of the APIs used to write them. It uses a simple approach based on file retrieval from the device storage ( Host-Device Data Transfer) before and after the app is exercised to identify the files created during the app's execution and to check if they contain sensitive data.\n\nSteps¶\nUse  Installing Apps to install the app.\nUse  Accessing App Data Directories to take a first copy of the app's private data directory as a reference for offline analysis.\nLaunch and use the app, going through the various workflows while inputting sensitive data wherever you can. Taking note of the data you input can help identify it later using tools to search for it.\nUse  Accessing App Data Directories to take a second copy of the app's private data directory and diff it with the first copy to identify all files created or modified during your testing session.\nObservation¶\nThe output should contain a list of files that were created in the app's private storage during execution.\n\nEvaluation¶\nThe test case fails if you find any sensitive data (keys, passwords, or any data inp",
    },
    {
        "section": 'Storage Tests',
        "level":   'L1',
        "name":    'Sensitive Data Not Excluded From Backup',
        "content": "verview¶\nThis test verifies whether apps correctly instruct the system to exclude sensitive files from backups by performing a backup and restore of the app data and checking which files are restored.\n\nSee  References to Backup Configurations Not Excluding Sensitive Data for a static analysis counterpart.\n\nAndroid provides a way to start the backup daemon to back up and restore app files, which you can use to verify which files are actually restored from the backup.\n\nSteps¶\nUse  Installing Apps to install the app.\nLaunch and use the app going through the various workflows while inputting sensitive data wherever you can.\nUse  Performing a Backup and Restore of App Data to perform a backup and restore of the app data.\nUninstall and reinstall the app but don't open it anymore.\nRestore the data from the backup and get the list of restored files.\nObservation¶\nThe output should contain a list of files that are restored from the backup.\n\nEvaluation¶\nThe test case fails if any of the files are considered sensitive.\n\nBest Practices¶\n MASTG-BEST-0004: Exclude Sensitive Data from Backups = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0004/\n\nDemos¶\n MASTG-DEMO-0035: Data Exclusion using backup_rules.xml with adb backup = https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0035/MASTG-DEMO-0035/\n MASTG-DEMO-0020: Data Exclusion using backup_rules.xml with Backup Manager = https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0020/MASTG-DEMO-0020/",
    },
    {
        "section": 'Storage Tests',
        "level":   'L1',
        "name":    'References to Logging APIs',
        "content": 'Overview¶\nThis test verifies if an app uses logging APIs like android.util.Log, Log, Logger, System.out.print, System.err.print, and java.lang.Throwable#printStackTrace.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should contain a list of locations where logging APIs are used.\n\nEvaluation¶\nThe test case fails if an app logs sensitive information from any of the listed locations.\n\nBest Practices¶\n MASTG-BEST-0002: Remove Logging Code = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0002/',
    },
    {
        "section": 'Storage Tests',
        "level":   'L1',
        "name":    'References to Backup Configurations Not Excluding Sensitive Data',
        "content": 'This test verifies whether apps correctly instruct the system to exclude sensitive files from backups by analyzing the app\'s AndroidManifest.xml and backup rule configuration files.\n\n"Android Backups" ( Backups) can be implemented via Auto Backup ↗ (Android 6.0 (API level 23) and higher) and Key-value backup ↗ (Android 2.2 (API level 8) and higher). Auto Backup is the recommended approach by Android as it is enabled by default and requires no work to implement.\n\nIn the AndroidManifest.xml file, the allowBackup flag controls whether the app\'s data can be backed up. In addition, the fullBackupContent attribute (for Android 11 or lower) or the dataExtractionRules attribute (for Android 12 and higher) can be used to reference XML files that specify which files should be included or excluded from backups using the exclude tag. The files are typically named:\n\nbackup_rules.xml (for Android 11 or lower using android:fullBackupContent)\ndata_extraction_rules.xml (for Android 12 and higher using android:dataExtractionRules)\nThe cloud-backup and device-transfer parameters can be used to exclude files from cloud backups and device-to-device transfers, respectively.\n\nThe key-value backup approach requires developers to set up a BackupAgent ↗ or BackupAgentHelper ↗ and specify what data should be backed up.\n\nRegardless of which approach the app used, Android provides a way to start the backup daemon to back up and restore app files. You can use this daemon for testing purposes and initiate the backup process and restore the app\'s data, allowing you to verify which files were restored from the backup.\n\nSteps¶\nUse  Obtaining Information from the AndroidManifest to obtain the AndroidManifest.xml.\nUse  Analyzing the AndroidManifest to obtain the relevant flag and attributes from the AndroidManifest.xml.\nUse  Exploring the App Package to extract the backup_rules.xml or data_extraction_rules.xml file from the app package.\nObservation¶\nThe output should explicitly show:\n\nwhether the allowBackup flag is set to true or false. If the flag is not specified, it is treated as true by default.\nwhether the fullBackupContent and/or dataExtractionRules attributes are present in the AndroidManifest.xml.\nthe contents of the backup_rules.xml or data_extraction_rules.xml file, if present.\nEvaluation¶\nThe test case fails if the app allows sensitive data to be backed up. Specifically, if the following conditions are met:\n\nandroid:allowBackup="true" in the AndroidManifest.xml\nandroid:fullBackup',
    },
    {
        "section": 'Storage Tests',
        "level":   'L1',
        "name":    'Runtime Storage of Unencrypted Data via the SharedPreferences API',
        "content": "In Android, applications can use the SharedPreferences ↗ API to store sensitive data without encryption, typically under the app's private data directory, such as /data/user/0/<package-name>/shared_prefs/ or /data/data/<package-name>/shared_prefs/.\n\nWhile MODE_PRIVATE restricts file access to the app itself, it doesn't protect the data from being read by attackers who gain access to the device's file system (for example, through device compromise, backup extraction, or physical access to rooted/unlocked devices).\n\nThis test uses runtime instrumentation to detect when the app writes data via SharedPreferences and determines whether sensitive data is being stored unencrypted.\n\nRelevant API calls regarding SharedPreferences include SharedPreferences.Editor.putString(...) and putStringSet(...), which write string values to the XML files in the app's sandbox. There's also put* methods for other data types, but strings are the most common way to store sensitive data such as API keys, tokens, passwords, or private keys.\n\nFor encryption, relevant API calls include javax.crypto.Cipher, java.security.KeyStore, or javax.crypto.KeyGenerator.\n\nFor more information about the SharedPreferences API, refer to  Shared Preferences.\n\nSteps¶\nUse  Installing Apps to install the app.\nUse  Method Hooking to hook the relevant API calls.\nExercise the app extensively to trigger as many flows as possible and enter sensitive data wherever you can.\nUse  Accessing App Data Directories to retrieve the app's SharedPreferences XML files.\nObservation¶\nThe output should contain a list of all calls to SharedPreferences write methods, including the keys, values, and stack traces showing where in the app's code these calls originate. The trace should also include related cryptographic operations that may indicate encryption is being used.\n\nThe output should also contain the contents of all SharedPreferences XML files.\n\nEvaluation¶\nThe test case fails if sensitive data is written to SharedPreferences without being encrypted first.\n\nFurther Validation Required:\n\nHigh-level trace inspection: Review the sequence of calls from the hook output to identify if SharedPreferences.Editor.putString or putStringSet calls are preceded by Cipher operations. Values written without prior encryption are likely stored in cleartext.\nPattern matching: Use a secrets detection tool (for example,  gitleaks) to scan the output for known secret patterns such as API keys, tokens, passwords, or private keys.\nManual verifi",
    },
    {
        "section": 'Storage Tests',
        "level":   'L1',
        "name":    'Sensitive Data Stored Unencrypted via DataStore',
        "content": 'This test checks if the app uses the modern Jetpack DataStore API (Preferences DataStore or Proto DataStore) to store sensitive data (e.g., tokens, PII) without encryption. It confirms the absence of secure serializers or mechanisms to protect data integrity and confidentiality.\n\nFor more details, check the associated weakness:  Sensitive Data Stored Unencrypted in Private Storage Locations\n\nDemos¶\n MASTG-DEMO-0069: Sensitive Data Stored Unencrypted via DataStore = https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0069/MASTG-DEMO-0069/',
    },
    {
        "section": 'Storage Tests',
        "level":   'L1',
        "name":    'References to Sensitive Data Stored Unencrypted via Android Room DB',
        "content": "This test checks if the app uses the Android Room Persistence Library to store sensitive data (e.g., tokens, PII) without integrating an encryption layer (e.g., SQLCipher). It confirms the database file is stored in plaintext within the app's private sandbox.\n\nFor more details, check the associated weakness:  Sensitive Data Stored Unencrypted in Private Storage Locations\nDemos¶\n MASTG-DEMO-0070: Sensitive Data Stored Unencrypted via Room Database = https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0070/MASTG-DEMO-0070/",
    },
    {
        "section": 'Cryptography tests',
        "level":   'L1',
        "name":    'Testing the Configuration of Cryptographic Standard Algorithms',
        "content": 'Static Analysis¶\nIdentify all the instances of the cryptographic primitives in code. Identify all custom cryptography implementations. You can look for:\n\nclasses Cipher, Mac, MessageDigest, Signature\ninterfaces Key, PrivateKey, PublicKey, SecretKey\nfunctions getInstance, generateKey\nexceptions KeyStoreException, CertificateException, NoSuchAlgorithmException\nclasses which uses java.security.*, javax.crypto.*, android.security.* and android.security.keystore.* packages.\nIdentify that all calls to getInstance use default provider of security services by not specifying it (it means AndroidOpenSSL aka Conscrypt). Provider can only be specified in KeyStore related code (in that situation KeyStore should be provided as provider). If other provider is specified it should be verified according to situation and business case (i.e. Android API version), and provider should be examined against potential vulnerabilities.\n\nEnsure that the best practices outlined in the "Cryptography for Mobile Apps" chapter are followed. Look at insecure and deprecated algorithms and common configuration issues.\n\nDynamic Analysis¶\nYou can use  Method Tracing on cryptographic methods to determine input / output values such as the keys that are being used. Monitor file system access while cryptographic operations are being performed to assess where key material is written to or read from. For example, monitor the file system by using the API monitor ↗ of  RMS Runtime Mobile Security.',
    },
    {
        "section": 'Cryptography tests',
        "level":   'L1',
        "name":    'Testing the Purposes of Keys',
        "content": "Static Analysis¶\nIdentify all instances where cryptography is used. You can look for:\n\nclasses Cipher, Mac, MessageDigest, Signature\ninterfaces Key, PrivateKey, PublicKey, SecretKey\nfunctions getInstance, generateKey\nexceptions KeyStoreException, CertificateException, NoSuchAlgorithmException\nclasses importing java.security.*, javax.crypto.*, android.security.*, android.security.keystore.*\nFor each identified instance, identify its purpose and its type. It can be used:\n\nfor encryption/decryption - to ensure data confidentiality\nfor signing/verifying - to ensure integrity of data (as well as accountability in some cases)\nfor maintenance - to protect keys during certain sensitive operations (such as being imported to the KeyStore)\nAdditionally, you should identify the business logic which uses identified instances of cryptography.\n\nDuring verification the following checks should be performed:\n\nare all keys used according to the purpose defined during its creation? (it is relevant to KeyStore keys, which can have KeyProperties defined)\nfor asymmetric keys, is the private key being exclusively used for signing and the public key encryption?\nare symmetric keys used for multiple purposes? A new symmetric key should be generated if it's used in a different context.\nis cryptography used according to its business purpose?\nDynamic Analysis¶\nYou can use  Method Tracing on cryptographic methods to determine input / output values such as the keys that are being used. Monitor file system access while cryptographic operations are being performed to assess where key material is written to or read from. For example, monitor the file system by using the API monitor ↗ of  RMS Runtime Mobile Security.",
    },
    {
        "section": 'Cryptography tests',
        "level":   'L1',
        "name":    'Testing Random Number Generation',
        "content": 'Static Analysis¶\nIdentify all the instances of random number generators and look for either custom or well-known insecure classes. For instance, java.util.Random produces an identical sequence of numbers for each given seed value; consequently, the sequence of numbers is predictable. Instead a well-vetted algorithm should be chosen that is currently considered to be strong by experts in the field, and a well-tested implementations with adequate length seeds should be used.\n\nIdentify all instances of SecureRandom that are not created using the default constructor. Specifying the seed value may reduce randomness. Use only the no-argument constructor of SecureRandom ↗ that uses the system-specified seed value to generate a 128-byte-long random number.\n\nIn general, if a PRNG is not advertised as being cryptographically secure (e.g. java.util.Random), then it is probably a statistical PRNG and should not be used in security-sensitive contexts. Pseudo-random number generators can produce predictable numbers ↗ if the generator is known and the seed can be guessed. A 128-bit seed is a good starting point for producing a "random enough" number.\n\nOnce an attacker knows what type of weak pseudo-random number generator (PRNG) is used, it can be trivial to write a proof-of-concept to generate the next random value based on previously observed ones, as it was done for Java Random ↗. In case of very weak custom random generators it may be possible to observe the pattern statistically. Although the recommended approach would anyway be to decompile the APK and inspect the algorithm (see Static Analysis).\n\nIf you want to test for randomness, you can try to capture a large set of numbers and check with the Burp\'s sequencer ↗ to see how good the quality of the randomness is.\n\nDynamic Analysis¶\nYou can use  Method Tracing on the mentioned classes and methods to determine input / output values being used.',
    },
    {
        "section": 'Cryptography tests',
        "level":   'L1',
        "name":    'Insecure Random API Usage',
        "content": 'Overview¶\nAndroid apps sometimes use an insecure pseudorandom number generator (PRNG), such as java.util.Random ↗, which is a linear congruential generator and produces a predictable sequence for any given seed value. As a result, java.util.Random and Math.random() (the latter ↗ simply calls nextDouble() on a static java.util.Random instance) generate reproducible sequences across all Java implementations whenever the same seed is used. This predictability makes them unsuitable for cryptographic or other security-sensitive contexts.\n\nIn general, if a PRNG is not explicitly documented as being cryptographically secure, it should not be used where randomness must be unpredictable. Refer to the Android Documentation ↗ and the "random number generation" guide for further details.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should contain a list of locations where insecure random APIs are used.\n\nEvaluation¶\nThe test case fails if you can find random numbers generated using those APIs that are used in security-relevant contexts, such as generating passwords or authentication tokens.\n\nFurther Validation Required:\n\nInspect each reported code location using  Reviewing Decompiled Java Code to determine whether the usage is security-relevant:\n\nDetermine whether the generated random values are used for security-relevant purposes, such as generating cryptographic keys, initialization vectors (IVs), nonces, authentication tokens, session identifiers, passwords, or PINs.\nBest Practices¶\n MASTG-BEST-0001: Use Secure Random Number Generator APIs = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0001/\n\nDemos¶\n MASTG-DEMO-0007: Common Uses of Insecure Random APIs = https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0007/MASTG-DEMO-0007/',
    },
    {
        "section": 'Cryptography tests',
        "level":   'L1',
        "name":    'Non-random Sources Usage',
        "content": 'Overview¶\nAndroid applications sometimes use non-random sources to generate "random" values, leading to potential security vulnerabilities. Common practices include relying on the current time, such as Date().getTime(), or accessing Calendar.MILLISECOND to produce values that are easily guessable and reproducible.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should contain a list of locations where non-random sources are used.\n\nEvaluation¶\nThe test case fails if you can find security-relevant values, such as passwords or tokens, generated using non-random sources.\n\nFurther Validation Required:\n\nInspect each reported code location using  Reviewing Decompiled Java Code to determine whether the usage is security-relevant:\n\nDetermine whether the generated values are used for security-relevant purposes, such as generating cryptographic keys, initialization vectors (IVs), nonces, authentication tokens, session identifiers, passwords, or PINs.\nBest Practices¶\n MASTG-BEST-0001: Use Secure Random Number Generator APIs = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0001/\n\nDemos¶\n MASTG-DEMO-0008: Uses of Non-random Sources = https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0008/MASTG-DEMO-0008/',
    },
    {
        "section": 'Cryptography tests',
        "level":   'L1',
        "name":    'Insufficient Key Sizes',
        "content": 'Overview¶\nIn this test case, we will look for the use insufficient key sizes in Android apps. To do this, we need to focus on the cryptographic frameworks and libraries that are available in Android and the methods that are used to generate, inspect and manage cryptographic keys.\n\nThe Java Cryptography Architecture (JCA) provides foundational classes for key generation which are often used directly when portability or compatibility with older systems is a concern.\n\nKeyGenerator: The KeyGenerator ↗ class is used to generate symmetric keys including AES, DES, ChaCha20 or Blowfish, as well as various HMAC keys. The key size can be specified using the init(int keysize) ↗ method.\nKeyPairGenerator: The KeyPairGenerator ↗ class is used for generating key pairs for asymmetric encryption (e.g., RSA, EC). The key size can be specified using the initialize(int keysize) ↗ method.\nFor more information you can consult the MASTG section about "Key Generation".\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should contain a list of locations where insufficient key lengths are used.\n\nEvaluation¶\nThe test case fails if you can find the use of insufficient key sizes within the source code. For example, a 1024-bit key size is considered insufficient for RSA encryption and a 128-bit key size is considered insufficient for AES encryption considering quantum computing attacks.\n\nDemos¶\n MASTG-DEMO-0012: Cryptographic Key Generation With Insufficient Key Length = https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0012/MASTG-DEMO-0012/',
    },
    {
        "section": 'Cryptography tests',
        "level":   'L1',
        "name":    'Use of Hardcoded Cryptographic Keys in Code',
        "content": 'Overview¶\nIn this test case, we will look for the use of hardcoded keys in Android applications. To do this, we need to focus on the cryptographic implementations of hardcoded keys. The Java Cryptography Architecture (JCA) provides the SecretKeySpec ↗ class, which allows you to create a SecretKey ↗ from a byte array.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should contain a list of locations where hardcoded keys are used.\n\nEvaluation¶\nThe test case fails if you find any hardcoded keys that are used in security-sensitive contexts.\n\nDemos¶\n MASTG-DEMO-0017: Use of Hardcoded AES Key in SecretKeySpec with semgrep = https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0017/MASTG-DEMO-0017/\n\n#Broken Symmetric Encryption Algorithms\n\nTo test for the use of broken encryption algorithms in Android apps, we need to focus on methods from cryptographic frameworks and libraries that are used to perform encryption and decryption operations.\n\nCipher.getInstance ↗: Initializes a Cipher object for encryption or decryption. The algorithm parameter can be one of the supported algorithms ↗.\nSecretKeyFactory.getInstance ↗: Returns a SecretKeyFactory object that converts keys into key specifications and vice versa. The algorithm parameter can be one of the supported algorithms ↗.\nKeyGenerator.getInstance ↗: Returns a KeyGenerator object that generates secret keys for symmetric algorithms. The algorithm parameter can be one of the supported algorithms ↗.\nSome broken symmetric encryption algorithms include:\n\nDES (Data Encryption Standard): 56-bit key, breakable, withdrawn by NIST in 2005 ↗.\n3DES (Triple DES, officially the Triple Data Encryption Algorithm (TDEA or Triple DEA)): 64-bit block size, vulnerable to Sweet32 birthday attacks ↗, withdrawn by NIST on January 1, 2024 ↗.\nRC4: Predictable key stream, allows plaintext recovery RC4 Weakness ↗, disapproved by NIST ↗ in 2014 and prohibited by IETF ↗ in 2015.\nBlowfish: 64-bit block size, vulnerable to Sweet32 attacks ↗, never FIPS-approved, and listed under "Non-Approved algorithms" in FIPS ↗.\nAndroid also provides additional guidance on broken cryptographic algorithms ↗.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should contain a list of locations where insecure symmetric encryptio',
    },
    {
        "section": 'Cryptography tests',
        "level":   'L1',
        "name":    'Broken Symmetric Encryption Modes',
        "content": 'To test for the use of broken encryption modes in Android apps, we should focus on methods in cryptographic frameworks and libraries used to configure and apply encryption modes.\n\nIn Android development, the Cipher class from the Java Cryptography Architecture (JCA) is the primary API for specifying the encryption mode for cryptographic operations. Cipher.getInstance ↗ defines the transformation string, which includes the encryption algorithm, mode of operation, and padding scheme. The general format is "Algorithm/Mode/Padding". For example:\n\n\nCipher.getInstance("AES/ECB/PKCS5Padding")\nIn this test, we\'re going to focus on symmetric encryption modes such as ECB (Electronic Codebook) ↗.\n\nECB (defined in NIST SP 800-38A ↗) is generally discouraged see NIST announcement in 2023 ↗ due to its inherent security weaknesses. While not explicitly prohibited, its use is limited and advised against in most scenarios. ECB is a block cipher mode that operates deterministically, dividing plaintext into blocks and encrypting them separately, which reveals patterns in the ciphertext. This makes it vulnerable to attacks like known-plaintext attacks ↗ and chosen-plaintext attacks ↗.\n\nFor example, the following transformations are all considered vulnerable ↗:\n\n"AES" (uses AES/ECB mode by default ↗)\n"AES/ECB/NoPadding"\n"AES/ECB/PKCS5Padding"\n"AES/ECB/ISO10126Padding"\nYou can learn more about ECB and other modes in NIST SP 800-38A - Recommendation for Block Cipher Modes of Operation: Methods and Techniques ↗. Also check the Decision to Revise NIST SP 800-38A, Recommendation for Block Cipher Modes of Operation: Methods and Techniques ↗ and NIST IR 8459 Report on the Block Cipher Modes of Operation in the NIST SP 800-38 Series ↗ for the latest information.\n\nOut of Scope: Asymmetric encryption modes, such as RSA, are out of scope for this test because they don\'t use block modes like ECB.\n\nIn the transformation strings like "RSA/ECB/OAEPPadding" or "RSA/ECB/PKCS1Padding", the inclusion of ECB in this context is misleading. Unlike symmetric ciphers, RSA doesn\'t operate in block modes like ECB. The ECB designation is a placeholder in some cryptographic APIs ↗ and doesn\'t imply that RSA uses ECB mode. Understanding these nuances helps prevent false positives.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should contain a list of locations where broken encryption modes a',
    },
    {
        "section": 'Cryptography tests',
        "level":   'L1',
        "name":    'References to Asymmetric Key Pairs Used For Multiple Purposes',
        "content": 'Overview¶\nAccording to section "5.2 Key Usage" of NIST SP 800-57 part 1 revision 5 ↗, cryptographic keys should be assigned a specific purpose and used only for that purpose (e.g., encryption, integrity authentication, key wrapping, random bit generation, or digital signatures). For example, a key intended for encryption should not be used for signing.\n\nOn Android, asymmetric keys are commonly generated with java.security.KeyPairGenerator ↗ configured through android.security.keystore.KeyGenParameterSpec ↗.\n\nThe KeyGenParameterSpec.Builder ↗ constructor has two arguments: the keystoreAlias and purposes, a bitmask of allowed operations documented in android.security.keystore.KeyProperties ↗.\n\nKeyProperties.PURPOSE_SIGN ↗\nKeyProperties.PURPOSE_VERIFY ↗\nKeyProperties.PURPOSE_ENCRYPT ↗\nKeyProperties.PURPOSE_DECRYPT ↗\nKeyProperties.PURPOSE_WRAP_KEY ↗\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should contain a list of locations where asymmetric keys are created using KeyGenParameterSpec.Builder and the associated purposes.\n\nEvaluation¶\nThe test case fails if you find any keys used for multiple roles (groups of purposes).\n\nUsing the output, ensure that each key pair is restricted to exactly one of the following roles:\n\nEncryption/Decryption (PURPOSE_ENCRYPT / PURPOSE_DECRYPT)\nSigning/Verification (PURPOSE_SIGN / PURPOSE_VERIFY)\nKey Wrapping (PURPOSE_WRAP_KEY)\nWhen reverse engineering the app, you will find the previously mentioned purpose constants combined into a single integer value. For example, a purpose value of 15 combines all four purposes, which is not acceptable:\n\n(PURPOSE_ENCRYPT = 1) | (PURPOSE_DECRYPT = 2) | (PURPOSE_SIGN = 4) | (PURPOSE_VERIFY = 8) = 15\n\nAcceptable purpose combinations are:\n\n(PURPOSE_ENCRYPT = 1) = 1\n(PURPOSE_DECRYPT = 2) = 2\n(PURPOSE_SIGN = 4) = 4\n(PURPOSE_VERIFY = 8) = 8\nPURPOSE_WRAP_KEY = 32\n(PURPOSE_ENCRYPT = 1) | (PURPOSE_DECRYPT = 2) = 3\n(PURPOSE_SIGN = 4) | (PURPOSE_VERIFY = 8) = 12\nDemos¶\n MASTG-DEMO-0071: References to Asymmetric Key Pairs Used For Multiple Purposes with Semgrep = https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0071/MASTG-DEMO-0071/',
    },
    {
        "section": 'Cryptography tests',
        "level":   'L1',
        "name":    'Runtime Use of Asymmetric Key Pairs Used For Multiple Purposes',
        "content": 'Overview¶\nThis test is the dynamic counterpart to  References to Asymmetric Key Pairs Used For Multiple Purposes, but it focuses on intercepting cryptographic operations rather than generating keys with multiple purposes.\n\nSome of the relevant functions to intercept are:\n\nCipher.init(int opmode, Key key, AlgorithmParameters params) ↗ where opmode is one of:\nCipher.ENCRYPT_MODE\nCipher.DECRYPT_MODE\nCipher.WRAP_MODE\nCipher.UNWRAP_MODE\nSignature.initSign(PrivateKey privateKey) ↗\nSignature.initVerify(PublicKey publicKey) ↗\nSteps¶\nUse  Installing Apps to install the app.\nUse  Method Hooking to hook the relevant API calls.\nExercise the app extensively to trigger as many flows as possible and enter sensitive data wherever you can.\nObservation¶\nThe output should contain a list of all cryptographic operations together with their corresponding keys.\n\nEvaluation¶\nThe test case fails if you find any keys used for multiple roles.\n\nUsing the output, ensure that each key (or key pair) is restricted to exactly one of the following groups of operations:\n\nEncryption/Decryption (used in Cipher operations with ENCRYPT_MODE or DECRYPT_MODE)\nSigning/Verification (used in Signature operations)\nKey Wrapping (used in Cipher operations with WRAP_MODE or UNWRAP_MODE)\nDemos¶\n MASTG-DEMO-0072: Runtime Use of Asymmetric Key Pairs Used For Multiple Purposes With Frida = https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0072/MASTG-DEMO-0072/',
    },
    {
        "section": 'Cryptography tests',
        "level":   'L1',
        "name":    'References to Reused Initialization Vectors in Symmetric Encryption',
        "content": "Reusing a symmetric key is acceptable when IVs or nonces follow the rules defined for the mode. NIST SP 800 38A states that CBC requires a fresh or unpredictable IV for every encryption. NIST SP 800 38D states that counter based modes require a nonce that never repeats under the same key. Repeating a key and IV or nonce pair defeats confidentiality and can also undermine integrity.\n\nFor more details, check the associated weakness:  Predictable Initialization Vectors (IVs) https://mas.owasp.org/MASWE-0022\n\n'Runtime Use of Reused Initialization Vectors in Symmetric Encryption\nReusing a symmetric key is acceptable when IVs or nonces follow the rules defined for the mode. NIST SP 800 38A states that CBC requires a fresh or unpredictable IV for every encryption. NIST SP 800 38D states that counter based modes require a nonce that never repeats under the same key. Repeating a key and IV or nonce pair defeats confidentiality and can also undermine integrity.\n\nFor more details, check the associated weakness:  Predictable Initialization Vectors (IVs) https://mas.owasp.org/MASWE-0022",
    },
    {
        "section": 'Cryptography tests',
        "level":   'L1',
        "name":    'References to Explicit Security Provider in Cryptographic APIs',
        "content": 'Overview¶\nAndroid cryptography APIs based on the Java Cryptography Architecture (JCA) allow developers to specify a security provider ↗ when calling getInstance methods. However, explicitly specifying a provider can cause security issues and break compatibility because several providers have been deprecated or removed in recent versions. For example:\n\nApps targeting Android 9 (API level 28) or above fail when a provider is specified ↗.\nThe Crypto provider was deprecated in Android 7.0 (API level 24) and removed in Android 9 (API level 28) ↗.\nThe BouncyCastle provider was deprecated in Android 9 (API level 28) and removed in Android 12 (API level 31) ↗.\nThis test identifies cases where an app explicitly specifies a security provider when using JCA APIs that is not the default provider, AndroidOpenSSL (Conscrypt ↗), which is actively maintained and should generally be used. It examines getInstance calls and flags any use of a named provider other than legitimate exceptions such as KeyStore.getInstance("AndroidKeyStore").\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should contain a list of locations where a security provider is explicitly specified in getInstance calls.\n\nEvaluation¶\nThe test case fails if any getInstance call explicitly specifies a security provider other than AndroidKeyStore for KeyStore operations.\n\nBest Practices¶\n MASTG-BEST-0020: Update the GMS Security Provider = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0020/\n\nDemos¶\n MASTG-DEMO-0075: Uses of Explicit Security Providers in Cryptographic APIs with semgrep = https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0075/MASTG-DEMO-0075/',
    },
    {
        "section": 'Cryptography tests',
        "level":   'L1',
        "name":    'Runtime Use of Broken Symmetric Encryption Modes',
        "content": 'Overview¶\nIf the app configures cryptographic operations with broken encryption modes at runtime, sensitive data can be exposed to pattern leakage and other cryptographic weaknesses. This test checks whether the running app sets insecure block modes, such as ECB, in security-relevant cryptographic flows.\n\nSteps¶\nUse  Installing Apps to install the app.\nUse  Method Hooking to hook the relevant API calls.\nExercise the app extensively to trigger as many flows as possible and enter sensitive data wherever you can.\nObservation¶\nThe output should contain a list of calls to encryption configuration APIs, including the transformation string argument and backtraces of each call.\n\nEvaluation¶\nThe test case fails if broken encryption modes are used in security-relevant cryptographic operations.\n\nFurther Validation Required:\n\nUsing the backtraces from the hook output, inspect the code locations using  Reviewing Decompiled Java Code to determine whether the encryption is applied to sensitive data:\n\nDetermine whether the data being encrypted or decrypted is sensitive (e.g., personal data, authentication tokens, cryptographic keys, or session identifiers).\nBest Practices¶\n MASTG-BEST-0005: Use Secure Encryption Modes = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0005/\n\nDemos¶\n MASTG-DEMO-0058: Using KeyGenParameterSpec with a Broken ECB Block Mode = https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0058/MASTG-DEMO-0058/',
    },
    {
        "section": 'Authentication',
        "level":   'L1',
        "name":    'Testing Confirm Credentials',
        "content": 'Overview¶\nStatic Analysis¶\nMake sure that the unlocked key is used during the application flow. For example, the key may be used to decrypt local storage or a message received from a remote endpoint. If the application simply checks whether the user has unlocked the key or not, the application may be vulnerable to a local authentication bypass.\n\nDynamic Analysis¶\nValidate the duration of time (seconds) for which the key is authorized to be used after the user is successfully authenticated. This is only needed if setUserAuthenticationRequired is used.',
    },
    {
        "section": 'Authentication',
        "level":   'L1',
        "name":    'Testing Biometric Authentication',
        "content": 'Overview¶\nStatic Analysis¶\nNote that there are quite some vendor/third party SDKs, which provide biometric support, but which have their own insecurities. Be very cautious when using third party SDKs to handle sensitive authentication logic.\n\nDynamic Analysis¶\nPlease take a look at this detailed blog article about the Android KeyStore and Biometric authentication ↗. This research includes two Frida scripts which can be used to test insecure implementations of biometric authentication and try to bypass them:\n\nFingerprint bypass ↗: This Frida script will bypass authentication when the CryptoObject is not used in the authenticate method of the BiometricPrompt class. The authentication implementation relies on the callback onAuthenticationSucceded being called.\nFingerprint bypass via exception handling ↗: This Frida script will attempt to bypass authentication when the CryptoObject is used, but used in an incorrect way. The detailed explanation can be found in the section "Crypto Object Exception Handling" in the blog post.',
    },
    {
        "section": 'Authentication',
        "level":   'L1',
        "name":    'References to APIs Allowing Fallback to Non-Biometric Authentication',
        "content": 'Overview¶\nThis test checks if the app uses biometric authentication mechanisms ( Biometric Authentication) that allow fallback to device credentials (PIN, pattern, or password) for sensitive operations.\n\nOn Android, the android.hardware.biometrics.BiometricPrompt ↗ API (or its Jetpack counterpart androidx.biometric.BiometricPrompt ↗ that backward compatibility to API level 23) can be configured to accept different types of BiometricManager.Authenticators ↗ via the setAllowedAuthenticators ↗ method.\n\nWhen the authenticator constant DEVICE_CREDENTIAL is included (either alone or combined with biometric authenticators using the OR operator "|"), the authentication allows fallback to device credentials, which is considered weaker than requiring biometrics alone because passcodes are more susceptible to compromise (e.g., through shoulder surfing ↗).\n\nSimilarly, using setDeviceCredentialAllowed(true) ↗ (deprecated since API 30) also enables fallback to device credentials.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should include a list of locations where the relevant APIs are used.\n\nEvaluation¶\nThe test case fails if the app uses BiometricPrompt with authenticators that include DEVICE_CREDENTIAL for any sensitive data resource that needs protection.\n\nNote\n\nUsing DEVICE_CREDENTIAL is not inherently a vulnerability, but in high-security applications (e.g., finance, government, health), their use can represent a weakness or misconfiguration that reduces the intended security posture. This issue is therefore better categorized as a security weakness or hardening issue, not a critical vulnerability.\n\nBest Practices¶\n MASTG-BEST-0031: Enforce Strong Biometrics for Sensitive Operations = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0031/\n\nDemos¶\n MASTG-DEMO-0089: Uses of BiometricPrompt with Device Credential Fallback with semgrep = https://mas.owasp.org/MASTG/demos/android/MASVS-AUTH/MASTG-DEMO-0089/MASTG-DEMO-0089/',
    },
    {
        "section": 'Authentication',
        "level":   'L1',
        "name":    'References to APIs for Event-Bound Biometric Authentication',
        "content": 'Overview¶\nThis test checks if the app implements event-bound biometric authentication ( Biometric Authentication) to access sensitive resources (e.g., tokens, keys), where authentication success relies solely on a callback result rather than being cryptographically bound to sensitive operations and requiring user presence.\n\nOn Android, BiometricPrompt.authenticate() can be called with a CryptoObject ↗ or without a CryptoObject ↗. When used without a CryptoObject the app relies on the onAuthenticationSucceeded ↗ callback to determine if authentication was successful (event-bound). This makes it susceptible to logic manipulation by overwriting the callback without successfully passing the biometric verification.\n\nIn contrast, when a CryptoObject is used (crypto-bound), the app passes a cryptographic object (e.g., Cipher, Signature, Mac) that requires user authentication. This ensures authentication is not just a one-time boolean, but part of a secure data retrieval path (out-of-process), so bypassing authentication becomes significantly harder.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should include a list of locations where the relevant APIs are used.\n\nEvaluation¶\nThe test case fails for each sensitive operation worth protecting if all of the following applies:\n\nBiometricPrompt.authenticate is used without a CryptoObject ↗.\nThere are no calls to key generation with setUserAuthenticationRequired(true) in conjunction with biometric authentication, as by default, the key is authorized to be used regardless of whether the user has been authenticated or not.\nBest Practices¶\n MASTG-BEST-0036: Use Cryptographic Binding for Biometric Authentication = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0036/\n\nDemos¶\n MASTG-DEMO-0090: Uses of BiometricPrompt with Event-Bound Authentication with semgrep = https://mas.owasp.org/MASTG/demos/android/MASVS-AUTH/MASTG-DEMO-0090/MASTG-DEMO-0090/',
    },
    {
        "section": 'Authentication',
        "level":   'L1',
        "name":    'References to APIs Detecting Biometric Enrollment Changes',
        "content": 'Overview¶\nThis test checks whether the app fails to protect sensitive operations against unauthorized access following biometric enrollment changes ( Biometric Authentication). An attacker who obtains the device passcode could add a new fingerprint or facial representation via system settings and use it to authenticate in the app.\n\nThis behaviour occurs when setInvalidatedByBiometricEnrollment ↗ is set to false when keys are generated.\n\nBy default and when set to true, a key becomes permanently invalidated if a new biometric is enrolled. As a result, only users whose biometric data was enrolled when the item was created can unlock it. This prevents unauthorized access through biometrics enrolled later.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should include a list of locations where the relevant APIs are used.\n\nEvaluation¶\nThe test case fails if the app uses setInvalidatedByBiometricEnrollment(false) for keys used to protect sensitive data resources.\n\nBest Practices¶\n MASTG-BEST-0037: Invalidate Biometric Keys on Enrollment Changes = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0037/\n\nDemos¶\n MASTG-DEMO-0091: Uses of setInvalidatedByBiometricEnrollment with semgrep = https://mas.owasp.org/MASTG/demos/android/MASVS-AUTH/MASTG-DEMO-0091/MASTG-DEMO-0091/',
    },
    {
        "section": 'Authentication',
        "level":   'L1',
        "name":    'References to APIs Enforcing Authentication without Explicit User Action',
        "content": 'Overview¶\nThis test checks if the app enforces biometric authentication ( Biometric Authentication) without requiring explicit user action ↗. When using android.hardware.biometrics.BiometricPrompt ↗ API (or its Jetpack counterpart androidx.biometric.BiometricPrompt ↗ that backward compatibility to API level 23), the setConfirmationRequired() ↗ method in BiometricPrompt.Builder ↗ controls whether the user must explicitly confirm their authentication, which is enforced by default.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should include a list of locations where the relevant APIs are used.\n\nEvaluation¶\nThe test case fails if the app sets setConfirmationRequired() to false for sensitive operations that require explicit user authorization.\n\nNote\n\nUsing setConfirmationRequired(false) ↗ is not inherently a vulnerability. It may be appropriate for low-risk operations, but for sensitive operations like payments or data access, the app should use setConfirmationRequired(true) or rely on the default behavior to ensure the user explicitly confirms the authentication ↗.\n\nBest Practices¶\n MASTG-BEST-0038: Require Explicit User Confirmation for Biometric Authentication\n\nDemos¶\n MASTG-DEMO-0092: Uses of BiometricPrompt without Explicit User Confirmation with semgrep',
    },
    {
        "section": 'Authentication',
        "level":   'L1',
        "name":    'References to APIs for Keys used in Biometric Authentication with Extended Validity Duration',
        "content": 'Overview¶\nThis test checks if the app configures cryptographic keys with an extended validity duration that allows keys to remain unlocked beyond the immediate operation. When using biometric authentication with CryptoObject ↗, the authentication validity duration determines how long a key remains usable after successful authentication.\n\nOn Android, developers can configure this behavior using setUserAuthenticationParameters(int timeout, int type) ↗ or the deprecated setUserAuthenticationValidityDurationSeconds(int) ↗ when generating keys with KeyGenParameterSpec.Builder ↗:\n\nDuration = 0: The key requires authentication for every cryptographic operation. This is the most secure configuration as each use of the key requires biometric verification.\nDuration > 0: The key remains unlocked for the specified duration (in seconds) after successful authentication. When the duration is set to a high value in the range of minutes or hours an attacker with physical access to the phone could trigger sensitive operations without biometric verification.\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should include a list of locations where the relevant APIs are used.\n\nEvaluation¶\nThe test case fails if the app configures keys used for sensitive operations with:\n\nsetUserAuthenticationParameters(duration, type) where duration > 0\nsetUserAuthenticationValidityDurationSeconds(duration) where duration > 0\nNote\n\nA non-zero authentication validity duration is not inherently a vulnerability. Short durations in the range of seconds may be acceptable for certain use cases where multiple related operations need to be performed in quick succession. However, for high-security applications and sensitive operations, requiring authentication per use (duration = 0) provides the strongest protection against unauthorized key usage and runtime attacks.\n\nBest Practices¶\n MASTG-BEST-0036: Use Cryptographic Binding for Biometric Authentication = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0036/\n\nDemos¶\n MASTG-DEMO-0093: Uses of Extended Validity Duration in setUserAuthenticationParameters with semgrep = https://mas.owasp.org/MASTG/demos/android/MASVS-AUTH/MASTG-DEMO-0093/MASTG-DEMO-0093/',
    },
    {
        "section": 'Network',
        "level":   'L1',
        "name":    'Testing Data Encryption on the Network',
        "content": 'Overview¶\nStatic Analysis¶\nTesting Network Requests over Secure Protocols¶\nFirst, you should identify all network requests in the source code and ensure that no plain HTTP URLs are used. Make sure that sensitive information is sent over secure channels by using HttpsURLConnection ↗ or SSLSocket ↗ (for socket-level communication using TLS).\n\nTesting Network API Usage¶\nNext, even when using a low-level API which is supposed to make secure connections (such as SSLSocket), be aware that it has to be securely implemented. For instance, SSLSocket doesn\'t verify the hostname. Use getDefaultHostnameVerifier to verify the hostname. The Android developer documentation includes a code example ↗.\n\nTesting for Cleartext Traffic¶\nNext, you should ensure that the app is not allowing cleartext HTTP traffic. Since Android 9 (API level 28) cleartext HTTP traffic is blocked by default (thanks to the default Network Security Configuration) but there are multiple ways in which an application can still send it:\n\nSetting the android:usesCleartextTraffic ↗ attribute of the <application> tag in the AndroidManifest.xml file. Note that this flag is ignored in case the Network Security Configuration is configured.\nConfiguring the Network Security Configuration to enable cleartext traffic by setting the cleartextTrafficPermitted attribute to true on <domain-config> elements.\nUsing low-level APIs (e.g. Socket ↗) to set up a custom HTTP connection.\nUsing a cross-platform framework (e.g. Flutter), as these typically have their own implementations for HTTP libraries.\nAll of the above cases must be carefully analyzed as a whole. For example, even if the app does not permit cleartext traffic in its Android Manifest or Network Security Configuration, it might actually still be sending HTTP traffic. That could be the case if it\'s using a low-level API (for which Network Security Configuration is ignored) or a badly configured cross-platform framework.\n\nFor more information refer to the article "Security with HTTPS and SSL" ↗.\n\nDynamic Analysis¶\nIntercept the tested app\'s incoming and outgoing network traffic and make sure that this traffic is encrypted. You can intercept network traffic in any of the following ways:\n\nCapture all HTTP(S) and Websocket traffic with an interception proxy like  ZAP (Zed Attack Proxy) or  Burp Suite and make sure all requests are made via HTTPS instead of HTTP.\nInterception proxies like Burp and  ZAP (Zed Attack Proxy) will show web related traffic primarily (e.g.',
    },
    {
        "section": 'Network',
        "level":   'L1',
        "name":    'Testing the TLS Settings =',
        "content": 'https://mas.owasp.org/MASTG/0x04f-Testing-Network-Communication/#verifying-the-tls-settings',
    },
    {
        "section": 'Network',
        "level":   'L1',
        "name":    'Testing Endpoint Identify Verification',
        "content": 'Static Analysis¶\nUsing TLS to transport sensitive information over the network is essential for security. However, encrypting communication between a mobile application and its backend API is not trivial. Developers often decide on simpler but less secure solutions (e.g., those that accept any certificate) to facilitate the development process, and sometimes these weak solutions make it into the production version ↗, potentially exposing users to Machine-in-the-Middle (MITM) attacks. See "CWE-295: Improper Certificate Validation" ↗.\n\nTwo key issues should be addressed:\n\nVerify that a certificate comes from a trusted source, i.e. a trusted CA (Certificate Authority).\nDetermine whether the endpoint server presents the right certificate.\nMake sure that the hostname and the certificate itself are verified correctly. Examples and common pitfalls are available in the official Android documentation ↗. Search the code for examples of TrustManager and HostnameVerifier usage. In the sections below, you can find examples of the kind of insecure usage that you should look for.\n\nNote\n\nFrom Android 8.0 (API level 26) onward, there is no support for SSLv3, and HttpsURLConnection will no longer perform a fallback to an insecure TLS/SSL protocol.\n\nVerifying the Target SDK Version¶\nApplications targeting Android 7.0 (API level 24) or higher will use a default Network Security Configuration that doesn\'t trust any user supplied CAs, reducing the possibility of MITM attacks by luring users to install malicious CAs.\n\nDecode the app using apktool ( Exploring the App Package) and verify that the targetSdkVersion in apktool.yml is equal to or higher than 24.\n\n\ngrep targetSdkVersion UnCrackable-Level3/apktool.yml\n  targetSdkVersion: \'28\'\nHowever, even if targetSdkVersion >=24, the developer can disable default protections by using a custom Network Security Configuration defining a custom trust anchor forcing the app to trust user supplied CAs. See "Analyzing Custom Trust Anchors".\n\nAnalyzing Custom Trust Anchors¶\nSearch for the Network Security Configuration file and inspect any custom <trust-anchors> defining <certificates src="user"> (which should be avoided).\n\nYou should carefully analyze the precedence of entries ↗:\n\nIf a value is not set in a <domain-config> entry or in a parent <domain-config>, the configurations in place will be based on the <base-config>\nIf not defined in this entry, the default configurations will be used.\nTake a look at this example of a Network Security ',
    },
    {
        "section": 'Network',
        "level":   'L1',
        "name":    'Testing Custom Certificate Stores and Certificate Pinning',
        "content": 'Overview¶\nStatic Analysis¶\nNetwork Security Configuration¶\nInspect the Network Security Configuration looking for any <pin-set> elements. Check their expiration date, if any. If expired, certificate pinning will be disabled for the affected domains.\n\nTesting Tip: If a certificate pinning validation check has failed, the following event should be logged in the system logs (see  Monitoring System Logs):\n\n\nI/X509Util: Failed to validate the certificate chain, error: Pin verification failed\nTrustManager¶\nImplementing certificate pinning involves three main steps:\n\nObtain the certificate of the desired host(s).\nMake sure the certificate is in .bks format.\nPin the certificate to an instance of the default Apache Httpclient.\nTo analyze the correct implementation of certificate pinning, the HTTP client should load the KeyStore:\n\n\nInputStream in = resources.openRawResource(certificateRawResource);\nkeyStore = KeyStore.getInstance("BKS");\nkeyStore.load(resourceStream, password);\nOnce the KeyStore has been loaded, we can use the TrustManager that trusts the CAs in our KeyStore:\n\n\nString tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();\nTrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);\ntmf.init(keyStore);\n// Create an SSLContext that uses the TrustManager\n// SSLContext context = SSLContext.getInstance("TLS");\nsslContext.init(null, tmf.getTrustManagers(), null);\nThe app\'s implementation may be different, pinning against the certificate\'s public key only, the whole certificate, or a whole certificate chain.\n\nNetwork Libraries and WebViews¶\nApplications that use third-party networking libraries may utilize the libraries\' certificate pinning functionality. For example, okhttp ↗ can be set up with the CertificatePinner as follows:\n\n\nOkHttpClient client = new OkHttpClient.Builder()\n        .certificatePinner(new CertificatePinner.Builder()\n            .add("example.com", "sha256/UwQAapahrjCOjYI3oLUx5AQxPBR02Jz6/E2pt0IeLXA=")\n            .build())\n        .build();\nApplications that use a WebView component may utilize the WebViewClient\'s event handler for some kind of "certificate pinning" of each request before the target resource is loaded. The following code shows an example verification:\n\n\nWebView myWebView = (WebView) findViewById(R.id.webview);\nmyWebView.setWebViewClient(new WebViewClient(){\n    private String expectedIssuerDN = "CN=Let\'s Encrypt Authority X3,O=Let\'s Encrypt,C=US;";\n\n    @Override\n    public void onLoadResource(WebView vie',
    },
    {
        "section": 'Network',
        "level":   'L1',
        "name":    'Testing the Security Provider',
        "content": "Static Analysis¶\nApplications based on the Android SDK should depend on GooglePlayServices. For example, in the gradle build file, you will find compile 'com.google.android.gms:play-services-gcm:x.x.x' in the dependencies block. You need to make sure that the ProviderInstaller class is called with either installIfNeeded or installIfNeededAsync. ProviderInstaller needs to be called by a component of the application as early as possible. Exceptions thrown by these methods should be caught and handled correctly. If the application cannot patch its  Security Provider, it can either inform the API of its less secure state or restrict user actions (because all HTTPS traffic should be deemed riskier in this situation).\n\nIf you have access to the source code, check if the app handle any exceptions related to the security provider updates properly, and if it reports to the backend when the application is working with an unpatched security provider. The Android Developer documentation provides different examples showing how to update the Security Provider to prevent SSL exploits ↗.\n\nLastly, make sure that NDK-based applications bind only to a recent and properly patched library that provides SSL/TLS functionality.\n\nDynamic Analysis¶\nWhen you have the source code:\n\nRun the application in debug mode, then create a breakpoint where the app will first contact the endpoint(s).\nRight click the highlighted code and select Evaluate Expression.\nType Security.getProviders() and press enter.\nCheck the providers and try to find GmsCore_OpenSSL, which should be the new top-listed provider.\nWhen you do not have the source code:\n\nUse  Frida (Android) to hook java.security.Security.getProviders() ↗ or use a script  Frida CodeShare like @platix/get-android-security-provider-mstg-network-6 ↗.\nDetermine whether the first provider is GmsCore_OpenSSL.",
    },
    {
        "section": 'Network',
        "level":   'L1',
        "name":    'Insecure TLS Protocols Explicitly Allowed in Code',
        "content": 'Overview¶\nThe Android Network Security Configuration does not provide direct control over specific TLS versions (unlike iOS ↗), and starting with Android 10, TLS v1.3 is enabled by default ↗ for all TLS connections.\n\nThere are still several ways to enable insecure versions of TLS, including:\n\nJava Sockets¶\nAn app can obtain an SSLContext using an insecure TLS protocol by calling SSLContext.getInstance("TLSv1.1") and can also enable specific, potentially insecure, protocol versions using the API call javax.net.ssl.SSLSocket.setEnabledProtocols(String[] protocols).\n\nThird-party Libraries¶\nSome third-party libraries, such as OkHttp ↗, Retrofit ↗ or Apache HttpClient, provide custom configurations for TLS protocols. These libraries may allow enabling outdated protocols if not carefully managed:\n\nFor example, using ConnectionSpec.COMPATIBLE_TLS in OkHttp (via okhttp3.ConnectionSpec.Builder.connectionSpecs(...)) can lead to insecure TLS versions, like TLS 1.1, being enabled by default in certain versions. Refer to OkHttp\'s configuration history ↗ for details on supported protocols.\n\nThe API call okhttp3.ConnectionSpec.Builder.tlsVersions(...) can also be used to set the enabled protocols (OkHttp documentation ↗).\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should contain a list of all enabled TLS versions in the above mentioned API calls.\n\nEvaluation¶\nThe test case fails if any insecure TLS version is directly enabled, or if the app enabled any settings allowing the use of outdated TLS versions, such as okhttp3.ConnectionSpec.COMPATIBLE_TLS.',
    },
    {
        "section": 'Network',
        "level":   'L1',
        "name":    'Insecure TLS Protocols in Network Traffic',
        "content": "Overview¶\nWhile static analysis can identify configurations that allow insecure TLS versions, it may not accurately reflect the actual protocol used during live communications. This is because TLS version negotiation occurs between the client (app) and the server at runtime, where they agree on the most secure, mutually supported version.\n\nBy capturing and analyzing real network traffic, you can observe the TLS version actually negotiated and in use. This approach provides an accurate view of the protocol's security, accounting for the server's configuration, which may enforce or limit specific TLS versions.\n\nIn cases where static analysis is either incomplete or infeasible, examining network traffic can reveal instances where insecure TLS versions (e.g., TLS 1.0 or TLS 1.1) are actively in use.\n\nSteps¶\nUse  Installing Apps to install the app.\nUse  Basic Network Monitoring/Sniffing to capture the app traffic.\nExercise the app extensively to trigger as many flows as possible and enter sensitive data wherever you can.\nObservation¶\nThe output should contain the app traffic.\n\nEvaluation¶\nThe test case fails if any insecure TLS version is used.",
    },
    {
        "section": 'Network',
        "level":   'L1',
        "name":    'Hardcoded HTTP URLs',
        "content": 'Overview¶\nAn Android app may have hardcoded HTTP URLs embedded in the app binary, library binaries, or other resources within the APK. These URLs may indicate potential locations where the app communicates with servers over an unencrypted connection.\n\nWarning\n\nThe presence of HTTP URLs alone does not necessarily mean they are actively used for communication. Their usage may depend on runtime conditions, such as how the URLs are invoked and whether cleartext traffic is allowed in the app\'s configuration. For example, HTTP requests may fail if cleartext traffic is disabled in the AndroidManifest.xml or restricted by the Network Security Configuration. See  Android App Configurations Allowing Cleartext Traffic.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Retrieving Strings to look for any http:// URLs.\nObservation¶\nThe output should contain a list of URLs and their locations within the app.\n\nEvaluation¶\nThe test case fails if any HTTP URLs are confirmed to be used for communication.\n\nThe presence of hardcoded HTTP URLs does not inherently mean they are used; their actual usage must be validated through careful inspection and testing:\n\nReverse Engineering: Inspect the code locations where the HTTP URLs are referenced. Determine if they are merely stored as constants or actively used to create HTTP requests through networking APIs like HttpURLConnection or OkHttp.\nStatic Analysis: Analyze the app\'s configuration to identify whether cleartext traffic is permitted. For example, check the AndroidManifest.xml for android:usesCleartextTraffic="true" or inspect the network_security_config. Refer to  Android App Configurations Allowing Cleartext Traffic for detailed guidance.\nAdditionally, complement this static inspection with dynamic testing methods:\n\nDynamic Analysis: Use tools like Frida to hook into networking APIs at runtime. This can reveal how and when the HTTP URLs are used during execution. See  Runtime Use of Network APIs Transmitting Cleartext Traffic for more details.\n\nNetwork Traffic Interception: Capture and analyze network traffic using tools like Burp Suite, mitmproxy, or Wireshark. This approach confirms whether the app connects to the identified HTTP URLs during real-world usage but depends on the tester\'s ability to exercise the app\'s functionality comprehensively. See  Cleartext Traffic Observed on the Network.',
    },
    {
        "section": 'Network',
        "level":   'L1',
        "name":    'Missing Implementation of Server Hostname Verification with SSLSockets',
        "content": "This test checks whether an Android app uses SSLSocket ↗ without a HostnameVerifier ↗, allowing connections to servers presenting certificates with wrong or invalid hostnames.\n\nBy default, SSLSocket does not perform hostname verification ↗. To enforce it, the app must explicitly invoke HostnameVerifier.verify() ↗ and implement proper checks.\n\nSuch unsafe implementations can allow an attacker to run a MITM attack with a valid (or self-signed) certificate and intercept or tamper with the app's traffic.\n\nNote: The connection succeeds even if the app has a fully secure Network Security Configuration (NSC) in place because SSLSocket is not affected by it.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should contain a list of locations where SSLSocket and HostnameVerifier are used.\n\nEvaluation¶\nThe test case fails if the app uses SSLSocket without a HostnameVerifier.\n\nNote\n\nIf a HostnameVerifier is present, ensure it's not implemented in an unsafe manner. See  Incorrect Implementation of Server Hostname Verification for guidance.\n\nDemos¶\n MASTG-DEMO-0049: SSLSocket Connection to Wrong Host Server Blocked by HostnameVerifier = https://mas.owasp.org/MASTG/demos/android/MASVS-NETWORK/MASTG-DEMO-0049/MASTG-DEMO-0049/\n MASTG-DEMO-0048: SSLSocket Connection to Wrong Host Server Allowed by Lack of HostnameVerifier = https://mas.owasp.org/MASTG/demos/android/MASVS-NETWORK/MASTG-DEMO-0048/MASTG-DEMO-0048/",
    },
    {
        "section": 'Network',
        "level":   'L1',
        "name":    'Android App Configurations Allowing Cleartext Traffic',
        "content": 'Overview¶\nSince Android 9 (API level 28) cleartext HTTP traffic is blocked by default (thanks to the default Network Security Configuration) but there are multiple ways in which an application can still send it:\n\nAndroidManifest.xml: Setting the android:usesCleartextTraffic ↗ attribute of the <application> tag. Note that this flag is ignored in case the Network Security Configuration is configured.\nNetwork Security Configuration: Setting the cleartextTrafficPermitted ↗ attribute to true on <base-config> or <domain-config> elements.\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Obtaining Information from the AndroidManifest to obtain the AndroidManifest.xml.\nUse  Analyzing the AndroidManifest to read the value of android:usesCleartextTraffic and check if android:networkSecurityConfig is present.\nUse  Analyzing the Network Security Configuration to read the values of cleartextTrafficPermitted in the <base-config> and <domain-config> elements from the Network Security Configuration file.\nObservation¶\nThe output should contain a list of configurations potentially allowing for cleartext traffic.\n\nEvaluation¶\nThe test case fails if cleartext traffic is permitted. This can happen if any of the following is true:\n\nThe AndroidManifest sets usesCleartextTraffic to true and there\'s no NSC.\nThe NSC sets cleartextTrafficPermitted to true in the <base-config>.\nThe NSC sets cleartextTrafficPermitted to true in any <domain-config>.\nNote\n\nThe test doesn\'t fail if the AndroidManifest sets usesCleartextTraffic to true and there\'s a NSC, even if it only has an empty <network-security-config> element. For example:\n\n\n<?xml version="1.0" encoding="utf-8"?>\n<network-security-config>\n</network-security-config>',
    },
    {
        "section": 'Network',
        "level":   'L1',
        "name":    'Cleartext Traffic Observed on the Network',
        "content": "Overview¶\nThis test intercepts the app's incoming and outgoing network traffic, and checks for any cleartext communication. Whilst the static checks can only show potential cleartext traffic, this dynamic test shows all communication the application definitely makes.\n\nWarning\n\nIntercepting traffic on a network level will show all traffic the device performs, not only the single app. Linking the traffic back to a specific app can be difficult, especially when more apps are installed on the device.\nLinking the intercepted traffic back to specific locations in the app can be difficult and requires manual analysis of the code.\nDynamic analysis works best when you interact extensively with the app. But even then there could be corner cases which are difficult or impossible to execute on every device. The results from this test therefore are likely not exhaustive.\nSteps¶\nYou can use one of the following approaches:\n\nSet up  Basic Network Monitoring/Sniffing (for Android) or  Basic Network Monitoring/Sniffing (for iOS) to capture all traffic.\nSet up  Setting Up an Interception Proxy (for Android) or  Setting up an Interception Proxy (for iOS) to capture all traffic.\nNotes:\n\nInterception proxies will show HTTP(S) traffic only. You can, however, use some tool-specific plugins such as Burp-non-HTTP-Extension ↗ or other tools like  MITM Relay to decode and visualize communication via XMPP and other protocols.\nSome apps may not function correctly with proxies like Burp and  ZAP (Zed Attack Proxy) because of certificate pinning. In such a scenario, you can still use basic network sniffing to detect cleartext traffic. Otherwise, you can try to disable pinning (see  Bypassing Certificate Pinning for Android and  Bypassing Certificate Pinning for iOS)\nObservation¶\nThe output should contain the captured network traffic.\n\nEvaluation¶\nThe test case fails if any clear text traffic originates from the target app.",
    },
    {
        "section": 'Network',
        "level":   'L1',
        "name":    'Cross-Platform Framework Configurations Allowing Cleartext Traffic',
        "content": 'Cross-platform frameworks (e.g. Flutter, React native, ...), typically have their own implementations for HTTP libraries, where cleartext traffic can be allowed.\n\nFor more details, check the associated weakness:  Cleartext Traffic = https://mas.owasp.org/MASWE-0050',
    },
    {
        "section": 'Network',
        "level":   'L1',
        "name":    'Runtime Use of Network APIs Transmitting Cleartext Traffic',
        "content": 'Using Frida, you can trace all traffic of the app, mitigating the limitation of the dynamic analysis that you do not know which app, or which location is responsible for the traffic. Using Frida (and .backtrace()), you can be sure this is from the analyzed app, and know the exact location. A new limitation is then that all relevant networking APIs need to be instrumented.\n\nFor more details, check the associated weakness:  Cleartext Traffic = https://mas.owasp.org/MASWE-0050',
    },
    {
        "section": 'Network',
        "level":   'L1',
        "name":    'Missing Certificate Pinning in Network Security Configuration',
        "content": 'Overview¶\nApps can configure certificate pinning using the Network Security Configuration. For each domain, one or multiple digests can be pinned.\n\nThe goal of this test is to check if the app does not implement certificate pinning using the NSC. However, note that the app may be using other pinning methods covered in other tests.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Obtaining Information from the AndroidManifest to obtain the AndroidManifest.xml\nUse  Analyzing the AndroidManifest to check if a networkSecurityConfig is set in the <application> tag.\nUse  Analyzing the Network Security Configuration to extract all domains from <domain-config> that have a pin set (<pin-set>) from the Network Security Configuration file.\nObservation¶\nThe output should contain a list of domains which enable certificate pinning.\n\nEvaluation¶\nThe test case fails if no networkSecurityConfig is set, or any relevant domain does not enable certificate pinning.',
    },
    {
        "section": 'Network',
        "level":   'L1',
        "name":    'Expired Certificate Pins in the Network Security Configuration',
        "content": "Overview¶\nApps can configure expiration dates for pinned certificates in the Network Security Configuration (NSC) ( Android Network Security Configuration) by using the expiration attribute. When a pin expires, the app no longer enforces certificate pinning and instead relies on its configured trust anchors. This means the connection will still succeed if the server presents a valid certificate from a trusted CA (such as a system CA or a custom CA defined in the app's configuration). However, if no trusted certificate is available, the connection will fail.\n\nIf developers assume pinning is still in effect but don't realize it has expired, the app may start trusting CAs it was never intended to.\n\nExample: A financial app previously pinned to its own private CA but, after expiration, starts trusting publicly trusted CAs, increasing the risk of compromise if a CA is breached.\n\nThe goal of this test is to check if any expiration date is in the past.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Obtaining Information from the AndroidManifest to obtain the AndroidManifest.xml.\nUse  Analyzing the AndroidManifest to check if android:networkSecurityConfig is set in the <application> tag.\nUse  Analyzing the Network Security Configuration to extract the expiration dates for all certificate pins from the Network Security Configuration file.\nObservation¶\nThe output should contain a list of expiration dates for pinned certificates.\n\nEvaluation¶\nThe test case fails if any expiration date is in the past.",
    },
    {
        "section": 'Network',
        "level":   'L1',
        "name":    'Missing Certificate Pinning in Network Traffic',
        "content": 'Overview¶\nThere are multiple ways an application can implement certificate pinning, including via the Android Network Security Config, custom TrustManager implementations, third-party libraries, and native code. Since some implementations might be difficult to identify through static analysis, especially when obfuscation or dynamic code loading is involved, this test uses network interception techniques to determine if certificate pinning is enforced at runtime.\n\nThe goal of this test case is to observe whether a MITM attack can intercept HTTPS traffic from the app. A successful MITM interception indicates that the app is either not using certificate pinning or implementing it incorrectly.\n\nIf the app is properly implementing certificate pinning, the MITM attack should fail because the app rejects certificates issued by an unauthorized CA, even if the CA is trusted by the system.\n\nTesting Tip: While performing the MITM attack, it can be useful to monitor the system logs (see  Monitoring System Logs). If a certificate pinning/validation check fails, an event similar to the following log entry might be visible, indicating that the app detected the MITM attack and did not establish a connection.\n\nI/X509Util: Failed to validate the certificate chain, error: Pin verification failed\n\nSteps¶\nUse  Installing Apps to install the app.\nUse  Setting Up an Interception Proxy to set up an interception proxy and to intercept the communication.\nObservation¶\nThe output should contain the intercepted traffic capture.\n\nEvaluation¶\nThe test case fails if any relevant domain appears in the intercepted traffic capture.',
    },
    {
        "section": 'Network',
        "level":   'L1',
        "name":    'Unsafe Custom Trust Evaluation',
        "content": "Overview¶\nThis test evaluates whether an Android app uses checkServerTrusted(...) ↗ in an unsafe manner ↗ as part of a custom TrustManager, causing any connection configured to use that TrustManager to skip certificate validation.\n\nSuch unsafe implementations can allow an attacker to run a MITM attack with a valid (or self-signed) certificate and intercept or tamper with the app's traffic.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should contain a list of locations where checkServerTrusted(...) is used.\n\nEvaluation¶\nThe test case fails if checkServerTrusted(...) is implemented in a custom X509TrustManager and does not properly validate server certificates.\n\nFurther Validation Required:\n\nInspect each reported code location using  Reviewing Decompiled Java Code, looking for cases such as:\n\n**Using checkServerTrusted(...) which is error prone, when NSC would be enough.\nTrust manager that does nothing: overriding checkServerTrusted(...) to accept all certificates without any validation, for example by returning immediately without verifying the certificate chain or by always returning true.\nIgnoring errors: failing to throw proper exceptions ↗ (e.g. CertificateException ↗ or IllegalArgumentException ↗) on validation failure, or catching and suppressing them.\nUsing checkValidity() ↗ instead of full validation: relying only on checkValidity() checks whether the certificate is expired or not yet valid, but does not verify trust or hostname matching.\nExplicitly loosening trust: disabling trust checks to accept self-signed or untrusted certificates for convenience during development or testing.\nMisusing getAcceptedIssuers() ↗: Returning null or an empty array without proper handling may effectively disable issuer validation.\nBest Practices¶\n MASTG-BEST-0021: Ensure Proper Error and Exception Handling = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0021/\n\nDemos¶\n MASTG-DEMO-0054: Use of a TrustManager that Does Not Validate Certificate Chains = https://mas.owasp.org/MASTG/demos/android/MASVS-NETWORK/MASTG-DEMO-0054/MASTG-DEMO-0054/",
    },
    {
        "section": 'Network',
        "level":   'L1',
        "name":    'Incorrect Implementation of Server Hostname Verification',
        "content": "This test evaluates whether an Android app implements a HostnameVerifier ↗ that uses verify(...) ↗ in an unsafe manner ↗, effectively turning off hostname validation for the affected connections.\n\nSuch unsafe implementations can allow an attacker to run a MITM attack with a valid (or self-signed) certificate and intercept or tamper with the app's traffic.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should contain a list of locations where HostnameVerifier is used.\n\nEvaluation¶\nThe test case fails if the app does not properly validate that the server's hostname matches the certificate.\n\nFurther Validation Required:\n\nInspect each reported code location using  Reviewing Decompiled Java Code, looking for cases such as:\n\nAlways accepting hostnames: overriding verify(...) to unconditionally return true, regardless of the actual hostname or certificate.\nOverly broad matching rules: using permissive wildcard logic that matches unintended domains.\nIncomplete verification coverage: failing to invoke hostname verification on all SSL/TLS channels, such as those created via SSLSocket, or during renegotiation.\nMissing manual verification: not performing hostname verification when it is not done automatically, such as when using the low-level SSLSocket API.\nDemos¶\n MASTG-DEMO-0055: Use of the HostnameVerifier that Allows Any Hostname = https://mas.owasp.org/MASTG/demos/android/MASVS-NETWORK/MASTG-DEMO-0055/MASTG-DEMO-0055/",
    },
    {
        "section": 'Network',
        "level":   'L1',
        "name":    'Incorrect SSL Error Handling in WebViews',
        "content": 'Overview¶\nThis test evaluates whether an Android app has WebViews that ignore SSL/TLS certificate errors by overriding the onReceivedSslError(...) ↗ method without proper validation.\n\nThe method onReceivedSslError(...) is triggered when a WebView encounters an SSL certificate error while loading a page. By default, the WebView cancels the request to protect users from insecure connections. Overriding this method and calling SslErrorHandler.proceed() ↗ without proper validation disables these protection.\n\nThis effectively bypasses SSL certificate checks in the WebView, exposing the app to MITM attacks using invalid, expired, or self-signed certificates.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should contain a list of locations where onReceivedSslError(...) that includes a proceed() is used without exception handling that properly handles SSL errors.\n\nEvaluation¶\nThe test case fails if onReceivedSslError(...) is overridden and certificate errors are ignored without proper validation or user involvement.\n\nFurther Validation Required:\n\nInspect each reported code location using  Reviewing Decompiled Java Code, looking for cases such as:\n\nUnconditionally accepting SSL errors: calling proceed() without checking the nature of the error.\nRelying only on primary error code: using getPrimaryError() ↗ for decision-making, such as proceeding if the primary error is not SSL_UNTRUSTED, which may overlook additional errors in the chain.\nSuppressing exceptions silently: catching exceptions in onReceivedSslError(...) without calling cancel() ↗, which allows the connection to continue silently.\nAccording to official Android guidance ↗, apps should never call proceed() in response to SSL errors. The correct behavior is to cancel the request to protect users from potentially insecure connections. User prompts are also discouraged, as users cannot reliably evaluate SSL issues.\n\nBest Practices¶\n MASTG-BEST-0021: Ensure Proper Error and Exception Handling - https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0021/\n\nDemos¶\n MASTG-DEMO-0056: WebView Ignoring TLS Errors in onReceivedSslError - https://mas.owasp.org/MASTG/demos/android/MASVS-NETWORK/MASTG-DEMO-0056/MASTG-DEMO-0056/',
    },
    {
        "section": 'Network',
        "level":   'L1',
        "name":    'Outdated Android Version Allowing Trust in User-Provided CAs',
        "content": 'Overview¶\nThis test evaluates whether an Android app implicitly trusts user-added CA certificates by default ↗, which is the case for apps that can be installed to devices running API level 23 or lower.\n\nThose apps rely on the default Network Security Configuration that trusts both system and user-installed Certificate Authorities (CAs). Such trust can expose the app to MITM attacks, as malicious CAs installed by users could intercept secure communications.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Obtaining Information from the AndroidManifest to obtain the AndroidManifest.xml.\nUse  Analyzing the AndroidManifest to read the value of the minSdkVersion attribute from the <uses-sdk> element.\nObservation¶\nThe output should contain the value of minSdkVersion.\n\nEvaluation¶\nThe test case fails if minSdkVersion is less than 24.',
    },
    {
        "section": 'Network',
        "level":   'L1',
        "name":    'Network Security Configuration Allowing Trust in User-Provided CAs',
        "content": 'Overview¶\nThis test evaluates whether an Android app explicitly trusts user-added CA certificates by including <certificates src="user"/> ↗ in its Network Security Configuration ↗ which is defined android:networkSecurityConfig ↗ attribute is set in the <application> tag. Even though starting with Android 7.0 (API level 24) apps no longer trust user-added CAs by default, this configuration overrides that behavior.\n\nSuch trust can expose the application to MITM attacks, as malicious CAs installed by users could intercept secure communications.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Obtaining Information from the AndroidManifest to obtain the AndroidManifest.xml.\nUse  Analyzing the AndroidManifest to check if the android:networkSecurityConfig attribute is present.\nUse  Analyzing the Network Security Configuration to extract all uses of <certificates src="user" /> from the Network Security Configuration file.\nObservation¶\nThe output should contain all the <trust-anchors> from the Network Security Configuration file along with any defined <certificates> entries, if present.\n\nEvaluation¶\nThe test case fails if <certificates src="user" /> has been defined as part of the <trust-anchors> in the Network Security Configuration file.\n\nDemos¶\n MASTG-DEMO-0057: Network Security Configuration Allows User-Added Certificates = https://mas.owasp.org/MASTG/demos/android/MASVS-NETWORK/MASTG-DEMO-0057/MASTG-DEMO-0057/',
    },
    {
        "section": 'Network',
        "level":   'L1',
        "name":    'GMS Security Provider Not Updated',
        "content": 'Overview¶\nThis test checks whether the Android app ensures the Security Provider is updated to mitigate SSL/TLS vulnerabilities ↗. The provider should be updated using Google Play Services APIs, and the implementation should handle exceptions properly.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should list all locations where the Security Provider update is performed and how exceptions are handled (for installIfNeeded), or how the ProviderInstallListener handles errors (for installIfNeededAsync).\n\nEvaluation¶\nThe test case fails if the app does not update the provider, or it does not handle exceptions properly. Check that these calls occur before any network connections are made.\n\nBest Practices¶\n MASTG-BEST-0020: Update the GMS Security Provider = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0020/',
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'Determining Whether Sensitive Stored Data Has Been Exposed via IPC Mechanisms',
        "content": 'Overview¶\nStatic Analysis¶\nThe first step is to look at AndroidManifest.xml to detect content providers exposed by the app. You can identify content providers by the <provider> element. Complete the following steps:\n\nDetermine whether the value of the export tag (android:exported) is "true". Even if it is not, the tag will be set to "true" automatically if an <intent-filter> has been defined for the tag. If the content is meant to be accessed only by the app itself, set android:exported to "false". If not, set the flag to "true" and define proper read/write permissions.\nDetermine whether the data is being protected by a permission tag (android:permission). Permission tags limit exposure to other apps.\nDetermine whether the android:protectionLevel attribute has the value signature. This setting indicates that the data is intended to be accessed only by apps from the same enterprise (i.e., signed with the same key). To make the data accessible to other apps, apply a security policy with the <permission> element and set a proper android:protectionLevel. If you use android:permission, other applications must declare corresponding <uses-permission> elements in their manifests to interact with your content provider. You can use the android:grantUriPermissions attribute to grant more specific access to other apps; you can limit access with the <grant-uri-permission> element.\nInspect the source code to understand how the content provider is meant to be used. Search for the following keywords:\n\nandroid.content.ContentProvider\nandroid.database.Cursor\nandroid.database.sqlite\n.query\n.update\n.delete\nTo avoid SQL injection attacks within the app, use parameterized query methods, such as query, update, and delete. Be sure to properly sanitize all method arguments; for example, the selection argument could lead to SQL injection if it is made up of concatenated user input.\n\nIf you expose a content provider, determine whether parameterized query methods ↗ (query, update, and delete) are being used to prevent SQL injection. If so, make sure all their arguments are properly sanitized.\n\nWe will use the vulnerable password manager app Sieve ↗ as an example of a vulnerable content provider.\n\nInspect the Android Manifest¶\nIdentify all defined <provider> elements:\n\n\n<provider\n      android:authorities="com.mwr.example.sieve.DBContentProvider"\n      android:exported="true"\n      android:multiprocess="true"\n      android:name=".DBContentProvider">\n    <path-permission\n          andr',
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'Checking for Sensitive Data Disclosure Through the User Interface',
        "content": 'Overview¶\nStatic Analysis¶\nCarefully review all UI components that either show such information or take it as input. Search for any traces of sensitive information and evaluate if it should be masked or completely removed.\n\nText Fields¶\nTo make sure an application is masking sensitive user input, check for the following attribute in the definition of EditText:\n\n\nandroid:inputType="textPassword"\nWith this setting, dots (instead of the input characters) will be displayed in the text field, preventing the app from leaking passwords or pins to the user interface.\n\nApp Notifications¶\nWhen statically assessing an application, it is recommended to search for any usage of the NotificationManager class which might be an indication of some form of notification management. If the class is being used, the next step would be to understand how the application is generating the notifications ↗.\n\nThese code locations can be fed into the Dynamic Analysis section below, providing an idea of where in the application notifications may be dynamically generated.\n\nDynamic Analysis¶\nTo determine whether the application leaks any sensitive information to the user interface, run the application and identify components that could be disclosing information.\n\nText Fields¶\nIf the information is masked by, for example, replacing input with asterisks or dots, the app isn\'t leaking data to the user interface.\n\nApp Notifications¶\nTo identify the usage of notifications run through the entire application and all its available functions looking for ways to trigger any notifications. Consider that you may need to perform actions outside of the application in order to trigger certain notifications.\n\nWhile running the application you may want to start tracing all calls to functions related to the notifications creation, e.g. setContentTitle or setContentText from NotificationCompat.Builder ↗. Observe the trace in the end and evaluate if it contains any sensitive information.',
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'Finding Sensitive Information in Auto-Generated Screenshots',
        "content": "Overview¶\nStatic Analysis¶\nA screenshot of the current activity is taken when an Android app goes into background and displayed for aesthetic purposes when the app returns to the foreground. However, this may leak sensitive information.\n\nTo determine whether the application may expose sensitive information via the app switcher, find out whether the FLAG_SECURE ↗ option has been set. You should find something similar to the following code snippet:\n\nExample in Java:\n\n\ngetWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,\n                WindowManager.LayoutParams.FLAG_SECURE);\n\nsetContentView(R.layout.activity_main);\nExample in Kotlin:\n\n\nwindow.setFlags(WindowManager.LayoutParams.FLAG_SECURE,\n                WindowManager.LayoutParams.FLAG_SECURE)\n\nsetContentView(R.layout.activity_main)\nIf the option has not been set, the application is vulnerable to screen capturing.\n\nDynamic Analysis¶\nWhile black-box testing the app, navigate to any screen that contains sensitive information and click the home button to send the app to the background, then press the app switcher button to see the snapshot. As shown below, if FLAG_SECURE is set (left image), the snapshot will be empty; if the flag has not been set (right image), activity information will be shown:\n\n\n\nOn devices supporting file-based encryption (FBE) ↗, snapshots are stored in the /data/system_ce/<USER_ID>/<IMAGE_FOLDER_NAME> folder. <IMAGE_FOLDER_NAME> depends on the vendor but most common names are snapshots and recent_images. If the device doesn't support FBE, the /data/system/<IMAGE_FOLDER_NAME> folder is used.\n\nAccessing these folders and the snapshots requires root.",
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'Testing for App Permissions',
        "content": 'Overview¶\nWhen testing app permissions the goal is to try and reduce the amount of permissions used by your app to the absolute minimum. While going through each permission, remember that it is best practice first to try and evaluate whether your app needs to use this permission ↗ because many functionalities such as taking a photo can be done without, limiting the amount of access to sensitive data. If permissions are required you will then make sure that the request/response to access the permission is handled handled correctly.\n\nStatic Analysis¶\nAndroid Permissions¶\nCheck permissions to make sure that the app really needs them and remove unnecessary permissions. For example, the INTERNET permission in the AndroidManifest.xml file is necessary for an Activity to load a web page into a WebView. Because a user can revoke an application\'s right to use a dangerous permission, the developer should check whether the application has the appropriate permission each time an action is performed that would require that permission.\n\n\n<uses-permission android:name="android.permission.INTERNET" />\nGo through the permissions with the developer to identify the purpose of every permission set and remove unnecessary permissions.\n\nBesides going through the AndroidManifest.xml file manually, you can also use the Android Asset Packaging tool (aapt) to examine the permissions of an APK file.\n\naapt comes with the Android SDK within the build-tools folder. It requires an APK file as input. You may list the APKs in the device by running adb shell pm list packages -f | grep -i <keyword> as seen in  Listing Installed Apps.\n\n\n$ aapt d permissions app-x86-debug.apk\npackage: sg.vp.owasp_mobile.omtg_android\nuses-permission: name=\'android.permission.WRITE_EXTERNAL_STORAGE\'\nuses-permission: name=\'android.permission.INTERNET\'\nAlternatively you may obtain a more detailed list of permissions via adb and the dumpsys tool:\n\n\n$ adb shell dumpsys package sg.vp.owasp_mobile.omtg_android | grep permission\n    requested permissions:\n      android.permission.WRITE_EXTERNAL_STORAGE\n      android.permission.INTERNET\n      android.permission.READ_EXTERNAL_STORAGE\n    install permissions:\n      android.permission.INTERNET: granted=true\n      runtime permissions:\nPlease reference this permissions overview ↗ for descriptions of the listed permissions that are considered dangerous.\n\n\nREAD_CALENDAR\nWRITE_CALENDAR\nREAD_CALL_LOG\nWRITE_CALL_LOG\nPROCESS_OUTGOING_CALLS\nCAMERA\nREAD_CONTACTS\nWRITE_CONTACTS\nGET_A',
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'Testing Deep Links',
        "content": 'Overview¶\nAny existing deep links (including App Links) can potentially increase the app attack surface. This includes many risks ↗ such as link hijacking, sensitive functionality exposure, etc.\n\nBefore Android 12 (API level 31), if the app has any non-verifiable links ↗, it can cause the system to not verify all Android App Links for that app.\nStarting on Android 12 (API level 31), apps benefit from a reduced attack surface ↗. A generic web intent resolves to the user\'s default browser app unless the target app is approved for the specific domain contained in that web intent.\nAll deep links must be enumerated and verified for correct website association. The actions they perform must be well tested, especially all input data, which should be deemed untrustworthy and thus should always be validated.\n\nNone of the input from these sources can be trusted; it must be validated and/or sanitized. Validation ensures processing of data that the app is expecting only. If validation is not enforced, any input can be sent to the app, which may allow an attacker or malicious app to exploit app functionality.\n\nStatic Analysis¶\nCheck for Android OS Version¶\nThe Android version in which the app runs also influences the risk of using deep links. Inspect the Android Manifest to check if minSdkVersion is 31 or higher.\n\nBefore Android 12 (API level 31), if the app has any non-verifiable deep links ↗, it can cause the system to not verify all Android App Links for that app.\nStarting on Android 12 (API level 31), apps benefit from a reduced attack surface ↗. A generic web intent resolves to the user\'s default browser app unless the target app is approved for the specific domain contained in that web intent.\nCheck for Deep Link Usage¶\nInspecting the Android Manifest:\n\nYou can easily determine whether deep links (with or without custom URL schemes) are defined by  Exploring the App Package and inspecting the Android Manifest file looking for <intent-filter> elements ↗.\n\nCustom Url Schemes: The following example specifies a deep link with a custom URL scheme called myapp://.\n\n<activity android:name=".MyUriActivity">\n  <intent-filter>\n      <action android:name="android.intent.action.VIEW" />\n      <category android:name="android.intent.category.DEFAULT" />\n      <category android:name="android.intent.category.BROWSABLE" />\n      <data android:scheme="myapp" android:host="path" />\n  </intent-filter>\n</activity>\nDeep Links: The following example specifies a deep Link using both the',
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'Testing for Sensitive Functionality Exposure Through IPC',
        "content": 'Overview¶\nTo test for sensitive functionality exposure through IPC mechanisms you should first enumerate all the IPC mechanisms the app uses and then try to identify whether sensitive data is leaked when the mechanisms are used.\n\nStatic Analysis¶\nWe start by looking at the AndroidManifest.xml, where all activities, services, and content providers included in the app must be declared (otherwise the system won\'t recognize them and they won\'t run).\n\n<intent-filter> ↗\n<service> ↗\n<provider> ↗\n<receiver> ↗\nAn "exported" activity, service, or content can be accessed by other apps. There are two common ways to designate a component as exported. The obvious one is setting the export tag to true android:exported="true". The second way involves defining an <intent-filter> within the component element (<activity>, <service>, <receiver>). When this is done, the export tag is automatically set to "true". To prevent all other Android apps from interacting with the IPC component element, be sure that the android:exported="true" value and an <intent-filter> aren\'t in their AndroidManifest.xml files unless this is necessary.\n\nRemember that using the permission tag (android:permission) will also limit other applications\' access to a component. If your IPC is intended to be accessible to other applications, you can apply a security policy with the <permission> element and set a proper android:protectionLevel. When android:permission is used in a service declaration, other applications must declare a corresponding <uses-permission> element in their own manifest to start, stop, or bind to the service.\n\nFor more information about the content providers, please refer to the test case "Testing Whether Stored Sensitive Data Is Exposed via IPC Mechanisms" in chapter "Testing Data Storage".\n\nOnce you identify a list of IPC mechanisms, review the source code to see whether sensitive data is leaked when the mechanisms are used. For example, content providers can be used to access database information, and services can be probed to see if they return data. Broadcast receivers can leak sensitive information if probed or sniffed.\n\nIn the following, we use two example apps and give examples of identifying vulnerable IPC components:\n\n"Sieve" ↗\n InsecureBankv2\nActivities¶\nInspect the AndroidManifest¶\nIn the "Sieve" app, we find three exported activities, identified by <activity>:\n\n\n<activity android:excludeFromRecents="true" android:label="@string/app_name" android:launchMode="singleTask" an',
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'Testing for Vulnerable Implementation of PendingIntent',
        "content": 'Overview¶\nWhen testing Pending Intents you must ensure that they are immutable and that the app explicitly specifies the exact package, action, and component that will receive the base intent.\n\nStatic Analysis¶\nTo identify vulnerable implementations, static analysis can be performed by looking for API calls used for obtaining a PendingIntent. Such APIs are listed below:\n\n\nPendingIntent getActivity(Context, int, Intent, int)\nPendingIntent getActivity(Context, int, Intent, int, Bundle)\nPendingIntent getActivities(Context, int, Intent, int, Bundle)\nPendingIntent getActivities(Context, int, Intent, int)\nPendingIntent getForegroundService(Context, int, Intent, int)\nPendingIntent getService(Context, int, Intent, int)\nOnce any of the above function is spotted, check the implementation of the base intent and the PendingIntent for the security pitfalls listed in the Pending Intents section.\n\nFor example, in A-156959408 ↗(CVE-2020-0389), the base intent is implicit and also the PendingIntent is mutable, thus making it exploitable.\n\n\nprivate Notification createSaveNotification(Uri uri) {\n    Intent viewIntent = new Intent(Intent.ACTION_VIEW)\n            .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_GRANT_READ_URI_PERMISSION)\n            .setDataAndType(uri, "video/mp4"); //Implicit Intent\n\n//... skip ...\n\n\nNotification.Builder builder = new Notification.Builder(this, CHANNEL_ID)\n                .setSmallIcon(R.drawable.ic_android)\n                .setContentTitle(getResources().getString(R.string.screenrecord_name))\n                .setContentText(getResources().getString(R.string.screenrecord_save_message))\n                .setContentIntent(PendingIntent.getActivity(\n                        this,\n                        REQUEST_CODE,\n                        viewIntent,\n                        Intent.FLAG_GRANT_READ_URI_PERMISSION))     // Mutable PendingIntent.\n                .addAction(shareAction)\n                .addAction(deleteAction)\n                .setAutoCancel(true);\nDynamic Analysis¶\nFrida can be used to hook the APIs used to get a PendingIntent. This information can be used to determine the code location of the call, which can be further used to perform static analysis as described above.\n\nHere\'s an example of such a Frida script that can be used to hook the PendingIntent.getActivity function:\n\n\nvar pendingIntent = Java.use(\'android.app.PendingIntent\');\n\nvar getActivity_1 = pendingIntent.getActivity.overload("android.content.Context", "int", "an',
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'Testing JavaScript Execution in WebViews',
        "content": 'Overview¶\nTo test for JavaScript execution in WebViews check the app for WebView usage and evaluate whether or not each WebView should allow JavaScript execution. If JavaScript execution is required for the app to function normally, then you need to ensure that the app follows the all best practices.\n\nStatic Analysis¶\nTo create and use a WebView, an app must create an instance of the WebView class.\n\n\nWebView webview = new WebView(this);\nsetContentView(webview);\nwebview.loadUrl("https://www.owasp.org/");\nVarious settings can be applied to the WebView (activating/deactivating JavaScript is one example). JavaScript is disabled by default for WebViews and must be explicitly enabled. Look for the method setJavaScriptEnabled ↗ to check for JavaScript activation.\n\n\nwebview.getSettings().setJavaScriptEnabled(true);\nThis allows the WebView to interpret JavaScript. It should be enabled only if necessary to reduce the attack surface to the app. If JavaScript is necessary, you should make sure that\n\nThe communication to the endpoints consistently relies on HTTPS (or other protocols that allow encryption) to protect HTML and JavaScript from tampering during transmission.\nJavaScript and HTML are loaded locally, from within the app data directory or from trusted web servers only.\nThe user cannot define which sources to load by means of loading different resources based on a user provided input.\nTo remove all JavaScript source code and locally stored data, clear the WebView\'s cache with clearCache ↗ when the app closes.\n\nDevices running platforms older than Android 4.4 (API level 19) use a version of WebKit that has several security issues. As a workaround, the app must confirm that WebView objects display only trusted content ↗ if the app runs on these devices.\n\nDynamic Analysis¶\nDynamic Analysis depends on operating conditions. There are several ways to inject JavaScript into an app\'s WebView:\n\nStored Cross-Site Scripting vulnerabilities in an endpoint; the exploit will be sent to the mobile app\'s WebView when the user navigates to the vulnerable function.\nAttacker takes a Machine-in-the-Middle (MITM) position and tampers with the response by injecting JavaScript.\nMalware tampering with local files that are loaded by the WebView.\nTo address these attack vectors, check the following:\n\nAll functions offered by the endpoint should be free of stored XSS ↗.\nOnly files that are in the app data directory should be rendered in a WebView (see test case "Testing for Local File In',
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'Testing WebView Protocol Handlers',
        "content": 'Overview¶\nTo test for WebView protocol handlers (or resource access) check the app for WebView usage and evaluate whether or not the WebView should have resource access. If resource access is necessary you need to verify that it\'s implemented following best practices.\n\nStatic Analysis¶\nCheck the source code for WebView usage. The following WebView settings ↗ control resource access:\n\nsetAllowContentAccess: Content URL access allows WebViews to load content from a content provider installed on the system, which is enabled by default .\nsetAllowFileAccess: Enables and disables file access within a WebView. The default value is true when targeting Android 10 (API level 29) and below and false for Android 11 (API level 30) and above. Note that this enables and disables file system access ↗ only. Asset and resource access is unaffected and accessible via file:///android_asset and file:///android_res.\nsetAllowFileAccessFromFileURLs: Does or does not allow JavaScript running in the context of a file scheme URL to access content from other file scheme URLs. The default value is true for Android 4.0.3 - 4.0.4 (API level 15) and below and false for Android 4.1 (API level 16) and above.\nsetAllowUniversalAccessFromFileURLs: Does or does not allow JavaScript running in the context of a file scheme URL to access content from any origin. The default value is true for Android 4.0.3 - 4.0.4 (API level 15) and below and false for Android 4.1 (API level 16) and above.\nIf one or more of the above methods is/are activated, you should determine whether the method(s) is/are really necessary for the app to work properly.\n\nIf a WebView instance can be identified, find out whether local files are loaded with the loadURL ↗ method.\n\n\nWebView = new WebView(this);\nwebView.loadUrl("file:///android_asset/filename.html");\nThe location from which the HTML file is loaded must be verified. If the file is loaded from external storage, for example, the file is readable and writable by everyone. This is considered a bad practice. Instead, the file should be placed in the app\'s assets directory.\n\n\nwebview.loadUrl("file:///" +\nEnvironment.getExternalStorageDirectory().getPath() +\n"filename.html");\nThe URL specified in loadURL should be checked for dynamic parameters that can be manipulated; their manipulation may lead to local file inclusion.\n\nUse the following code snippet and best practices ↗ to deactivate protocol handlers, if applicable:\n\n\n//If attackers can inject script into a WebView, they ',
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'Testing for Java Objects Exposed Through WebViews',
        "content": 'Overview¶\nTo test for Java objects exposed through WebViews check the app for WebViews having JavaScript enabled and determine whether the WebView is creating any JavaScript interfaces aka. "JavaScript Bridges". Finally, check whether an attacker could potentially inject malicious JavaScript code.\n\nStatic Analysis¶\nThe following example shows how addJavascriptInterface is used to bridge a Java Object and JavaScript in a WebView:\n\n\nWebView webview = new WebView(this);\nWebSettings webSettings = webview.getSettings();\nwebSettings.setJavaScriptEnabled(true);\n\nMSTG_ENV_008_JS_Interface jsInterface = new MSTG_ENV_008_JS_Interface(this);\n\nmyWebView.addJavascriptInterface(jsInterface, "Android");\nmyWebView.loadURL("http://example.com/file.html");\nsetContentView(myWebView);\nIn Android 4.2 (API level 17) and above, an annotation @JavascriptInterface explicitly allows JavaScript to access a Java method.\n\n\npublic class MSTG_ENV_008_JS_Interface {\n\n        Context mContext;\n\n        /** Instantiate the interface and set the context */\n        MSTG_ENV_005_JS_Interface(Context c) {\n            mContext = c;\n        }\n\n        @JavascriptInterface\n        public String returnString () {\n            return "Secret String";\n        }\n\n        /** Show a toast from the web page */\n        @JavascriptInterface\n        public void showToast(String toast) {\n            Toast.makeText(mContext, toast, Toast.LENGTH_SHORT).show();\n        }\n}\nThis is how you can call the method returnString from JavaScript, the string "Secret String" will be stored in the variable result:\n\n\nvar result = window.Android.returnString();\nWith access to the JavaScript code, via, for example, stored XSS or a MITM attack, an attacker can directly call the exposed Java methods.\n\nIf addJavascriptInterface is necessary, take the following considerations:\n\nOnly JavaScript provided with the APK should be allowed to use the bridges, e.g. by verifying the URL on each bridged Java method (via WebView.getUrl).\nNo JavaScript should be loaded from remote endpoints, e.g. by keeping page navigation within the app\'s domains and opening all other domains on the default browser (e.g. Chrome, Firefox).\nIf necessary for legacy reasons (e.g. having to support older devices), at least set the minimal API level to 17 in the manifest file of the app (<uses-sdk android:minSdkVersion="17" />).\nDynamic Analysis¶\nDynamic analysis of the app can show you which HTML or JavaScript files are loaded and which vulnerabilities are pres',
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'Testing for Overlay Attacks',
        "content": 'Overview¶\nTo test for overlay attacks you need to check the app for usage of certain APIs and attributed typically used to protect against overlay attacks as well as check the Android version that app is targeting.\n\nTo mitigate these attacks please carefully read the general guidelines about Android View security in the Android Developer Documentation ↗. For instance, the so-called touch filtering is a common defense against tapjacking, which contributes to safeguarding users against these vulnerabilities, usually in combination with other techniques and considerations as we introduce in this section.\n\nStatic Analysis¶\nTo start your static analysis you can check the app for the following methods and attributes (non-exhaustive list):\n\nOverride onFilterTouchEventForSecurity ↗ for more fine-grained control and to implement a custom security policy for views.\nSet the layout attribute android:filterTouchesWhenObscured ↗ to true or call setFilterTouchesWhenObscured ↗.\nCheck FLAG_WINDOW_IS_OBSCURED ↗ (since API level 9) or FLAG_WINDOW_IS_PARTIALLY_OBSCURED ↗ (starting on API level 29).\nSome attributes might affect the app as a whole, while others can be applied to specific components. The latter would be the case when, for example, there is a business need to specifically allow overlays while wanting to protect sensitive input UI elements. The developers might also take additional precautions to confirm the user\'s actual intent which might be legitimate and tell it apart from a potential attack.\n\nAs a final note, always remember to properly check the API level that app is targeting and the implications that this has. For instance, Android 8.0 (API level 26) introduced changes ↗ to apps requiring SYSTEM_ALERT_WINDOW ("draw on top"). From this API level on, apps using TYPE_APPLICATION_OVERLAY will be always shown above other windows ↗ having other types such as TYPE_SYSTEM_OVERLAY or TYPE_SYSTEM_ALERT. You can use this information to ensure that no overlay attacks may occur at least for this app in this concrete Android version.\n\nDynamic Analysis¶\nAbusing this kind of vulnerability on a dynamic manner can be pretty challenging and very specialized as it closely depends on the target Android version. For instance, for versions up to Android 7.0 (API level 24) you can use the following APKs as a proof of concept to identify the existence of the vulnerabilities.\n\nTapjacking POC ↗: This APK creates a simple overlay which sits on top of the testing application.\nInvisibl',
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'Testing WebViews Cleanup',
        "content": 'Overview¶\nTo test for WebViews cleanup you should inspect all APIs related to WebView data deletion and try to fully track the data deletion process.\n\nStatic Analysis¶\nStart by identifying the usage of the following WebView APIs and carefully validate the mentioned best practices.\n\nInitialization: an app might be initializing the WebView in a way to avoid storing certain information by using setDomStorageEnabled, setAppCacheEnabled or setDatabaseEnabled from android.webkit.WebSettings ↗. The DOM Storage (for using the HTML5 local storage), Application Caches and Database Storage APIs are disabled by default, but apps might set these settings explicitly to "true".\n\nCache: Android\'s WebView class offers the clearCache ↗ method which can be used to clear the cache for all WebViews used by the app. It receives a boolean input parameter (includeDiskFiles) which will wipe all stored resource including the RAM cache. However if it\'s set to false, it will only clear the RAM cache. Check the app for usage of the clearCache method and verify its input parameter. Additionally, you may also check if the app is overriding onRenderProcessUnresponsive for the case when the WebView might become unresponsive, as the clearCache method might also be called from there.\n\nWebStorage APIs: WebStorage.deleteAllData ↗ can be also used to clear all storage currently being used by the JavaScript storage APIs, including the Web SQL Database and the HTML5 Web Storage APIs.\n\nSome apps will need to enable the DOM storage in order to display some HTML5 sites that use local storage. This should be carefully investigated as this might contain sensitive data.\n\nCookies: any existing cookies can be deleted by using CookieManager.removeAllCookies ↗.\n\nFile APIs: proper data deletion in certain directories might not be that straightforward, some apps use a pragmatic solution which is to manually delete selected directories known to hold user data. This can be done using the java.io.File API such as java.io.File.deleteRecursively ↗.\n\nExample:\n\nThis example in Kotlin from the open source Firefox Focus ↗ app shows different cleanup steps:\n\n\noverride fun cleanup() {\n    clearFormData() // Removes the autocomplete popup from the currently focused form field, if present. Note this only affects the display of the autocomplete popup, it does not remove any saved form data from this WebView\'s store. To do that, use WebViewDatabase#clearFormData.\n    clearHistory()\n    clearMatches()\n    clearSslPreferenc',
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'References to Content Provider Access in WebViews',
        "content": 'Overview¶\nThis test checks for references to Content Provider access in WebViews, which is enabled by default and can be disabled using the setAllowContentAccess method in the WebSettings class. If improperly configured, this can introduce security risks such as unauthorized file access and data exfiltration.\n\nThe JavaScript code would have access to any content providers on the device, such as:\n\ndeclared by the app, even if they are not exported.\ndeclared by other apps, only if they are exported and if they are not following recommended best practices ↗ to restrict access.\nRefer to  WebViews for more information on the setAllowContentAccess method, the specific files that can be accessed, and the conditions under which they can be accessed.\n\nExample Attack Scenario:\n\nSuppose a banking app uses a WebView to display dynamic content. The developers have not explicitly set the setAllowContentAccess method, so it defaults to true. Additionally, JavaScript is enabled in the WebView, and the setAllowUniversalAccessFromFileURLs method is also used.\n\nAn attacker exploits a vulnerability (such as an XSS flaw) to inject malicious JavaScript into the WebView. This could occur through a compromised or malicious link that the WebView loads without proper validation.\nThanks to setAllowUniversalAccessFromFileURLs(true), the malicious JavaScript can issue requests to content:// URIs to read locally stored files or data exposed by content providers. Even those content providers in the app that are not exported can be accessed because the malicious code runs in the same process and origin as the trusted code.\nThe attacker-controlled script exfiltrates sensitive data from the device to an external server.\nNote 1: We do not consider minSdkVersion since setAllowContentAccess defaults to true regardless of the Android version.\n\nNote 2: The provider\'s android:grantUriPermissions attribute is irrelevant in this scenario as it does not affect the app itself accessing its own content providers. It allows other apps to temporarily access URIs from the provider even though restrictions such as permission attributes, or android:exported="false" are set. Also, if the app uses a FileProvider, the android:grantUriPermissions attribute must be set to true by definition ↗ (otherwise you\'ll get a SecurityException: Provider must grant uri permissions").\n\nNote 3: allowUniversalAccessFromFileURLs is critical in the attack since it relaxes the default restrictions, allowing pages loaded from f',
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'Runtime Use of Content Provider Access APIs in WebViews',
        "content": 'Overview¶\nThis test is the dynamic counterpart to  References to Content Provider Access in WebViews.\n\nIn this case you can take two approaches when hooking or tracing the relevant APIs:\n\nenumerate instances of WebView in the app and list their configuration values.\nor, explicitly hook the setters of the WebView settings.\nSteps¶\nUse  Installing Apps to install the app.\nUse  Method Hooking to hook the relevant API calls.\nExercise the app extensively to trigger as many flows as possible and enter sensitive data wherever you can.\nObservation¶\nThe output should contain a list of WebView setting calls, including the argument values and backtraces of each call.\n\nEvaluation¶\nThe test case fails if all the following applies:\n\nJavaScriptEnabled is true.\nAllowContentAccess is true.\nAllowUniversalAccessFromFileURLs is true.\nFurther Validation Required:\n\nUsing the backtraces from the hook output, inspect the code locations using  Reviewing Decompiled Java Code:\n\nDetermine whether the settings are explicitly used and configured to the identified values.\nDetermine which WebView instance receives the configuration and whether it handles sensitive information or functionality.\nDetermine whether the WebView loads content in a context where content provider data could be accessed via content:// URLs.\nFor the identified WebViews, determine whether attacker-controlled JavaScript could execute in a context where it can access content providers that handle sensitive data. Also use the list of content providers obtained in  References to Content Provider Access in WebViews to verify if they handle sensitive data.\n\nNote\n\nAllowContentAccess being true does not represent a security vulnerability by itself, but it can be used in combination with other vulnerabilities to escalate the impact of an attack.\n\nBest Practices¶\n MASTG-BEST-0011: Securely Load File Content in a WebView =https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0011/\n MASTG-BEST-0012: Disable JavaScript in WebViews = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0012/\n MASTG-BEST-0013: Disable Content Provider Access in WebViews = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0013/\n MASTG-BEST-0049: Restrict and Validate Access to Exported Content Providers = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0049/\n\nDemos¶\n MASTG-DEMO-0030: Uses of WebViews Allowing Content Access with Frida = https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0030/MASTG-DEMO-0030/',
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'References to Local File Access in WebViews',
        "content": "Overview¶\nThis test checks for references to methods from the WebSettings ↗ class used by Android WebViews which enable loading content from various sources, including local files. If improperly configured, these methods can introduce security risks such as unauthorized file access and data exfiltration. These methods are:\n\nsetAllowFileAccess: allows the WebView to load local files from the app's internal storage or external storage.\nsetAllowFileAccessFromFileURLs: lets JavaScript within those local files access other local files.\nsetAllowUniversalAccessFromFileURLs: removes any cross-origin restrictions, allowing JavaScript to read data across origins. The JavaScript can always send data to any origin (e.g., via POST), regardless of this setting; this setting only affects reading data (e.g., the code wouldn't get a response to a POST request, but the data would still be sent).\nWhen these settings are combined, they can enable an attack in which a malicious HTML file gains elevated privileges, accesses local resources, and exfiltrates data over the network, effectively bypassing the security boundaries typically enforced by the same-origin policy.\n\nEven though these methods have secure defaults and are deprecated in Android 10 (API level 29) and later, they can still be explicitly set to true or their insecure defaults may be used in apps that run on older versions of Android (due to their minSdkVersion).\n\nRefer to Android WebView Local File Access Settings for more information on these methods (default values, deprecation status, security implications), the specific files that can be accessed, and the conditions under which they can be accessed.\n\nExample Attack Scenario:\n\nSuppose a banking app uses a WebView to display dynamic content, and the developers have enabled all three insecure settings. Additionally, JavaScript is enabled in the WebView.\n\nAn attacker injects a malicious HTML file into the device (via phishing or another exploit) into a location that the attacker knows the WebView will access it from (e.g. thanks to reverse engineering). For example, an HTML file is used to display the app's terms and conditions.\nThe WebView can load the malicious file because of setAllowFileAccess(true).\nThanks to setJavaScriptEnabled(true) and setAllowFileAccessFromFileURLs(true), the JavaScript in the malicious file (running in a file:// context) is able to access other local files using file:// URLs.\nThe attacker-controlled script exfiltrates sensitive data fr",
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'Runtime Use of Local File Access APIs in WebViews',
        "content": 'Overview¶\nThis test is the dynamic counterpart to  References to Local File Access in WebViews.\n\nIn this case you can follow one of these approaches:\n\nenumerate instances of WebView in the app and list their configuration values\nor explicitly hook the setters of the WebView settings, including:\nsetJavaScriptEnabled\nsetAllowFileAccess\nsetAllowFileAccessFromFileURLs\nsetAllowUniversalAccessFromFileURLs\nSteps¶\nUse  Installing Apps to install the app.\nUse  Method Hooking to hook the relevant API calls.\nExercise the app extensively to trigger as many flows as possible and enter sensitive data wherever you can.\nObservation¶\nThe output should contain a list of WebView setting calls, including the argument values and backtraces of each call.\n\nEvaluation¶\nThe test case fails if all of the following applies (based on the API behavior across different Android versions):\n\nsetJavaScriptEnabled is explicitly set to true.\nsetAllowFileAccess is explicitly set to true (or not used at all when minSdkVersion < 30, inheriting the default value, true).\nEither setAllowFileAccessFromFileURLs or setAllowUniversalAccessFromFileURLs is explicitly set to true (or not used at all when minSdkVersion < 16, inheriting the default value, true).\nFurther Validation Required:\n\nUsing the backtraces from the hook output, inspect the code locations using  Reviewing Decompiled Java Code:\n\nDetermine whether the settings are explicitly used and configured to the identified values.\nDetermine which WebView instance receives the configuration and whether it handles sensitive information or functionality.\nDetermine whether that WebView loads local file:// content, for example via loadUrl("file://...") or loadDataWithBaseURL with a file:// base URL.\nFor the identified WebViews, determine whether attacker-controlled JavaScript could execute in the local file context, for example through HTML injection, JavaScript injection, or other untrusted content. Also determine whether the attacker could exfiltrate local files or other sensitive data accessible via file:// URLs.\n\nNote\n\nAllowFileAccess being true does not represent a security vulnerability by itself, but it can be used in combination with other vulnerabilities to escalate the impact of an attack.\n\nBest Practices¶\n MASTG-BEST-0010: Use Up-to-Date minSdkVersion = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0010/\n MASTG-BEST-0011: Securely Load File Content in a WebView = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0011/\n MASTG-BEST',
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'References to Keyboard Caching Attributes in UI Elements',
        "content": 'Overview¶\nThis test verifies that the app appropriately configures text input fields to prevent the keyboard from caching sensitive information, such as passwords or personal data.\n\nAndroid apps can configure the behavior of text input fields using:\n\nFrom layout files within the res/layout directory:\nUsing the android:inputType XML attributes.\nProgrammatically in the code:\nBy calling the setInputType method on input fields and passing appropriate input type values.\nIn Jetpack Compose, by using the KeyboardOptions constructors ↗ and setting the keyboardType and autoCorrect parameters.\nSee section "Non-Caching Input Types" in  Keyboard Cache for more details on the input types that prevent keyboard caching of sensitive information.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nUse  Exploring the App Package to extract the layout files from the app package.\nObservation¶\nThe output should include:\n\nAll android:inputType XML attributes, if using XML for the UI.\nAll calls to the setInputType method and the input type values passed to it.\nEvaluation¶\nThe test case fails if there are any fields handling sensitive data for which the app does not use non-caching input types.\n\nBest Practices¶\n MASTG-BEST-0019: Use Non-Caching Input Types for Sensitive Fields = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0019/\n\nDemos¶\n MASTG-DEMO-0064: Uses of Caching UI Elements with semgrep = https://mas.owasp.org/MASTG/demos/android/MASVS-STORAGE/MASTG-DEMO-0064/MASTG-DEMO-0064/',
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding',
        "content": 'Overview¶\nThis test verifies that the app hides sensitive content from the screen when it moves to the background. This is important because Android captures a task screenshot of the app UI when it moves to the background. This screenshot is used for the Recents screen ↗ and transitions, and can expose sensitive content if the app does not protect it.\n\nSteps¶\nExercise your app until you get to each of the screens identified as sensitive. While on each of those screens, move the app to the background (for example by pressing Home or opening the Recents screen and exiting it) and continue to the next screen.\nUse  Host-Device Data Transfer to copy the screenshots taken by the system to your laptop for further analysis. The system stores the screenshots in their containers /data/system_ce/0/snapshots or /data/system.\nObservation¶\nThe output should include a collection of screenshots cached when the app entered the background state.\n\nEvaluation¶\nThe test case fails if any screenshot displays sensitive data that should have been protected.\n\nFurther Validation Required:\n\nInspect each screenshot visually, looking for sensitive information such as passwords, tokens, personally identifiable information, or other sensitive content that should not be exposed when the app is in the background.\n\nBest Practices¶\n MASTG-BEST-0014: Preventing Screenshots and Screen Recording = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0014/',
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'References to Screen Capturing Prevention APIs',
        "content": 'Overview¶\nThis test verifies whether an app references Android screen capture prevention APIs. On Android, developers can prevent screenshots and nonsecure display mirroring using FLAG_SECURE ↗. When set, Android blocks screenshots and prevents content from appearing on a nonsecure display, including remote screen sharing. Users see a blank screen if they attempt a screenshot or when the app moves to the background.\n\nDevelopers typically apply the flag with addFlags() ↗ or setFlags() ↗. Common failure modes include not setting FLAG_SECURE on all sensitive screens or clearing the flag during transitions e.g., using clearFlags() ↗ or setFlags().\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should include a list of locations where the relevant APIs are used.\n\nEvaluation¶\nThe test case fails if the relevant APIs are missing or inconsistently applied on any UI component that displays sensitive data, or if code paths clear the protection without an adequate justification.\n\nBest Practices¶\n MASTG-BEST-0014: Preventing Screenshots and Screen Recording = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0014/\n\nDemos¶\n MASTG-DEMO-0061: Uses of FLAG_SECURE with semgrep = https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0061/MASTG-DEMO-0061/',
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'Sensitive Data Exposed via Notifications',
        "content": "Overview¶\nThis test verifies that the app correctly handles notifications, ensuring that sensitive information, such as personally identifiable information (PII), one-time passwords (OTPs), or other sensitive data, like health or financial details, is not exposed.\n\nOn Android 13 and higher, apps targeting API level 33 or above must request the runtime permission POST_NOTIFICATIONS ↗ to send notifications. Below API level 33, this permission is not required. For testing purposes, we consider the value of the app's minSdkVersion because it indicates the lowest Android version on which the app can run.\n\nNotifications can be created using the setContentTitle ↗ and setContentText ↗ methods of Notification.Builder ↗ or NotificationCompat.Builder ↗.\n\nNotification usage should not expose sensitive information that could be disclosed accidentally, e.g., through shoulder surfing or when sharing the device with another person.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nUse  Obtaining Information from the AndroidManifest to obtain the AndroidManifest.xml.\nUse  Analyzing the AndroidManifest to obtain the minSdkVersion from the AndroidManifest.xml file.\nUse  Obtaining App Permissions to obtain the relevant permissions.\nObservation¶\nThe output should contain:\n\nthe POST_NOTIFICATIONS permission, if declared,\nthe value of minSdkVersion, and\na list of locations where notification APIs are used.\nEvaluation¶\nThe test case fails if the app exposes any sensitive data in any notifications and either:\n\nminSdkVersion is 33 or higher and the POST_NOTIFICATIONS permission is declared in the manifest file, or\nminSdkVersion is 32 or lower, regardless of whether the POST_NOTIFICATIONS permission is declared.\nWhy minSdkVersion and not targetSdkVersion?: Using minSdkVersion ensures the test accounts for the least secure environment in which the app can operate, which is what determines the real exposure risk.\n\ntargetSdkVersion only influences how the app behaves on newer Android versions and how the system enforces newer platform restrictions. It does not change the behavior of older Android versions. As a result, an app with a high targetSdkVersion but a low minSdkVersion must still be evaluated against the security guarantees, or lack thereof, of those older versions.\n\nBest Practices¶\n MASTG-BEST-0027: Preventing Sensitive Data Exposure in Notifications - https://mas.owasp.org/MASTG/best-prac",
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'App Exposing User Authentication Data in Text Input Fields',
        "content": 'Overview¶\nThis test verifies that the app handles user input correctly, ensuring that access codes (passwords or pins) and verification codes (OTPs) are not exposed in plain text within text input fields.\n\nProper masking (e.g., dots instead of input characters) of these codes is essential to protect user privacy. This can be achieved by using appropriate input types that obscure the characters entered by the user. In Jetpack Compose, SecureTextField uses TextObfuscationMode, which by default is TextObfuscationMode.RevealLastTyped ↗, so a developer can simply use SecureTextField without explicitly setting textObfuscationMode unless another behavior is required.\n\nXML view:\n\n\n<EditText\n    android:inputType="textPassword"\n    ...\n/>\nJetpack Compose:\n\n\nSecureTextField(\n    // textObfuscationMode defaults to TextObfuscationMode.RevealLastTyped\n    textObfuscationMode = TextObfuscationMode.RevealLastTyped, // or TextObfuscationMode.Hidden\n    ...\n)\nNote\n\nEven if SecureTextField uses the default TextObfuscationMode.RevealLastTyped or is configured explicitly with RevealLastTyped or Hidden, it can later be changed to Visible programmatically.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should contain a list of locations where text input fields for access or verification codes are used.\n\nEvaluation¶\nThe test case fails if any text input field used for access or verification codes is found to be unmasked. For example, due to the following:\n\nTextField is used\nSecureTextField is used but configured with TextObfuscationMode.Visible\nFurther Validation Required:\n\nSince determining which fields handle access or verification codes is context-dependent, inspect each reported code location using  Reviewing Decompiled Java Code to determine whether the field handles sensitive data and whether it is properly masked.\n\nExpected False Negatives:\n\nThis test may produce false negatives if the app uses custom text input controls that do not rely on standard classes such as TextField or SecureTextField (for example in custom UI frameworks or game engines).\n\nDemos¶\n MASTG-DEMO-0079: App Exposing Access and Verification Codes in Text Input Fields = https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0079/MASTG-DEMO-0079/',
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'WebViews Not Cleaning Up Sensitive Data',
        "content": 'Overview¶\nThis test verifies whether the app cleans up sensitive data used by WebViews. Apps can enable several specific storage areas in their WebViews and not clean them up properly, leading to sensitive data being stored on the device longer than necessary. For example:\n\nNot calling WebView.clearCache(includeDiskFiles = true) ↗ when:\nWebSettings.setAppCacheEnabled() is enabled,\nor WebSettings.setCacheMode() ↗ is any value other than WebSettings.LOAD_NO_CACHE ↗.\nNot calling WebStorage.deleteAllData() ↗ when:\nWebSettings.setDomStorageEnabled ↗ is enabled.\nNot calling WebStorage.deleteAllData() ↗ when:\nWebSettings.setDatabaseEnabled() ↗ is enabled.\nNot calling CookieManager.removeAllCookies(ValueCallback<Boolean> ...) ↗ when:\nCookieManager.setAcceptCookie() ↗ is not explicitly set to false (default is set to true).\nThis test uses dynamic analysis to monitor the relevant API calls and file system operations. Regardless of whether the app uses these APIs directly, WebViews may use them internally when rendering content (e.g., JavaScript code using localStorage). So tracing calls to APIs such as open, openat, opendir, unlinkat, etc., can help identify file operations in the WebView storage directory.\n\nWhen exercising the app, make sure to keep a list of the sensitive data you expect to be cleaned up, so you can verify whether it is still present in the WebView storage directory after closing the app.\n\nSteps¶\nUse  Installing Apps to install the app.\nUse  Method Hooking to hook the relevant API calls.\nExercise the app extensively to trigger as many flows as possible and enter sensitive data wherever you can.\nClose the app.\nUse  Host-Device Data Transfer to pull the contents of the /data/data/<app_package>/app_webview/ directory or simply search for the sensitive data used in the WebView within that directory.\nObservation¶\nThe output should include:\n\nThe list of WebView storage enablement APIs used.\nThe list of WebView storage cleanup APIs used.\nThe list of sensitive data expected to be cleaned up.\nThe result of searching the contents of the /data/data/<app_package>/app_webview/ directory for the sensitive data used in the WebView after closing the app.\nEvaluation¶\nThe test case fails if the app still has sensitive data on the /data/data/<app_package>/app_webview/ directory after the app is closed. This could be due to the app not calling the relevant cleanup APIs after using the WebView.\n\nNote\n\nIt can be challenging to determine whether the right cleanup APIs w',
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'References to Overlay Attack Protections',
        "content": 'Overview¶\nOverlay attacks (also known as tapjacking) allow malicious apps to place deceptive UI elements over a legitimate app\'s interface, potentially tricking users into performing unintended actions such as granting permissions, revealing credentials, or authorizing payments. If the app does not implement appropriate protections, users can interact with overlaid malicious content while believing they are interacting with the legitimate app.\n\nAndroid provides several mechanisms to protect against overlay attacks through touch filtering. These mechanisms can detect when a view is obscured and filter touch events accordingly. However, if the app does not use these protections on sensitive UI elements, it remains vulnerable to overlay attacks.\n\nThis test checks whether the app implements overlay attack protections by looking for references to touch filtering APIs and attributes that prevent interaction when views are obscured.\n\nThese include:\n\nThe setFilterTouchesWhenObscured method.\nThe android:filterTouchesWhenObscured attribute in layout files.\nThe onFilterTouchEventForSecurity method.\nChecks for FLAG_WINDOW_IS_OBSCURED or FLAG_WINDOW_IS_PARTIALLY_OBSCURED flags.\nThe setHideOverlayWindows ↗ method and the required HIDE_OVERLAY_WINDOWS permission for API level 31 and above.\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nUse  Obtaining Information from the AndroidManifest to obtain the AndroidManifest.xml.\nUse  Analyzing the AndroidManifest to obtain the targetSdkVersion from the AndroidManifest.xml file.\nUse  Obtaining App Permissions to obtain the relevant permissions.\nObservation¶\nThe output should contain:\n\nA list of locations where overlay protection mechanisms are used\nThe app\'s targetSdkVersion\nAny relevant permissions, such as HIDE_OVERLAY_WINDOWS\nEvaluation¶\nThe test fails if the app handles sensitive user interactions (such as login, payment confirmation, permission requests, or security settings) and does not implement any overlay attack protections on those sensitive UI elements.\n\nFor example:\n\nThe app doesn\'t implement setFilterTouchesWhenObscured(true) or android:filterTouchesWhenObscured="true" on sensitive UI elements.\nThe app doesn\'t override onFilterTouchEventForSecurity to implement custom security policies.\nThe app doesn\'t check for FLAG_WINDOW_IS_OBSCURED or FLAG_WINDOW_IS_PARTIALLY_OBSCURED in touch event handlers for sensitive interactions.\nThe ',
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'References to Unauthorized Database Access through Content Providers',
        "content": 'Overview¶\nThis test checks whether the app exposes content providers that can be accessed by other apps without appropriate permission enforcement. Specifically, it verifies whether exported <provider> elements in the AndroidManifest.xml enforce access control via android:readPermission and android:writePermission ↗ (or the combined android:permission). If a content provider is exported (android:exported="true") without these permissions, any app on the device can query the underlying database to retrieve sensitive data such as user PII, account details, or internal app configurations.\n\nThe same applies when no protection level is configured and becomes automatically android:protectionLevel="normal", which is granting access automatically to any requesting app.\n\nExample Attack Scenario:\n\nSuppose a health app exposes a content provider backed by a database of medical records, and the <provider> element in the AndroidManifest declares no android:readPermission.\n\nAn attacker reverse engineers the app and finds an exported <provider> element in the AndroidManifest with no permission restrictions.\nThe manifest shows the provider\'s authority and no declared read or write permission.\nBecause no permission guards the provider, any app on the device can call ContentResolver.query() against it and retrieve the underlying data without any user interaction.\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Obtaining Information from the AndroidManifest to obtain the AndroidManifest.xml.\nUse  Analyzing the AndroidManifest to identify exported content providers and check their permission configuration.\nObservation¶\nThe output should contain a list of exported <provider> elements from the AndroidManifest, including their declared read and write permission attributes.\n\nEvaluation¶\nThe test case fails if one or more content providers are exported (android:exported="true") without declaring android:readPermission, android:writePermission, or android:permission.\n\nFurther Validation Required:\n\nInspect the permission configuration of each reported provider to determine whether the enforced permission provides adequate protection:\n\nDetermine whether the declared permission uses android:protectionLevel="normal" or android:protectionLevel="dangerous", which does not guarantee that only trusted apps can access the provider.\nDetermine whether the data exposed through the provider is sensitive.\nBest Practices¶\n MASTG-BEST-0049: Restrict and Validate Acce',
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'Runtime Verification of Unauthorized Database Access through Content Providers',
        "content": 'Overview¶\nIf an app exports a content provider without requiring permissions, any app on the device can directly query its underlying database using ContentResolver ↗ or using the adb shell content command. Even when a permission is declared, a misconfigured protection level (for example, android:protectionLevel="normal") allows any requesting app to obtain it automatically, effectively bypassing the restriction. This test verifies at runtime whether the app\'s exported content providers are accessible without the required permissions.\n\nExample Attack Scenario:\n\nSuppose a health app stores medical records in a database exposed through an exported content provider with no declared android:readPermission and protection level.\n\nAn attacker identifies the exported provider\'s authority from the AndroidManifest.\nThe attacker uses adb shell content query to query the provider\'s URI without any restrictions.\nThe content provider returns all database rows without checking the caller\'s identity.\nThe attacker reads PII or medical information directly from the app.\nWith this knowledge the attacker crafts a malicious app by using ContentResolver and trying to lure potential victims into side-loading the app on their device.\nWhen a victim is installing the malicious app it will query for the data and sent it to the attackers server.\nSteps¶\nUse  Installing Apps to install the app.\nExercise the app extensively to trigger as many flows as possible and enter sensitive data wherever you can.\nUse  Interacting with Android ContentProviders to query the app\'s exported content providers.\nObservation¶\nThe output should contain the content of the database that is available through the content provider.\n\nEvaluation¶\nThe test case fails if sensitive data can be accessed through content providers.\n\nFurther Validation Required:\n\nInspect the content of each row returned by the query to determine whether the data is sensitive:\n\nDetermine whether the records contain sensitive information (e.g., personal data, credentials, tokens, or health data).\nDetermine whether the accessible data represents a security risk given the app\'s data classification.\nBest Practices¶\n MASTG-BEST-0049: Restrict and Validate Access to Exported Content Providers = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0049/\n\nDemos¶\n MASTG-DEMO-0121: Unauthorized Access to Database Records through Exported Content Provider = https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0121/MASTG-DEMO-0121/',
    },
    {
        "section": 'Platform',
        "level":   'L1',
        "name":    'References to Oversharing of File-Based Content Providers',
        "content": 'Overview¶\nIf the app exports an Android content provider without enforcing access restrictions, external callers may open private files through content:// URIs. This test checks whether exported providers expose sensitive stored data to callers that don\'t hold the required permissions.\n\nExample Attack Scenario:\n\nSuppose an app exports a FileProvider with a files-path element using path=".", exposing the entire internal filesDir.\n\nAn attacker reverse engineers the app and finds the exported FileProvider authority and a files-path entry with path=".", which maps the entire internal filesDir into the provider\'s shareable root.\nThe attacker identifies an exported component in the victim app (e.g. an Activity or Service) that accepts a filename or path from the caller and uses it to build a URI via FileProvider.getUriForFile(context, authority, new File(filesDir, attackerInput)).\nThe attacker crafts a malicious app that invokes that component with a traversal payload such as ../databases/auth.db, causing the victim app to construct a content:// URI pointing outside the intended shared subdirectory and return it with FLAG_GRANT_READ_URI_PERMISSION.\nThe malicious app calls ContentResolver.openInputStream() on the returned content:// URI to access any file under filesDir, including sensitive files such as tokens or private databases.\nThe FileProvider serves the file without restricting which paths are accessible, exposing data beyond the intended shared directory.\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Verify Usage of File-Based Content Providers to identify exported file-based content providers and inspect their path configurations.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should contain a list of exported file-based content providers with their path configurations, and a list of code locations where provider-backed file access occurs.\n\nEvaluation¶\nThe test case fails if the app exports a FileProvider and if the provider\'s path configuration allows access outside the intended shared directory (for example, via <root-path>, path="/", path=".", or path="").\n\nFurther Validation Required:\n\nInspect each reported code location using  Reviewing Decompiled Java Code to determine whether the exposure is security-relevant:\n\nDetermine whether FileProvider.getUriForFile() is called with attacker-controlled input (for example, values derived from URI query parameters or user input).\nDetermin',
    },
    {
        "section": 'CODE QUALITY & BUILD SETTINGS',
        "level":   'L1',
        "name":    'Testing Local Storage for Input Validation',
        "content": 'Overview¶\nFor any publicly accessible data storage, any process can override the data. This means that input validation needs to be applied the moment the data is read back again.\n\nNote\n\nThe same is true for private accessible data on a rooted device\n\nStatic analysis¶\nUsing Shared Preferences¶\nWhen you use the SharedPreferences.Editor to read or write int/boolean/long values, you cannot check whether the data is overridden or not. However: it can hardly be used for actual attacks other than chaining the values (e.g. no additional exploits can be packed which will take over the control flow). In the case of a String or a StringSet you should be careful with how the data is interpreted. Using reflection based persistence? Check the section on "Testing Object Persistence" for Android to see how it should be validated. Using the SharedPreferences.Editor to store and read certificates or keys? Make sure you have patched your security provider given vulnerabilities such as found in Bouncy Castle ↗.\n\nIn all cases, having the content HMACed can help to ensure that no additions and/or changes have been applied.\n\nUsing Other Storage Mechanisms¶\nIn case other public storage mechanisms (than the SharedPreferences.Editor) are used, the data needs to be validated the moment it is read from the storage mechanism.',
    },
    {
        "section": 'CODE QUALITY & BUILD SETTINGS',
        "level":   'L1',
        "name":    'Testing for Injection Flaws',
        "content": 'Overview¶\nTo test for injection flaws you need to first rely on other tests and check for functionality that might have been exposed:\n\n Testing Deep Links\n Testing for Sensitive Functionality Exposure Through IPC\n Testing for Overlay Attacks\nStatic Analysis¶\nAn example of a vulnerable IPC mechanism is shown below.\n\nYou can use ContentProviders to access database information, and you can probe services to see if they return data. If data is not validated properly, the content provider may be prone to SQL injection while other apps are interacting with it. See the following vulnerable implementation of a ContentProvider.\n\n\n<provider\n    android:name=".OMTG_CODING_003_SQL_Injection_Content_Provider_Implementation"\n    android:authorities="sg.vp.owasp_mobile.provider.College">\n</provider>\nThe AndroidManifest.xml above defines a content provider that\'s exported and therefore available to all other apps. The query function in the OMTG_CODING_003_SQL_Injection_Content_Provider_Implementation.java class should be inspected.\n\n\n@Override\npublic Cursor query(Uri uri, String[] projection, String selection,String[] selectionArgs, String sortOrder) {\n    SQLiteQueryBuilder qb = new SQLiteQueryBuilder();\n    qb.setTables(STUDENTS_TABLE_NAME);\n\n    switch (uriMatcher.match(uri)) {\n        case STUDENTS:\n            qb.setProjectionMap(STUDENTS_PROJECTION_MAP);\n            break;\n\n        case STUDENT_ID:\n            // SQL Injection when providing an ID\n            qb.appendWhere( _ID + "=" + uri.getPathSegments().get(1));\n            Log.e("appendWhere",uri.getPathSegments().get(1).toString());\n            break;\n\n        default:\n            throw new IllegalArgumentException("Unknown URI " + uri);\n    }\n\n    if (sortOrder == null || sortOrder == ""){\n        /**\n         * By default sort on student names\n         */\n        sortOrder = NAME;\n    }\n    Cursor c = qb.query(db, projection, selection, selectionArgs,null, null, sortOrder);\n\n    /**\n     * register to watch a content URI for changes\n     */\n    c.setNotificationUri(getContext().getContentResolver(), uri);\n    return c;\n}\nWhile the user is providing a STUDENT_ID at content://sg.vp.owasp_mobile.provider.College/students, the query statement is prone to SQL injection. Obviously prepared statements ↗ must be used to avoid SQL injection, but input validation ↗ should also be applied so that only input that the app is expecting is processed.\n\nAll app functions that process data coming in through the UI should imp',
    },
    {
        "section": 'CODE QUALITY & BUILD SETTINGS',
        "level":   'L1',
        "name":    'Testing Implicit Intents',
        "content": 'Overview¶\nWhen testing for implicit intents you need to check if they are vulnerable to injection attacks or potentially leaking sensitive data.\n\nStatic Analysis¶\nInspect the Android Manifest and look for any <intent> signatures defined inside blocks ↗ (which specify the set of other apps an app intends to interact with), check if it contains any system actions (e.g. android.intent.action.GET_CONTENT, android.intent.action.PICK, android.media.action.IMAGE_CAPTURE, etc.) and browse the source code for their occurrence.\n\nFor example, the following Intent doesn\'t specify any concrete component, meaning that it\'s an implicit intent. It sets the action android.intent.action.GET_CONTENT to ask the user for input data and then the app starts the intent by startActivityForResult and specifying an image chooser.\n\n\nIntent intent = new Intent();\nintent.setAction("android.intent.action.GET_CONTENT");\nstartActivityForResult(Intent.createChooser(intent, ""), REQUEST_IMAGE);\nThe app uses startActivityForResult instead of startActivity, indicating that it expects a result (in this case an image), so you should check how the return value of the intent is handled by looking for the onActivityResult callback. If the return value of the intent isn\'t properly validated, an attacker may be able to read arbitrary files or execute arbitrary code from the app\'s internal `/data/data/\' storage. A full description of this type of attack can be found in the following blog post ↗.\n\nCase 1: Arbitrary File Read¶\nIn this example we\'re going to see how an attacker can read arbitrary files from within the app\'s internal storage /data/data/<appname> due to the improper validation of the return value of the intent.\n\nThe performAction method in the following example reads the implicit intents return value, which can be an attacker provided URI and hands it to getFileItemFromUri. This method copies the file to a temp folder, which is usual if this file is displayed internally. But if the app stores the URI provided file in an external temp directory e.g by calling getExternalCacheDir or getExternalFilesDir an attacker can read this file after setting the permission android.permission.READ_EXTERNAL_STORAGE.\n\n\nprivate void performAction(Action action){\n  ...\n  Uri data = intent.getData();\n  if (!(data == null || (fileItemFromUri = getFileItemFromUri(data)) == null)) {\n      ...\n  }\n}\n\nprivate FileItem getFileItemFromUri(Context, context, Uri uri){\n  String fileName = UriExtensions.getFileName(uri',
    },
    {
        "section": 'CODE QUALITY & BUILD SETTINGS',
        "level":   'L1',
        "name":    'Testing for URL Loading in WebViews',
        "content": 'Overview¶\nIn order to test for URL loading in WebViews you need to carefully analyze handling page navigation ↗, especially when users might be able to navigate away from a trusted environment. The default and safest behavior on Android is to let the default web browser open any link that the user might click inside the WebView. However, this default logic can be modified by configuring a WebViewClient which allows navigation requests to be handled by the app itself.\n\nStatic Analysis¶\nCheck for Page Navigation Handling Override¶\nTo test if the app is overriding the default page navigation logic by configuring a WebViewClient you should search for and inspect the following interception callback functions:\n\nshouldOverrideUrlLoading allows your application to either abort loading WebViews with suspicious content by returning true or allow the WebView to load the URL by returning false. Considerations:\nThis method is not called for POST requests.\nThis method is not called for XmlHttpRequests, iFrames, "src" attributes included in HTML or <script> tags. Instead, shouldInterceptRequest should take care of this.\nshouldInterceptRequest allows the application to return the data from resource requests. If the return value is null, the WebView will continue to load the resource as usual. Otherwise, the data returned by the shouldInterceptRequest method is used. Considerations:\nThis callback is invoked for a variety of URL schemes (e.g., http(s):, data:, file:, etc.), not only those schemes which send requests over the network.\nThis is not called for javascript: or blob: URLs, or for assets accessed via file:///android_asset/ or file:///android_res/ URLs. In the case of redirects, this is only called for the initial resource URL, not any subsequent redirect URLs.\nWhen Safe Browsing is enabled, these URLs still undergo Safe Browsing checks but the developer can allow the URL with setSafeBrowsingWhitelist or even ignore the warning via the onSafeBrowsingHit callback.\nAs you can see there are a lot of points to consider when testing the security of WebViews that have a WebViewClient configured, so be sure to carefully read and understand all of them by checking the WebViewClient Documentation ↗.\n\nCheck for EnableSafeBrowsing Disabled¶\nWhile the default value of EnableSafeBrowsing is true, some applications might opt to disable it. To verify that SafeBrowsing is enabled, inspect the AndroidManifest.xml file and make sure that the configuration below is not present:\n\n\n<man',
    },
    {
        "section": 'CODE QUALITY & BUILD SETTINGS',
        "level":   'L1',
        "name":    'Testing Object Persistence',
        "content": 'Overview¶\nTo test for object persistence being used for storing sensitive information on the device, first identify all instances of object serialization and check if they carry any sensitive data. If yes, check if it is properly protected against eavesdropping or unauthorized modification.\n\nThere are a few generic remediation steps that you can always take:\n\nMake sure that sensitive data has been encrypted and HMACed/signed after serialization/persistence. Evaluate the signature or HMAC before you use the data. See the chapter "Android Cryptographic APIs" for more details.\nMake sure that the keys used in step 1 can\'t be extracted easily. The user and/or application instance should be properly authenticated/authorized to obtain the keys. See the chapter "Data Storage on Android" for more details.\nMake sure that the data within the de-serialized object is carefully validated before it is actively used (e.g., no exploit of business/application logic).\nFor high-risk applications that focus on availability, we recommend that you use Serializable only when the serialized classes are stable. Second, we recommend not using reflection-based persistence because\n\nthe attacker could find the method\'s signature via the String-based argument\nthe attacker might be able to manipulate the reflection-based steps to execute business logic.\nStatic Analysis¶\nObject Serialization¶\nSearch the source code for the following keywords:\n\nimport java.io.Serializable\nimplements Serializable\nJSON¶\nIf you need to counter memory-dumping, make sure that very sensitive information is not stored in the JSON format because you can\'t guarantee prevention of anti-memory dumping techniques with the standard libraries. You can check for the following keywords in the corresponding libraries:\n\nJSONObject Search the source code for the following keywords:\n\nimport org.json.JSONObject;\nimport org.json.JSONArray;\nGSON Search the source code for the following keywords:\n\nimport com.google.gson\nimport com.google.gson.annotations\nimport com.google.gson.reflect\nimport com.google.gson.stream\nnew Gson();\nAnnotations such as @Expose, @JsonAdapter, @SerializedName,@Since, and @Until\nJackson Search the source code for the following keywords:\n\nimport com.fasterxml.jackson.core\nimport org.codehaus.jackson for the older version.\nORM¶\nWhen you use an ORM library, make sure that the data is stored in an encrypted database and the class representations are individually encrypted before storing it. See the chapters "D',
    },
    {
        "section": 'CODE QUALITY & BUILD SETTINGS',
        "level":   'L1',
        "name":    'Testing Enforced Updating',
        "content": 'Overview¶\nTo test for enforced updating you need to check if the app has support for in-app updates and validate if it\'s properly enforced so that the user is not able to continue using the app without updating it first.\n\nStatic analysis¶\nThe code sample below shows the example of an app-update:\n\n\n//Part 1: check for update\n// Creates instance of the manager.\nAppUpdateManager appUpdateManager = AppUpdateManagerFactory.create(context);\n\n// Returns an intent object that you use to check for an update.\nTask<AppUpdateInfo> appUpdateInfo = appUpdateManager.getAppUpdateInfo();\n\n// Checks that the platform will allow the specified type of update.\nif (appUpdateInfo.updateAvailability() == UpdateAvailability.UPDATE_AVAILABLE\n      // For a flexible update, use AppUpdateType.FLEXIBLE\n      && appUpdateInfo.isUpdateTypeAllowed(AppUpdateType.IMMEDIATE)) {\n\n\n\n                  //...Part 2: request update\n                  appUpdateManager.startUpdateFlowForResult(\n                     // Pass the intent that is returned by \'getAppUpdateInfo()\'.\n                     appUpdateInfo,\n                     // Or \'AppUpdateType.FLEXIBLE\' for flexible updates.\n                     AppUpdateType.IMMEDIATE,\n                     // The current activity making the update request.\n                     this,\n                     // Include a request code to later monitor this update request.\n                     MY_REQUEST_CODE);\n\n\n\n                     //...Part 3: check if update completed successfully\n @Override\n public void onActivityResult(int requestCode, int resultCode, Intent data) {\n   if (myRequestCode == MY_REQUEST_CODE) {\n     if (resultCode != RESULT_OK) {\n       log("Update flow failed! Result code: " + resultCode);\n       // If the update is cancelled or fails,\n       // you can request to start the update again in case of forced updates\n     }\n   }\n }\n\n //..Part 4:\n // Checks that the update is not stalled during \'onResume()\'.\n// However, you should execute this check at all entry points into the app.\n@Override\nprotected void onResume() {\n  super.onResume();\n\n  appUpdateManager\n      .getAppUpdateInfo()\n      .addOnSuccessListener(\n          appUpdateInfo -> {\n            ...\n            if (appUpdateInfo.updateAvailability()\n                == UpdateAvailability.DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS) {\n                // If an in-app update is already running, resume the update.\n                manager.startUpdateFlowForResult(\n                    appUpdateInfo,\n  ',
    },
    {
        "section": 'CODE QUALITY & BUILD SETTINGS',
        "level":   'L1',
        "name":    'Checking for Weaknesses in Third Party Libraries',
        "content": "Overview¶\nStatic Analysis¶\nDetecting vulnerabilities in third party dependencies can be done by means of the OWASP Dependency checker. This is best done by using a gradle plugin, such as dependency-check-gradle ↗. In order to use the plugin, the following steps need to be applied: Install the plugin from the Maven central repository by adding the following script to your build.gradle:\n\n\nbuildscript {\n    repositories {\n        mavenCentral()\n    }\n    dependencies {\n        classpath 'org.owasp:dependency-check-gradle:3.2.0'\n    }\n}\n\napply plugin: 'org.owasp.dependencycheck'\nOnce gradle has invoked the plugin, you can create a report by running:\n\n\ngradle assemble\ngradle dependencyCheckAnalyze --info\nThe report will be in build/reports unless otherwise configured. Use the report in order to analyze the vulnerabilities found. See remediation on what to do given the vulnerabilities found with the libraries.\n\nPlease be advised that the plugin requires to download a vulnerability feed. Consult the documentation in case issues arise with the plugin.\n\nLastly, please note that for hybrid applications, you will have to check the JavaScript dependencies with RetireJS. Similarly for mobile cross platform frameworks, you will have to check their dependencies.\n\nWhen a library is found to contain vulnerabilities, then the following reasoning applies:\n\nIs the library packaged with the application? Then check whether the library has a version in which the vulnerability is patched. If not, check whether the vulnerability actually affects the application. If that is the case or might be the case in the future, then look for an alternative which provides similar functionality, but without the vulnerabilities.\nIs the library not packaged with the application? See if there is a patched version in which the vulnerability is fixed. If this is not the case, check if the implications of the vulnerability for the build-process. Could the vulnerability impede a build or weaken the security of the build-pipeline? Then try looking for an alternative in which the vulnerability is fixed.\nWhen the sources are not available, one can decompile the app and check the JAR files. When Dexguard or  ProGuard are applied properly, then version information about the library is often obfuscated and therefore gone. Otherwise you can still find the information very often in the comments of the Java files of given libraries. Tools such as MobSF can help in analyzing the possible libraries packed with ",
    },
    {
        "section": 'CODE QUALITY & BUILD SETTINGS',
        "level":   'L1',
        "name":    'Memory Corruption Bugs',
        "content": 'Overview¶\nStatic Analysis¶\nThere are various items to look for:\n\nAre there native code parts? If so: check for the given issues in the general memory corruption section. Native code can easily be spotted given JNI-wrappers, .CPP/.H/.C files, NDK or other native frameworks.\nIs there Java code or Kotlin code? Look for Serialization/deserialization issues, such as described in A brief history of Android deserialization vulnerabilities ↗.\nNote that there can be Memory leaks in Java/Kotlin code as well. Look for various items, such as: BroadcastReceivers which are not unregistered, static references to Activity or View classes, Singleton classes that have references to Context, Inner Class references, Anonymous Class references, AsyncTask references, Handler references, Threading done wrong, TimerTask references. For more details, please check:\n\n9 ways to avoid memory leaks in Android ↗\nMemory Leak Patterns in Android ↗.\nDynamic Analysis¶\nThere are various steps to take:\n\nIn case of native code: use Valgrind or Mempatrol to analyze the memory usage and memory calls made by the code.\nIn case of Java/Kotlin code, try to recompile the app and use it with Squares leak canary ↗.\nCheck with the Memory Profiler from Android Studio ↗ for leakage.\nCheck with the Android Java Deserialization Vulnerability Tester ↗, for serialization vulnerabilities.',
    },
    {
        "section": 'CODE QUALITY & BUILD SETTINGS',
        "level":   'L1',
        "name":    'Make Sure That Free Security Features Are Activated',
        "content": 'Static Analysis¶\nTest the app native libraries to determine if they have the PIE and stack smashing protections enabled.\n\nYou can use  rabin2 to get the binary information. We\'ll use the  Android UnCrackable L4 v1.0 APK as an example.\n\nAll native libraries must have canary and pic both set to true.\n\nThat\'s the case for libnative-lib.so:\n\n\nrabin2 -I lib/x86_64/libnative-lib.so | grep -E "canary|pic"\ncanary   true\npic      true\nBut not for libtool-checker.so:\n\n\nrabin2 -I lib/x86_64/libtool-checker.so | grep -E "canary|pic"\ncanary   false\npic      true\nIn this example, libtool-checker.so must be recompiled with stack smashing protection support.',
    },
    {
        "section": 'CODE QUALITY & BUILD SETTINGS',
        "level":   'L1',
        "name":    'Position Independent Code (PIC) Not Enabled',
        "content": 'Overview¶\nThis test case checks if the native libraries of the app are compiled without enabling Position Independent Code (PIC), a common mitigation technique against memory corruption attacks.\n\nSince Android 5.0 (API level 21), Android requires all dynamically linked executables to support PIE ↗.\n\nBuild System Maintainers Guide - Additional Required Arguments ↗: Android requires Position-independent executables beginning with API 21. Clang builds PIE executables by default. If invoking the linker directly or not using Clang, use -pie when linking.\n\nSteps¶\nUse  Extracting Bundled Native Libraries to extract the native libraries from the app package.\nUse  Obtaining Compiler-Provided Security Features on each native library to obtain the compiler-provided security features.\nObservation¶\nThe output should show all the security features enabled for each native library, including PIC.\n\nEvaluation¶\nThe test case fails if PIC is disabled.',
    },
    {
        "section": 'CODE QUALITY & BUILD SETTINGS',
        "level":   'L1',
        "name":    'Stack Canaries Not Enabled',
        "content": "Overview¶\nThis test case checks if the native libraries of the app are compiled without common binary protection mechanisms ( Binary Protection Mechanisms) such as stack smashing protection, a mitigation technique against buffer overflow attacks.\n\nNDK libraries should have stack canaries enabled since the compiler does it by default ↗.\nOther custom C/C++ libraries might not have stack canaries enabled because they lack the necessary compiler flags (-fstack-protector-strong, or -fstack-protector-all) or the canaries were optimized out by the compiler.\nSteps¶\nUse  Extracting Bundled Native Libraries to extract the native libraries from the app package.\nUse  Obtaining Compiler-Provided Security Features on each native library to obtain the compiler-provided security features.\nObservation¶\nThe output should show all the security features enabled for each native library, including stack canaries.\n\nEvaluation¶\nThe test case fails if stack canaries are disabled.\n\nDevelopers need to ensure that the flags -fstack-protector-strong, or -fstack-protector-all are set in the compiler flags for all native libraries. This is especially important for custom C/C++ libraries that are not part of the NDK.\n\nWhen evaluating this please note that there are potential expected false positives for which the test case should be considered as passed. To be certain for these cases, they require manual review of the original source code and the compilation flags used.\n\nThe following examples cover some of the false positive cases that might be encountered:\n\nUse of Memory Safe Languages¶\nThe Flutter framework does not use stack canaries because of the way Dart mitigates buffer overflows ↗.\n\nCompiler Optimizations¶\nSometimes, due to the size of the library and the optimizations applied by the compiler, it might be possible that the library was originally compiled with stack canaries but they were optimized out. For example, this is the case for some react native apps ↗. They are built with -fstack-protector-strong but when attempting to search for stack_chk_fail inside the .so files, it is not found.\n\nEmpty .so files: Some .so files such as libruntimeexecutor.so or libreact_render_debug.so are effectively empty in release and therefore contain no symbols. Even if you were to attempt to build with -fstack-protector-all, you still won't be able to see the stack_chk_fail string as there are no method calls there.\nLack of stack buffer calls: Other files such as libreact_utils.so, libreact_co",
    },
    {
        "section": 'CODE QUALITY & BUILD SETTINGS',
        "level":   'L1',
        "name":    'References to Platform Version APIs',
        "content": 'Overview¶\nThis test verifies whether an app is running on a recent version of the Android operating system.\n\nIn Kotlin, Android apps can determine the OS version using the Build.VERSION.SDK_INT property, which returns the API level of the current system. By comparing it to a specific version constant, such as Build.VERSION_CODES.UPSIDE_DOWN_CAKE for Android 14 (API level 34), apps can conditionally execute code based on the OS version. In this example, "Upside Down Cake" is the internal codename for Android 14.\n\nAndroid apps specify a minSdkVersion, which defines the oldest OS version they support. While a high minSdkVersion reduces the need for runtime version checks, dynamically verifying the OS version using Build.VERSION.SDK_INT remains beneficial. It allows apps to take advantage of newer, more secure features when available while maintaining backward compatibility.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should contain a list of locations where relevant APIs are used.\n\nEvaluation¶\nThe test case fails if the app does not include any API calls to verify the operating system version.\n\nDemos¶\n MASTG-DEMO-0025: Uses of Build.VERSION.SDK_INT with semgrep = https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0025/MASTG-DEMO-0025/',
    },
    {
        "section": 'CODE QUALITY & BUILD SETTINGS',
        "level":   'L1',
        "name":    'Identify Dependencies with Known Vulnerabilities in the Android Project',
        "content": 'Overview¶\nIn this test case we will identify dependencies in Android Studio.\n\nSteps¶\nUse  Software Composition Analysis (SCA) of Android Dependencies at Build Time to scan through the build environment of Android Studio by using Gradle.\nObservation¶\nThe output should include the dependency and the CVE identifiers for any dependency with known vulnerabilities.\n\nEvaluation¶\nThe test case fails if you can find dependencies with known vulnerabilities.\n\nDemos¶\n MASTG-DEMO-0050: Identifying Insecure Dependencies in Android Studio - https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0050/MASTG-DEMO-0050/\n MASTG-DEMO-0051: Identifying Insecure Dependencies through SBOM Creation - https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0051/MASTG-DEMO-0051/',
    },
    {
        "section": 'CODE QUALITY & BUILD SETTINGS',
        "level":   'L1',
        "name":    "Dependencies with Known Vulnerabilities in the App's SBOM",
        "content": 'Overview¶\nIn this test case we are identifying dependencies with known vulnerabilities by relying on a Software Bill of Material (SBOM).\n\nSteps¶\nUse  Software Composition Analysis (SCA) of Android Dependencies by Creating a SBOM to generate a SBOM, or request one in CycloneDX format from the development team.\nUpload the SBOM to  dependency-track.\nInspect the  dependency-track project for the use of vulnerable dependencies.\nObservation¶\nThe output should include a list of dependencies with names and CVE identifiers, if any.\n\nEvaluation¶\nThe test case fails if you can find dependencies with known vulnerabilities.',
    },
    {
        "section": 'CODE QUALITY & BUILD SETTINGS',
        "level":   'L1',
        "name":    'References to Object Deserialization of Untrusted Data',
        "content": 'Overview¶\nAndroid apps can reconstruct objects from serialized data received through platform mechanisms such as Intent extras, Bundle values, IPC payloads, files, or network responses. If the app deserializes data from these sources without restricting the allowed classes or validating the input before use, the deserialization logic can introduce unintended application behavior or unsafe state changes.\n\nThis test checks whether the app uses object deserialization on Android and whether the deserialized data originates from potentially untrusted sources without appropriate filtering or validation. For background on Android serialization and deserialization mechanisms, see  Object Serialization.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should contain a list of locations where object deserialization is used.\n\nEvaluation¶\nThe test case fails if the app deserializes data received from untrusted sources (e.g., Intent extras from any other application) without proper validation or type filtering.\n\nDemos¶\n MASTG-DEMO-0100: Object Deserialization Using Serializable with semgrep - https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0100/MASTG-DEMO-0100/',
    },
    {
        "section": 'CODE QUALITY & BUILD SETTINGS',
        "level":   'L1',
        "name":    'Integrity and Authenticity Validation of Local Storage Data',
        "content": "Overview¶\nApps may store sensitive data in local storage and later use it in security-relevant decisions. If that data can be modified by an attacker and the app does not verify its integrity and authenticity before using it, the app may trust tampered input.\n\nThis test applies to local storage broadly, including SharedPreferences, files, databases, and other app managed storage locations.\n\nFor example, when using SharedPreferences specifically, the data is stored in the app's private sandbox and normally cannot be modified by other apps. However, it can still be tampered with in local attack scenarios, such as on rooted devices, during dynamic analysis, through backups, or by directly manipulating the app's data directory after obtaining privileged access, as described in  Shared Preferences. Because of that, apps should not blindly trust security-relevant data loaded from local storage.\n\nWhen performing this test, look not only for storage read APIs, but also for nearby integrity and authenticity validation logic. Depending on the implementation, this may include APIs and patterns related to HMACs, MAC comparison, cryptographic initialization, signature verification, checksums, or other mechanisms intended to detect tampering.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should contain code locations where the app reads data from local storage. Depending on the storage API and the analysis rule, these code locations may include APIs such as SharedPreferences.getString, file reads, database queries, or nearby comparison and verification logic such as HMAC or MAC related operations.\n\nEvaluation¶\nThe test case fails if the app doesn't verify the integrity and authenticity of data loaded from local storage before being used in security-relevant decisions.\n\nFurther Validation Required:\n\nInspect each reported code location using  Reviewing Decompiled Java Code to determine whether the data is used in security-relevant decisions without adequate integrity and authenticity verification:\n\nDetermine whether the loaded value can influence a security-relevant decision, such as authentication state, authorization, feature access, configuration, or trust decisions.\nDetermine whether the app verifies the integrity and authenticity of the loaded value before using it, for example with an HMAC, MAC, signature, or similar verification mechanism.\nDetermine w",
    },
    {
        "section": 'CODE QUALITY & BUILD SETTINGS',
        "level":   'L1',
        "name":    'SQL Injection in Content Providers',
        "content": 'Overview¶\nAndroid applications can share structured data via ContentProvider components. However, if these providers create SQL queries using untrusted input from URIs without adequate validation or parameterization, they risk becoming susceptible to SQL injection attacks.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should contain a list of locations where user-controlled input from URIs or selection arguments is concatenated into SQL queries, for example via Uri.getPathSegments() and SQLiteQueryBuilder.appendWhere().\n\nEvaluation¶\nThe test case fails if:\n\nUntrusted user input (e.g., from getPathSegments()) is directly concatenated into SQL statements.\nThe app uses appendWhere() or builds queries unsafely without sanitization or parameterization.\nBest Practices¶\n MASTG-BEST-0039: Prevent SQL Injection in ContentProviders - https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0039/\n\nDemos¶\n MASTG-DEMO-0102: SQL Injection via URI Path and Selection in Android Content Providers - https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0102/MASTG-DEMO-0102/',
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Making Sure that the App is Properly Signed',
        "content": "Overview¶\nEnsure that the release builds are properly signed to safeguard their integrity and protect them from tampering. Android has evolved its signing schemes over time to enhance security, with newer versions offering more robust mechanisms.\n\nAndroid 7.0 (API level 24) and above: Use at least the v2 signature scheme, which signs the APK as a whole, providing stronger protection compared to the older v1 (JAR) signing method.\nAndroid 9 (API level 28) and above: It's recommended to use both the v2 and v3 signature schemes. The v3 scheme supports key rotation, enabling developers to replace keys in the event of a compromise without invalidating old signatures.\nAndroid 11 (API level 30) and above: Optionally include the v4 signature scheme to enable faster incremental updates.\nAvoid using the v1 signature scheme (JAR signing) unless absolutely necessary for backward compatibility with Android 6.0 (API level 23) and below as it is considered insecure. For example, it is affected by the Janus vulnerability (CVE-2017-13156), which can allow malicious actors to modify APK files without invalidating the v1 signature. As such, v1 should never be relied on exclusively for devices running Android 7.0 and above.\n\nYou should also ensure that the APK's code-signing certificate is valid and belongs to the developer.\n\nFor further guidance, refer to the official Android app signing documentation ↗ and best practices for configuring apps for release ↗.\n\nStatic Analysis¶\nAPK signatures can be verified with the apksigner ↗ tool. It is located at [SDK-Path]/build-tools/[version]/apksigner.\n\n\n$ apksigner verify --verbose example.apk\nVerifies\nVerified using v1 scheme (JAR signing): false\nVerified using v2 scheme (APK Signature Scheme v2): true\nVerified using v3 scheme (APK Signature Scheme v3): true\nVerified using v3.1 scheme (APK Signature Scheme v3.1): false\nVerified using v4 scheme (APK Signature Scheme v4): false\nVerified for SourceStamp: false\nNumber of signers: 1\nThe contents of the signing certificate can be also examined with apksigner:\n\n\n$ apksigner verify --print-certs --verbose example.apk\n[...]\nSigner #1 certificate DN: CN=Example Developers, OU=Android, O=Example\nSigner #1 certificate SHA-256 digest: 1fc4de52d0daa33a9c0e3d67217a77c895b46266ef020fad0d48216a6ad6cb70\nSigner #1 certificate SHA-1 digest: 1df329fda8317da4f17f99be83aa64da62af406b\nSigner #1 certificate MD5 digest: 3dbdca9c1b56f6c85415b67957d15310\nSigner #1 key algorithm: RSA\nSigner #1 key size (bits): 20",
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Testing whether the App is Debuggable',
        "content": 'Static Analysis¶\nCheck AndroidManifest.xml to determine whether the android:debuggable attribute has been set and to find the attribute\'s value:\n\n\n    ...\n    <application android:allowBackup="true" android:debuggable="true" android:icon="@drawable/ic_launcher" android:label="@string/app_name" android:theme="@style/AppTheme">\n    ...\nYou can use aapt tool from the Android SDK with the following command line to quickly check if the android:debuggable="true" directive is present:\n\n\n#If the command print 1 then the directive is present\n#The regex search for this line: android:debuggable(0x0101000f)=(type 0x12)0xffffffff\n$ aapt d xmltree sieve.apk AndroidManifest.xml | grep -Ec "android:debuggable\\(0x[0-9a-f]+\\)=\\(type\\s0x[0-9a-f]+\\)0xffffffff"\n1\nFor a release build, this attribute should always be set to "false" (the default value).\n\nDynamic Analysis¶\nadb can be used to determine whether an application is debuggable.\n\nUse the following command:\n\n\n#If the command print a number superior to zero then the application have the debug flag\n#The regex search for these lines:\n#flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]\n#pkgFlags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]\n$ adb shell dumpsys package com.mwr.example.sieve | grep -c "DEBUGGABLE"\n2\n$ adb shell dumpsys package com.nondebuggableapp | grep -c "DEBUGGABLE"\n0\nIf an application is debuggable, executing application commands is trivial. In the adb shell, execute run-as by appending the package name and application command to the binary name:\n\n\n$ run-as com.vulnerable.app id\nuid=10084(u0_a84) gid=10084(u0_a84) groups=10083(u0_a83),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats) context=u:r:untrusted_app:s0:c512,c768\nAndroid Studio ↗ can also be used to debug an application and verify debugging activation for an app.\n\nAnother method for determining whether an application is debuggable is attaching jdb to the running process. If this is successful, debugging will be activated.\n\nThe following procedure can be used to start a debug session with jdb:\n\nUsing adb and jdwp, identify the PID of the active application that you want to debug:\n\n\n$ adb jdwp\n2355\n16346  <== last launched, corresponds to our application\nCreate a communication channel by using adb between the application process (with the PID) and your host computer by using a specific local port:\n\n\n#adb forward tcp:[LOCAL_PORT] jdwp:[APPLICATION_PI',
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Testing for Debugging Symbols',
        "content": 'Static Analysis¶\nSymbols are usually stripped during the build process, so you need the compiled bytecode and libraries to make sure that unnecessary metadata has been discarded.\n\nFirst, find the nm binary in your Android NDK and export it (or create an alias).\n\n\nexport NM = $ANDROID_NDK_DIR/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64/bin/arm-linux-androideabi-nm\nTo display debug symbols:\n\n\n$NM -a libfoo.so\n/tmp/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64/bin/arm-linux-androideabi-nm: libfoo.so: no symbols\nTo display dynamic symbols:\n\n\n$NM -D libfoo.so\nAlternatively, open the file in your favorite disassembler and check the symbol tables manually.\n\nDynamic symbols can be stripped via the visibility compiler flag. Adding this flag causes gcc to discard the function names while preserving the names of functions declared as JNIEXPORT.\n\nMake sure that the following has been added to build.gradle:\n\n\nexternalNativeBuild {\n    cmake {\n        cppFlags "-fvisibility=hidden"\n    }\n}\nDynamic Analysis¶\nStatic analysis should be used to verify debugging symbols.',
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Testing for Debugging Code and Verbose Error Logging',
        "content": "Static Analysis¶\nTo determine whether StrictMode ↗ is enabled, you can look for the StrictMode.setThreadPolicy or StrictMode.setVmPolicy methods. Most likely, they will be in the onCreate method.\n\nThe detection methods for the thread policy are:\n\ndetectDiskWrites()\ndetectDiskReads()\ndetectNetwork()\nThe penalties for thread policy violation are:\n\npenaltyLog(): Logs a message to LogCat.\npenaltyDeath(): Crashes application, runs at the end of all enabled penalties.\npenaltyDialog(): Shows a dialog.\nHave a look at the best practices ↗ for using StrictMode.\n\nDynamic Analysis¶\nThere are several ways of detecting StrictMode; the best choice depends on how the policies' roles are implemented. They include\n\nLogcat,\na warning dialog,\napplication crash.",
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Testing Root Detection',
        "content": 'Bypassing Root Detection¶\nRun execution traces with jdb, Android Studio Profiler, strace, and/or kernel modules to find out what the app is doing (see  Execution Tracing). You\'ll usually see all kinds of suspect interactions with the operating system, such as opening su for reading and obtaining a list of processes. These interactions are surefire signs of root detection. Identify and deactivate the root detection mechanisms, one at a time. If you\'re performing a black box resilience assessment, disabling the root detection mechanisms is your first step.\n\nTo bypass these checks, you can use several techniques, most of which were introduced in the "Reverse Engineering and Tampering" chapter:\n\nRenaming binaries. For example, in some cases simply renaming the su binary is enough to defeat root detection (try not to break your environment though!).\nUnmounting /proc to prevent reading of process lists. Sometimes, the unavailability of /proc is enough to bypass such checks.\nUsing Frida or Xposed to hook APIs on the Java and native layers. This hides files and processes, hides the contents of files, and returns all kinds of bogus values that the app requests.\nHooking low-level APIs by using kernel modules.\nPatching the app to remove the checks.\nEffectiveness Assessment¶\nCheck for root detection mechanisms, including the following criteria:\n\nMultiple detection methods are scattered throughout the app (as opposed to putting everything into a single method).\nThe root detection mechanisms operate on multiple API layers (Java APIs, native library functions, assembler/system calls).\nThe mechanisms are somehow original (they\'re not copied and pasted from StackOverflow or other sources).\nDevelop bypass methods for the root detection mechanisms and answer the following questions:\n\nCan the mechanisms be easily bypassed with standard tools, such as  objection (Android)?\nIs static/dynamic analysis necessary to handle the root detection?\nDo you need to write custom code?\nHow long did successfully bypassing the mechanisms take?\nWhat is your assessment of the difficulty of bypassing the mechanisms?\nIf root detection is missing or too easily bypassed, make suggestions in line with the effectiveness criteria listed above. These suggestions may include more detection mechanisms and better integration of existing mechanisms with other defenses.',
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Testing Anti-Debugging Detection',
        "content": 'Bypassing Debugger Detection¶\nThere\'s no generic way to bypass anti-debugging: the best method depends on the particular mechanism(s) used to prevent or detect debugging and the other defenses in the overall protection scheme. For example, if there are no integrity checks or you\'ve already deactivated them, patching the app might be the easiest method. In other cases, a hooking framework or kernel modules might be preferable. The following methods describe different approaches to bypass debugger detection:\n\nPatching the anti-debugging functionality: Disable the unwanted behavior by simply overwriting it with NOP instructions. Note that more complex patches may be required if the anti-debugging mechanism is well designed.\nUsing Frida or Xposed to hook APIs on the Java and native layers: manipulate the return values of functions such as isDebuggable and isDebuggerConnected to hide the debugger.\nChanging the environment: Android is an open environment. If nothing else works, you can modify the operating system to subvert the assumptions the developers made when designing the anti-debugging tricks.\nBypassing Example: UnCrackable App for Android Level 2¶\nWhen dealing with obfuscated apps, you\'ll often find that developers purposely "hide away" data and functionality in native libraries. You\'ll find an example of this in  Android UnCrackable L2.\n\nAt first glance, the code looks like the prior challenge. A class called CodeCheck is responsible for verifying the code entered by the user. The actual check appears to occur in the bar method, which is declared as a native method.\n\n\npackage sg.vantagepoint.uncrackable2;\n\npublic class CodeCheck {\n    public CodeCheck() {\n        super();\n    }\n\n    public boolean a(String arg2) {\n        return this.bar(arg2.getBytes());\n    }\n\n    private native boolean bar(byte[] arg1) {\n    }\n}\n\n    static {\n        System.loadLibrary("foo");\n    }\nPlease see different proposed solutions for the Android Crackme Level 2 in GitHub.\n\nEffectiveness Assessment¶\nCheck for anti-debugging mechanisms, including the following criteria:\n\nAttaching jdb and ptrace-based debuggers fails or causes the app to terminate or malfunction.\nMultiple detection methods are scattered throughout the app\'s source code (as opposed to their all being in a single method or function).\nThe anti-debugging defenses operate on multiple API layers (Java, native library functions, assembler/system calls).\nThe mechanisms are somehow original (as opposed to being copied ',
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Testing File Integrity Checks',
        "content": 'Bypassing File Integrity Checks¶\nBypassing the application-source integrity checks¶\nPatch the anti-debugging functionality. Disable the unwanted behavior by simply overwriting the associated bytecode or native code with NOP instructions.\nUse Frida or Xposed to hook file system APIs on the Java and native layers. Return a handle to the original file instead of the modified file.\nUse the kernel module to intercept file-related system calls. When the process attempts to open the modified file, return a file descriptor for the unmodified version of the file.\nRefer to Method Hooking for examples of patching, code injection, and kernel modules.\n\nBypassing the storage integrity checks¶\nRetrieve the data from the device.\nAlter the retrieved data and then put it back into storage.\nEffectiveness Assessment¶\nApplication-source integrity checks:\n\nRun the app in an unmodified state and make sure that everything works. Apply simple patches to classes.dex and any .so libraries in the app package. Re-package and re-sign the app as described in the "Basic Security Testing" chapter, then run the app. The app should detect the modification and respond in some way. At the very least, the app should alert the user and/or terminate. Work on bypassing the defenses and answer the following questions:\n\nCan the mechanisms be bypassed trivially (e.g., by hooking a single API function)?\nHow difficult is identifying the anti-debugging code via static and dynamic analysis?\nDid you need to write custom code to disable the defenses? How much time did you need?\nWhat is your assessment of the difficulty of bypassing the mechanisms?\nStorage integrity checks:\n\nAn approach similar to that for application-source integrity checks applies. Answer the following questions:\n\nCan the mechanisms be bypassed trivially (e.g., by changing the contents of a file or a key-value)?\nHow difficult is getting the HMAC key or the asymmetric private key?\nDid you need to write custom code to disable the defenses? How much time did you need?\nWhat is your assessment of the difficulty of bypassing the mechanisms?',
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Testing Reverse Engineering Tools Detection',
        "content": 'Effectiveness Assessment¶\nLaunch the app with various reverse engineering tools and frameworks installed in your test device. Include at least the following:  Frida,  Xposed.\n\nThe app should respond in some way to the presence of those tools. For example by:\n\nAlerting the user and asking for accepting liability.\nPreventing execution by gracefully terminating.\nSecurely wiping any sensitive data stored on the device.\nReporting to a backend server, e.g, for fraud detection.\nNext, work on bypassing the detection of the reverse engineering tools and answer the following questions:\n\nCan the mechanisms be bypassed trivially (e.g., by hooking a single API function)?\nHow difficult is identifying the anti reverse engineering code via static and dynamic analysis?\nDid you need to write custom code to disable the defenses? How much time did you need?\nWhat is your assessment of the difficulty of bypassing the mechanisms?\nThe following steps should guide you when bypassing detection of reverse engineering tools:\n\nPatch the anti reverse engineering functionality. Disable the unwanted behavior by simply overwriting the associated bytecode or native code with NOP instructions.\nUse Frida or Xposed to hook file system APIs on the Java and native layers. Return a handle to the original file, not the modified file.\nUse a kernel module to intercept file-related system calls. When the process attempts to open the modified file, return a file descriptor for the unmodified version of the file.',
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Testing Emulator Detection',
        "content": "Bypassing Emulator Detection¶\nPatch the emulator detection functionality. Disable the unwanted behavior by simply overwriting the associated bytecode or native code with NOP instructions.\nUse Frida or Xposed APIs to hook file system APIs on the Java and native layers. Return innocent-looking values (preferably taken from a real device) instead of the telltale emulator values. For example, you can override the TelephonyManager.getDeviceID method to return an IMEI value.\nEffectiveness Assessment¶\nInstall and run the app in the emulator. The app should detect that it is being executed in an emulator and terminate or refuse to execute the functionality that's meant to be protected.\n\nWork on bypassing the defenses and answer the following questions:\n\nHow difficult is identifying the emulator detection code via static and dynamic analysis?\nCan the detection mechanisms be bypassed trivially (e.g., by hooking a single API function)?\nDid you need to write custom code to disable the anti-emulation feature(s)? How much time did you need?\nWhat is your assessment of the difficulty of bypassing the mechanisms?",
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Testing Runtime Integrity Checks',
        "content": 'Effectiveness Assessment¶\nMake sure that all file-based detection of reverse engineering tools is disabled. Then, inject code by using Xposed, Frida, and Substrate, and attempt to install native hooks and Java method hooks. The app should detect the "hostile" code in its memory and respond accordingly.\n\nWork on bypassing the checks with the following techniques:\n\nPatch the integrity checks. Disable the unwanted behavior by overwriting the respective bytecode or native code with NOP instructions.\nUse Frida or Xposed to hook the APIs used for detection and return fake values.',
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Testing Obfuscation',
        "content": 'Overview¶\nStatic Analysis¶\nDecompile the APK ( Decompiling Java Code) and review it ( Reviewing Decompiled Java Code) to determine whether the codebase has been obfuscated.\n\nBelow you can find a sample for an obfuscated code block:\n\n\npackage com.a.a.a;\n\nimport com.a.a.b.a;\nimport java.util.List;\n\nclass a$b\n  extends a\n{\n  public a$b(List paramList)\n  {\n    super(paramList);\n  }\n\n  public boolean areAllItemsEnabled()\n  {\n    return true;\n  }\n\n  public boolean isEnabled(int paramInt)\n  {\n    return true;\n  }\n}\nHere are some considerations:\n\nMeaningful identifiers, such as class names, method names, and variable names, might have been discarded.\nString resources and strings in binaries might have been encrypted.\nCode and data related to the protected functionality might be encrypted, packed, or otherwise concealed.\nFor native code:\n\nlibc APIs ↗ (e.g open, read) might have been replaced with OS syscalls ↗.\nObfuscator-LLVM ↗ might have been applied to perform "Control Flow Flattening" ↗ or "Bogus Control Flow" ↗.\nSome of these techniques are discussed and analyzed in the blog post "Security hardening of Android native code" ↗ by Gautam Arvind and in the "APKiD: Fast Identification of AppShielding Products" ↗ presentation by Eduardo Novella.\n\nFor a more detailed assessment, you need a detailed understanding of the relevant threats and the obfuscation methods used. Tools such as  APKiD may give you additional indications about which techniques were used for the target app such as obfuscators, packers and anti-debug measures.\n\nDynamic Analysis¶\nYou can use  APKiD to detect if the app has been obfuscated.\n\nExample using the  Android UnCrackable L4:\n\n\napkid mastg/Crackmes/Android/Level_04/r2pay-v1.0.apk\n[+] APKiD 2.1.2 :: from RedNaga :: rednaga.io\n[*] mastg/Crackmes/Android/Level_04/r2pay-v1.0.apk!classes.dex\n |-> anti_vm : Build.TAGS check, possible ro.secure check\n |-> compiler : r8\n |-> obfuscator : unreadable field names, unreadable method names\nIn this case it detects that the app has unreadable field names and method names, among other things.',
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Usage of Insecure APK Signature Version',
        "content": 'Overview¶\nNot using newer APK signing schemes means that the app lacks the enhanced security provided by more robust, updated mechanisms.\n\nThis test checks if the outdated v1 signature scheme is enabled. The v1 scheme is vulnerable to certain attacks, such as the "Janus" vulnerability (CVE-2017-13156 ↗), because it does not cover all parts of the APK file, allowing malicious actors to potentially modify parts of the APK without invalidating the signature. Relying solely on v1 signing therefore increases the risk of tampering and compromises app security.\n\nTo learn more about APK Signing Schemes, see "Signing Process".\n\nSteps¶\nUse  Obtaining Information from the AndroidManifest to obtain the AndroidManifest.xml.\nUse  Analyzing the AndroidManifest to obtain the minSdkVersion from the AndroidManifest.xml file.\nUse  Obtaining Information about the APK Signature to list all used signature schemes.\nObservation¶\nThe output should contain the value of the minSdkVersion attribute and the used signature schemes (for example Verified using v3 scheme (APK Signature Scheme v3): true).\n\nEvaluation¶\nThe test case fails if the app has a minSdkVersion attribute of 24 and above, and only the v1 signature scheme is enabled.\n\nBest Practices¶\n MASTG-BEST-0006: Use Up-to-Date APK Signing Schemes = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0006/',
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Usage of Insecure APK Signature Key Size',
        "content": "Overview¶\nFor Android apps, the cryptographic strength of the APK signature is essential for maintaining the app's integrity and authenticity. Using a signature key with insufficient length, such as an RSA key shorter than 2048 bits, weakens security, making it easier for attackers to compromise the signature. This vulnerability could allow malicious actors to forge signatures, tamper with the app's code, or distribute unauthorized, modified versions.\n\nSteps¶\nUse  Obtaining Information about the APK Signature to list the additional signature information.\nObservation¶\nThe output should contain the information about the key size in a line like: Signer #1 key size (bits):.\n\nEvaluation¶\nThe test case fails if any of the key sizes (in bits) is less than 2048 (RSA). For example, Signer #1 key size (bits): 1024.",
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Debuggable Flag Enabled in the AndroidManifest',
        "content": "Overview¶\nThis test case checks if the app has the debuggable flag (android:debuggable ↗) set to true in the AndroidManifest.xml. When this flag is enabled, it allows the app to be debugged enabling attackers to inspect the app's internals, bypass security controls, or manipulate runtime behavior.\n\nAlthough having the debuggable flag set to true is not considered a direct vulnerability ↗, it significantly increases the attack surface by providing unauthorized access to app data and resources, particularly in production environments.\n\nSteps¶\nUse  Obtaining Information from the AndroidManifest to obtain the AndroidManifest.xml.\nUse  Analyzing the AndroidManifest to obtain the debuggable flag.\nObservation¶\nThe output should explicitly show whether the debuggable flag is set (true or false). If the flag is not specified, it is treated as false by default for release builds.\n\nEvaluation¶\nThe test case fails if the debuggable flag is explicitly set to true. This indicates that the app is configured to allow debugging, which is inappropriate for production environments.\n\nBest Practices¶\n MASTG-BEST-0007: Debuggable Flag Disabled in the AndroidManifest = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0007/\n\nDemos¶\n MASTG-DEMO-0040: Debuggable Flag Enabled in the AndroidManifest with semgrep = https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0040/MASTG-DEMO-0040/",
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Debugging Enabled for WebViews',
        "content": 'Overview¶\nThe WebView.setWebContentsDebuggingEnabled(true) API enables debugging for all WebViews in the application. This feature can be useful during development, but introduces significant security risks if left enabled in production. When enabled, a connected PC can debug, eavesdrop, or modify communication within any WebView in the application. See the "Android Documentation" ↗ for more details.\n\nNote that this flag works independently of the debuggable attribute (ApplicationInfo.FLAG_DEBUGGABLE) in the AndroidManifest.xml (see  Debuggable Flag Enabled in the AndroidManifest). Even if the app is not marked as debuggable, the WebViews can still be debugged by calling this API.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should list:\n\nAll locations where WebView.setWebContentsDebuggingEnabled is called with true at runtime.\nAny references to ApplicationInfo.FLAG_DEBUGGABLE.\nEvaluation¶\nThe test case fails if WebView.setWebContentsDebuggingEnabled(true) is called unconditionally or in contexts where the ApplicationInfo.FLAG_DEBUGGABLE flag is not checked.\n\nBest Practices¶\n MASTG-BEST-0008: Debugging Disabled for WebViews = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0008/',
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'References to APIs for Detecting Secure Screen Lock',
        "content": "Overview¶\nThis test verifies whether an app is running on a device with a passcode set. Android apps can determine whether a secure screen lock (such as PIN, or password) ↗ is enabled by using platform-provided APIs. Specifically, apps can utilize the KeyguardManager ↗ API, which provides the isDeviceSecure() ↗ and isKeyguardSecure() ↗ methods to check if the device has a secure lock mechanism in place.\n\nAdditionally, apps can use the BiometricManager#canAuthenticate(int) ↗ API to check whether biometric authentication is available and can be used. Since biometric authentication on Android requires a secure screen lock as a fallback, this method can serve as an alternative check when KeyguardManager ↗ is unavailable or restricted by device manufacturers.\n\nIf an app relies on biometrics for authentication, it should ensure that biometric authentication is enforced using the BiometricPrompt ↗ API or by requiring authentication for cryptographic key access via the Android KeyStore System. However, apps cannot force users to enable biometrics at the system level, only enforce their use within the app for accessing sensitive functionality.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should contain a list of locations where relevant APIs are used.\n\nEvaluation¶\nThe test case fails if an app doesn't use any APIs to verify the presence of a secure screen lock.\n\nDemos¶\n MASTG-DEMO-0028: Uses of KeyguardManager.isDeviceSecure and BiometricManager.canAuthenticate with semgrep = https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0028/MASTG-DEMO-0028/",
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Runtime Use of Secure Screen Lock Detection APIs',
        "content": "Overview¶\nThis test is the dynamic counterpart to  References to APIs for Detecting Secure Screen Lock.\n\nIn this case, we'll look for uses of KeyguardManager.isDeviceSecure and BiometricManager.canAuthenticate APIs.\n\nSteps¶\nUse  Installing Apps to install the app.\nUse  Method Hooking to hook the relevant API calls.\nExercise the app extensively to trigger as many flows as possible and enter sensitive data wherever you can.\nObservation¶\nThe output should contain a list of locations where relevant APIs are used.\n\nEvaluation¶\nThe test case fails if an app doesn't use any API to verify the secure screen lock presence.\n\nDemos¶\n MASTG-DEMO-0027: Runtime Use of KeyguardManager.isDeviceSecure and BiometricManager.canAuthenticate APIs with Frida - https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0027/MASTG-DEMO-0027/",
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Logging of StrictMode Violations',
        "content": 'Overview¶\nThis test checks whether an app enables StrictMode in production. While useful for developers to log policy violations such as disk I/O or network operations in production apps, leaving StrictMode enabled can expose sensitive implementation details in the logs that could be exploited by attackers.\n\nThe target of this test is the production build of the app.\n\nSteps¶\nUse  Installing Apps to install the app.\nUse  Monitoring System Logs to show the system logs StrictMode creates.\nOpen the app and let it execute.\nObservation¶\nThe output should contain a list of log statements related to StrictMode.\n\nEvaluation¶\nThe test case fails if an app logs any StrictMode policy violations.\n\nDemos¶\n MASTG-DEMO-0037: App Leaking Information about Unclosed SQL Cursor via StrictMode = https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0037/MASTG-DEMO-0037/',
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Runtime Use of StrictMode APIs',
        "content": "Overview¶\nThis test checks whether the app uses StrictMode by dynamically analyzing the app's behavior and placing relevant hooks to detect the use of StrictMode APIs, such as StrictMode.setVmPolicy and StrictMode.VmPolicy.Builder.penaltyLog.\n\nWhile StrictMode is useful for developers to log policy violations such as disk I/O or network operations during development, it can expose sensitive implementation details in the logs that could be exploited by attackers.\n\nSteps¶\nUse  Installing Apps to install the app.\nUse  Method Hooking to hook the relevant API calls.\nExercise the app extensively to trigger as many flows as possible and enter sensitive data wherever you can.\nObservation¶\nThe output should show the runtime usage of StrictMode APIs.\n\nEvaluation¶\nThe test case fails if the output shows the runtime usage of StrictMode APIs.\n\nDemos¶\n MASTG-DEMO-0038: Detecting StrictMode Uses with Frida\n\nOverview¶\nThis test checks whether the app uses StrictMode by dynamically analyzing the app's behavior and placing relevant hooks to detect the use of StrictMode APIs, such as StrictMode.setVmPolicy and StrictMode.VmPolicy.Builder.penaltyLog.\n\nWhile StrictMode is useful for developers to log policy violations such as disk I/O or network operations during development, it can expose sensitive implementation details in the logs that could be exploited by attackers.\n\nSteps¶\nUse  Installing Apps to install the app.\nUse  Method Hooking to hook the relevant API calls.\nExercise the app extensively to trigger as many flows as possible and enter sensitive data wherever you can.\nObservation¶\nThe output should show the runtime usage of StrictMode APIs.\n\nEvaluation¶\nThe test case fails if the output shows the runtime usage of StrictMode APIs.\n\nDemos¶\n MASTG-DEMO-0038: Detecting StrictMode Uses with Frida",
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'References to StrictMode APIs',
        "content": 'Overview¶\nThis test checks whether the app uses StrictMode. While useful for developers to log policy violations such as disk I/O or network operations during development, it can expose sensitive implementation details in the logs that could be exploited by attackers.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should identify all instances of StrictMode usage in the app.\n\nEvaluation¶\nThe test case fails if the app uses StrictMode APIs.\n\nDemos¶\n MASTG-DEMO-0039: Detecting StrictMode PenaltyLog Usage with Semgrep = https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0039/MASTG-DEMO-0039/',
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Debugging Symbols in Native Binaries',
        "content": 'Overview¶\nThis test checks whether the app includes debugging symbols in its native binaries. Debugging symbols can provide valuable information during reverse engineering and vulnerability analysis by exposing sensitive implementation details such as function names, variable names, and source file references.\n\nSteps¶\nUse  Obtaining Debugging Information and Symbols to retrieve any debugging information present in the native binaries.\nObservation¶\nThe output should identify all instances of debugging information in the native binaries.\n\nEvaluation¶\nThe test case fails if debugging information is present in any native binary, including if actual debugging symbols were successfully extracted.',
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'References to Root Detection Mechanisms',
        "content": 'Overview¶\nThis test checks whether the app implements root detection by statically analyzing the app binary for common root detection patterns. These may include checks for files and artifacts typically associated with rooted devices, as well as calls to known root detection APIs or libraries.\n\nSee  Root Detection for more information on root detection techniques and specific APIs and artifacts to look for.\n\nThis test is best combined with  Runtime Use of Root Detection Techniques, which performs dynamic testing to confirm whether the identified root detection mechanisms are active at runtime. This way, you can use static analysis to surface potential root detection logic and then focus your dynamic testing on those specific checks to confirm they are triggered at runtime. Alternatively, you can perform dynamic testing first to identify any root detection mechanisms that are active at runtime, and then use static analysis to further investigate their implementation and coverage.\n\nOut of Scope\n\nThis test does not cover robustness or effectiveness of root detection mechanisms, which can be very difficult to assess through static analysis alone and may require manual reverse engineering and custom instrumentation. See  Implementing Root Detection for best practices on implementing root detection effectively and understanding its limitations.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should contain a list of locations where root detection checks are implemented, including specific methods and file paths being checked.\n\nEvaluation¶\nThe test case fails if the app does not implement any root detection checks. However, note that static analysis may not detect all root detection mechanisms, especially if they are proprietary, obfuscated, or implemented in native code.\n\nIf root detection checks are found, this is a positive sign, but you should still evaluate their effectiveness. See  Implementing Root Detection.\n\nBest Practices¶\n MASTG-BEST-0029: Implementing Resilience and RASP Signals = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0029/\n MASTG-BEST-0030: Implementing Root Detection = https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0030/\n\nDemos¶\n MASTG-DEMO-0087: Uses of Root Detection Techniques with Semgrep = https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0087/MASTG-DEMO-0087/',
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Runtime Use of Root Detection Techniques',
        "content": 'Overview¶\nThis test verifies whether an app implements runtime root detection by attempting to hook into common root detection mechanisms. These may include checks for files and artifacts typically associated with rooted devices, as well as calls to known root detection APIs or libraries.\n\nSee  Root Detection for more information on root detection techniques and specific APIs and artifacts to look for.\n\nThis test is best combined with  References to Root Detection Mechanisms, which checks for the presence of root detection logic through static analysis. This way, you can obtain a list of potential root detection mechanisms from static analysis and then focus your dynamic testing on those specific checks to confirm they are triggered at runtime. Or you can perform dynamic testing first to identify any root detection mechanisms that are active at runtime, and then use static analysis to further investigate their implementation and coverage.\n\nIt is recommended to run this test using a rooted device or emulator to ensure that root detection mechanisms are triggered during testing. However, even on a non-rooted device, this test can still surface root detection logic if the app performs checks that do not require root access (for example, checking for the presence of root-related files or system properties).\n\nOut of Scope\n\nThis test does not cover robustness or effectiveness of root detection mechanisms, which can be very difficult to assess through automated testing alone and may require manual reverse engineering and custom instrumentation. See  Implementing Root Detection for best practices on implementing root detection effectively.\n\nIn this test we focus our approach on identifying the presence of root detection mechanisms at runtime by hooking into common root detection APIs and tracing relevant system calls. But, optionally, you can use  Bypassing Root Detection to try to bypass root detection checks in the app and observe the results. For example, successful bypassing of certain checks or failed detections may indicate the presence of root detection mechanisms.\n\nSteps¶\nUse  Installing Apps to install the app.\nUse  Method Hooking to hook the relevant API calls.\nUse  Execution Tracing to trace the relevant system API calls.\nExercise the app extensively to trigger as many flows as possible and enter sensitive data wherever you can.\nObservation¶\nThe output should contain any instances of root detection checks, along with the methods or APIs that were hooked',
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Runtime Use of Hook Detection Techniques',
        "content": "Overview¶\nThis test verifies whether the app detects and responds to instrumentation and hooking attempts at runtime. For example, if the app does not terminate immediately when the following methods are called:\n\nAuthentication tokens, OAuth tokens, session credentials, and stored account passwords could be extracted if AccountManager.getPassword() ↗, AccountManager.getAuthToken() ↗ are hooked.\nCryptographic keys and certificates could be extracted if KeyStore.getKey() ↗, KeyStore.getCertificate() ↗ are hooked.\nEphemeral/Session Keys could be extracted if Cipher.doFinal() ↗ is hooked.\nDatabase contents could be extracted if SQLiteDatabase.rawQuery() ↗, SQLiteDatabase.query() ↗, SQLiteDatabase.execSQL() ↗ are hooked.\nEncrypted data could be extracted if EncryptedSharedPreferences ↗ APIs are hooked.\nAuthentication could be bypassed if KeyGenParameterSpec.Builder.setUserAuthenticationRequired() ↗ is hooked.\nAny other function that processes or returns sensitive data is hooked.\nWarning\n\nThis list is just indicative, and each app may have its own defensive response mechanisms.\n\nSteps¶\nUse  Installing Apps to install the app.\nUse  Method Hooking to hook the relevant API calls.\nExercise the app extensively to trigger as many flows as possible and enter sensitive data wherever you can.\nObservation¶\nThe output should contain one of the following:\n\nThe expected hook callback data (e.g., function arguments, return values).\nSession termination, script errors, empty responses, or absence of expected hook data.\nEvaluation¶\nThe test case fails if the hook executes successfully and returns the expected data, indicating the app lacks runtime integrity verification.\n\nThe test case passes if the hooking attempt fails due to the app's defensive response (e.g., session terminates unexpectedly, hook callbacks never execute, or the process exits).\n\nNote\n\nEven if the test case passes, it might still be possible to bypass the app's defensive response.  Reverse Engineering Tool Detection and  Runtime Integrity Verification describe such challenges.\n\nBest Practices¶\n MASTG-BEST-0041: Hardening Against Runtime Hooking - https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0041/\n\nDemos¶\n MASTG-DEMO-0107: Detecting Frida hooks and terminating the application on response - https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0107/MASTG-DEMO-0107/\n MASTG-DEMO-0108: Bypassing Frida Detection in /proc/self/maps to Extract Sensitive Data = https://mas.owasp.org/MASTG/demos",
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Runtime Use of Emulator Detection Techniques',
        "content": 'Overview¶\nThis test verifies whether an app implements runtime emulator detection by attempting to hook into common emulator detection mechanisms. These may include checks for build properties and artifacts typically associated with emulated devices, as well as calls to known emulator detection APIs.\n\nSee  Emulator Detection for more information on emulator detection techniques and specific APIs and artifacts to look for.\n\nIt is recommended to run this test on an emulator to ensure that emulator detection mechanisms are triggered during testing. However, some checks may still surface on a physical device if the app runs them unconditionally.\n\nOut of Scope\n\nThis test does not cover robustness or effectiveness of emulator detection mechanisms, which can be very difficult to assess through automated testing alone and may require manual reverse engineering and custom instrumentation. See  Hardening Against Emulation for best practices on implementing emulator detection effectively.\n\nIn this test we focus our approach on identifying the presence of emulator detection mechanisms at runtime by hooking into common emulator detection APIs and tracing relevant system calls. But, optionally, you can try to bypass emulator detection checks in the app and observe the results. For example, successful bypassing of certain checks or failed detections may indicate the presence of emulator detection mechanisms.\n\nSteps¶\nUse  Installing Apps to install the app.\nUse  Method Hooking to hook the relevant API calls.\nUse  Execution Tracing to trace the relevant system API calls.\nExercise the app extensively to trigger as many flows as possible and enter sensitive data wherever you can.\nObservation¶\nThe output should contain any instances of emulator detection checks, along with the methods or APIs that were hooked.\n\nEvaluation¶\nThe test case fails if no instances of emulator detection checks are observed. However, results from this test should be interpreted as evidence of the presence of emulator detection logic, not as an assessment of its robustness or effectiveness. See  Hardening Against Emulation.\n\nExpected False Negatives:\n\nThis test may produce false negatives if the app uses emulator detection techniques that are not covered by the hooks or traces used in this test, or if the emulator detection logic is implemented in a way that evades detection (for example, through obfuscation, dynamic code loading, or anti-instrumentation techniques). In such cases, the absence of find',
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'References to Debugging Detection APIs',
        "content": 'Overview¶\nApps can implement debugging detection at the Java/Kotlin level using APIs such as Debug.isDebuggerConnected() ↗, or at the native level using mechanisms such as ptrace calls, TracerPid checks in /proc/self/status, or inlined syscalls. If these checks are absent or not applied in security-relevant code paths, an attacker can attach a debugger undetected and use it to inspect or modify runtime state, extract sensitive data, or bypass security controls.\n\nSee  Anti-Debugging for more information on debugging detection techniques and specific APIs and artifacts to look for.\n\nThis test checks whether the app references JDWP and/or native debugging detection mechanisms in its code.\n\nThis test is best combined with  Runtime Use of Debugging Detection APIs, which performs dynamic testing to confirm whether the identified debugging detection mechanisms are active at runtime. Use the findings from this test to focus dynamic analysis in  Runtime Use of Debugging Detection APIs on specific checks.\n\nOut of Scope\n\nThis test does not cover robustness or effectiveness of debugging detection mechanisms, which can be very difficult to assess through static analysis alone and may require manual reverse engineering and custom instrumentation. See  Continuous Anti-Debugging Checks for best practices on implementing debugging detection effectively.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for Java/Kotlin debugging detection APIs.\nUse  Extracting Bundled Native Libraries to extract the native libraries from the app package.\nUse  Disassembling Native Code to look for native debugging detection patterns in the extracted libraries, such as calls to ptrace, reads of /proc/self/status, or checks for the TracerPid field.\nObservation¶\nThe output should contain a list of locations in the Java/Kotlin code and/or native libraries where debugging detection patterns are found.\n\nEvaluation¶\nThe test case fails if the app contains no debugging detection patterns in either its Java/Kotlin code or its native libraries. However, note that static analysis may not detect all debugging detection mechanisms, especially if they are obfuscated or implemented in native code using patterns not covered by the analysis.\n\nIf debugging detection patterns are found, this is a positive sign, but you should still evaluate their effectiveness using  Runtime Use of Debugging Detection APIs.\n\nFurther Validation Required:\n\nInspect ',
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Runtime Use of Debugging Detection APIs',
        "content": "Overview¶\nEven if an app references debugging detection APIs, those checks may not execute in security-relevant code paths at runtime. For example, they may only run in debug build variants, fire only once at startup, or be dead code that's never reached. If the app doesn't invoke its debugging detection logic at the right moments, an attacker can attach a debugger without triggering any defensive response.\n\nSee  Anti-Debugging for more information on debugging detection techniques and specific APIs and artifacts to look for.\n\nThis test hooks debugging detection APIs at runtime to confirm whether they are invoked during app execution.\n\nThis test is best combined with  References to Debugging Detection APIs, which checks for the presence of debugging detection logic through static analysis. Obtain a list of potential debugging detection mechanisms from static analysis and then focus your dynamic testing on those specific checks to confirm they are triggered at runtime. Alternatively, you can perform dynamic testing first to identify any debugging detection mechanisms that are active at runtime, and then use static analysis to further investigate their implementation and coverage.\n\nIt is recommended to run this test while actively attempting to attach a debugger (or on a debuggable build), to ensure that debugging detection mechanisms are triggered during testing. However, even without attaching a debugger, this test can still surface debugging detection logic if the app runs those checks unconditionally.\n\nOut of Scope\n\nThis test does not cover robustness or effectiveness of debugging detection mechanisms, which can be very difficult to assess through automated testing alone and may require manual reverse engineering and custom instrumentation. See  Continuous Anti-Debugging Checks for best practices on implementing debugging detection effectively.\n\nIn this test we focus on identifying the presence of debugging detection mechanisms at runtime by hooking into common debugging detection APIs and tracing relevant system calls.\n\nSteps¶\nUse  Installing Apps to install the app.\nUse  Method Hooking to hook the relevant API calls.\nUse  Execution Tracing to trace the relevant system API calls.\nExercise the app extensively to trigger as many flows as possible and enter sensitive data wherever you can.\nObservation¶\nThe output should contain a list of calls to debugging detection APIs observed at runtime, including their return values and backtraces.\n\nEvaluation¶\nThe te",
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Undeclared PII in Network Traffic Capture',
        "content": "Overview¶\nAttackers may capture network traffic from Android devices using an intercepting proxy, such as  ZAP (Zed Attack Proxy),  Burp Suite, or  mitmproxy, to analyze the data being transmitted by the app. This works even if the app uses HTTPS, as the attacker can install a custom root certificate on the Android device to decrypt the traffic. Inspecting traffic that is not encrypted with HTTPS is even easier and can be done without installing a custom root certificate for example by using  Wireshark.\n\nThe goal of this test is to verify that sensitive data, specifically PII, is not being sent over the network, even if the traffic is encrypted. This test is especially important for apps that handle sensitive data, such as financial or health data, and should be performed in conjunction with a review of the app's privacy policy and the app's marketplace privacy declarations (e.g., Data Safety section in Google Play).\n\nSteps¶\nUse  Installing Apps to install the app.\nUse  Logging Sensitive Data from Network Traffic to capture and log the app's network traffic.\nLaunch and use the app going through the various workflows while inputting sensitive data wherever you can. Especially, places where you know that will trigger network traffic.\nObservation¶\nThe output should contain a network traffic log that includes the decrypted HTTPS traffic.\n\nEvaluation¶\nThe test case fails if you can find the PII you entered in the app that is not declared in the app's marketplace privacy declarations (e.g., Data Safety section in Google Play) and/or in its privacy policy.\n\nNote that this test does not provide any code locations where the sensitive data is being sent over the network. In order to identify the code locations you can use  Static Analysis on Android or  Dynamic Analysis on Android. Consult  References to SDK APIs Known to Handle Sensitive User Data and  Runtime Use of SDK APIs Known to Handle Sensitive User Data, respectively, for more details.\n\nDemos¶\n MASTG-DEMO-0009: Detecting Undeclared PII in Network Traffic - https://mas.owasp.org/MASTG/demos/android/MASVS-PRIVACY/MASTG-DEMO-0009/MASTG-DEMO-0009/",
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Dangerous App Permissions',
        "content": "Overview¶\nIn Android apps, permissions are acquired through different methods to access information and system functionalities, including the camera, location, or storage. The necessary permissions are specified in the AndroidManifest.xml file with <uses-permission> tags.\n\nSteps¶\nUse  Obtaining Information from the AndroidManifest to obtain the AndroidManifest.xml.\nUse  Obtaining App Permissions to obtain the list of declared permissions.\nObservation¶\nThe output should contain the list of permissions declared by the app.\n\nEvaluation¶\nThe test case fails if there are any dangerous permissions in the app.\n\nCompare the list of declared permissions with the list of dangerous permissions ↗ defined by Android. You can find more details in the Android documentation ↗.\n\nContext Consideration:\n\nContext is essential when evaluating permissions. For example, an app that uses the camera to scan QR codes should have the CAMERA permission. However, if the app does not have a camera feature, the permission is unnecessary and should be removed.\n\nAlso, consider if there are any privacy-preserving alternatives to the permissions used by the app. For example, instead of using the CAMERA permission, the app could use the device's built-in camera app ↗ to capture photos or videos by invoking the ACTION_IMAGE_CAPTURE or ACTION_VIDEO_CAPTURE intent actions. This approach allows the app to access the camera functionality without directly requesting the CAMERA permission, thereby enhancing user privacy.\n\nDemos¶\n MASTG-DEMO-0033: Dangerous Permissions in the AndroidManifest with semgrep - https://mas.owasp.org/MASTG/demos/android/MASVS-PRIVACY/MASTG-DEMO-0033/MASTG-DEMO-0033/",
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'References to SDK APIs Known to Handle Sensitive User Data',
        "content": "Overview¶\nThis test verifies whether an app uses SDK (third-party library) APIs known to handle sensitive user data (e.g., as defined in Google Play's Data safety section ↗ or the relevant privacy regulations).\n\nAs a prerequisite, we need to identify the SDK API methods it uses as entry points for data collection by reviewing the library's documentation or codebase. For example, Google Analytics for Firebase ↗ in its class FirebaseAnalytics provides methods such as setUserId ↗, setUserProperty ↗, and logEvent ↗ that can be used to collect user data.\n\nNote: This test detects only potential sensitive user data handling. For confirming that actual user data are being shared, please refer to  Runtime Use of SDK APIs Known to Handle Sensitive User Data.\n\nSteps¶\nUse  Reverse Engineering Android Apps to reverse engineer the app.\nUse  Static Analysis on Android to look for the relevant APIs.\nObservation¶\nThe output should list the locations where SDK methods are called.\n\nEvaluation¶\nThe test case fails if you can find the use of these SDK methods in the app code, indicating that the app is sharing sensitive user data with the third-party SDK.",
    },
    {
        "section": 'RESILIENCE',
        "level":   'L2',
        "name":    'Runtime Use of SDK APIs Known to Handle Sensitive User Data',
        "content": 'Overview¶\nThis test is the dynamic counterpart to  References to SDK APIs Known to Handle Sensitive User Data.\n\nIn this case we will hook any SDK methods known to handle sensitive user data.\n\nSteps¶\nUse  Installing Apps to install the app.\nUse  Method Hooking to hook the relevant API calls.\nExercise the app extensively to trigger as many flows as possible and enter sensitive data wherever you can.\nObservation¶\nThe output should list the locations where SDK methods are called, their stacktrace (call hierarchy leading to the call), and the arguments (values) passed to the SDK method at runtime.\n\nEvaluation¶\nThe test case fails if you can find sensitive user data being passed to these SDK methods in the app code, indicating that the app is sharing sensitive user data with the third-party SDK.\n\nDemos¶\n MASTG-DEMO-0081: Sensitive User Data Sent to Firebase Analytics with Frida - https://mas.owasp.org/MASTG/demos/android/MASVS-PRIVACY/MASTG-DEMO-0081/MASTG-DEMO-0081/',
    },
]


# ── Self-update ───────────────────────────────────────────────────────────────
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
        SCRIPT_PATH.write_bytes(remote)
        print(f"  {_G}[✓] Updated successfully. Please restart the script.{_R}")
        sys.exit(0)


# ── Prompt-improvement store (persists across sessions) ───────────────────────
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


# ── Session state ─────────────────────────────────────────────────────────────
def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return _sanitize_session_paths(json.load(f))
        except Exception:
            return {}
    return {}

def save_state(state: dict) -> None:
    _sanitize_session_paths(state)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)

def new_session(tests, app_name, pkg_name,
                apk_path, decomp_path, level_filter,
                model="claude", ollama_model="", ollama_host=OLLAMA_HOST):
    return {
        "session_id":       datetime.datetime.now().strftime("%Y%m%d_%H%M%S"),
        "app_name":         app_name,
        "package_name":     pkg_name,
        "apk_path":         _clean_terminal_text(apk_path),
        "decompiled_path":  _clean_terminal_text(decomp_path),
        "level_filter":     level_filter,
        "model":            model,
        "ollama_model":     ollama_model,
        "ollama_host":      ollama_host,
        "created_at":       datetime.datetime.now().isoformat(),
        "last_run":         None,
        "tests":            tests,
        "last_report_path": None,
    }


def _list_ollama_models(host=OLLAMA_HOST, port=OLLAMA_PORT):
    """Return list of model names available on the Ollama server, or []."""
    try:
        url = f"http://{host}:{port}/api/tags"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        return [m["name"] for m in data.get("models", [])]
    except Exception:
        return []


def _pick_ollama_model(host=OLLAMA_HOST, port=OLLAMA_PORT):
    """Interactively select an Ollama model. Returns model cfg dict."""
    print(f"\n  {_C}[*] Connecting to Ollama at {host}:{port}…{_R}", end="", flush=True)
    models = _list_ollama_models(host, port)

    if models:
        print(f" {_G}OK{_R}  ({len(models)} model(s) available)\n")
        for i, m in enumerate(models, 1):
            print(f"  {_C}{i}{_R}  {m}")
        print()
        while True:
            ch = input(f"  Select model [1-{len(models)}]: ").strip()
            if ch.isdigit() and 1 <= int(ch) <= len(models):
                chosen = models[int(ch) - 1]
                print(f"  {_G}[✓] Using Ollama: {chosen}{_R}")
                return {"model": "ollama", "ollama_model": chosen, "ollama_host": host}
            if ch:  # allow typing a name directly
                print(f"  {_G}[✓] Using Ollama: {ch}{_R}")
                return {"model": "ollama", "ollama_model": ch, "ollama_host": host}
    else:
        print(f" {_Y}unreachable or no models found{_R}")
        name = input(
            f"  Enter model name manually (e.g. llama3:latest), or Enter to cancel: "
        ).strip()
        if name:
            print(f"  {_G}[✓] Using Ollama: {name}{_R}")
            return {"model": "ollama", "ollama_model": name, "ollama_host": host}
        print(f"  {_Y}Cancelled – falling back to Claude.{_R}")
        return {"model": "claude", "ollama_model": "", "ollama_host": host}


def _choose_model():
    """Ask the user to pick the AI runner. Returns a cfg dict."""
    print(f"  {_B}AI model:{_R}")
    print(f"  {_G}1{_R}  Claude  (claude -p)               {_D}← default{_R}")
    print(f"  {_C}2{_R}  Codex   (codex exec)")
    print(f"  {_Y}3{_R}  Ollama  (remote at {OLLAMA_HOST}:{OLLAMA_PORT})")
    while True:
        ch = input("  Choice [1/2/3, default=1]: ").strip()
        if ch in ("", "1"):
            print(f"  {_G}[✓] Using Claude{_R}")
            return {"model": "claude", "ollama_model": "", "ollama_host": OLLAMA_HOST}
        if ch == "2":
            print(f"  {_C}[✓] Using Codex  (codex exec){_R}")
            return {"model": "codex", "ollama_model": "", "ollama_host": OLLAMA_HOST}
        if ch == "3":
            return _pick_ollama_model()
        print(f"  {_Y}Enter 1, 2, or 3.{_R}")


# ── Prompt builder ────────────────────────────────────────────────────────────
_ENV_CONTEXT = """\
## ENVIRONMENT
- OS              : Kali Linux
- ADB device      : Android phone/emulator connected via USB
                    Verify : adb devices
                    Packages: adb shell pm list packages
- Frida server    : running on device
                    Verify : frida-ps -U | head -20
- Tools available : adb, frida, frida-ps, objection, jadx, apktool,
                    apksigner, openssl, grep, strings, semgrep, sqlite3,
                    burpsuite / mitmproxy  (for traffic interception)
"""

def build_prompt(test, session, improvement, model="claude"):
    all_tests = session["tests"]
    idx       = next((i for i, t in enumerate(all_tests) if t["name"] == test["name"]), 0)
    total     = len(all_tests)
    run_cnt   = improvement.get("run_count", 0)

    if improvement.get("current_prompt"):
        guidance     = improvement["current_prompt"]
        guidance_src = "(refined from previous run – use as primary guidance)"
    else:
        guidance     = test.get("content") or "No specific guidance – apply MASTG methodology."
        guidance_src = "(from embedded MASTG test definitions)"

    extras = ""
    fps = improvement.get("false_positives", [])
    if fps:
        extras += "\n### Known False Positives – skip these\n"
        for fp in fps[:10]:
            extras += f"- {fp}\n"
    cmds = improvement.get("known_commands", [])
    if cmds:
        extras += "\n### Commands that found issues in previous runs\n"
        for cmd in cmds[:10]:
            extras += f"- `{cmd}`\n"

    # Build optional sections as plain strings (can't nest triple-quotes in f-strings)
    if model == "ollama":
        _ollama_section = (
            "\n## HOW TO RUN COMMANDS\n"
            "You cannot run commands yourself, but the test harness will run them for you.\n"
            "To execute a command, write it inside <run_command> tags (EXACTLY this format):\n\n"
            "  <run_command>adb devices</run_command>\n"
            "  <run_command>grep -rn \"password\" --include=\"*.smali\" -l</run_command>\n\n"
            "After you write your <run_command> blocks the harness will stop, execute each\n"
            "command on the real Kali Linux machine, and return the real output wrapped in\n"
            "<command_output> tags. You then continue your analysis.\n\n"
            "STRICT RULES — breaking these will invalidate the test:\n"
            "1. NEVER write <command_output> yourself. ONLY the harness writes those.\n"
            "2. NEVER simulate, guess, or assume command output. Wait for the real result.\n"
            "3. Use EXACTLY <run_command>...</run_command> — no variations, no underscores removed.\n"
            "4. Run 2-5 commands per turn, then STOP and wait for the output before continuing.\n"
            "5. ONLY write the ===TEST_RESULT_START=== block when you have real evidence.\n"
            "6. Do NOT include <run_command> tags inside the result block.\n"
        )
    else:
        _ollama_section = ""

    if model in ("claude", "codex"):
        _script_section = (
            "\n## SCRIPT SELF-IMPROVEMENT (optional)\n"
            "You are running with filesystem access. If during this test you discover that\n"
            f"the embedded test guidance for \"{test['name']}\" is incomplete or misleading,\n"
            "you may edit this script directly to improve it:\n\n"
            f"  {SCRIPT_PATH}\n\n"
            "What you may change:\n"
            f"  - The `content` value for the test named \"{test['name']}\" in the TESTS list\n"
            f"    (search for  name=\"{test['name']}\"  and update its `content` key)\n"
            "  - Nothing else – do NOT alter test names, levels, sections, or script logic\n\n"
            "If you make changes, note what you changed and why in the NOTES section above.\n"
        )
    else:
        _script_section = ""

    return f"""\
You are an expert Android application security tester performing OWASP MASTG tests.

{_ENV_CONTEXT}
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
0. SCOPE CONSTRAINT – you are performing ONE test only: "{test["name"]}".
   Do NOT investigate, report, or run commands for any other test or issue.
   If you notice something unrelated, record it in NOTES as a one-line observation
   and move on. Do not pursue it further.
1. Perform this test using only commands directly relevant to its guidance. Run the
   minimum number of commands needed to reach a conclusion — stop as soon as you have
   sufficient evidence. Do NOT keep running extra commands once a finding is confirmed.
2. STOP AND WRITE THE RESULT BLOCK as soon as you have confirmed evidence (or confirmed
   absence of the issue). Do not run follow-up commands "to gather more detail" after a
   finding is confirmed — that detail belongs in a separate dedicated test.
3. Evidence must include file paths, line numbers, or command output – no assumptions.
4. Flag any findings that are library/framework code (not app code) as low-priority.
5. Note any false positives explicitly so future runs can skip them.
6. When done, output the result block below EXACTLY – do not alter the delimiters.
{_ollama_section}

===TEST_RESULT_START===
STATUS: PASS|FAIL|INFO|SKIP
SEVERITY: Critical|High|Medium|Low|Info|N/A
FALSE_POSITIVES:
- <false positive you identified, or "None">
JIRA_TICKET_SUMMARY:
<one-line Jira title; blank if PASS>
JIRA_TICKET_DESCRIPTION:
<2-3 sentence description of the issue and why it matters; blank if PASS>
JIRA_TICKET_CONCERN:
<one paragraph explaining the specific security concern and risk to the app or its users; blank if PASS>
JIRA_TICKET_STEPS:
<numbered steps to reproduce the finding; blank if PASS>
JIRA_TICKET_EVIDENCE:
<specific evidence bullets: file paths, command output excerpts, line numbers; blank if PASS>
JIRA_TICKET_RECOMMENDATION:
<what the developer must do to fix this; blank if PASS>
===TEST_RESULT_END===

Now suggest an improved version of the TEST GUIDANCE section for the next run:
===PROMPT_IMPROVEMENT_START===
<rewrite only the guidance – incorporate what you learned, useful commands, edge cases>
===PROMPT_IMPROVEMENT_END===

Finally, mark this test complete by printing this exact line:
TEST_COMPLETED: {test["name"]}
{_script_section}"""


# ── Grep augmentation ────────────────────────────────────────────────────────
def _augment_grep(cmd, decomp_path):
    """
    For grep commands issued by Ollama that have no explicit search path,
    automatically append all smali* directories from the decompiled APK so
    searches hit the right source files.

    Only modifies the command when:
      - it starts with 'grep'
      - it does not already reference 'smali', the decompiled path, or end with
        a path-like token (starts with / or ~, or is . or ..)
    """
    if not re.match(r"^grep\b", cmd.strip()):
        return cmd

    # Already has smali or an absolute/relative path → leave untouched
    if re.search(r"smali", cmd) or (decomp_path and decomp_path in cmd):
        return cmd

    # Check whether the last token looks like a path argument
    tokens = cmd.split()
    if tokens:
        last = tokens[-1]
        # Flags start with - ; patterns are quoted; paths start with / ~ . or are bare dirs
        if last.startswith("/") or last.startswith("~") or last in (".", ".."):
            return cmd  # already has a path

    # Build smali target: if decomp_path given, use absolute glob; else relative
    if decomp_path:
        import glob as _glob
        smali_dirs = _glob.glob(os.path.join(decomp_path, "smali*"))
        if smali_dirs:
            target = " ".join(smali_dirs)
        else:
            target = os.path.join(decomp_path, "smali")
    else:
        target = "smali*"

    return f"{cmd} {target}"


# ── Claude runner ─────────────────────────────────────────────────────────────
def run_claude(prompt, cwd=None, timeout=600, model="claude",
               ollama_model="", ollama_host=OLLAMA_HOST, test_name=""):
    """Run the selected AI model with the given prompt. Returns (ok, full_output)."""
    import threading, time

    if model == "ollama":
        label = f"Ollama  ({ollama_model})"
    elif model == "codex":
        label = "Codex output"
    else:
        label = "Claude output"

    w = _term_w()
    print(f"\n  {_C}┌{'─' * w}┐{_R}")
    print(f"  {_C}│{label:^{w}}│{_R}")
    print(f"  {_C}├{'─' * w}┤{_R}")

    # Spinner so the user knows the process is alive
    spinning = [True]
    tick = [0]

    def _spin():
        chars = r"|/-\\"
        while spinning[0]:
            c = chars[tick[0] % len(chars)]
            print(
                f"\r  {_C}│ {c} Waiting for {label.split()[0]}… {tick[0]}s{_R}{'':>{w - 30}}  ",
                end="", flush=True,
            )
            time.sleep(1)
            tick[0] += 1
        # clear the spinner line so box lines look clean
        print(f"\r  {_C}│{' ' * w}│{_R}")

    spin_t = threading.Thread(target=_spin, daemon=True)
    spin_t.start()

    try:
        if model == "ollama":
            # ── Ollama agentic loop ───────────────────────────────────────────
            # Ollama only generates text; we execute any <run_command> blocks
            # it produces, feed the output back, and loop until it writes the
            # ===TEST_RESULT_START=== block or we hit the step limit.
            MAX_STEPS   = 25
            CMD_TIMEOUT = 30          # seconds per shell command
            MAX_CMD_OUT = 3000        # chars of output to feed back per command
            conversation  = prompt
            all_responses = []

            def _ollama_call(conv):
                url = f"http://{ollama_host}:{OLLAMA_PORT}/api/generate"
                pay = json.dumps({
                    "model":  ollama_model,
                    "prompt": conv,
                    "stream": True,
                }).encode("utf-8")
                req = urllib.request.Request(
                    url, data=pay,
                    headers={"Content-Type": "application/json"},
                )
                pieces = []
                line_buf = ""
                visible_started = False
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    for raw_line in r:
                        if not raw_line.strip():
                            continue
                        try:
                            ev = json.loads(raw_line.decode("utf-8", errors="replace"))
                        except json.JSONDecodeError:
                            continue
                        chunk = ev.get("response", "")
                        if chunk:
                            if not visible_started:
                                spinning[0] = False
                                spin_t.join(2)
                                visible_started = True
                            pieces.append(chunk)
                            line_buf += chunk
                            while "\n" in line_buf:
                                line, line_buf = line_buf.split("\n", 1)
                                _print_response_lines(line)
                        if ev.get("done"):
                            break
                if visible_started and line_buf.strip():
                    _print_response_lines(line_buf)
                return "".join(pieces)

            # Regex catches <run_command> AND common model variations like <runcommand>
            _CMD_TAG = re.compile(r"<run_?command>(.*?)</run_?command>",
                                  re.DOTALL | re.IGNORECASE)
            # Strip model-hallucinated <command_output> blocks before feeding back
            _OUT_TAG = re.compile(r"<command_output>.*?</command_output>",
                                  re.DOTALL | re.IGNORECASE)

            no_cmd_streak = 0
            _seen_cmds    = set()   # deduplicate commands within this test run

            # Regex to detect tag lines for display filtering
            _TAG_RE = re.compile(
                r"</?run_?command|</?command_output|<system_instruction",
                re.IGNORECASE,
            )
            # A "command" that is only a bare file path is not runnable
            _PATH_ONLY = re.compile(r"^/\S+\.\w{1,6}$")

            def _print_response_lines(txt):
                for ln in txt.splitlines():
                    cl = ln.strip()
                    if (cl
                            and not cl.startswith("===")
                            and not cl.startswith("TEST_COMPLETED")
                            and not cl.startswith("STATUS:")
                            and not cl.startswith("SEVERITY:")
                            and not _TAG_RE.search(cl)):
                        print(f"\r  {_D}│ {cl[:w-2]:<{w-2}} │{_R}")

            for step in range(MAX_STEPS):
                print(f"\r  {_C}│ Ollama step {step + 1}/{MAX_STEPS}: generating response…{' ' * 14}│{_R}")
                response = _ollama_call(conversation)
                all_responses.append(response)

                if "===TEST_RESULT_START===" in response:
                    print(f"\r  {_G}│ Ollama produced final result block.{' ' * 35}│{_R}")
                    break

                clean_response = _OUT_TAG.sub("", response).strip()
                cmds = _CMD_TAG.findall(clean_response)

                if not cmds:
                    no_cmd_streak += 1
                    print(f"\r  {_Y}│ Ollama did not request commands on this step ({no_cmd_streak}/3).{' ' * 8}│{_R}")
                    if no_cmd_streak >= 3:
                        conversation += (
                            f"\n\n{clean_response}\n\n"
                            "STOP. You have not run any commands for several turns.\n"
                            "Based on the evidence collected so far, output ONLY the "
                            "result block below (fill in the brackets):\n\n"
                            "===TEST_RESULT_START===\n"
                            f"**Test:** {test_name}\n"
                            "**Status:** [PASS or FAIL or PARTIAL]\n"
                            "**Severity:** [Critical/High/Medium/Low/Info]\n"
                            "**Findings:**\n[your findings]\n"
                            "**Recommendations:**\n[your recommendations]\n"
                            "===TEST_RESULT_END===\n"
                            f"TEST_COMPLETED: {test_name}"
                        )
                    else:
                        conversation += (
                            f"\n\n{clean_response}\n\n"
                            "REMINDER: Use <run_command>your command</run_command> to run "
                            "commands. Do NOT write <command_output> yourself. "
                            "Run the next 2-5 commands now, or write the "
                            "===TEST_RESULT_START=== block if you have enough evidence."
                        )
                    continue

                no_cmd_streak = 0
                cmd_outputs = []
                print(f"\r  {_C}│ Ollama requested {len(cmds)} command(s); executing now.{' ' * 20}│{_R}")
                for raw_cmd in cmds:
                    cmd = _augment_grep(raw_cmd.strip(), cwd)
                    # Skip bare file paths (not shell commands)
                    if _PATH_ONLY.match(cmd.strip()):
                        print(f"\r  {_Y}│ Skipping non-command path: {cmd[:w-30]:<{w-30}} │{_R}")
                        continue
                    # Skip duplicates
                    if cmd in _seen_cmds:
                        print(f"\r  {_Y}│ Already executed: {cmd[:w-22]:<{w-22}} │{_R}")
                        cmd_outputs.append(
                            f"<command_output>\n$ {cmd}\n"
                            "[Already executed — see earlier output]\n"
                            "</command_output>"
                        )
                        continue
                    _seen_cmds.add(cmd)
                    print(f"\r  {_C}│ $ {cmd[:w-4]:<{w-4}} │{_R}")
                    try:
                        cr = subprocess.run(
                            cmd, shell=True,
                            capture_output=True, text=True,
                            timeout=CMD_TIMEOUT,
                            encoding="utf-8", errors="replace",
                            cwd=cwd or str(SCRIPT_DIR),
                        )
                        out_txt = (cr.stdout + cr.stderr).strip()
                        if len(out_txt) > MAX_CMD_OUT:
                            out_txt = out_txt[:MAX_CMD_OUT] + "\n... [truncated]"
                        print(f"\r  {_D}│   {len(out_txt)} chars{_R}")
                    except subprocess.TimeoutExpired:
                        out_txt = f"[TIMEOUT after {CMD_TIMEOUT}s]"
                    except Exception as ce:
                        out_txt = f"[ERROR: {ce}]"
                    cmd_outputs.append(
                        f"<command_output>\n$ {cmd}\n{out_txt}\n</command_output>"
                    )

                if cmd_outputs:
                    conversation += (
                        f"\n\n{clean_response}\n\n"
                        + "\n".join(cmd_outputs)
                        + "\n\nReal command output above. Analyse it and continue. "
                        "Do NOT write <command_output> yourself."
                    )

            else:
                # Max steps — force result block with pre-filled template
                print(f"\r  {_Y}│ [!] Max steps reached — forcing result block…{_R}")
                forced = _ollama_call(
                    conversation
                    + "\n\nMax steps reached. Write ONLY the block below "
                    "(fill in the brackets, no other text):\n\n"
                    "===TEST_RESULT_START===\n"
                    f"**Test:** {test_name}\n"
                    "**Status:** [PASS or FAIL or PARTIAL]\n"
                    "**Severity:** [Critical/High/Medium/Low/Info]\n"
                    "**Findings:**\n[summarise your findings from the evidence above]\n"
                    "**Recommendations:**\n[your recommendations]\n"
                    "===TEST_RESULT_END===\n"
                    f"TEST_COMPLETED: {test_name}\n\n"
                    "Start your response with ===TEST_RESULT_START==="
                )
                all_responses.append(forced)
                _print_response_lines(forced)

            spinning[0] = False
            spin_t.join(2)
            out = "\n\n".join(all_responses)

        elif model == "codex":
            # ── Codex — requires a real TTY (isatty check) ────────────────────
            # Run inside a PTY.  Codex reads its task from stdin so we send the
            # prompt after a short startup pause rather than as a CLI argument
            # (avoids arg-length and shell-escaping problems).
            import pty, os as _os, select as _select, struct, fcntl, termios
            codex_bin = _resolve_cli("codex") or "codex"

            def _strip_esc(txt):
                """Remove ANSI CSI, OSC, DCS and stray control codes."""
                # CSI  — \x1b[ ... final-byte
                txt = re.sub(r"\x1B\[[0-?]*[ -/]*[@-~]", "", txt)
                # OSC  — \x1b] ... BEL  or  ST (\x1b\\)
                txt = re.sub(r"\x1B\][^\x07\x1B]*(?:\x07|\x1B\\)", "", txt)
                # DCS / PM / APC
                txt = re.sub(r"\x1B[P_^][^\x1B]*\x1B\\", "", txt)
                # Remaining lone ESC + one char
                txt = re.sub(r"\x1B[@-Z\\-_]", "", txt)
                # Bare ESC
                txt = re.sub(r"\x1B", "", txt)
                # Non-printable control chars (keep \t \n \r)
                txt = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", txt)
                return txt

            master_fd, slave_fd = pty.openpty()
            try:
                # Give the slave a proper terminal size so Codex doesn't complain
                try:
                    ws = struct.pack("HHHH", 50, 220, 0, 0)
                    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, ws)
                except Exception:
                    pass
                try:
                    attrs = termios.tcgetattr(slave_fd)
                    attrs[3] = attrs[3] & ~termios.ECHO
                    termios.tcsetattr(slave_fd, termios.TCSANOW, attrs)
                except Exception:
                    pass

                _env = _cli_env(codex_bin if os.path.isabs(codex_bin) else None)
                _env.update({
                        "TERM": "xterm-256color",
                        "COLUMNS": "220", "LINES": "50",
                })

                # PTY is only here to satisfy Codex's isatty() check.
                # Prompt is sent on stdin to avoid OS argv limits on long
                # feedback prompts that include previous raw output.
                proc = subprocess.Popen(
                    [
                        codex_bin, "exec",
                        "--dangerously-bypass-approvals-and-sandbox",
                        "--skip-git-repo-check",
                        "--color", "never",
                        "-",
                    ],
                    stdin=slave_fd,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    close_fds=True,
                    cwd=cwd or str(SCRIPT_DIR),
                    preexec_fn=_os.setsid,
                    env=_env,
                )
                _os.close(slave_fd)
                slave_fd = -1

                chunks = []

                def _pty_send(text):
                    try:
                        _os.write(master_fd, text.encode("utf-8"))
                    except OSError:
                        pass

                _sent_prompt = False

                # Debug log path — shows raw PTY bytes so we can diagnose
                _dbg_path = SCRIPT_DIR / "codex_pty_debug.log"
                _dbg      = open(_dbg_path, "wb")

                # ── Startup: drain banner, auto-answer any y/n prompts ────
                _TRUST_PAT = re.compile(
                    r"trust|proceed|continue|allow|permission"
                    r"|y/n|yes/no|\[y\]|\[y/n\]|\(y\)|download.*apply",
                    re.IGNORECASE,
                )
                _trust_buf  = ""
                _trust_cool = 0.0
                _start_dl   = time.time() + 3
                while time.time() < _start_dl:
                    try:
                        r2, _, _ = _select.select([master_fd], [], [], 0.5)
                    except (ValueError, OSError):
                        break
                    if r2:
                        try:
                            d2 = _os.read(master_fd, 8192)
                        except OSError:
                            break
                        if d2:
                            chunks.append(d2)
                            _dbg.write(b"[STARTUP] " + d2 + b"\n")
                            _dbg.flush()
                            _trust_buf += _strip_esc(
                                d2.decode("utf-8", errors="replace")
                            )
                            if time.time() > _trust_cool and _TRUST_PAT.search(_trust_buf[-300:]):
                                time.sleep(0.3)
                                _pty_send("y\n")
                                _trust_buf  = ""
                                _trust_cool = time.time() + 1.5
                    if proc.poll() is not None:
                        break

                if proc.poll() is None:
                    _pty_send(prompt)
                    _os.write(master_fd, b"\n\x04")
                    _sent_prompt = True
                    _dbg.write(b"[PROMPT_SENT_STDIN]\n")
                    _dbg.flush()

                # ── Read until Codex finishes ─────────────────────────────
                # Exit when: process exits, idle IDLE_SECS (even with no
                # output at all), back at input prompt, or hard timeout.
                _DONE_PAT      = re.compile(r"(?:^|\n)\s*[>❯❱]\s*$", re.MULTILINE)
                IDLE_SECS      = 60
                NO_OUTPUT_SECS = 30   # give up if NOTHING arrives in 30 s
                MIN_DONE_CHARS = 400
                deadline       = time.time() + timeout
                p3_text        = ""
                last_data_t    = time.time()

                def _drain_pty():
                    while True:
                        try:
                            r2, _, _ = _select.select([master_fd], [], [], 0.05)
                            if not r2:
                                break
                            d2 = _os.read(master_fd, 8192)
                            if d2:
                                chunks.append(d2)
                            else:
                                break
                        except OSError:
                            break

                while time.time() < deadline:
                    try:
                        r, _, _ = _select.select([master_fd], [], [], 1.0)
                    except (ValueError, OSError):
                        break
                    if r:
                        try:
                            data = _os.read(master_fd, 8192)
                        except OSError:
                            break
                        if data:
                            chunks.append(data)
                            _dbg.write(b"[P3] " + data + b"\n")
                            _dbg.flush()
                            p3_text += _strip_esc(
                                data.decode("utf-8", errors="replace")
                            )
                            last_data_t = time.time()

                    if proc.poll() is not None:
                        time.sleep(0.4)
                        _drain_pty()
                        break

                    elapsed_idle = time.time() - last_data_t
                    # No output at all after NO_OUTPUT_SECS — something is wrong
                    if not p3_text and elapsed_idle > NO_OUTPUT_SECS:
                        _drain_pty()
                        proc.terminate()
                        try:
                            proc.wait(timeout=3)
                        except Exception:
                            proc.kill()
                        break

                    if len(p3_text.strip()) >= MIN_DONE_CHARS:
                        if _DONE_PAT.search(p3_text[-300:]):
                            _drain_pty()
                            proc.terminate()
                            try:
                                proc.wait(timeout=3)
                            except Exception:
                                proc.kill()
                            break
                        if elapsed_idle > IDLE_SECS:
                            _drain_pty()
                            proc.terminate()
                            try:
                                proc.wait(timeout=3)
                            except Exception:
                                proc.kill()
                            break

                    # After enough output, check whether Codex is back at its
                    # input prompt (task finished, waiting for next instruction)
                    if len(p3_text.strip()) >= MIN_DONE_CHARS:
                        if _DONE_PAT.search(p3_text[-300:]):
                            _drain_pty()
                            proc.terminate()
                            try:
                                proc.wait(timeout=3)
                            except Exception:
                                proc.kill()
                            break
                        # Also exit if idle for too long (command still running?)
                        if time.time() - last_data_t > IDLE_SECS:
                            _drain_pty()
                            proc.terminate()
                            try:
                                proc.wait(timeout=3)
                            except Exception:
                                proc.kill()
                            break
                else:
                    # Hard timeout
                    proc.kill()
                    proc.wait()

            finally:
                try:
                    _dbg.close()
                except Exception:
                    pass
                if slave_fd != -1:
                    try:
                        _os.close(slave_fd)
                    except OSError:
                        pass
                try:
                    _os.close(master_fd)
                except OSError:
                    pass

            spinning[0] = False
            spin_t.join(2)
            raw = b"".join(chunks).decode("utf-8", errors="replace")
            out = _strip_esc(raw)

            # If output is suspiciously short it likely means Codex didn't start
            # properly — surface the raw text so the user can diagnose
            if len(out.strip()) < 80:
                print(f"  {_Y}│ [!] Codex produced very little output.{_R}")
                print(f"  {_Y}│     Raw (first 200 chars): {raw[:200]!r}{_R}")
                print(f"  {_Y}│     Ensure 'codex' is authenticated: run 'codex' interactively first.{_R}")

        else:
            # ── Claude — stream-json so we can show tool calls live ────────────
            import queue as _queue
            claude_bin = _resolve_cli("claude") or "claude"
            proc_c = subprocess.Popen(
                [claude_bin, "-p", "--verbose",
                 "--dangerously-skip-permissions",
                 "--max-turns", "25",
                 "--output-format", "stream-json", prompt],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=cwd or str(SCRIPT_DIR),
                env=_cli_env(claude_bin if os.path.isabs(claude_bin) else None),
                bufsize=1,
            )

            _cq      = _queue.Queue()
            _out_buf = []   # collects plain-text lines for the final result

            def _c_reader():
                try:
                    for ln in proc_c.stdout:
                        _cq.put(ln)
                finally:
                    _cq.put(None)

            threading.Thread(target=_c_reader, daemon=True).start()

            _c_deadline = time.time() + timeout
            _got_output = False

            while time.time() < _c_deadline:
                try:
                    ln = _cq.get(timeout=1.0)
                except _queue.Empty:
                    if proc_c.poll() is not None:
                        break
                    continue
                if ln is None:
                    break

                if not _got_output:
                    spinning[0] = False
                    spin_t.join(2)
                    _got_output = True

                raw_ln = ln.rstrip()

                # Try to parse as a stream-json event
                try:
                    ev = json.loads(raw_ln)
                except (json.JSONDecodeError, ValueError):
                    # Plain text fallback (shouldn't happen with stream-json)
                    _out_buf.append(raw_ln)
                    _cl = raw_ln.strip()
                    if _cl and not _cl.startswith("===") and not _cl.startswith("TEST_COMPLETED"):
                        print(f"  {_D}│ {_cl[:w-2]:<{w-2}} │{_R}")
                    continue

                if not isinstance(ev, dict):
                    continue
                ev_type = ev.get("type", "")

                try:
                    if ev_type == "assistant":
                        for blk in ev.get("message", {}).get("content", []):
                            if not isinstance(blk, dict):
                                continue
                            if blk.get("type") == "text":
                                for tl in blk.get("text", "").splitlines():
                                    _out_buf.append(tl)
                                    cl = tl.strip()
                                    if cl and not cl.startswith("===") and not cl.startswith("TEST_COMPLETED"):
                                        print(f"  {_D}│ {cl[:w-2]:<{w-2}} │{_R}")
                            elif blk.get("type") == "tool_use":
                                tool_name = blk.get("name", "tool")
                                inp       = blk.get("input", {})
                                if not isinstance(inp, dict):
                                    inp = {}
                                cmd = inp.get("command", inp.get("description", str(inp)))
                                tag = f"[{tool_name}]"
                                print(f"  {_C}│ {tag} {cmd[:w-len(tag)-3]:<{w-len(tag)-3}} │{_R}")
                                _out_buf.append(f"$ {cmd}")

                    elif ev_type == "user":
                        for blk in ev.get("message", {}).get("content", []):
                            if not isinstance(blk, dict):
                                continue
                            if blk.get("type") == "tool_result":
                                raw_content = blk.get("content", "")
                                if isinstance(raw_content, str):
                                    txt = raw_content
                                elif isinstance(raw_content, list):
                                    parts = []
                                    for rb in raw_content:
                                        if isinstance(rb, dict):
                                            parts.append(rb.get("text", ""))
                                        elif isinstance(rb, str):
                                            parts.append(rb)
                                    txt = "\n".join(parts)
                                else:
                                    txt = str(raw_content) if raw_content else ""
                                if txt:
                                    first = txt.splitlines()[0][:w-6]
                                    print(f"  {_D}│   → {first:<{w-6}} │{_R}")
                                    _out_buf.append(txt)

                    elif ev_type == "result":
                        if not _out_buf:
                            res_text = ev.get("result", "")
                            for tl in res_text.splitlines():
                                _out_buf.append(tl)
                                cl = tl.strip()
                                if cl and not cl.startswith("===") and not cl.startswith("TEST_COMPLETED"):
                                    print(f"  {_D}│ {cl[:w-2]:<{w-2}} │{_R}")

                except Exception as _ev_exc:
                    print(f"  {_D}│ [stream-parse error: {_ev_exc}]{' '*(w-22)} │{_R}")

            else:
                proc_c.kill()
                proc_c.wait()

            if not _got_output:
                spinning[0] = False
                spin_t.join(2)

            _cerr = (proc_c.stderr.read() or "").strip() if proc_c.stderr else ""
            out   = "\n".join(_out_buf)
            if not out and _cerr:
                out = _cerr

        _DISP_SKIP = re.compile(
            r"</?run_?command|</?command_output|<system_instruction",
            re.IGNORECASE,
        )
        for raw in out.splitlines():
            clean = raw.strip()
            if (clean
                    and not clean.startswith("===")
                    and not clean.startswith("TEST_COMPLETED")
                    and not _DISP_SKIP.search(clean)):
                print(f"  {_D}│ {clean[:w - 2]:<{w - 2}} │{_R}")

        print(f"  {_C}└{'─' * w}┘{_R}\n")
        return True, out

    except urllib.error.URLError as exc:
        spinning[0] = False
        spin_t.join(2)
        print(f"  {_Y}│ [ERROR] Ollama unreachable: {exc.reason}{_R}")
        print(f"  {_C}└{'─' * w}┘{_R}\n")
        return False, f"[ERROR] Ollama unreachable: {exc.reason}"
    except subprocess.TimeoutExpired:
        spinning[0] = False
        spin_t.join(2)
        print(f"  {_Y}│ [TIMEOUT] No response after {timeout}s{_R}")
        print(f"  {_C}└{'─' * w}┘{_R}\n")
        return False, f"[ERROR] {model} timed out after {timeout}s"
    except FileNotFoundError as exc:
        spinning[0] = False
        spin_t.join(2)
        binary = "codex" if model == "codex" else "claude"
        missing = exc.filename or binary
        if missing == (cwd or str(SCRIPT_DIR)):
            print(f"  {_Y}│ [ERROR] working directory not found: {missing}{_R}")
        else:
            print(f"  {_Y}│ [ERROR] file not found while starting {binary}: {missing}{_R}")
        print(f"  {_C}└{'─' * w}┘{_R}\n")
        return False, f"[ERROR] file not found while starting {binary}: {missing}"
    except Exception as exc:
        spinning[0] = False
        spin_t.join(2)
        print(f"  {_Y}│ [ERROR] {exc}{_R}")
        print(f"  {_C}└{'─' * w}┘{_R}\n")
        return False, f"[ERROR] {exc}"


# ── Result parser ─────────────────────────────────────────────────────────────
def parse_result(output, test_name):
    r = {
        "status": "UNKNOWN", "severity": "Info",
        "false_positives": [], "jira_summary": "",
        "jira_description": "", "jira_concern": "", "jira_steps": "",
        "jira_evidence": "", "jira_recommendation": "",
        "completed": False, "improved_prompt": "",
        "raw_output": output,
    }

    r["completed"] = f"TEST_COMPLETED: {test_name}" in output

    matches = list(re.finditer(
        r"===TEST_RESULT_START===(.*?)===TEST_RESULT_END===",
        output,
        re.DOTALL,
    ))
    m = None
    for candidate in reversed(matches):
        blk0 = candidate.group(1)
        if "PASS|FAIL|INFO|SKIP" in blk0:
            continue
        if "<finding 1 with evidence" in blk0 or "<exact command" in blk0:
            continue
        if re.search(r"STATUS:\s*(PASS|FAIL|INFO|SKIP)\b", blk0, re.IGNORECASE):
            m = candidate
            break
    if m:
        blk = m.group(1)
        r["completed"] = True

        def _field(key: str) -> str:
            pat = rf"{re.escape(key)}:\s*\n?(.*?)(?=\n[A-Z_]{{3,}}:|===|$)"
            mm  = re.search(pat, blk, re.DOTALL | re.IGNORECASE)
            return mm.group(1).strip() if mm else ""

        sm = re.search(r"STATUS:\s*(PASS|FAIL|INFO|SKIP)", blk, re.IGNORECASE)
        if sm: r["status"] = sm.group(1).upper()

        vm = re.search(r"SEVERITY:\s*(Critical|High|Medium|Low|Info|N/A)", blk, re.IGNORECASE)
        if vm: r["severity"] = vm.group(1).title()

        def _bullets(raw):
            return [
                l.lstrip("-•*# \t").strip() for l in raw.splitlines()
                if l.strip() and l.strip().lower() not in ("none", "-", "n/a")
            ]

        r["false_positives"]     = _bullets(_field("FALSE_POSITIVES"))
        r["jira_summary"]        = _field("JIRA_TICKET_SUMMARY")
        r["jira_description"]    = _field("JIRA_TICKET_DESCRIPTION")
        r["jira_concern"]        = _field("JIRA_TICKET_CONCERN")
        r["jira_steps"]          = _field("JIRA_TICKET_STEPS")
        r["jira_evidence"]       = _field("JIRA_TICKET_EVIDENCE")
        r["jira_recommendation"] = _field("JIRA_TICKET_RECOMMENDATION")

    pm = re.search(
        r"===PROMPT_IMPROVEMENT_START===(.*?)===PROMPT_IMPROVEMENT_END===",
        output, re.DOTALL)
    if pm: r["improved_prompt"] = pm.group(1).strip()

    return r


def _jira_evidence_text(result: dict) -> str:
    """Return explicit Jira evidence, or derive it from parsed findings."""
    explicit = (result.get("jira_evidence") or "").strip()
    if explicit:
        return explicit
    findings = result.get("findings") or []
    if findings:
        return "\n".join(f"- {finding}" for finding in findings)
    return ""


# ── Per-test result file ──────────────────────────────────────────────────────
def _result_markdown(test: dict, result: dict, session: dict | None = None) -> str:
    session = session or {}
    dt = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
    app_name = session.get("app_name", "")
    package_name = session.get("package_name", "")

    summary = result.get("jira_summary") or test["name"]
    lines = [
        f"# {summary}",
        "",
        f"**App:** {app_name}  |  **Package:** `{package_name}`" if app_name else "",
        f"**Status:** `{result['status']}`  |  **Severity:** `{result['severity']}`  |  **Date:** {dt}",
        "",
    ]
    lines = [l for l in lines if l is not None]

    if result.get("jira_description"):
        lines += ["## Description", "", result["jira_description"], ""]

    if result.get("jira_concern"):
        lines += ["## Concern", "", result["jira_concern"], ""]

    if result.get("jira_steps"):
        lines += ["## Steps to Reproduce", "", result["jira_steps"], ""]

    evidence = _jira_evidence_text(result)
    if evidence:
        lines += ["## Evidence", "", evidence, ""]

    if result.get("jira_recommendation"):
        lines += ["## Recommendation", "", result["jira_recommendation"], ""]

    return "\n".join(lines)


def save_result_file(test: dict, result: dict, session_id: str, session: dict | None = None) -> Path:
    dest = RESULTS_DIR / session_id
    dest.mkdir(parents=True, exist_ok=True)
    slug = _test_slug(test["name"])
    path = dest / f"{slug}.md"
    md = _result_markdown(test, result, session)
    path.write_text(md, encoding="utf-8")

    if session:
        app_dest = _app_results_path(session.get("app_name", ""), session.get("package_name", ""))
        app_dest.mkdir(parents=True, exist_ok=True)
        (app_dest / f"{slug}.md").write_text(md, encoding="utf-8")
    return path


def _section_text(md: str, heading: str) -> str:
    pat = rf"^## {re.escape(heading)}\s*\n(.*?)(?=^## |\Z)"
    m = re.search(pat, md, re.DOTALL | re.MULTILINE)
    return m.group(1).strip() if m else ""


def _markdown_bullets(section: str) -> list[str]:
    return [
        line.lstrip("-•* \t").strip()
        for line in section.splitlines()
        if line.strip().startswith(("-", "•", "*"))
    ]


def _parse_result_markdown(path: Path) -> dict | None:
    try:
        md = path.read_text(encoding="utf-8")
    except OSError:
        return None

    status_m = re.search(r"\*\*Status:\*\*\s*`?([A-Z]+)`?", md)
    severity_m = re.search(r"\*\*Severity:\*\*\s*`?([^`\n|]+)`?", md)
    if not status_m:
        return None

    # Extract heading 1 as jira_summary
    title_m = re.search(r"^#\s+(.+)$", md, re.MULTILINE)

    return {
        "status": status_m.group(1).upper(),
        "severity": (severity_m.group(1).strip() if severity_m else "Info"),
        "false_positives": [],
        "jira_summary": title_m.group(1).strip() if title_m else "",
        "jira_description": _section_text(md, "Description"),
        "jira_concern": _section_text(md, "Concern"),
        "jira_steps": _section_text(md, "Steps to Reproduce"),
        "jira_evidence": _section_text(md, "Evidence"),
        "jira_recommendation": _section_text(md, "Recommendation"),
        "completed": True,
        "improved_prompt": "",
        "raw_output": "",
        "imported_from": str(path),
    }


def _sync_session_results_to_app_history(session: dict) -> int:
    """Mirror existing session markdown files into app-based history."""
    app_name = session.get("app_name", "")
    package_name = session.get("package_name", "")
    if not (app_name or package_name):
        return 0
    src = RESULTS_DIR / str(session.get("session_id", ""))
    if not src.is_dir():
        return 0
    dest = _app_results_path(app_name, package_name)
    dest.mkdir(parents=True, exist_ok=True)
    copied = 0
    for md in src.glob("*.md"):
        if md.name.startswith("debug_"):
            continue
        target = dest / md.name
        try:
            if not target.exists() or md.stat().st_mtime >= target.stat().st_mtime:
                shutil.copy2(md, target)
                copied += 1
        except OSError:
            pass
    return copied


def _sync_legacy_results_to_app_history(app_name: str, package_name: str) -> int:
    """Find older session result md files for this app and mirror them into app history."""
    if not (app_name or package_name):
        return 0
    dest = _app_results_path(app_name, package_name)
    dest.mkdir(parents=True, exist_ok=True)
    needles = [n.lower() for n in (package_name, app_name) if n]
    copied = 0
    for md in RESULTS_DIR.glob("*/*.md"):
        if md.parts[-2] == "by_app" or md.name.startswith("debug_"):
            continue
        try:
            text = md.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        text_l = text.lower()
        if needles and not any(n in text_l for n in needles):
            continue
        result = _parse_result_markdown(md)
        if not result:
            continue
        target = dest / md.name
        try:
            if not target.exists() or md.stat().st_mtime >= target.stat().st_mtime:
                shutil.copy2(md, target)
                copied += 1
        except OSError:
            pass
    return copied


def _load_app_completed_results(app_name: str, package_name: str) -> dict[str, dict]:
    hist = _app_results_path(app_name, package_name)
    completed: dict[str, dict] = {}
    if not hist.is_dir():
        return completed
    for md in hist.glob("*.md"):
        result = _parse_result_markdown(md)
        if result:
            completed[md.stem] = result
    return completed


def apply_app_history(session: dict, force_rerun: bool = False) -> int:
    """Mark selected tests completed when app history already has their md result."""
    if force_rerun:
        return 0
    _sync_session_results_to_app_history(session)
    _sync_legacy_results_to_app_history(
        session.get("app_name", ""),
        session.get("package_name", ""),
    )
    completed = _load_app_completed_results(
        session.get("app_name", ""),
        session.get("package_name", ""),
    )
    imported = 0
    for test in session.get("tests", []):
        if test.get("status") == "completed":
            continue
        result = completed.get(_test_slug(test["name"]))
        if result:
            test["status"] = "completed"
            test["result"] = result
            imported += 1
    if imported:
        session["last_run"] = datetime.datetime.now().isoformat()
    return imported


# ── Jira report generator ─────────────────────────────────────────────────────
def generate_report(session: dict) -> str:
    app    = session.get("app_name", "Unknown App")
    pkg    = session.get("package_name", "")
    dt     = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    tests  = session["tests"]

    done    = [t for t in tests if t.get("status") == "completed" and t.get("result")]
    passed  = [t for t in done  if t["result"].get("status") == "PASS"]
    skipped = [t for t in tests if t.get("status") == "skipped"]
    issues  = [t for t in done  if t["result"].get("status") not in ("PASS", "SKIP")]

    by_sev: dict = {s: [] for s in SEVERITY_ORDER}
    for t in issues:
        sev = t["result"].get("severity", "Info")
        by_sev.setdefault(sev, []).append(t)

    sev_emoji = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🔵","Info":"⚪"}

    lines: list = [
        f"# Security Report: {app}",
        f"**Package:** `{pkg}`" if pkg else "",
        f"**Date:** {dt}",
        f"**Test Level:** {session.get('level_filter', 'N/A')}",
        "",
        "| Metric | Count |",
        "|--------|-------|",
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
        em = sev_emoji.get(sev, "•")
        lines.append(f"## {em} {sev} Severity Issues\n")
        for t in grp:
            r = t["result"]
            lines += [
                f"### [SEC-{ticket:03d}] {t['name']}",
                f"> **Section:** {t['section']}  |  **Level:** {t['level']}  |  **Severity:** {r['severity']}",
                "",
            ]
            if r.get("jira_summary"):
                lines += [f"**Summary:** {r['jira_summary']}", ""]
            if r.get("jira_description"):
                lines += ["**Description:**", "", r["jira_description"], ""]
            if r.get("jira_concern"):
                lines += ["**Concern:**", "", r["jira_concern"], ""]
            if r.get("jira_steps"):
                lines += ["**Steps to Reproduce:**", "", r["jira_steps"], ""]
            evidence = _jira_evidence_text(r)
            if evidence:
                lines += ["**Evidence:**", "", evidence, ""]
            if r.get("jira_recommendation"):
                lines += ["**Recommendation:**", "", r["jira_recommendation"], ""]
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


# ── Checklist display ─────────────────────────────────────────────────────────
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
            tag  = f" {_Y}[{sev}]{_R}" if sev not in ("N/A","Info","") and rs != "pass" else ""
            print(f"  {icon} {t['name']}{tag}")
        else:
            print(f"  {_ICONS.get(st,'[ ]')} {t['name']}")

    print(f"\n  {_B}{_hr()}{_R}")




# ── Interactive test selection ────────────────────────────────────────────────
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
    print(f"  Selected: {_G}{_B}{len(selected)}{_R}/{len(items)}   Pos: {current+1}/{len(items)}")
    print(f"  {'─' * (w-2)}")
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
    if we < len(items): print(f"  {_D}v {len(items)-we} more below  (↓ / PgDn){_R}")
    print(f"\n  {'─' * (w-2)}")
    print(f"  {_B}↑↓{_R}=Navigate  {_B}SPACE{_R}=Toggle  {_B}A{_R}=All  "
          f"{_B}N{_R}=None  {_B}ENTER{_R}=Confirm  {_B}Q{_R}=Quit")
    print(f"{_B}{'=' * w}{_R}")


def _plain_select(items, presel, title):
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
        elif k == "PGDN":  cur = min(len(items)-1, cur + _PAGE)
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
        stdscr.addstr(row, 0, "=" * min(72,w-1), _curses.A_BOLD); row+=1
        stdscr.addstr(row, 0, f"  {title}"[:w-1], _curses.A_BOLD); row+=1
        stdscr.addstr(row, 0, "=" * min(72,w-1), _curses.A_BOLD); row+=1
        stdscr.addstr(row, 0, f"  Sel:{len(sel)}/{len(items)}  Pos:{cur+1}/{len(items)}"[:w-1]); row+=1
        stdscr.addstr(row, 0, "-" * min(68,w-1)); row+=1

        for di in range(ws, we):
            if row >= h-3: break
            dtype = disp[di][0]
            if dtype == "hdr":
                _, sec, lvl = disp[di]
                a = (_curses.color_pair(4 if lvl=="L2" else 3)|_curses.A_BOLD) if hc else _curses.A_BOLD
                stdscr.addstr(row, 0, f"  [{lvl}] {sec}"[:w-1], a)
            else:
                idx = disp[di][1]
                t   = items[idx]
                cb  = "[*]" if idx in sel else "[ ]"
                ar  = ">>>" if idx == cur else "   "
                txt = f"  {ar} {cb} {t['name']}"[:w-1]
                a   = (_curses.color_pair(1)|_curses.A_BOLD) if idx==cur and hc \
                      else (_curses.A_REVERSE|_curses.A_BOLD) if idx==cur \
                      else _curses.color_pair(2) if idx in sel and hc else 0
                stdscr.addstr(row, 0, txt, a)
            row += 1

        if ws > 0:         stdscr.addstr(h-3, w-11, "^ MORE  ^")
        if we < len(disp): stdscr.addstr(h-2, w-11, "v  MORE v")
        stdscr.addstr(h-2, 0, "-" * min(68,w-1))
        stdscr.addstr(h-1, 0, "ARROWS  SPACE=Toggle  A=All  N=None  ENTER=Confirm  Q=Quit"[:w-1])
        stdscr.refresh()

        k = stdscr.getch()
        if   k == _curses.KEY_UP:    cur = (cur-1) % len(items)
        elif k == _curses.KEY_DOWN:  cur = (cur+1) % len(items)
        elif k == _curses.KEY_PPAGE: cur = max(0, cur-pg//2)
        elif k == _curses.KEY_NPAGE: cur = min(len(items)-1, cur+pg//2)
        elif k == ord(" "):          sel.symmetric_difference_update({cur})
        elif k in (ord("a"),ord("A")): sel = set(range(len(items)))
        elif k in (ord("n"),ord("N")): sel = set()
        elif k in (ord("\n"),10,13):   return sel
        elif k in (ord("q"),ord("Q"),27): return None


def run_selection_menu(items, presel, title):
    if _HAS_CURSES:
        try:
            return _curses.wrapper(_curses_select, items, presel, title)
        except Exception:
            pass
    return _plain_select(items, presel, title)


def choose_level_filter(total):
    print()
    _box("SELECT TEST LEVEL")
    print(f"  Tests embedded in this script: {_B}{total}{_R}\n")
    print(f"  {_B}1{_R}  {_C}L1{_R}     Standard Security  – all apps           ({sum(1 for t in TESTS if t['level']=='L1')} tests)")
    print(f"  {_B}2{_R}  {_Y}L2{_R}     Defense-in-Depth   – Resilience only    ({sum(1 for t in TESTS if t['level']=='L2')} tests)")
    print(f"  {_B}3{_R}  {_G}Both{_R}   Full suite  (L1 + L2)                   ({total} tests)")
    print(f"  {_B}4{_R}  Custom  Pick any tests individually")
    print(f"  {_B}Q{_R}  Quit")
    print()
    while True:
        raw = input("  Choice (1/2/3/4/Q): ").strip().upper()
        if raw in ("1","L1"):          return "L1"
        if raw in ("2","L2"):          return "L2"
        if raw in ("3","BOTH","B"):    return "BOTH"
        if raw in ("4","CUSTOM","C"):  return "CUSTOM"
        if raw in ("Q","QUIT",""):     return None
        print("  [!] Enter 1, 2, 3, 4, or Q.")


# ── Main test execution loop ──────────────────────────────────────────────────
def _preflight_ai(model="claude", ollama_host=OLLAMA_HOST):
    """Verify the selected AI runner is reachable before starting tests."""
    if model == "ollama":
        print(f"  {_C}[*] Checking Ollama at {ollama_host}:{OLLAMA_PORT}…{_R}", end="", flush=True)
        try:
            url = f"http://{ollama_host}:{OLLAMA_PORT}/api/tags"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            count = len(data.get("models", []))
            print(f" {_G}OK{_R}  ({count} model(s))")
            return True
        except urllib.error.URLError as e:
            print(f"\n  {_Y}[!] Cannot reach Ollama: {e.reason}{_R}")
            print(f"  {_Y}    Ensure the server is running and accessible at {ollama_host}:{OLLAMA_PORT}{_R}\n")
            return False
        except Exception as e:
            print(f"\n  {_Y}[!] Ollama check failed: {e}{_R}\n")
            return False

    binary = "codex" if model == "codex" else "claude"
    binary_path = _resolve_cli(binary)
    if not binary_path:
        print(f"\n  {_Y}[!] '{binary}' not found in PATH or common user install locations.{_R}")
        checked = ", ".join(_candidate_cli_paths(binary)[:6])
        if checked:
            print(f"  {_Y}    Checked: {checked}{_R}")
        if model == "claude":
            print(f"  {_Y}    Install: npm install -g @anthropic-ai/claude-code{_R}\n")
        else:
            print(f"  {_Y}    Install: npm install -g @openai/codex{_R}\n")
        return False

    print(f"  {_C}[*] Checking {binary} CLI…{_R}", end="", flush=True)
    try:
        r = subprocess.run(
            [binary_path, "--version"],
            capture_output=True, text=True, timeout=15,
            env=_cli_env(binary_path),
        )
        if r.returncode == 0:
            ver = r.stdout.strip() or r.stderr.strip()
            suffix = f" at {binary_path}" if binary_path != binary else ""
            print(f" {_G}OK{_R} ({ver}{suffix})")
            return True
        print(f"\n  {_Y}[!] '{binary} --version' returned exit {r.returncode}{_R}")
        print(f"  {_Y}    stderr: {r.stderr.strip()[:120]}{_R}")
        if model == "claude":
            print(f"  {_Y}    Run 'claude' in a terminal and complete auth, then re-run.{_R}\n")
        else:
            print(f"  {_Y}    Run 'codex' in a terminal to verify setup.{_R}\n")
        return False
    except subprocess.TimeoutExpired:
        print(f"\n  {_Y}[!] '{binary} --version' timed out.{_R}")
        if model == "claude":
            print(f"  {_Y}    Open a new terminal, run 'claude', complete auth, then retry.{_R}\n")
        return False
    except FileNotFoundError:
        print(f"\n  {_Y}[!] '{binary}' not found in PATH.{_R}")
        if model == "claude":
            print(f"  {_Y}    Install: npm install -g @anthropic-ai/claude-code{_R}\n")
        else:
            print(f"  {_Y}    Install: npm install -g @openai/codex{_R}\n")
        return False


def _build_feedback_prompt(test, session, improvements, previous_output, feedback, model="claude"):
    """Rebuild the test prompt adding tester feedback + previous analysis for revision."""
    imp = get_improvement(improvements, test["name"])
    base = build_prompt(test, session, imp, model=model)
    if len(previous_output) > 50000:
        previous_output = (
            previous_output[:12000]
            + "\n\n... [previous analysis truncated for feedback rerun] ...\n\n"
            + previous_output[-30000:]
        )
    return f"""{base}

## ── TESTER FEEDBACK: PLEASE REVISE YOUR ANALYSIS ──────────────────────────

The security tester reviewed your analysis and provided the following correction or context.
Apply it to reconsider every finding before producing the revised result.

  "{feedback}"

Guidelines for common feedback types:
- "staging / test / dev build" → findings tied solely to debug/test configuration
  (android:debuggable, test credentials, profiler flags) should be noted as
  EXPECTED IN NON-PRODUCTION and their severity downgraded or moved to NOTES.
- "firebase / google API keys are public" → google-services.json API keys are
  client-side identifiers intentionally shipped with Android apps; they are NOT
  secret. Move any such finding to FALSE_POSITIVES with this explanation.
- "this is expected" / "not an issue" → reclassify as INFO or FALSE_POSITIVE.
- "severity too high" → downgrade to the next lower tier and justify.
- "re-check X" → re-examine only that finding; leave others unchanged.

## ── YOUR PREVIOUS ANALYSIS (for context only) ─────────────────────────────

{previous_output}

## ── REVISED OUTPUT ─────────────────────────────────────────────────────────

Now output the COMPLETE revised structured result, incorporating the feedback above.
Only include genuine, unexplained vulnerabilities in FINDINGS.
Explain what changed and why in NOTES.

===TEST_RESULT_START===
STATUS: PASS|FAIL|INFO|SKIP
SEVERITY: Critical|High|Medium|Low|Info|N/A
FINDINGS:
- <revised finding 1, or "None">
COMMANDS_USED:
- <same or updated list>
NOTES:
<what changed from the previous analysis and why>
FALSE_POSITIVES:
- <all false positives, including any reclassified per feedback>
JIRA_TICKET_SUMMARY:
<revised one-line Jira summary; blank if PASS>
JIRA_TICKET_DESCRIPTION:
<revised Jira description>
JIRA_TICKET_EVIDENCE:
<revised evidence bullets or excerpts to place after steps and before recommendation>
JIRA_TICKET_RECOMMENDATION:
<revised developer recommendations>
===TEST_RESULT_END===

===PROMPT_IMPROVEMENT_START===
<updated test guidance incorporating lessons from both runs>
===PROMPT_IMPROVEMENT_END===

TEST_COMPLETED: {test["name"]}
"""


def _show_result_summary(result):
    st  = result["status"]
    sev = result["severity"]
    col = _G if st == "PASS" else _Y if st == "INFO" else _RE
    print(f"\n  Result: {col}{_B}{st}{_R}  |  Severity: {sev}")
    if result.get("jira_summary"):
        print(f"  {_D}{result['jira_summary'][:90]}{_R}")


def _feedback_loop(test, result, output, session, improvements, cwd,
                   model="claude", ollama_model="", ollama_host=OLLAMA_HOST):
    """
    After showing results, let the tester accept, provide feedback to re-run,
    or skip.  Returns (final_result, final_output, action) where action is
    'accepted', 'skipped', or 'quit'.
    """
    MAX_RERUNS = 5
    reruns = 0

    while True:
        print(f"\n  {'─' * 70}")
        print(f"  {_B}What would you like to do?{_R}")
        print(f"  {_G}[Enter]{_R}  Accept these results and continue")
        print(f"  {_C}[F]{_R}      Give feedback and re-run this test")
        print(f"  {_Y}[S]{_R}      Skip (mark as skipped, move on)")
        print(f"  {_RE}[Q]{_R}      Save progress and quit")
        if reruns:
            print(f"  {_D}  (re-run {reruns}/{MAX_RERUNS}){_R}")
        ch = input("\n  > ").strip().upper()

        if ch in ("", "A"):
            return result, output, "accepted"

        if ch == "S":
            return result, output, "skipped"

        if ch == "Q":
            return result, output, "quit"

        if ch == "F":
            if reruns >= MAX_RERUNS:
                print(f"  {_Y}[!] Maximum re-runs ({MAX_RERUNS}) reached. Accept or skip.{_R}")
                continue

            print(f"\n  {_C}Describe what Claude got wrong or should reconsider:{_R}")
            print(f"  {_D}Examples:{_R}")
            print(f"  {_D}  - 'This is a staging build — debug flag and test creds are expected'{_R}")
            print(f"  {_D}  - 'Firebase API keys in google-services.json are public, not secrets'{_R}")
            print(f"  {_D}  - 'Severity is too high for X finding — it is only in test builds'{_R}")
            feedback = input(f"\n  Feedback: ").strip()
            if not feedback:
                print(f"  {_Y}No feedback entered — try again.{_R}")
                continue

            model_label = "Codex" if model == "codex" else "Claude"
            print(f"\n  {_C}[*] Re-running with your feedback ({model_label})…{_R}")
            rerun_prompt = _build_feedback_prompt(
                test, session, improvements, output, feedback, model=model
            )
            success, new_output = run_claude(
                rerun_prompt, cwd=cwd, model=model,
                ollama_model=ollama_model, ollama_host=ollama_host,
                test_name=test["name"],
            )

            if not success or not new_output.strip():
                print(f"  {_RE}[!] Re-run produced no output. Keeping previous result.{_R}")
                continue

            new_result = parse_result(new_output, test["name"])
            reruns += 1
            result = new_result
            output = new_output

            _show_result_summary(result)
            continue

        print(f"  {_Y}Unrecognised key — press Enter, F, S, or Q.{_R}")


def run_tests(session, improvements):
    tests        = session["tests"]
    model        = session.get("model", "claude")
    ollama_model = session.get("ollama_model", "")
    ollama_host  = session.get("ollama_host", OLLAMA_HOST)

    if not _preflight_ai(model, ollama_host=ollama_host):
        input("  Press Enter to continue anyway, or Ctrl-C to abort… ")

    for i, test in enumerate(tests):
        if test.get("status") == "completed":
            continue

        test["status"] = "running"
        save_state(session)
        show_checklist(session)

        print(f"\n{_B}{_hr()}{_R}")
        print(f"{_B}  Test {i+1} / {len(tests)}: {test['name']}{_R}")
        print(f"  Section: {test['section']}  |  Level: {test['level']}")
        print(f"{_B}{_hr()}{_R}")

        imp = get_improvement(improvements, test["name"])
        if imp.get("run_count", 0):
            print(f"  {_C}[~] Refinement from {imp['run_count']} prior run(s) loaded{_R}")

        prompt = build_prompt(test, session, imp, model=model)

        # Brief prompt preview
        preview = [l for l in prompt.splitlines() if l.strip()][:6]
        print(f"\n  {_D}Prompt preview:")
        for pl in preview:
            print(f"    {pl[:88]}")
        print(f"    …{_R}\n")

        model_label = "Codex" if model == "codex" else ("Ollama" if model == "ollama" else "Claude")
        print(f"  {_C}[*] Sending to {model_label} (timeout 10 min)…{_R}")
        cwd = session.get("decompiled_path") or str(SCRIPT_DIR)

        # Snapshot script hash so we can detect if Claude/Codex self-improves it
        _can_edit = model in ("claude", "codex")
        _hash_before = hashlib.sha256(SCRIPT_PATH.read_bytes()).hexdigest() if _can_edit else None

        success, output = run_claude(
            prompt, cwd=cwd, model=model,
            ollama_model=ollama_model, ollama_host=ollama_host,
            test_name=test["name"],
        )

        # Write full prompt + response to a per-test debug file
        _dbg_dir = RESULTS_DIR / session["session_id"]
        _dbg_dir.mkdir(parents=True, exist_ok=True)
        _safe = re.sub(r"[^a-zA-Z0-9_-]", "_", test["name"])[:60]
        _dbg_file = _dbg_dir / f"debug_{i+1:03d}_{_safe}.txt"
        try:
            with open(_dbg_file, "w", encoding="utf-8") as _df:
                _df.write(f"=== PROMPT ===\n{prompt}\n\n=== RESPONSE ===\n{output}\n")
        except OSError:
            pass

        # Report any script self-modification
        if _can_edit:
            _hash_after = hashlib.sha256(SCRIPT_PATH.read_bytes()).hexdigest()
            if _hash_after != _hash_before:
                print(f"  {_G}[✓] Script was updated by {model_label} during this test.{_R}")
                bak = SCRIPT_PATH.with_suffix(".py.bak")
                if bak.exists():
                    print(f"  {_D}    Backup: {bak}{_R}")

        # Handle runner errors
        if not success and not output.strip():
            print(f"\n  {_RE}[!] {model_label} failed to produce output.{_R}")
            print("  R=Retry  S=Skip  Q=Save & quit")
            ch = input("  Choice: ").strip().upper()
            if ch == "R":
                test["status"] = "pending"; continue
            if ch == "Q":
                test["status"] = "pending"; save_state(session); return
            test["status"] = "skipped"; save_state(session); continue

        result = parse_result(output, test["name"])

        # Completion check
        if not result["completed"]:
            print(f"\n  {_Y}[!] TEST_COMPLETED marker not found in output.{_R}")
            print("  C=Accept anyway  R=Retry  S=Skip")
            ch = input("  Choice (C/R/S): ").strip().upper()
            if ch == "R":
                test["status"] = "pending"; continue
            if ch == "S":
                test["status"] = "skipped"; save_state(session); continue

        # Show initial summary and open feedback loop
        _show_result_summary(result)
        result, output, action = _feedback_loop(
            test, result, output, session, improvements, cwd,
            model, ollama_model, ollama_host,
        )

        if action == "quit":
            test["result"] = result
            test["status"] = "completed"
            save_state(session)
            return

        if action == "skipped":
            test["status"] = "skipped"
            save_state(session)
            continue

        # Persist accepted result
        test["result"] = result
        test["status"] = "completed"
        session["last_run"] = datetime.datetime.now().isoformat()
        save_state(session)

        update_improvement(improvements, test["name"],
                           result, result.get("improved_prompt", ""))
        save_improvements(improvements)

        rf = save_result_file(test, result, session["session_id"], session)

        if result.get("improved_prompt"):
            print(f"  {_G}[✓] Prompt improved for next run{_R}")
        print(f"  {_D}Saved: {rf}{_R}")

        if i < len(tests) - 1:
            rem = sum(1 for t in tests[i+1:] if t.get("status") != "completed")
            print(f"\n  {rem} test(s) remaining.")
            input("  Press Enter for next test…")

    # ── All done ──
    show_checklist(session)
    print(f"\n  {_G}{_B}All tests completed!{_R}\n")

    report_md = generate_report(session)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", session.get("app_name", "app"))
    rfile = REPORTS_DIR / f"{safe}_{session['session_id']}.md"
    rfile.write_text(report_md, encoding="utf-8")

    session["last_report_path"] = str(rfile)
    save_state(session)

    print(f"  {_G}Report:{_R}  {_C}{rfile}{_R}")
    print(f"  Individual results: {_C}{RESULTS_DIR / session['session_id']}{_R}\n")


# ── Entry point ───────────────────────────────────────────────────────────────
def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="selfImprovementtest.py",
        description=(
            "AI-Assisted Android Security Test Runner  (OWASP MASTG)\n"
            "Runs Kali Linux + ADB + Frida + Claude Code\n\n"
            "Quick start (interactive):\n"
            "  python selfImprovementtest.py\n\n"
            "Quick start (pre-filled):\n"
            "  python selfImprovementtest.py \\\n"
            "    --app MyApp \\\n"
            "    --pkg com.example.app \\\n"
            "    --apk /root/Desktop/MyApp.apk \\\n"
            "    --src /root/Desktop/MyApp_decompiled/ \\\n"
            "    --level l1"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--app", metavar="NAME",
        help="App name used in the report filename  (e.g. MyBankingApp)",
    )
    p.add_argument(
        "--pkg", metavar="PACKAGE",
        help="Android package name  (e.g. com.example.myapp)",
    )
    p.add_argument(
        "--apk", metavar="PATH",
        help="Path to the APK file  (e.g. /root/Desktop/MyApp.apk)",
    )
    p.add_argument(
        "--src", metavar="PATH",
        help=(
            "Path to the decompiled APK folder produced by jadx or apktool\n"
            "(e.g. /root/Desktop/MyApp_decompiled/).  Claude uses this as its\n"
            "working directory so it can grep/strings/navigate the source."
        ),
    )
    p.add_argument(
        "--level", metavar="LEVEL",
        choices=["l1", "l2", "both", "custom", "L1", "L2", "BOTH", "CUSTOM"],
        help=(
            "Pre-select a test level without the interactive menu:\n"
            "  l1     Standard Security (100 tests)\n"
            "  l2     Defense-in-Depth / Resilience (31 tests)\n"
            "  both   Full suite (131 tests)\n"
            "  custom Opens selection menu with nothing pre-selected"
        ),
    )
    p.add_argument(
        "--new", action="store_true",
        help="Force a new session even if a resumable one exists",
    )
    p.add_argument(
        "--rerun-completed", action="store_true",
        help="Do not import completed app-history results; rerun selected tests",
    )
    p.add_argument(
        "--reset", action="store_true",
        help="Delete the saved session state and start fresh",
    )
    p.add_argument(
        "--list", action="store_true",
        help="List all embedded tests and exit",
    )
    p.add_argument(
        "--no-update", action="store_true",
        help="Skip the GitHub update check",
    )
    return p.parse_args()


def main() -> None:
    _enable_ansi()
    args = _parse_args()

    # ── --list ────────────────────────────────────────────────────────────────
    if args.list:
        prev_sec = None
        for t in TESTS:
            if t["section"] != prev_sec:
                lc = _Y if t["level"] == "L2" else _C
                print(f"\n{lc}{_B}[{t['level']}] {t['section']}{_R}")
                prev_sec = t["section"]
            print(f"  • {t['name']}")
        print(f"\n  Total: {len(TESTS)} tests  "
              f"(L1: {sum(1 for t in TESTS if t['level']=='L1')}  "
              f"L2: {sum(1 for t in TESTS if t['level']=='L2')})")
        sys.exit(0)

    _clear()
    print(f"\n{_B}{'=' * 72}{_R}")
    print(f"{_B}  selfImprovementtest.py  v{__version__}  –  {len(TESTS)} tests embedded{_R}")
    print(f"{_B}  AI-Assisted Android Security Testing  |  OWASP MASTG{_R}")
    print(f"{_B}  Platform: Kali Linux  |  ADB + Frida  |  Claude / Codex CLI{_R}")
    print(f"{_B}{'=' * 72}{_R}\n")

    if not args.no_update:
        check_for_update()

    # ── --reset ───────────────────────────────────────────────────────────────
    if args.reset:
        if STATE_FILE.exists():
            STATE_FILE.unlink()
            print(f"  {_G}[✓] Session state cleared.{_R}")
        else:
            print(f"  [~] No session state to clear.")

    state        = load_state()
    improvements = load_improvements()

    # ── Resume or new session ─────────────────────────────────────────────────
    session = None
    pending = [t for t in state.get("tests", [])
               if t.get("status") not in ("completed", "skipped")]

    if state.get("tests") and pending and not args.new and not args.reset:
        done  = sum(1 for t in state["tests"] if t.get("status") == "completed")
        total = len(state["tests"])
        print(f"  {_Y}[?] Resumable session:{_R}  {_B}{state.get('app_name','?')}{_R}")
        print(f"      Package : {state.get('package_name','?')}")
        print(f"      Source  : {state.get('decompiled_path','?')}")
        print(f"      Progress: {done}/{total} tests completed")
        print()
        print("  1  Resume this session")
        print("  2  Start a new session")
        print("  Q  Quit")
        print()
        ch = input("  Choice (1/2/Q): ").strip().upper()
        if ch == "Q":  sys.exit(0)
        if ch == "1":  session = state

    # ── New session setup ─────────────────────────────────────────────────────
    if session is None:
        print()
        _box("NEW TEST SESSION")
        print()

        # AI model selection
        model_cfg    = _choose_model()
        model        = model_cfg["model"]
        ollama_model = model_cfg.get("ollama_model", "")
        ollama_host  = model_cfg.get("ollama_host", OLLAMA_HOST)
        print()

        # Use CLI args if provided, otherwise prompt interactively
        if args.app:
            app_name = args.app
            print(f"  App name       : {_G}{app_name}{_R}  (from --app)")
        else:
            app_name = input("  App name (used in report filename): ").strip() or "UnknownApp"

        if args.pkg:
            pkg_name = args.pkg
            print(f"  Package        : {_G}{pkg_name}{_R}  (from --pkg)")
        else:
            pkg_name = input("  Package name  (e.g. com.example.app): ").strip()

        if args.apk:
            apk_path = args.apk
            print(f"  APK file       : {_G}{apk_path}{_R}  (from --apk)")
        else:
            apk_path = input("  APK file path (optional, Enter to skip): ").strip()

        if args.src:
            decomp_path = args.src
            print(f"  Decompiled src : {_G}{decomp_path}{_R}  (from --src)")
        else:
            decomp_path = input(
                "  Decompiled APK folder (e.g. /root/Desktop/AppName/): "
            ).strip()

        # Validate decompiled path if given
        if decomp_path and not os.path.isdir(decomp_path):
            print(f"\n  {_Y}[!] Warning: '{decomp_path}' does not exist or is not a directory.{_R}")
            print(f"      Claude will still run but may not find source files.")

        print()
        l1 = sum(1 for t in TESTS if t["level"] == "L1")
        l2 = sum(1 for t in TESTS if t["level"] == "L2")
        print(f"  {_G}[✓]{_R} {len(TESTS)} tests embedded  "
              f"({_C}L1: {l1}{_R}  {_Y}L2: {l2}{_R})")

        # Level filter — use --level flag or interactive menu
        if args.level:
            level_filter = args.level.upper()
            if level_filter == "BOTH": level_filter = "BOTH"
            print(f"  Level filter   : {_G}{level_filter}{_R}  (from --level)")
        else:
            level_filter = choose_level_filter(len(TESTS))
            if level_filter is None:
                print("[*] Exiting.\n"); sys.exit(0)

        if   level_filter == "L1":   presel = {i for i,t in enumerate(TESTS) if t["level"]=="L1"}
        elif level_filter == "L2":   presel = {i for i,t in enumerate(TESTS) if t["level"]=="L2"}
        elif level_filter == "BOTH": presel = set(range(len(TESTS)))
        else:                        presel = set()

        title   = (f"SELECT TESTS [{level_filter}]  –  "
                   "SPACE=toggle  ENTER=confirm  A=all  N=none  Q=quit")
        sel_idx = run_selection_menu(list(TESTS), presel, title)

        if not sel_idx:
            print("\n[*] No tests selected. Exiting.\n"); sys.exit(0)

        selected = []
        for i in sorted(sel_idx):
            t = dict(TESTS[i])
            t["status"] = "pending"
            t["result"] = None
            selected.append(t)

        session = new_session(selected, app_name, pkg_name,
                              apk_path, decomp_path, level_filter,
                              model, ollama_model, ollama_host)
        imported = apply_app_history(session, force_rerun=args.rerun_completed)
        if imported:
            print(f"  {_G}[✓] Reused {imported} completed test result(s) from app history.{_R}")
        elif args.rerun_completed:
            print(f"  {_Y}[~] App-history reuse disabled; selected tests will rerun.{_R}")
        save_state(session)

    # ── Confirm & run ─────────────────────────────────────────────────────────
    imported = apply_app_history(session, force_rerun=args.rerun_completed)
    if imported:
        print(f"  {_G}[✓] Reused {imported} completed test result(s) from app history.{_R}")
        save_state(session)
    show_checklist(session)
    done = sum(1 for t in session["tests"] if t.get("status") == "completed")
    rem  = len(session["tests"]) - done

    _model = session.get("model", "claude")
    if _model == "codex":
        _model_label = "Codex  (codex --yolo)"
    elif _model == "ollama":
        _om   = session.get("ollama_model", "?")
        _oh   = session.get("ollama_host", OLLAMA_HOST)
        _model_label = f"Ollama  {_om}  @ {_oh}:{OLLAMA_PORT}"
    else:
        _model_label = "Claude  (claude -p)"
    print(f"  App      : {_B}{session.get('app_name','?')}{_R}")
    print(f"  Package  : {session.get('package_name') or _D+'(not set)'+_R}")
    print(f"  Source   : {_C}{session.get('decompiled_path') or '(not set)'}{_R}")
    print(f"  APK      : {session.get('apk_path') or _D+'(not set)'+_R}")
    print(f"  Model    : {_C}{_model_label}{_R}")
    print(f"  Queued   : {rem} tests remaining")
    print(f"\n  {_Y}Ensure ADB device is connected and the AI CLI is in PATH.{_R}\n")

    ans = input("  Start testing? [Y/n]: ").strip().lower()
    if ans in ("n", "no", "q"):
        print("[*] Session saved.\n"); sys.exit(0)

    run_tests(session, improvements)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Interrupted – progress saved.\n")
        sys.exit(0)
