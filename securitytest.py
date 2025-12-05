# Disable Python bytecode caching to prevent stale results across multiple test runs
import sys
sys.dont_write_bytecode = True

import argparse
import os
import re
import shutil
import subprocess
import tempfile
import frida
import html
import xml.etree.ElementTree as ET
import time
import ast
import select
from collections import defaultdict
import math
import curses
import hashlib
import urllib.request
import urllib.error
from datetime import datetime
import platform

# Platform-specific imports
if platform.system() == 'Windows':
    import msvcrt
else:
    import fcntl
from html import escape, unescape

# Version tracking for auto-update
__version__ = "4.2.2"
__script_url__ = "https://raw.githubusercontent.com/freelanceontime/SecurityTest/main/securitytest.py"

## Add new test as def
## Add to Tests
## Add to HTML Special
## Add to Group MASVS

def curses_select_menu(stdscr, items, title="SELECT TESTS"):
    """
    DOS-style menu using arrow keys to navigate and Enter to toggle.
    Returns a set of selected indices.
    """
    curses.curs_set(0)  # Hide cursor
    current = 0
    selected = set()

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
        display_start = max(0, current - (height - 10))
        display_end = min(len(items), display_start + (height - 10))

        for idx in range(display_start, display_end):
            y = 5 + (idx - display_start)
            if y >= height - 3:
                break

            status = "[*]" if idx in selected else "[ ]"
            marker = ">" if idx == current else " "
            item_text = f"{marker} {status} [{idx+1:2d}] {items[idx][0]}"

            if idx == current:
                stdscr.addstr(y, 0, item_text[:width-1], curses.A_REVERSE)
            else:
                stdscr.addstr(y, 0, item_text[:width-1])

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

def check_for_updates():
    """
    Check if a newer version exists on GitHub and offer to update.
    Compares local file hash with remote file hash.
    """
    try:
        print(f"[*] Current version: {__version__}")
        print(f"[*] Checking for updates from GitHub...")

        # Get local file hash
        script_path = os.path.abspath(__file__)
        with open(script_path, 'rb') as f:
            local_hash = hashlib.sha256(f.read()).hexdigest()

        # Fetch remote file
        try:
            with urllib.request.urlopen(__script_url__, timeout=5) as response:
                remote_content = response.read()
                remote_hash = hashlib.sha256(remote_content).hexdigest()
        except urllib.error.URLError as e:
            print(f"[!] Could not check for updates: {e}")
            print("[*] Continuing with current version...")
            return
        except Exception as e:
            print(f"[!] Update check failed: {e}")
            print("[*] Continuing with current version...")
            return

        # Compare hashes
        if local_hash == remote_hash:
            print("[+] You have the latest version!")
            return

        # Newer version available
        print("\n" + "="*70)
        print("[!] A newer version is available on GitHub!")
        print("="*70)
        print(f"Local hash:  {local_hash[:16]}...")
        print(f"Remote hash: {remote_hash[:16]}...")
        print(f"Source: {__script_url__}")

        # Ask user if they want to update
        try:
            response = input("\n[?] Do you want to update now? [y/N]: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Update cancelled. Continuing with current version...")
            return

        if response not in ['y', 'yes']:
            print("[*] Update declined. Continuing with current version...")
            return

        # Perform update
        print("\n[*] Downloading update...")

        # Create temporary backup (for safety during update)
        backup_path = script_path + ".backup"
        shutil.copy2(script_path, backup_path)

        # Write new version
        try:
            with open(script_path, 'wb') as f:
                f.write(remote_content)
            print("[+] Update installed successfully!")

            # Clean up backup after successful update
            try:
                os.remove(backup_path)
            except:
                pass  # Ignore if cleanup fails

            print("\n[*] Please restart the script to use the new version.")
            print("="*70)
            sys.exit(0)
        except Exception as e:
            # Restore backup on failure
            print(f"[!] Update failed: {e}")
            print("[*] Restoring backup...")
            shutil.copy2(backup_path, script_path)
            print("[+] Backup restored. Continuing with current version...")

            # Clean up backup after restore
            try:
                os.remove(backup_path)
            except:
                pass

    except Exception as e:
        print(f"[!] Update check error: {e}")
        print("[*] Continuing with current version...")

    print()  # Empty line for spacing

def interactive_frida_monitor(proc, test_name, instructions, send_exit_on_stop=False):
    """
    Interactive Frida log collection with user prompt.
    Replaces hardcoded timeouts with "Press ENTER when done" workflow.
    Works on both Windows and Unix systems.

    Args:
        proc: Frida subprocess
        test_name: Name of test (e.g., "CERTIFICATE PINNING")
        instructions: List of strings with testing instructions
        send_exit_on_stop: If True, send 'exit' command to Frida and wait for graceful exit (needed for some tests)

    Returns:
        List of collected log lines (raw, not escaped)
    """
    print("\n" + "="*70)
    print(f"DYNAMIC {test_name} TEST - FRIDA ACTIVE")
    print("="*70)
    print(f"[*] Frida is monitoring {test_name.lower()} in real-time")
    print("\n[!] INSTRUCTIONS:")
    for i, instruction in enumerate(instructions, 1):
        print(f"    {i}. {instruction}")
    print("    {0}. When done testing, press ENTER to stop and analyze results".format(len(instructions) + 1))
    print("\n[*] Frida output will appear below as you use the app...")
    print("="*70 + "\n")

    logs = []
    is_windows = platform.system() == 'Windows'

    # Import threading/queue for Windows
    if is_windows:
        import threading
        import queue

    # Platform-specific setup
    if not is_windows:
        # Unix: Make stdout non-blocking
        fd = proc.stdout.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    # Real-time log collection with user prompt
    try:
        while True:
            # Check for user input (platform-specific)
            user_pressed_enter = False
            if is_windows:
                # Windows: Use msvcrt.kbhit() to check for keyboard input
                if msvcrt.kbhit():
                    key = msvcrt.getwche()
                    if key == '\r' or key == '\n':
                        user_pressed_enter = True
            else:
                # Unix: Use select on stdin
                user_ready, _, _ = select.select([sys.stdin], [], [], 0.1)
                if user_ready:
                    input()  # User pressed Enter
                    user_pressed_enter = True

            if user_pressed_enter:
                print("\n[*] Stopping Frida and analyzing results...")
                if send_exit_on_stop:
                    print("[*] Sending exit command to Frida...")
                    try:
                        proc.stdin.write('exit\n')
                        proc.stdin.flush()
                    except:
                        pass
                break

            # Collect Frida output (platform-specific)
            line = None
            if is_windows:
                # Windows: Poll stdout without blocking
                # Check if process has data available
                if proc.poll() is None:  # Process is still running
                    try:
                        # Try to read with short timeout using threading
                        def read_line(q):
                            try:
                                l = proc.stdout.readline()
                                if l:
                                    q.put(l)
                            except:
                                pass

                        q = queue.Queue()
                        t = threading.Thread(target=read_line, args=(q,))
                        t.daemon = True
                        t.start()
                        t.join(timeout=0.1)

                        try:
                            line = q.get_nowait()
                        except queue.Empty:
                            pass
                    except:
                        pass
            else:
                # Unix: Use select on file descriptor
                fd = proc.stdout.fileno()
                r, _, _ = select.select([fd], [], [], 0.1)
                if r:
                    try:
                        line = proc.stdout.readline()
                    except:
                        pass

            if line:
                # Print RAW to console for real-time feedback
                print(line.rstrip())
                # Store log line
                logs.append(line.rstrip())

            # Small delay to prevent CPU spinning (only on Windows, Unix already has timeout in select)
            if is_windows:
                time.sleep(0.05)

    except KeyboardInterrupt:
        print("\n[!] Test interrupted by user")
        pass

    # Only do graceful exit and output draining if requested
    if send_exit_on_stop:
        # Give a moment for any remaining daemon threads to finish their timeout and exit
        # This prevents "could not acquire lock" errors at interpreter shutdown
        time.sleep(0.3)

        # Wait for Frida to exit gracefully (we sent 'exit' command)
        # This ensures all output is flushed
        print("[*] Waiting for Frida to exit and flush output...")
        try:
            proc.wait(timeout=5)  # Wait up to 5 seconds for graceful exit
        except subprocess.TimeoutExpired:
            print("[!] Frida didn't exit in time, forcing termination...")
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except:
                proc.kill()

        # Now read ALL remaining output (Frida has exited so all output is available)
        print("[*] Reading all remaining output...")
        try:
            # Read everything that's left in the pipe
            remaining = proc.stdout.read()
            if remaining:
                for line in remaining.splitlines():
                    print(line)
                    logs.append(line)
        except:
            pass

    return logs

# HTML template with professional, client-ready styling
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mobile Security Assessment Report</title>
<style>
  /* === GLOBAL STYLES === */
  * {{
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }}

  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    font-size: 14px;
    line-height: 1.6;
    color: #1a1a1a;
    background: #f5f7fa;
    padding: 20px;
    max-width: 1400px;
    margin: 0 auto;
  }}

  /* === HEADER === */
  h1 {{
    font-size: 28px;
    font-weight: 600;
    color: #1a1a1a;
    margin-bottom: 8px;
    padding-bottom: 16px;
    border-bottom: 3px solid #2563eb;
  }}

  h2 {{
    font-size: 20px;
    font-weight: 600;
    color: #1a1a1a;
    margin: 32px 0 16px 0;
    padding: 12px 16px;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
  }}

  h3 {{
    font-size: 18px;
    font-weight: 600;
    color: #374151;
    margin: 24px 0 12px 0;
  }}

  h4 {{
    font-size: 16px;
    font-weight: 600;
    color: #4b5563;
    margin: 20px 0 12px 0;
  }}

  /* === STATUS COLORS === */
  .pass {{
    color: #059669;
    font-weight: 600;
  }}

  .fail {{
    color: #dc2626;
    font-weight: 600;
  }}

  .warn {{
    color: #d97706;
    font-weight: 600;
  }}

  .info {{
    color: #2563eb;
    font-weight: 600;
  }}

  /* === DETAILS/SUMMARY (Collapsible Sections) === */
  details {{
    background: white;
    border-radius: 8px;
    margin-bottom: 12px;
    border: 1px solid #e5e7eb;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    transition: all 0.2s ease;
  }}

  details:hover {{
    box-shadow: 0 4px 12px rgba(0,0,0,0.08);
    border-color: #d1d5db;
  }}

  details[open] {{
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
  }}

  summary {{
    display: flex;
    align-items: center;
    padding: 14px 18px;
    cursor: pointer;
    user-select: none;
    font-size: 14px;
    gap: 12px;
    transition: background 0.2s ease;
    border-radius: 8px;
  }}

  summary:hover {{
    background: #f9fafb;
  }}

  summary .bullet {{
    font-size: 12px;
    color: #6b7280;
    transition: transform 0.2s ease;
    width: 16px;
    flex-shrink: 0;
  }}

  details[open] > summary .bullet {{
    transform: rotate(90deg);
  }}

  summary .check-name {{
    flex: 1;
    font-weight: 500;
    color: #374151;
    min-width: 250px;
  }}

  summary .check-status {{
    flex-shrink: 0;
    padding: 4px 12px;
    border-radius: 4px;
    font-size: 13px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}

  summary.pass .check-status {{
    background: #d1fae5;
    color: #065f46;
  }}

  summary.fail .check-status {{
    background: #fee2e2;
    color: #991b1b;
  }}

  summary.warn .check-status {{
    background: #fef3c7;
    color: #92400e;
  }}

  /* === CONTENT INSIDE DETAILS === */
  details > div {{
    padding: 16px 20px;
    border-top: 1px solid #f3f4f6;
    background: #fafbfc;
    font-size: 14px;
    line-height: 1.7;
  }}

  .detail-content {{
    padding: 16px 20px;
    border-top: 1px solid #f3f4f6;
    background: #fafbfc;
    color: #1a1a1a;
  }}

  .detail-content > div {{
    color: #1a1a1a;
  }}

  /* Override code block styling for non-code content in details */
  details > pre {{
    background: #f8f9fa;
    color: #1a1a1a;
    border: 1px solid #e5e7eb;
    padding: 12px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px;
    line-height: 1.6;
  }}

  /* But keep dark theme for actual code snippets */
  .code-snippet {{
    background: #1e293b !important;
    color: #e2e8f0 !important;
    border: 1px solid #334155 !important;
    font-family: 'Menlo', 'Monaco', 'Courier New', monospace !important;
  }}

  .detail-list-item {{
    margin-left: 20px;
    margin-top: 4px;
    color: #374151;
  }}

  .detail-section {{
    margin-top: 10px;
    color: #1a1a1a;
  }}

  .code-evidence {{
    margin-left: 20px;
    font-family: 'Menlo', 'Monaco', 'Courier New', monospace;
    font-size: 13px;
    background: #f5f5f5;
    padding: 12px;
    border-left: 3px solid #4caf50;
    border-radius: 4px;
    color: #1a1a1a;
  }}

  .storage-section {{
    margin-top: 8px;
    color: #1a1a1a;
  }}

  .storage-item {{
    margin-left: 15px;
    margin-top: 3px;
    font-family: 'Menlo', 'Monaco', 'Courier New', monospace;
    font-size: 14px;
    color: #374151;
  }}

  .storage-issue-box {{
    margin-left: 15px;
    margin-top: 3px;
    background: #fff8e1;
    padding: 8px;
    border-left: 3px solid #ffc107;
    border-radius: 4px;
    color: #1a1a1a;
  }}

  .file-list-box {{
    margin-left: 15px;
    background: #f8f9fa;
    padding: 6px;
    border-left: 2px solid #ddd;
    border-radius: 4px;
    color: #1a1a1a;
  }}

  /* === CODE BLOCKS === */
  pre, code {{
    font-family: 'Menlo', 'Monaco', 'Courier New', monospace;
    font-size: 13px;
    background: #1e293b;
    color: #e2e8f0;
    border-radius: 6px;
  }}

  pre {{
    padding: 16px;
    overflow-x: auto;
    margin: 12px 0;
    border: 1px solid #334155;
    box-shadow: 0 2px 8px rgba(0,0,0,0.15);
  }}

  code {{
    padding: 2px 6px;
    display: inline-block;
  }}

  /* === TABLES === */
  table {{
    width: 100%;
    border-collapse: collapse;
    margin: 16px 0;
    background: white;
    border-radius: 8px;
    overflow: hidden;
    box-shadow: 0 2px 8px rgba(0,0,0,0.05);
    font-size: 14px;
  }}

  thead {{
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
  }}

  th {{
    padding: 12px 16px;
    text-align: left;
    font-weight: 600;
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}

  td {{
    padding: 12px 16px;
    border-bottom: 1px solid #f3f4f6;
    vertical-align: top;
  }}

  tbody tr:hover {{
    background: #f9fafb;
  }}

  tbody tr:last-child td {{
    border-bottom: none;
  }}

  /* === LINKS === */
  a {{
    color: #2563eb;
    text-decoration: none;
    transition: color 0.2s ease;
  }}

  a:hover {{
    color: #1d4ed8;
    text-decoration: underline;
  }}

  /* === INFO BOXES === */
  .info-box {{
    background: #eff6ff;
    border-left: 4px solid #2563eb;
    padding: 14px 16px;
    margin: 12px 0;
    border-radius: 4px;
    font-size: 14px;
  }}

  .warning-box {{
    background: #fef3c7;
    border-left: 4px solid #d97706;
    padding: 14px 16px;
    margin: 12px 0;
    border-radius: 4px;
    font-size: 14px;
  }}

  .error-box {{
    background: #fee2e2;
    border-left: 4px solid #dc2626;
    padding: 14px 16px;
    margin: 12px 0;
    border-radius: 4px;
    font-size: 14px;
  }}

  /* === FILTER CONTROLS === */
  .filter-controls {{
    background: white;
    padding: 16px;
    border-radius: 8px;
    margin-bottom: 20px;
    border: 1px solid #e5e7eb;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
  }}

  .filter-select {{
    padding: 8px 12px;
    border: 1px solid #d1d5db;
    border-radius: 6px;
    font-size: 14px;
    margin-right: 12px;
    background: white;
    cursor: pointer;
    transition: all 0.2s ease;
  }}

  .filter-select:hover {{
    border-color: #2563eb;
  }}

  .filter-select:focus {{
    outline: none;
    border-color: #2563eb;
    box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
  }}

  /* === UTILITY === */
  .chevron {{
    display: inline-block;
    margin-left: 6px;
    color: #6b7280;
    font-size: 12px;
  }}

  strong {{
    font-weight: 600;
    color: #1f2937;
  }}

  .text-success {{
    color: #059669;
  }}

  .text-danger {{
    color: #dc2626;
  }}

  .text-warning {{
    color: #d97706;
  }}

  .text-muted {{
    color: #6b7280;
    font-size: 13px;
  }}

  /* === FINDING CARDS === */
  .finding-card {{
    margin: 12px 0;
    padding: 14px 16px;
    background: #fafbfc;
    border-left: 3px solid #d97706;
    border-radius: 6px;
  }}

  .finding-detail {{
    margin: 8px 0 8px 20px;
    padding: 8px 12px;
    background: #ffffff;
    border-radius: 4px;
    font-size: 13px;
    line-height: 1.6;
  }}

  summary.warning {{
    background: #fef3c7;
    border-left: 4px solid #d97706;
  }}

  summary.warning:hover {{
    background: #fde68a;
  }}

  .code-toggle {{
    font-size: 12px;
    color: #2563eb;
    text-decoration: none;
    margin-left: 8px;
  }}

  .code-toggle:hover {{
    color: #1d4ed8;
    text-decoration: underline;
  }}

  .code-snippet {{
    margin-top: 8px;
    max-height: 200px;
    overflow-y: auto;
    font-size: 12px;
  }}

  .highlight {{
    background: #fef3c7;
    color: #1a1a1a;
    display: block;
    font-weight: 600;
  }}

  .code-details {{
    margin-top: 8px;
    display: inline-block;
  }}

  .code-details summary {{
    padding: 4px 8px;
    font-size: 12px;
  }}

  /* === INFO BOXES === */
  .info-box {{
    background: #eff6ff;
    border-left: 4px solid #2563eb;
    padding: 14px 16px;
    margin: 12px 0;
    border-radius: 4px;
    font-size: 14px;
  }}

  .info-box em {{
    font-style: normal;
    color: #1e40af;
  }}

  /* === RESPONSIVE === */
  @media (max-width: 768px) {{
    body {{
      padding: 12px;
    }}

    h1 {{
      font-size: 22px;
    }}

    h2 {{
      font-size: 18px;
    }}

    summary {{
      flex-wrap: wrap;
      gap: 8px;
    }}

    summary .check-name {{
      min-width: 100%;
    }}

    table {{
      font-size: 12px;
    }}

    th, td {{
      padding: 8px 10px;
    }}
  }}
</style>
<script>
// Sort table by column idx, toggling ▲/▼
function sortTable(colIndex) {{
  const table = document.getElementById('checksecTable');
  const tbody = table.tBodies[0];
  const rows = Array.from(tbody.rows);
  const asc = !(table.getAttribute('data-sort-col') == colIndex 
                && table.getAttribute('data-sort-dir') == 'asc');
  rows.sort((a, b) => {{
    let x = a.cells[colIndex].innerText.trim();
    let y = b.cells[colIndex].innerText.trim();
    let xn = parseFloat(x.replace(/[^\\d.-]/g,'')), 
        yn = parseFloat(y.replace(/[^\\d.-]/g,''));
    let cmp = (!isNaN(xn) && !isNaN(yn)) ? xn - yn : x.localeCompare(y);
    return asc ? cmp : -cmp;
  }});
  rows.forEach(r => tbody.appendChild(r));
  table.setAttribute('data-sort-col', colIndex);
  table.setAttribute('data-sort-dir', asc ? 'asc' : 'desc');
  table.querySelectorAll('.chevron').forEach(c => c.textContent = '');
  table.tHead.rows[1].cells[colIndex]
       .querySelector('.chevron').textContent = asc ? '▲' : '▼';
}}

// Filter rows by dropdowns
function applyFilters() {{
  const table = document.getElementById('checksecTable');
  const selects = document.querySelectorAll('.filter-select');
  Array.from(table.tBodies[0].rows).forEach(row => {{
    let show = true;
    selects.forEach((sel, idx) => {{
      const val = sel.value;
      if (val && row.cells[idx].innerText !== val) show = false;
    }});
    row.style.display = show ? '' : 'none';
  }});
}}
</script>
</head>
<body>
<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 12px; margin-bottom: 30px; color: white; box-shadow: 0 4px 20px rgba(0,0,0,0.15);">
  <h1 style="color: white; border: none; margin: 0; padding: 0; font-size: 32px; margin-bottom: 20px;">Mobile Security Assessment Report</h1>

  <div style="background: rgba(255,255,255,0.15); border-radius: 8px; padding: 20px; backdrop-filter: blur(10px);">
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 15px;">
      <div>
        <div style="font-size: 11px; text-transform: uppercase; letter-spacing: 1px; opacity: 0.9; margin-bottom: 5px;">Package</div>
        <div style="font-size: 16px; font-weight: 600; font-family: 'Courier New', monospace;">{package}</div>
      </div>
      <div>
        <div style="font-size: 11px; text-transform: uppercase; letter-spacing: 1px; opacity: 0.9; margin-bottom: 5px;">Version</div>
        <div style="font-size: 16px; font-weight: 600;">{version_name} ({version_code})</div>
      </div>
      <div>
        <div style="font-size: 11px; text-transform: uppercase; letter-spacing: 1px; opacity: 0.9; margin-bottom: 5px;">Size</div>
        <div style="font-size: 16px; font-weight: 600;">{size_mb} MB</div>
      </div>
    </div>

    <div style="border-top: 1px solid rgba(255,255,255,0.3); padding-top: 15px; margin-top: 5px;">
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; font-size: 13px;">
        <div>
          <span style="opacity: 0.9;">Started:</span> <strong>{start_time}</strong>
        </div>
        <div>
          <span style="opacity: 0.9;">Finished:</span> <strong>{finish_time}</strong>
        </div>
      </div>
    </div>
  </div>
</div>

{sections}
</body>
</html>
'''

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        return e.output

def extract_apk_metadata(apk_path, manifest_path):
    """
    Extract APK metadata for the report header.
    Returns: dict with package, version_name, version_code, size_mb
    """
    metadata = {
        'package': 'Unknown',
        'version_name': 'Unknown',
        'version_code': 'Unknown',
        'size_mb': 'Unknown'
    }

    # Try aapt first (most reliable for version info)
    if apk_path and os.path.exists(apk_path):
        try:
            result = subprocess.check_output(
                ['aapt', 'dump', 'badging', apk_path],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=10
            )
            # Parse aapt output
            for line in result.splitlines():
                if line.startswith('package:'):
                    # package: name='com.example' versionCode='1276' versionName='6.5.0'
                    import shlex
                    parts = shlex.split(line)
                    for part in parts:
                        if part.startswith('name='):
                            metadata['package'] = part.split('=', 1)[1]
                        elif part.startswith('versionCode='):
                            metadata['version_code'] = part.split('=', 1)[1]
                        elif part.startswith('versionName='):
                            metadata['version_name'] = part.split('=', 1)[1]
                    break
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            pass  # aapt not available or failed, fall back to XML parsing

    # Fallback: Get package name and version from manifest XML
    if metadata['package'] == 'Unknown' or metadata['version_name'] == 'Unknown':
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            if metadata['package'] == 'Unknown':
                metadata['package'] = root.get('package', 'Unknown')

            # Version info from XML
            if metadata['version_code'] == 'Unknown':
                version_code = root.get('{http://schemas.android.com/apk/res/android}versionCode')
                if version_code:
                    metadata['version_code'] = version_code
            if metadata['version_name'] == 'Unknown':
                version_name = root.get('{http://schemas.android.com/apk/res/android}versionName')
                if version_name:
                    metadata['version_name'] = version_name
        except Exception as e:
            print(f"[!] Could not parse manifest: {e}")

    # Get APK file size
    if apk_path and os.path.exists(apk_path):
        try:
            size_bytes = os.path.getsize(apk_path)
            size_mb = size_bytes / (1024 * 1024)
            metadata['size_mb'] = f"{size_mb:.1f}"
        except Exception as e:
            print(f"[!] Could not get APK size: {e}")

    return metadata

# Helper to grep code patterns

def grep_code(base, pattern):
    hits = []
    for root, _, files in os.walk(base):
        for f in files:
            if f.endswith(('.smali', '.xml', '.java')):
                try:
                    txt = open(os.path.join(root, f), errors='ignore').read()
                    if re.search(pattern, txt):
                        hits.append(os.path.relpath(os.path.join(root, f), base))
                except:
                    pass
    return hits

# Entropy calculation for detecting high-entropy secrets
def calculate_entropy(data):
    """
    Calculate Shannon entropy of a string.
    High entropy (>4.5) often indicates random/encrypted data like keys, tokens.
    """
    if not data:
        return 0.0

    import math
    entropy = 0.0
    data_len = len(data)

    # Count frequency of each character
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1

    # Calculate entropy
    for count in freq.values():
        probability = count / data_len
        entropy -= probability * math.log2(probability)

    return entropy

# Comprehensive sensitive keyword detection
SENSITIVE_KEYWORDS = {
    'credentials': ['password', 'passwd', 'pwd', 'pass', 'credential', 'cred'],
    'tokens': ['token', 'jwt', 'bearer', 'auth', 'authorization', 'session', 'cookie'],
    'keys': ['apikey', 'api_key', 'api-key', 'secretkey', 'secret_key', 'secret-key',
             'privatekey', 'private_key', 'private-key', 'publickey', 'masterkey',
             'hardcoded_api', 'hardcoded_key', 'hardcoded_secret'],  # Common in vulnerable apps
    'secrets': ['secret', 'sec', 'encryption', 'cipher', 'hardcoded'],
    'financial': ['credit', 'card', 'cvv', 'ccv', 'pan', 'payment', 'billing', 'bank', 'account'],
    'pii': ['ssn', 'social', 'tax', 'license', 'passport', 'dob', 'birthdate'],
    'cloud': ['aws', 'azure', 'gcp', 'firebase', 's3', 'bucket', 'region'],
    'database': ['database', 'db', 'sql', 'mongodb', 'redis', 'connection', 'dsn'],
    'oauth': ['client_id', 'client_secret', 'refresh_token', 'access_token', 'oauth'],
    'encryption': ['aes', 'rsa', 'des', '3des', 'blowfish', 'iv', 'salt', 'hmac'],
    'signing': ['signature', 'signing', 'certificate', 'cert', 'pem', 'p12', 'jks', 'keystore'],
}

def is_sensitive_keyword(text):
    """
    Check if text contains sensitive keywords.
    Returns (bool, list of matched categories)
    """
    if not text:
        return False, []

    text_lower = text.lower()
    matches = []

    for category, keywords in SENSITIVE_KEYWORDS.items():
        for keyword in keywords:
            if keyword in text_lower:
                matches.append(category)
                break

    return len(matches) > 0, matches

def is_word_based_identifier(text):
    """
    Check if a string is likely a word-based identifier (like variable names).
    Similar to detect-secrets' WordDetector approach.

    Returns True if the string appears to be composed of regular words
    separated by underscores, hyphens, or camelCase - indicating it's likely
    a variable name or resource identifier rather than a secret.

    Examples that should return True:
        - exo_controls_fastforward_by_amount_description
        - user_profile_settings
        - getApplicationContext
        - my-custom-property
    """
    if not text or len(text) < 3:
        return False

    # Quick check: if it's mostly readable text with spaces, it's UI text
    if ' ' in text and len(text.split()) >= 2:
        # Count non-alphanumeric chars (excluding spaces)
        special_chars = sum(1 for c in text if not c.isalnum() and c != ' ')
        # If mostly alphanumeric + spaces, it's UI text
        if special_chars <= 2:
            return True

    # Remove common separators and split into potential words
    # Handle snake_case, kebab-case, and dot notation
    potential_words = re.split(r'[_\-.]', text)

    # Also handle camelCase by splitting on case boundaries
    # This regex splits before uppercase letters that follow lowercase letters
    camel_split = re.sub(r'([a-z])([A-Z])', r'\1 \2', text)
    camel_parts = camel_split.lower().split()

    # Use whichever splitting method produces more meaningful segments
    if len(camel_parts) > len(potential_words):
        potential_words = camel_parts
    else:
        potential_words = [w.lower() for w in potential_words]

    # Filter out very short segments (< 3 chars) as they're less meaningful
    meaningful_words = [w for w in potential_words if len(w) >= 3]

    if not meaningful_words:
        return False

    # Common English words and programming terms that appear in identifiers
    # This is a curated list similar to detect-secrets approach
    common_words = {
        'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had', 'her',
        'was', 'one', 'our', 'out', 'get', 'set', 'has', 'him', 'his', 'how', 'man',
        'new', 'now', 'old', 'see', 'two', 'way', 'who', 'boy', 'did', 'its', 'let',
        'put', 'say', 'she', 'too', 'use', 'add', 'sub', 'run', 'end', 'var',
        # Common programming/Android terms
        'app', 'api', 'data', 'user', 'name', 'text', 'view', 'button', 'image',
        'list', 'item', 'file', 'path', 'string', 'value', 'type', 'size', 'time',
        'date', 'mode', 'code', 'info', 'main', 'test', 'utils', 'base', 'config',
        'action', 'event', 'state', 'status', 'result', 'error', 'message', 'title',
        'content', 'layout', 'color', 'style', 'theme', 'resource', 'drawable',
        'activity', 'fragment', 'service', 'receiver', 'provider', 'intent',
        'bundle', 'context', 'manager', 'controller', 'handler', 'listener',
        'callback', 'adapter', 'holder', 'factory', 'builder', 'helper',
        'description', 'summary', 'detail', 'label', 'hint', 'placeholder',
        'enabled', 'disabled', 'visible', 'hidden', 'selected', 'checked',
        'amount', 'count', 'index', 'position', 'offset', 'length', 'width',
        'height', 'left', 'right', 'start', 'stop', 'play', 'pause', 'next',
        'previous', 'prev', 'forward', 'backward', 'rewind', 'fastforward',
        'controls', 'settings', 'options', 'preferences', 'properties',
        'exo', 'player', 'media', 'audio', 'video', 'track', 'subtitle',
        'application', 'window', 'screen', 'container', 'component', 'element',
        'custom', 'default', 'current', 'update', 'create', 'delete', 'remove',
        'show', 'hide', 'open', 'close', 'save', 'load', 'read', 'write',
        # Material Design / UI terms
        'material', 'comp', 'primary', 'secondary', 'tertiary', 'surface', 'background',
        'navigation', 'tab', 'bar', 'card', 'chip', 'dialog', 'divider', 'sheet',
        'rail', 'badge', 'banner', 'bottom', 'top', 'fab', 'floating', 'icon',
        'indicator', 'menu', 'modal', 'popup', 'ripple', 'scrim', 'snackbar',
        'switch', 'slider', 'progress', 'search', 'toolbar', 'tooltip',
        'active', 'inactive', 'hover', 'focus', 'pressed', 'dragged', 'selected',
        'layer', 'opacity', 'elevation', 'shadow', 'outline', 'border', 'radius',
        'container', 'wrapper', 'header', 'footer', 'body', 'section',
        'padding', 'margin', 'spacing', 'gap', 'inset', 'full', 'half', 'quarter',
        # Numbers as words
        'zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten',
        # Additional UI/UX terms
        'completed', 'expand', 'buffers', 'pause', 'flag', 'query', 'article', 'mental',
        'health', 'cta', 'design', 'searchview', 'consulta', 'pesquisa', 'extra',
        'horizontal', 'vertical', 'translation', 'hovered', 'focused', 'abc'
    }

    # Count how many segments match common words
    word_matches = sum(1 for w in meaningful_words if w in common_words)

    # If most segments (>40%) are recognizable words, it's likely an identifier
    match_ratio = word_matches / len(meaningful_words)

    return match_ratio > 0.4

def is_likely_secret(value, key_name=""):
    """
    Determine if a value is likely a secret based on:
    - Entropy (randomness)
    - Length
    - Character composition
    - Key name
    Returns (bool, confidence, reason)
    """
    if not value or len(value) < 8:
        return False, 0.0, "too short"

    # Filter out Kotlin mangled function names (e.g., "functionName-ABC123XYZ")
    # Kotlin compiler adds random suffixes to inline functions for uniqueness
    kotlin_mangle_pattern = r'^[a-zA-Z][a-zA-Z0-9_]*-[A-Za-z0-9]{6,12}$'
    if re.match(kotlin_mangle_pattern, value):
        return False, 0.0, "Kotlin mangled function name"

    # Filter out word-based identifiers (like variable names, resource IDs)
    # Check both the value and key name
    if is_word_based_identifier(value):
        return False, 0.0, "word-based identifier"

    if key_name and is_word_based_identifier(key_name):
        # Key name is word-based identifier, very likely not a secret
        return False, 0.0, "word-based key name"

    # Calculate entropy
    entropy = calculate_entropy(value)

    # Check key name for sensitive keywords
    has_sensitive_key, key_categories = is_sensitive_keyword(key_name)

    # Check value for sensitive patterns
    has_sensitive_val, val_categories = is_sensitive_keyword(value)

    confidence = 0.0
    reasons = []

    # High entropy strings are likely secrets
    if entropy > 4.5:
        confidence += 0.4
        reasons.append(f"high entropy ({entropy:.2f})")
    elif entropy > 4.0:
        confidence += 0.2
        reasons.append(f"medium entropy ({entropy:.2f})")

    # Base64-like patterns
    if re.match(r'^[A-Za-z0-9+/]+=*$', value) and len(value) >= 16:
        confidence += 0.3
        reasons.append("base64 pattern")

    # Hex patterns (keys often in hex)
    if re.match(r'^[0-9a-fA-F]+$', value) and len(value) >= 32:
        confidence += 0.3
        reasons.append("hex pattern")

    # UUID/GUID patterns
    if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.I):
        confidence += 0.2
        reasons.append("UUID format")

    # Long alphanumeric strings (API keys)
    if len(value) >= 32 and re.match(r'^[A-Za-z0-9_-]+$', value):
        confidence += 0.2
        reasons.append(f"long key ({len(value)} chars)")

    # Sensitive key name
    if has_sensitive_key:
        confidence += 0.4
        reasons.append(f"sensitive key name: {', '.join(key_categories)}")

    # Sensitive value content
    if has_sensitive_val:
        confidence += 0.2
        reasons.append(f"sensitive value: {', '.join(val_categories)}")

    # Common secret prefixes and patterns (CRITICAL indicators)
    secret_prefixes = [
        'sk_', 'pk_', 'rk_',  # Stripe
        'AKIA',               # AWS
        'AIza',               # Google API
        'ya29.',              # Google OAuth
        'glpat-', 'ghp_', 'gho_', 'github_pat_',  # GitHub/GitLab
        'sq0atp-', 'sq0csp-', # Square
        'xox',                # Slack
        'SG.',                # SendGrid
    ]

    # OBVIOUS hardcoded secret patterns (training/vulnerable apps)
    obvious_patterns = [
        'super_secret', 'my_secret', 'test_secret',
        'hardcoded_api', 'hardcoded_key', 'hardcoded_secret',
        'demo_key', 'sample_key', 'example_key'
    ]

    # Check for obvious patterns FIRST (highest priority)
    for pattern in obvious_patterns:
        if pattern in value.lower():
            confidence += 0.7
            reasons.append(f"OBVIOUS hardcoded secret pattern: {pattern}")
            break

    # Check for known secret prefixes
    for prefix in secret_prefixes:
        if value.startswith(prefix):
            confidence += 0.5
            reasons.append(f"known secret prefix: {prefix}")
            break

    # Check for known secret patterns (not just prefixes)
    if re.match(r'^[0-9]+-[0-9A-Za-z_]+\.apps\.googleusercontent\.com$', value):
        confidence += 0.6
        reasons.append("Google OAuth Client ID pattern")
    elif value.endswith('.apps.googleusercontent.com'):
        confidence += 0.6
        reasons.append("Google OAuth Client ID domain")

    # Cap confidence at 1.0
    confidence = min(confidence, 1.0)

    is_secret = confidence >= 0.5
    reason = "; ".join(reasons) if reasons else "low confidence"

    return is_secret, confidence, reason

# Security check functions

def check_checksec(lib_dir):
    out = run_cmd(f"checksec --dir={lib_dir}")
    text = re.sub(r"\x1b\[[0-9;]*m", "", out)
    text = re.sub(r"[^\x20-\x7E\n]", "", text)
    return True, text

# Other check_* implementations (unchanged)...

def check_debug_symbols(lib_dir):
    """
    For each .so under lib_dir, run:
      readelf --sections <fullpath> | grep '.debug_'
    and if any debug sections are found, include the command and output.
    """

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0040/' target='_blank'>MASTG-TEST-0040: Testing for Debugging Symbols</a></div>"

    details = []
    for root, _, files in os.walk(lib_dir):
        for f in files:
            if not f.endswith('.so'):
                continue
            full_path = os.path.join(root, f)
            # Build and run the grep command
            cmd = f"readelf --sections {full_path}"
            grep_cmd = cmd + " | grep '\\.debug_'"
            out = run_cmd(grep_cmd)
            clean = out.strip()
            if clean:
                # Record the command and its output
                details.append(f"$ {grep_cmd}")
                for line in clean.splitlines():
                    details.append("  " + line)

    if not details:
        return True, "None" + mastg_ref

    # Fail and show the detailed output
    return False, "\n".join(details) + mastg_ref

def check_s3_bucket_security(base):
    """
    Searches for AWS S3 bucket references in the decompiled code and tests for common misconfigurations:
    1. Attempts to write a test file to discovered buckets
    2. Checks if directory listing is enabled

    SECURITY NOTE: This test only attempts writes - it does not exfiltrate data or modify existing files.
    """

    # Find S3 bucket references
    bucket_patterns = [
        r's3://([a-zA-Z0-9.\-]+)',  # s3://bucket-name
        r'([a-zA-Z0-9.\-]+)\.s3\.amazonaws\.com',  # bucket-name.s3.amazonaws.com
        r's3\.amazonaws\.com/([a-zA-Z0-9.\-]+)',  # s3.amazonaws.com/bucket-name
        r'([a-zA-Z0-9.\-]+)\.s3-([a-z0-9\-]+)\.amazonaws\.com',  # bucket-name.s3-region.amazonaws.com
    ]

    buckets_found = set()
    bucket_locations = {}

    for root, _, files in os.walk(base):
        for fn in files:
            if not fn.endswith(('.smali', '.xml', '.json', '.properties')):
                continue

            path = os.path.join(root, fn)
            rel = os.path.relpath(path, base)

            try:
                content = open(path, errors='ignore').read()

                for pattern in bucket_patterns:
                    for match in re.finditer(pattern, content, re.IGNORECASE):
                        bucket_name = match.group(1)
                        # Filter out obvious false positives
                        if bucket_name and not bucket_name.startswith('.') and len(bucket_name) > 3:
                            buckets_found.add(bucket_name)
                            if bucket_name not in bucket_locations:
                                bucket_locations[bucket_name] = []
                            bucket_locations[bucket_name].append(f"{rel}:{content[:match.start()].count(chr(10)) + 1}")

            except Exception:
                continue

    if not buckets_found:
        return True, "<div>No S3 bucket references found in app code</div>"

    # Test discovered buckets
    import tempfile
    import subprocess

    findings = []
    test_content = b"security-test-file-safe-to-delete"

    for bucket in sorted(buckets_found):
        bucket_info = []
        bucket_info.append(f"<div><strong>Bucket: {html.escape(bucket)}</strong></div>")

        # Show where it was found
        locations = bucket_locations.get(bucket, [])
        bucket_info.append("<div style='margin-left:15px; font-size:10px; color:#666'>")
        for loc in locations[:3]:
            bucket_info.append(f"Found in: <code>{html.escape(loc)}</code><br>")
        if len(locations) > 3:
            bucket_info.append(f"...and {len(locations) - 3} more locations<br>")
        bucket_info.append("</div>")

        # Test 1: Try to write a file
        write_test_passed = False
        try:
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(test_content)
                tmp.flush()
                tmp_path = tmp.name

            # Attempt PUT request
            test_url = f"https://{bucket}.s3.amazonaws.com/security-test-{os.urandom(8).hex()}.txt"
            result = subprocess.run(
                ['curl', '-X', 'PUT', '--upload-file', tmp_path, test_url, '-s', '-o', '/dev/null', '-w', '%{http_code}'],
                capture_output=True,
                text=True,
                timeout=10
            )

            os.unlink(tmp_path)

            http_code = result.stdout.strip()

            if http_code == '200':
                bucket_info.append("<div style='margin-left:15px; color:#dc3545'><strong>WRITE ACCESS: Successfully uploaded test file!</strong></div>")
                write_test_passed = True
            elif http_code == '403':
                bucket_info.append("<div style='margin-left:15px; color:#28a745'>Write access denied (expected)</div>")
            elif http_code == '404':
                bucket_info.append("<div style='margin-left:15px; color:#666'>Bucket does not exist or is private</div>")
            else:
                bucket_info.append(f"<div style='margin-left:15px; color:#666'>Write test returned HTTP {html.escape(http_code)}</div>")

        except subprocess.TimeoutExpired:
            bucket_info.append("<div style='margin-left:15px; color:#666'>Write test timed out</div>")
        except Exception as e:
            bucket_info.append(f"<div style='margin-left:15px; color:#666'>Write test failed: {html.escape(str(e)[:100])}</div>")

        # Test 2: Check for directory listing
        try:
            list_url = f"https://{bucket}.s3.amazonaws.com/"
            result = subprocess.run(
                ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', list_url],
                capture_output=True,
                text=True,
                timeout=10
            )

            http_code = result.stdout.strip()

            if http_code == '200':
                # Check if response contains XML listing
                result = subprocess.run(
                    ['curl', '-s', list_url],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if '<ListBucketResult' in result.stdout:
                    bucket_info.append("<div style='margin-left:15px; color:#dc3545'><strong>DIRECTORY LISTING ENABLED!</strong></div>")
                else:
                    bucket_info.append("<div style='margin-left:15px; color:#28a745'>Directory listing disabled</div>")
            else:
                bucket_info.append("<div style='margin-left:15px; color:#28a745'>Directory listing disabled</div>")

        except subprocess.TimeoutExpired:
            bucket_info.append("<div style='margin-left:15px; color:#666'>Directory listing test timed out</div>")
        except Exception as e:
            bucket_info.append(f"<div style='margin-left:15px; color:#666'>Directory listing test failed: {html.escape(str(e)[:100])}</div>")

        findings.append("".join(bucket_info))

    if not findings:
        return True, "<div>No S3 buckets found to test</div>"

    detail = "<div><strong>Found {0} S3 bucket reference(s):</strong></div><br>".format(len(buckets_found)) + "<br>".join(findings)
    detail += "<br><div style='margin-top:10px; font-size:10px; color:#666'><em>Note: These tests only check for misconfigurations. No data was exfiltrated.</em></div>"

    # Return FAIL if any security issues found
    has_issues = any('WRITE ACCESS' in f or 'DIRECTORY LISTING ENABLED' in f for f in findings)
    return (False if has_issues else True, detail)


def check_x509(base):
    """
    Comprehensive SSL/TLS security check covering multiple MASTG tests:
    - MASTG-TEST-0282: Endpoint Identity Verification
    - MASTG-TEST-0283: Custom Certificate Stores and Certificate Pinning
    - MASTG-TEST-0234: Data Encryption on the Network

    Detects:
      1) Insecure TrustManager implementations (empty checkServerTrusted/checkClientTrusted)
      2) HostnameVerifier bypasses (always returns true)
      3) SSLSocket without endpoint identification algorithm
      4) Custom certificate pinning implementations
      5) SSL verification bypasses

    Skips native delegates and legitimate verification implementations.
    """

    mastg_refs = (
        "<br><div><strong>References:</strong><br>"
        "• <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0282/' target='_blank'>MASTG-TEST-0282: Testing Endpoint Identity Verification</a><br>"
        "• <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0283/' target='_blank'>MASTG-TEST-0283: Testing Custom Certificate Stores and Certificate Pinning</a><br>"
        "• <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0234/' target='_blank'>MASTG-TEST-0234: Testing Data Encryption on the Network</a>"
        "</div>"
    )

    issues = []
    seen = set()

    # Patterns for TrustManager
    tm_method_re = re.compile(r'\.method\s+[^\n]*\b(checkServerTrusted|checkClientTrusted)\b')
    cert_exc_re = re.compile(r'throw-new.*CertificateException')
    validity_re = re.compile(r'\.checkValidity\(')
    verify_re = re.compile(r'(->verify\(|\.verify\()')
    verify_remote_re = re.compile(r'verifyRemoteCertificate')

    # Patterns for HostnameVerifier
    hv_method_re = re.compile(r'\.method\s+.*?verify\(')
    hv_stub_re = re.compile(r'const/4\s+\S+,\s+0x1[\s\S]*?return', re.MULTILINE)

    # Patterns for SSLSocket endpoint identification
    sslsocket_init_re = re.compile(r'(invoke-.*Ljavax/net/ssl/SSLSocket;-><init>|invoke-.*Ljavax/net/ssl/SSLSocketFactory;->createSocket)')
    endpoint_algo_re = re.compile(r'Ljavax/net/ssl/SSLParameters;->setEndpointIdentificationAlgorithm')

    # Patterns for certificate pinning
    cert_pinner_re = re.compile(r'(Lokhttp3/CertificatePinner|certificatePinner|pinning)')

    inst_re = re.compile(r'^(?!\.(?:locals|line|annotation))\s*\S+')

    for root, _, files in os.walk(base):
        for fn in files:
            if not fn.endswith('.smali'):
                continue
            path = os.path.join(root, fn)
            rel = os.path.relpath(path, base)

            # Skip well-known library code that properly handles SSL/TLS
            library_paths = [
                'androidx/', 'android/support/', 'com/google/',
                'okhttp3/', 'retrofit2/', 'com/squareup/okhttp/',
                'org/apache/http/', 'io/grpc/', 'com/android/org/conscrypt/'
            ]
            if any(lib in rel.replace('\\', '/') for lib in library_paths):
                continue

            lines = open(path, errors='ignore').read().splitlines()
            i = 0

            while i < len(lines):
                line = lines[i]

                # -- TrustManager methods --
                m = tm_method_re.search(line)
                if m:
                    name = m.group(1)
                    start = i
                    body = []
                    j = i + 1
                    while j < len(lines) and not lines[j].startswith('.end method'):
                        body.append(lines[j])
                        j += 1
                    text_body = "\n".join(body)

                    key = (rel, start, name)
                    if key not in seen:
                        seen.add(key)

                        is_native_delegate = any(
			    'invoke-direct' in l and (
			    '->n_checkClientTrusted' in l or
			    '->n_checkServerTrusted' in l
			    )
			    for l in body
			)

                        if not (
                            cert_exc_re.search(text_body)
                            or validity_re.search(text_body)
                            or verify_re.search(text_body)
                            or verify_remote_re.search(text_body)
                            or is_native_delegate
                        ):
                            snippet = []
                            for b in body:
                                if inst_re.match(b):
                                    idx = body.index(b)
                                    snippet = body[idx:idx+3]
                                    break
                            if not snippet:
                                snippet = body[:3]
                            snippet_html = html.escape("\n".join(snippet))
                            link = (
                                f'<a href="file://{html.escape(path)}">'
                                f'{html.escape(rel)}:{start+1}</a>'
                            )
                            issues.append(
                                f"{link} – <strong>{name}()</strong> missing validation<br>"
                                f"<pre>{snippet_html}</pre>"
                            )
                    i = j

                # -- HostnameVerifier stubs --
                elif hv_method_re.search(line):
                    key = (rel, i)
                    if key not in seen:
                        seen.add(key)
                        for k in range(i+1, min(i+20, len(lines))):
                            if hv_stub_re.search(lines[k]):
                                snippet = html.escape(lines[k].strip())
                                link = (
                                    f'<a href="file://{html.escape(path)}">'
                                    f'{html.escape(rel)}:{k+1}</a>'
                                )
                                issues.append(
                                    f"{link} – <strong>HostnameVerifier.verify()</strong> always returns true<br>"
                                    f"<code>{snippet}</code>"
                                )
                                break
                    while i < len(lines) and not lines[i].startswith('.end method'):
                        i += 1

                # -- SSLSocket endpoint identification check --
                elif sslsocket_init_re.search(line):
                    # Check if setEndpointIdentificationAlgorithm is called in the next 30 lines
                    has_endpoint_id = False
                    for k in range(i, min(i+30, len(lines))):
                        if endpoint_algo_re.search(lines[k]):
                            has_endpoint_id = True
                            break
                        # Stop at end of method
                        if lines[k].startswith('.end method'):
                            break

                    if not has_endpoint_id:
                        key = (rel, i)
                        if key not in seen:
                            seen.add(key)
                            snippet = html.escape(line.strip())
                            link = (
                                f'<a href="file://{html.escape(path)}">'
                                f'{html.escape(rel)}:{i+1}</a>'
                            )
                            issues.append(
                                f"{link} – <strong>SSLSocket</strong> created without endpoint identification algorithm<br>"
                                f"<code>{snippet}</code><br>"
                                f"<em>Missing: SSLParameters.setEndpointIdentificationAlgorithm(\"HTTPS\")</em>"
                            )

                i += 1

    # Check for network_security_config.xml and expired certificates (MASTG-TEST-0243)
    manifest_path = os.path.join(base, 'AndroidManifest.xml')
    network_config_ref = None
    if os.path.exists(manifest_path):
        try:
            manifest_content = open(manifest_path, errors='ignore').read()
            if 'networkSecurityConfig' in manifest_content:
                # Extract the network security config file reference
                config_match = re.search(r'android:networkSecurityConfig="@xml/(\w+)"', manifest_content)
                if config_match:
                    network_config_ref = config_match.group(1)
                    # Look for the XML file
                    config_path = os.path.join(base, 'res', 'xml', f'{network_config_ref}.xml')
                    if os.path.exists(config_path):
                        config_content = open(config_path, errors='ignore').read()
                        # Check for certificate pinning with expiration dates
                        if '<pin' in config_content and 'expiration' in config_content:
                            # Parse expiration dates
                            expiration_matches = re.findall(r'expiration="([^"]+)"', config_content)
                            from datetime import datetime
                            current_date = datetime.now()
                            for exp_date_str in expiration_matches:
                                try:
                                    # Parse date format: YYYY-MM-DD
                                    exp_date = datetime.strptime(exp_date_str, '%Y-%m-%d')
                                    if exp_date < current_date:
                                        issues.append(
                                            f"<strong>EXPIRED Certificate Pin in network_security_config.xml</strong><br>"
                                            f"Expiration date: {exp_date_str} (already expired)<br>"
                                            f"<em>Reference: MASTG-TEST-0243</em>"
                                        )
                                except ValueError:
                                    pass  # Invalid date format
        except Exception:
            pass

    if not issues:
        return True, "None" + mastg_refs

    # Group issues by category for better readability
    return False, "<br>\n".join(issues) + mastg_refs


def check_strict_mode(base):
    """
    Check if the app uses android.os.StrictMode APIs.
    StrictMode should be disabled in production builds as it can leak debug info.
    Shows actual API calls with line numbers and context.
    """
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0263/' target='_blank'>MASTG-TEST-0263: Logging of StrictMode Violations</a></div>"

    # StrictMode API patterns (SMALI patterns for decompiled APK)
    strictmode_apis = {
        'setThreadPolicy': r'Landroid/os/StrictMode;->setThreadPolicy',
        'setVmPolicy': r'Landroid/os/StrictMode;->setVmPolicy',
        'enableDefaults': r'Landroid/os/StrictMode;->enableDefaults',
        'ThreadPolicy.Builder': r'Landroid/os/StrictMode\$ThreadPolicy\$Builder',
        'VmPolicy.Builder': r'Landroid/os/StrictMode\$VmPolicy\$Builder',
        'detectAll': r'StrictMode\$.*Builder;->detectAll',
        'penaltyLog': r'StrictMode\$.*Builder;->penaltyLog',
        'penaltyDeath': r'StrictMode\$.*Builder;->penaltyDeath',
    }

    findings = []
    scanned_files = 0

    for root, _, files in os.walk(base):
        for f in files:
            if not f.endswith('.smali'):
                continue

            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, base)

            # Skip library files
            if any(lib in rel_path for lib in ['androidx/', 'android/support/', 'com/google/']):
                continue

            scanned_files += 1

            try:
                with open(full_path, errors='ignore') as file:
                    lines = file.readlines()

                # Look for StrictMode API calls
                for line_num, line in enumerate(lines, 1):
                    # First check for any StrictMode reference
                    if 'Landroid/os/StrictMode' not in line:
                        continue

                    # Check if this is guarded by BuildConfig.DEBUG
                    context_start = max(0, line_num - 15)
                    context = ''.join(lines[context_start:line_num])
                    has_debug_guard = 'BuildConfig' in context and 'DEBUG' in context

                    # Then check specific APIs
                    for api_name, pattern in strictmode_apis.items():
                        if re.search(pattern, line):
                            findings.append({
                                'file': rel_path,
                                'line': line_num,
                                'api': api_name,
                                'snippet': line.strip(),
                                'has_debug_guard': has_debug_guard
                            })
                            break

            except Exception:
                continue

    if not findings:
        return 'PASS', f"<div>No StrictMode usage detected</div><div>Scanned {scanned_files} files</div>" + mastg_ref

    # Build detailed report
    lines = []
    lines.append(f"<div><strong>Scanned:</strong> {scanned_files} app files</div>")

    # Count guarded vs unguarded
    guarded = [f for f in findings if f.get('has_debug_guard')]
    unguarded = [f for f in findings if not f.get('has_debug_guard')]

    lines.append(f"<div><strong>StrictMode API calls found:</strong> {len(findings)} instance(s)</div>")
    if guarded:
        lines.append(f"<div> <strong>Guarded by DEBUG check:</strong> {len(guarded)} instance(s)</div>")
    if unguarded:
        lines.append(f"<div>WARNING: <strong>Not guarded (production risk):</strong> {len(unguarded)} instance(s)</div>")
    lines.append("<br>")

    # Group by file
    files_with_strictmode = {}
    for finding in findings:
        file_path = finding['file']
        if file_path not in files_with_strictmode:
            files_with_strictmode[file_path] = []
        files_with_strictmode[file_path].append(finding)

    # Collapsible section
    lines.append('<details open>')
    lines.append('<summary class="warning">')
    lines.append(f'WARNING: StrictMode Usage ({len(files_with_strictmode)} files) - Click to expand/collapse')
    lines.append('</summary>')
    lines.append('<div>')

    for file_path in sorted(files_with_strictmode.keys()):
        full = os.path.abspath(os.path.join(base, file_path))
        file_findings = files_with_strictmode[file_path]

        lines.append(
            f'<div class="finding-card">'
            f'<a href="file://{html.escape(full)}">{html.escape(file_path)}</a><br>'
            f'<strong>StrictMode calls:</strong> {len(file_findings)}<br>'
        )

        for finding in file_findings[:5]:  # Show first 5 per file
            guarded_indicator = ' ' if finding.get('has_debug_guard') else 'WARNING: '
            guard_status = '<span class="text-success">(DEBUG-guarded)</span>' if finding.get('has_debug_guard') else '<span class="text-danger">(not guarded)</span>'

            lines.append(f'<div class="finding-detail">')
            lines.append(f'{guarded_indicator}<strong>Line {finding["line"]}:</strong> <code>{finding["api"]}</code> {guard_status}')
            lines.append(f'<br><code>{html.escape(finding["snippet"])}</code>')
            lines.append('</div>')

        if len(file_findings) > 5:
            lines.append(f'<div class="finding-detail"><em>...and {len(file_findings) - 5} more in this file</em></div>')

        lines.append('</div>')

    lines.append('</div></details>')

    lines.append(
        '<div class="info-box"><em> Recommendation: StrictMode is a development tool for detecting performance issues. '
        'It should be disabled in production builds as it can expose debug information and impact performance. '
        'Use BuildConfig.DEBUG checks to conditionally enable StrictMode only during development.</em></div>'
    )

    # Return WARN since StrictMode in production is a concern but not always critical
    return 'WARN', '\n'.join(lines) + mastg_ref
    
def check_kotlin_assert(base):
    """
    Scan for Kotlin Intrinsics calls leaking parameters.
    Returns (ok, details_html, total_hits).
    Only the first 100 hits are shown; total_hits is the real count.
    Filters out library code to show only app code issues.
    """
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0044/' target='_blank'>MASTG-TEST-0044: Make Sure That Free Security Features Are Activated</a></div>"

    # Library paths to exclude (same pattern as other checks)
    lib_paths = (
        '/androidx/', '/android/support/',
        '/com/google/android/gms/', '/com/google/firebase/', '/com/google/android/play/',
        '/okhttp3/', '/retrofit2/', '/com/squareup/',
        '/com/facebook/', '/kotlin/', '/kotlinx/',
        '/io/reactivex/', '/rx/', '/dagger/',
        '/lib/', '/jetified-'
    )

    def is_library_path(path):
        """Check if path is library code"""
        normalized = '/' + path.replace('\\', '/')
        return any(lib in normalized for lib in lib_paths)

    patterns = [
        r'checkNotNullParameter\([^)]*\)',
        r'checkNotNullExpressionValue\([^)]*\)',
    ]
    hits = []
    for root, _, files in os.walk(base):
        for f in files:
            if not f.endswith(('.smali','.java')): continue
            full = os.path.join(root, f)
            rel = os.path.relpath(full, base)

            # Skip library code
            if is_library_path(rel):
                continue

            try:
                for line in open(full, errors='ignore'):
                    for pat in patterns:
                        m = re.search(pat, line)
                        if m:
                            snippet = m.group(0).strip()
                            hits.append((rel, snippet))
            except:
                pass

    total = len(hits)
    if total == 0:
        return True, "None" + mastg_ref, 0

    # only show first 100
    display = hits[:100]
    lines = []
    for rel, snippet in display:
        full = os.path.abspath(os.path.join(base, rel))
        lines.append(
            f'<a href="file://{html.escape(full)}">{html.escape(rel)}</a>: '
            f'<code>{html.escape(snippet)}</code>'
        )
    if total > 100:
        lines.append(f"...and {total-100} more")

    return False, "<br>\n".join(lines) + mastg_ref, total


def check_uri_scheme(manifest):
    """
    Detect custom URI scheme vulnerabilities (OAuth takeover + general deep link hijacking).

    VULNERABILITY: Custom URI schemes can be hijacked by malicious apps.
    When an app uses a custom scheme (e.g., mycustomscheme://), a malicious app
    can register the same scheme and intercept intents/data.

    Real-world impact:
    - OAuth Account Takeover: Microsoft, GitHub/Travis CI token theft
    - Task Hijacking: StrandHogg-style attacks via deep links
    - 41.21% of OAuth mobile apps found vulnerable
    - Over 1 billion users potentially at risk

    MASVS: MASVS-AUTH-1, MASVS-PLATFORM-1, MSTG-PLATFORM-3

    Checks for:
    1. Custom schemes (NOT http/https) with VIEW action
    2. Both BROWSABLE and DEFAULT categories (all are vulnerable)
    3. Common OAuth redirect patterns (higher severity)
    4. Provides ADB test commands for manual verification
    """
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0028/' target='_blank'>MASTG-TEST-0028: Testing Deep Links</a></div>"

    ANDROID_NS = 'http://schemas.android.com/apk/res/android'
    def ns(a): return f'{{{ANDROID_NS}}}{a}'

    try:
        tree = ET.parse(manifest)
        root = tree.getroot()
        pkg = root.attrib.get('package', '')
    except:
        return True, "Unable to parse manifest"

    # Use dict to deduplicate by (activity, scheme) - one issue per activity+scheme combo
    vulnerable_schemes = {}
    oauth_indicators = [
        'oauth', 'redirect', 'callback', 'auth', 'login',
        'RedirectUriReceiverActivity', 'RedirectUriReceiver',
        'OAuthRedirect', 'CallbackActivity'
    ]

    for activity in root.findall('.//activity'):
        activity_name = activity.get(ns('name'), 'unknown')
        full_name = activity_name if '.' in activity_name else f"{pkg}.{activity_name}"

        for intent_filter in activity.findall('intent-filter'):
            # Check for VIEW action (makes it externally accessible)
            categories = {c.get(ns('name')) for c in intent_filter.findall('category')}
            # Accept both BROWSABLE (web-accessible) and DEFAULT (intent-accessible)
            # Both are vulnerable to hijacking
            has_browsable = 'android.intent.category.BROWSABLE' in categories
            has_default = 'android.intent.category.DEFAULT' in categories

            if not (has_browsable or has_default):
                continue

            actions = {a.get(ns('name')) for a in intent_filter.findall('action')}
            if 'android.intent.action.VIEW' not in actions:
                continue

            data_tags = intent_filter.findall('data')
            if not data_tags:
                continue

            # Collect all custom schemes from this intent-filter
            custom_schemes = set()
            scheme_hosts = {}
            for data_tag in data_tags:
                scheme = data_tag.get(ns('scheme'))
                host = data_tag.get(ns('host'), '')

                # Skip http/https - those are handled by check_browsable_deeplinks
                if not scheme or scheme in ('http', 'https'):
                    continue

                custom_schemes.add(scheme)
                # Collect hosts for this scheme
                if scheme not in scheme_hosts:
                    scheme_hosts[scheme] = []
                if host:
                    scheme_hosts[scheme].append(host)

            # Report once per (activity, scheme) combination
            for scheme in custom_schemes:
                dedup_key = (activity_name, scheme)
                if dedup_key in vulnerable_schemes:
                    continue  # Already reported this activity + scheme combo

                # Found a custom scheme - potential OAuth/hijacking vulnerability
                hosts = scheme_hosts.get(scheme, [])
                host_display = hosts[0] if hosts else 'test'

                is_likely_oauth = any(indicator.lower() in activity_name.lower() or
                                     any(indicator.lower() in h.lower() for h in hosts)
                                     for indicator in oauth_indicators)

                # Store minimal info: scheme, host, test command, and OAuth flag
                test_uri = f"{scheme}://{host_display}"
                vulnerable_schemes[dedup_key] = {
                    'scheme': scheme,
                    'host': host_display,
                    'test_uri': test_uri,
                    'is_oauth': is_likely_oauth,
                    'activity': activity_name
                }

    issues = list(vulnerable_schemes.values())

    if not issues:
        return True, "No custom URI schemes detected" + mastg_ref, 0

    # Get unique schemes (deduplicate)
    unique_schemes = sorted(set(info['scheme'] for info in issues))
    oauth_count = sum(1 for info in issues if info['is_oauth'])

    # Build simplified output
    result = f"<strong>Found {len(issues)} vulnerable custom URI scheme(s)</strong><br><br>"

    # Show all unique schemes
    result += f"<strong>Schemes:</strong> {', '.join(f'<code>{s}://</code>' for s in unique_schemes)}<br>"

    if oauth_count > 0:
        result += f"<strong>⚠ OAuth Indicators:</strong> {oauth_count} instance(s) may be used for OAuth (high risk for account takeover)<br>"

    result += "<br><strong>Vulnerable Activities:</strong><br>"
    for info in issues:
        oauth_marker = " 🔴 OAuth" if info['is_oauth'] else ""
        result += f"<div>• <code>{info['activity']}</code> - <code>{info['scheme']}://{info['host']}</code>{oauth_marker}</div>"

    result += "<br><strong>Vulnerability:</strong> Custom URI schemes can be hijacked by malicious apps to intercept intents/tokens.<br>"

    # Show test command for first scheme
    first_issue = issues[0]
    result += f"<br><strong>Test for vulnerability:</strong><br>"
    result += f"<pre>adb shell am start -a android.intent.action.VIEW -d \"{first_issue['test_uri']}\" {pkg}</pre>"
    result += f"Or create a test app with the same custom scheme and install both apps to see which receives the intent.<br>"

    result += f"<br><strong>Fix:</strong> Replace custom schemes with HTTPS App Links using <code>android:autoVerify=\"true\"</code>"
    result += mastg_ref

    return False, result, len(issues)

def check_logging(base):
    """
    Find logging statements and analyze for potentially sensitive data.
    Uses keyword detection and entropy analysis to identify risky logs.
    Returns (ok, details_html, total_sensitive_hits).
    """

    # Comprehensive sensitive keywords that indicate potentially sensitive data being logged
    sensitive_keywords = [
        # Authentication & Access
        'password', 'passwd', 'pwd', 'pass', 'passphrase', 'passcode',
        'secret', 'token', 'auth', 'authorization', 'authenticate', 'bearer',
        'session', 'sessionid', 'sessid', 'jsessionid', 'phpsessid',
        'cookie', 'csrf', 'xsrf',
        'credential', 'credentials', 'login', 'signin', 'oauth', 'jwt',

        # API & Cryptographic Keys
        'api_key', 'apikey', 'api-key', 'api key', 'client_id', 'client_secret',
        'access_token', 'refresh_token', 'id_token',
        'private_key', 'privatekey', 'public_key', 'encryption_key', 'decrypt',
        'master_key', 'secret_key', 'crypto', 'cipher', 'salt', 'iv', 'nonce',
        'signature', 'hmac', 'rsa', 'aes', 'sha', 'md5',

        # Financial Information
        'credit_card', 'creditcard', 'card_number', 'cardnumber', 'pan',
        'cvv', 'cvc', 'cvv2', 'cid', 'expiry', 'expiration',
        'pin', 'account_number', 'routing_number', 'iban', 'swift',
        'balance', 'payment', 'transaction', 'amount', 'bank',
        'debit', 'paypal', 'venmo', 'bitcoin', 'wallet',

        # Personal Identifiable Information (PII)
        'ssn', 'social_security', 'social security', 'passport', 'license',
        'dob', 'date_of_birth', 'birthdate', 'birthday',
        'firstname', 'lastname', 'full_name', 'fullname',
        'email', 'e-mail', 'phone', 'mobile', 'telephone', 'cell',
        'address', 'street', 'zipcode', 'postal', 'city',
        'nationality', 'citizenship', 'tax_id', 'taxpayer',

        # Location Data
        'location', 'gps', 'latitude', 'longitude', 'lat', 'lng', 'lon',
        'coordinate', 'geolocation', 'position', 'altitude',

        # User Account Data
        'user_id', 'userid', 'username', 'user', 'account', 'accountid',
        'profile', 'device_id', 'deviceid', 'imei', 'imsi', 'serial',
        'mac_address', 'macaddress', 'uuid', 'guid',

        # Health & Medical
        'health', 'medical', 'diagnosis', 'prescription', 'patient',
        'blood', 'allergy', 'medication', 'symptom',

        # Biometric
        'biometric', 'fingerprint', 'faceprint', 'retina', 'iris',
        'voiceprint', 'facial',

        # Network & Infrastructure
        'database', 'db_password', 'connection_string', 'connectionstring',
        'host', 'server', 'endpoint', 'url', 'uri',
        'admin', 'root', 'superuser', 'privilege',

        # Sensitive Operations
        'decrypt', 'decipher', 'unwrap', 'plaintext', 'clear_text',
        'sensitive', 'confidential', 'private', 'internal',
        'debug', 'test_mode', 'dev_mode', 'development',

        # Common Sensitive Field Names
        'accesstoken', 'authtoken', 'securitytoken', 'apitoken',
        'clientsecret', 'secretkey', 'encryptionkey',
        'accountnumber', 'cardnumber', 'socialsecurity'
    ]

    # Patterns per level, both Java and smali forms
    log_patterns = {
        "VERBOSE":   [r"Log\.v\(",       r"Landroid/util/Log;->v\("],
        "DEBUG":     [r"Log\.d\(",       r"Landroid/util/Log;->d\("],
        "INFO":      [r"Log\.i\(",       r"Landroid/util/Log;->i\("],
        "WARN":      [r"Log\.w\(",       r"Landroid/util/Log;->w\("],
        "ERROR":     [r"Log\.e\(",       r"Landroid/util/Log;->e\("],
        "PRINTLN":   [r"System\.out\.println\("],
        "STACKTRACE":[r"\.printStackTrace\("]
    }

    # Collect stats and potentially sensitive findings
    stats = {lvl: 0 for lvl in log_patterns}
    sensitive_findings = []
    scanned_files = 0

    for root, _, files in os.walk(base):
        for fn in files:
            if not fn.endswith(('.smali', '.java')):
                continue

            path = os.path.join(root, fn)
            rel = os.path.relpath(path, base)
            scanned_files += 1

            try:
                content = open(path, errors='ignore').read()
                lines = content.splitlines()

                # Check for each log level
                for lvl, pats in log_patterns.items():
                    for pat in pats:
                        for match in re.finditer(pat, content):
                            stats[lvl] += 1

                            # Extract the line and surrounding context
                            line_num = content[:match.start()].count('\n')
                            start_idx = max(0, line_num - 1)
                            end_idx = min(len(lines), line_num + 3)
                            context = lines[start_idx:end_idx]
                            log_line = lines[line_num] if line_num < len(lines) else ""

                            # Check for sensitive keywords in the context
                            context_text = ' '.join(context).lower()
                            found_keywords = [kw for kw in sensitive_keywords if kw in context_text]

                            # Check for high-entropy strings (potential secrets/tokens)
                            high_entropy_strings = []
                            # Look for quoted strings in the log line
                            string_matches = re.findall(r'"([^"]{8,})"', log_line)
                            for s in string_matches:
                                entropy = calculate_entropy(s)
                                if entropy > 4.0:  # High entropy threshold
                                    high_entropy_strings.append((s[:50], round(entropy, 2)))

                            # Only add to findings if sensitive keywords or high entropy detected
                            if found_keywords or high_entropy_strings:
                                severity = "High" if found_keywords else "Medium"
                                reason_parts = []
                                if found_keywords:
                                    reason_parts.append(f"Keywords: {', '.join(found_keywords[:3])}")
                                if high_entropy_strings:
                                    reason_parts.append(f"High-entropy strings: {len(high_entropy_strings)}")

                                finding = {
                                    'file': rel,
                                    'line': line_num + 1,
                                    'level': lvl,
                                    'severity': severity,
                                    'context': context,
                                    'keywords': found_keywords,
                                    'high_entropy': high_entropy_strings,
                                    'reason': ' | '.join(reason_parts)
                                }

                                # Avoid duplicates
                                dup_key = (rel, line_num)
                                if dup_key not in [(f['file'], f['line']) for f in sensitive_findings]:
                                    sensitive_findings.append(finding)

            except Exception:
                continue

    # Build response
    total_logs = sum(stats.values())
    total_sensitive = len(sensitive_findings)

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0003/' target='_blank'>MASTG-TEST-0003: Testing Logs for Sensitive Data</a></div>"

    if total_logs == 0:
        return True, f"<div>No logging statements detected</div>{mastg_ref}", 0

    # Generate summary stats
    summary_parts = [f"{lvl}: {stats[lvl]}" for lvl in log_patterns if stats[lvl] > 0]
    summary = ", ".join(summary_parts)

    lines = []
    lines.append(f"<div style='margin:10px 0'><strong>Total Logs:</strong> {total_logs} ({summary})</div>")
    lines.append(f"<div style='margin:10px 0'><strong>Potentially Sensitive Logs:</strong> {total_sensitive} (filtered by keywords & entropy)</div>")

    if total_sensitive == 0:
        lines.append("<div style='padding:10px; background:#d4edda; border-left:3px solid #28a745;'><strong>✓ No sensitive data detected in logs</strong><br>All log statements appear to be non-sensitive.</div>")
        return 'WARN', "<br>\n".join(lines) + mastg_ref, 0

    # Generate table ID
    import random
    table_id = f"logging_table_{random.randint(1000, 9999)}"

    # Add filter controls
    lines.append(f'''
<div style="margin:15px 0; padding:12px; background:#f8f9fa; border-radius:4px;">
    <div style="display:flex; gap:15px; align-items:center; flex-wrap:wrap;">
        <div style="display:flex; gap:8px; align-items:center;">
            <label style="font-weight:600; margin-right:5px;">Filter by Severity:</label>
            <label style="cursor:pointer;"><input type="checkbox" id="{table_id}_filter_high" checked onchange="filterLogTable_{table_id}()"> <span style="color:#dc3545; font-weight:600;">High</span></label>
            <label style="cursor:pointer;"><input type="checkbox" id="{table_id}_filter_medium" checked onchange="filterLogTable_{table_id}()"> <span style="color:#ffc107; font-weight:600;">Medium</span></label>
        </div>
        <div style="display:flex; gap:8px; align-items:center; flex-grow:1;">
            <label style="font-weight:600;">Search:</label>
            <input type="text" id="{table_id}_search" placeholder="Search file, level, or reason..."
                   style="flex-grow:1; max-width:400px; padding:6px 10px; border:1px solid #ced4da; border-radius:4px;"
                   onkeyup="filterLogTable_{table_id}()">
        </div>
    </div>
</div>
''')

    # Start table
    lines.append(f'''
<div style="overflow-x:auto; margin:10px 0; border:1px solid #dee2e6; border-radius:4px;">
<table id="{table_id}" style="width:100%; min-width:900px; border-collapse:collapse; font-size:13px; background:white;">
    <thead>
        <tr style="background:#343a40; color:white; text-align:left;">
            <th style="padding:10px; width:40px; border:1px solid #dee2e6;">#</th>
            <th style="padding:10px; min-width:200px; border:1px solid #dee2e6;">Location</th>
            <th style="padding:10px; width:80px; border:1px solid #dee2e6;">Level</th>
            <th style="padding:10px; width:100px; border:1px solid #dee2e6;">Severity</th>
            <th style="padding:10px; min-width:300px; border:1px solid #dee2e6;">Reason</th>
            <th style="padding:10px; width:100px; text-align:center; border:1px solid #dee2e6;">Code</th>
        </tr>
    </thead>
    <tbody>
''')

    # Add findings to table
    for idx, finding in enumerate(sensitive_findings, 1):
        severity_color = '#dc3545' if finding['severity'] == 'High' else '#ffc107'
        level_badge_color = {
            'VERBOSE': '#6c757d', 'DEBUG': '#17a2b8', 'INFO': '#28a745',
            'WARN': '#ffc107', 'ERROR': '#dc3545', 'PRINTLN': '#fd7e14', 'STACKTRACE': '#dc3545'
        }.get(finding['level'], '#6c757d')

        file_path = os.path.abspath(os.path.join(base, finding['file']))
        context_html = html.escape('\n'.join(finding['context']))
        code_id = f"{table_id}_code_{idx}"

        lines.append(f'''
        <tr class="log-row" data-severity="{finding['severity'].lower()}" data-searchtext="{html.escape(finding['file'])} {finding['level']} {html.escape(finding['reason'])}">
            <td style="padding:8px; border:1px solid #dee2e6; text-align:center;">{idx}</td>
            <td style="padding:8px; border:1px solid #dee2e6;">
                <a href="file://{html.escape(file_path)}" style="color:#007bff; text-decoration:none;">
                    {html.escape(finding['file'])}:{finding['line']}
                </a>
            </td>
            <td style="padding:8px; border:1px solid #dee2e6;">
                <span style="background:{level_badge_color}; color:white; padding:3px 8px; border-radius:3px; font-size:11px; font-weight:600;">
                    {finding['level']}
                </span>
            </td>
            <td style="padding:8px; border:1px solid #dee2e6;">
                <span style="color:{severity_color}; font-weight:600;">{finding['severity']}</span>
            </td>
            <td style="padding:8px; border:1px solid #dee2e6; font-size:12px;">
                {html.escape(finding['reason'])}
            </td>
            <td style="padding:8px; border:1px solid #dee2e6; text-align:center;">
                <button onclick="document.getElementById('{code_id}').style.display = document.getElementById('{code_id}').style.display === 'none' ? 'block' : 'none';"
                        style="padding:4px 10px; background:#007bff; color:white; border:none; border-radius:3px; cursor:pointer; font-size:11px;">
                    View
                </button>
                <pre id="{code_id}" style="display:none; margin-top:8px; padding:8px; background:#f8f9fa; border:1px solid #dee2e6; border-radius:3px; text-align:left; font-size:11px; white-space:pre-wrap; max-width:500px; color:#212529;">{context_html}</pre>
            </td>
        </tr>
''')

    lines.append('''
    </tbody>
</table>
</div>
''')

    # Add JavaScript for filtering
    lines.append(f'''
<script>
function filterLogTable_{table_id}() {{
    const searchText = document.getElementById('{table_id}_search').value.toLowerCase();
    const showHigh = document.getElementById('{table_id}_filter_high').checked;
    const showMedium = document.getElementById('{table_id}_filter_medium').checked;

    const rows = document.querySelectorAll('#{table_id} .log-row');
    rows.forEach(row => {{
        const severity = row.getAttribute('data-severity');
        const rowText = row.getAttribute('data-searchtext').toLowerCase();

        const severityMatch = (severity === 'high' && showHigh) || (severity === 'medium' && showMedium);
        const textMatch = rowText.includes(searchText);

        row.style.display = (severityMatch && textMatch) ? '' : 'none';
    }});
}}
</script>
''')

    lines.append(mastg_ref)

    return False, "<br>\n".join(lines), total_sensitive

def check_updates(base):
    """
    Checks for update implementation by searching for either:

    METHOD 1 - Google Play In-App Updates (official API):
      • AppUpdateManager (Google Play Core library)
      • updateAvailability (checking for available updates)
      • startUpdateFlowForResult (initiating update flow)

    METHOD 2 - Custom server-side updates (alternative pattern):
      • UpdateAppDialog / showUpdateDialog (custom update dialog)
      • latestVersion / minimumVersion (version comparison fields)
      • market://details (Play Store redirect intent)
    """
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0036/' target='_blank'>MASTG-TEST-0036: Testing Enforced Updating</a></div>"

    # Search patterns for Google Play In-App Updates API
    google_play_patterns = {
        'AppUpdateManager': 'Google Play Core library usage',
        'updateAvailability': 'Update availability checking',
        'startUpdateFlowForResult': 'Update flow initiation'
    }

    # Search patterns for custom server-side updates
    custom_update_patterns = {
        'UpdateAppDialog': 'Custom update dialog class',
        'latestVersion': 'Version comparison field',
        'market://details': 'Play Store redirect intent'
    }

    google_found = {}
    custom_found = {}
    file_count = 0

    # Scan all code files
    for root, _, files in os.walk(base):
        for f in files:
            if f.endswith(('.smali', '.java')):
                file_count += 1
                file_path = os.path.join(root, f)
                try:
                    content = open(file_path, errors='ignore').read()

                    # Check for Google Play patterns
                    for pattern, description in google_play_patterns.items():
                        if pattern in content and pattern not in google_found:
                            rel_path = os.path.relpath(file_path, base)
                            google_found[pattern] = (description, rel_path)

                    # Check for custom update patterns
                    for pattern, description in custom_update_patterns.items():
                        if pattern in content and pattern not in custom_found:
                            rel_path = os.path.relpath(file_path, base)
                            custom_found[pattern] = (description, rel_path)
                except:
                    continue

    # Check if either method is implemented
    google_play_ok = len(google_found) == len(google_play_patterns)
    custom_ok = len(custom_found) >= 2  # At least 2 of 3 custom patterns

    ok = google_play_ok or custom_ok

    if ok:
        # Success case - show what was found
        details = "<div> Update mechanism detected</div>"

        if google_play_ok:
            details += "<div class='detail-section'><strong>Google Play In-App Updates API:</strong></div>"
            for pattern in google_play_patterns:
                if pattern in google_found:
                    _, file_path = google_found[pattern]
                    details += f"<div class='detail-list-item'>• Found '{pattern}' in: {file_path}</div>"

        if custom_ok:
            details += "<div class='detail-section'><strong>Custom server-side update check:</strong></div>"
            for pattern in custom_update_patterns:
                if pattern in custom_found:
                    _, file_path = custom_found[pattern]
                    details += f"<div class='detail-list-item'>• Found '{pattern}' in: {file_path}</div>"

            details += "<div style='margin-top:10px;'><em>Note: App uses custom update dialog that redirects to Play Store. This is an acceptable alternative to Google Play In-App Updates API.</em></div>"
    else:
        # Failure case - show missing components
        details = f"<div>Searched {file_count} code files (.smali/.java)</div>"
        details += "<div class='detail-section'><strong>Missing: Google Play In-App Updates API components:</strong></div>"
        for pattern, desc in google_play_patterns.items():
            if pattern not in google_found:
                details += f"<div class='detail-list-item'>✗ '{pattern}' ({desc})</div>"

        details += "<div class='detail-section'><strong>Missing: Custom server-side update components:</strong></div>"
        for pattern, desc in custom_update_patterns.items():
            if pattern not in custom_found:
                details += f"<div class='detail-list-item'>✗ '{pattern}' ({desc})</div>"

        details += "<div style='margin-top:10px;'><em>Neither Google Play In-App Updates API nor custom server-side update mechanism detected.</em></div>"

    return ok, details + mastg_ref

def check_memtag(manifest):
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0044/' target='_blank'>MASTG-TEST-0044: Make Sure That Free Security Features Are Activated</a></div>"
    txt = open(manifest, errors='ignore').read()
    ok = bool(re.search(r'memtagMode="(async|sync)"', txt))
    return ok, ('Enabled' if ok else 'Memtag Not Enabled') + mastg_ref

def check_min_sdk(manifest, apk_path=None, threshold=28):
    """
    Ensures android:minSdkVersion is declared and ≥ threshold.

    1) Parse the decompiled XML <uses-sdk> if present.
    2) Otherwise fall back to `aapt dump badging` on the APK.
    """

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0044/' target='_blank'>MASTG-TEST-0044: Make Sure That Free Security Features Are Activated</a></div>"

    # 1) Try decompiled XML
    try:
        tree = ET.parse(manifest)
        root = tree.getroot()
        AND_NS = 'http://schemas.android.com/apk/res/android'
        uses = root.find('uses-sdk') or root.find('./uses-sdk')
        if uses is not None:
            minSdk = uses.get(f'{{{AND_NS}}}minSdkVersion')
            if minSdk:
                v = int(minSdk)
                if v < threshold:
                    return False, f"minSdkVersion={v} (below recommended {threshold})" + mastg_ref
                return True, f"minSdkVersion={v}" + mastg_ref
    except Exception:
        # ignore and fall back
        pass

    # 2) Fallback: use `aapt dump badging` on the original APK
    if apk_path:
        try:
            out = subprocess.check_output(
                ['aapt', 'dump', 'badging', apk_path],
                stderr=subprocess.DEVNULL,
                universal_newlines=True
            )
            m = re.search(r"sdkVersion:'(\d+)'", out)
            if m:
                v = int(m.group(1))
                if v < threshold:
                    return False, f"minSdkVersion={v} (below recommended {threshold})" + mastg_ref
                return True, f"minSdkVersion={v}" + mastg_ref
        except Exception:
            pass

    # If we still don't have a valid value:
    return False, (
        "minSdkVersion is missing (neither decompiled manifest nor aapt badging "
        "produced a value)"
    ) + mastg_ref

def check_file_provider(res_dir):
    """
    FAIL on any of:
      1) Insecure FileProvider path elements (root-path, external-path, etc.) with path="." or path="/"
      2) Overly-broad <grant-uri-permission> or <path-permission>
    Emits clickable file:// links with the XML filename and shows the actual insecure XML element.
    """

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0001/' target='_blank'>MASTG-TEST-0001: Testing Local Storage for Sensitive Data</a></div>"

    issues = []
    xml_dir = os.path.join(res_dir, 'xml')

    if not os.path.exists(xml_dir):
        return True, "No xml directory found" + mastg_ref

    for root, _, files in os.walk(xml_dir):
        for f in files:
            if not f.endswith('.xml'):
                continue

            full = os.path.join(root, f)
            rel  = os.path.relpath(full, res_dir)
            href = f'file://{html.escape(full)}'
            link = f'<a href="{href}">{html.escape(rel)}</a>'

            try:
                txt = open(full, errors='ignore').read()
                tree = ET.parse(full)
                root_elem = tree.getroot()

                # Check all FileProvider path types for insecure configurations
                path_types = [
                    'root-path',           # Most dangerous - exposes device root
                    'files-path',          # App's internal storage files directory
                    'cache-path',          # App's internal cache directory
                    'external-path',       # External storage root
                    'external-files-path', # External files directory
                    'external-cache-path', # External cache directory
                    'external-media-path'  # External media directory
                ]

                for path_type in path_types:
                    for elem in root_elem.findall(f'.//{path_type}'):
                        path_attr = elem.get('path', '')
                        name_attr = elem.get('name', '')

                        # Check for insecure path values
                        if path_attr in ('.', '/', ''):
                            # Reconstruct the XML element to show in output
                            attrs = []
                            if name_attr:
                                attrs.append(f'name="{name_attr}"')
                            attrs.append(f'path="{path_attr}"')

                            xml_element = f'&lt;{path_type} {" ".join(attrs)}/&gt;'

                            # Determine severity
                            if path_type == 'root-path':
                                severity = '<strong style="color:#dc2626;">CRITICAL</strong>'
                            elif path_attr in ('.', '/'):
                                severity = '<strong style="color:#dc2626;">HIGH</strong>'
                            else:
                                severity = '<strong style="color:#d97706;">MEDIUM</strong>'

                            issues.append(
                                f"{link} – {severity} insecure {xml_element}"
                            )

                # Check for overly-broad grant-uri-permission / path-permission
                for tag in ('grant-uri-permission', 'path-permission'):
                    for perm in root_elem.findall(f'.//{tag}'):
                        p = perm.get('path') or perm.get('pathPrefix') or perm.get('pathPattern') or ''
                        if p in ('.', '/', '..') or p.startswith('../'):
                            issues.append(
                                f"{link} – <strong>&lt;{tag}&gt;</strong> insecure path=\"{html.escape(p)}\""
                            )

            except Exception as e:
                # If XML parsing fails, continue to next file
                continue

    if not issues:
        return True, "None" + mastg_ref
    return False, "<br>\n".join(issues) + mastg_ref

def check_serialize(base):
    """
    Check for unsafe deserialization patterns:
    1. Bundle.getSerializable(...) without proper API version handling
    2. ObjectInputStream.readObject() usage (insecure deserialization)
    3. Custom readObject implementations

    SAFE pattern (no warning):
        if (Build.VERSION.SDK_INT >= 33) {
            bundle.getSerializable("key", Class.class)  // Type-safe API
        } else {
            bundle.getSerializable("key")  // Fallback for older Android
        }

    UNSAFE patterns (warning):
        bundle.getSerializable("key")  // No version check, no type safety
        ObjectInputStream.readObject()  // Insecure deserialization

    Also filters out third-party library code.
    """

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0034/' target='_blank'>MASTG-TEST-0034: Testing Object Persistence</a></div>"

    # Library paths to exclude (Google GSON, Tink, Protobuf use serialization internally - these are safe)
    lib_paths = (
        '/androidx/', '/android/support/',
        '/com/google/android/gms/', '/com/google/firebase/',
        '/com/google/gson/', '/com/google/crypto/tink/', '/com/google/protobuf/',
        '/okhttp3/', '/retrofit2/', '/com/squareup/',
        '/com/facebook/', '/kotlin/', '/kotlinx/',
        '/org/chromium/', '/io/reactivex/',
        '/lib/', '/jetified-'
    )

    def is_library_path(path):
        """Check if path is library code"""
        normalized = '/' + path.replace('\\', '/')
        return any(lib in normalized for lib in lib_paths)

    # Patterns to detect
    old_api_pattern = re.compile(r'getSerializable\(Ljava/lang/String;\)Ljava/io/Serializable;')
    new_api_pattern = re.compile(r'getSerializable\(Ljava/lang/String;Ljava/lang/Class;\)Ljava/io/Serializable;')
    version_check_pattern = re.compile(r'(VERSION\.SDK_INT|sget.*Build\$VERSION;->SDK_INT:I|const/16.*0x21)')

    # ObjectInputStream patterns (CRITICAL - insecure deserialization)
    object_input_stream_pattern = re.compile(r'Ljava/io/ObjectInputStream;')
    read_object_pattern = re.compile(r'->readObject\(\)')
    custom_read_object_pattern = re.compile(r'\.method private readObject\(Ljava/io/ObjectInputStream;\)')

    hits = []

    for root, _, files in os.walk(base):
        for fn in files:
            if not fn.endswith('.smali'):
                continue
            path = os.path.join(root, fn)

            # Skip library code
            rel_path = os.path.relpath(path, base)
            if is_library_path(rel_path):
                continue

            try:
                with open(path, errors='ignore') as f:
                    content = f.read()
                    lines = content.splitlines()
            except:
                continue

            # Check for ObjectInputStream usage (CRITICAL vulnerability)
            has_object_input_stream = object_input_stream_pattern.search(content)
            has_read_object = read_object_pattern.search(content)
            has_custom_read_object = custom_read_object_pattern.search(content)

            if has_object_input_stream and has_read_object:
                # Found insecure ObjectInputStream deserialization
                for i, line in enumerate(lines, 1):
                    if read_object_pattern.search(line):
                        link = f'<a href="file://{html.escape(path)}">' \
                               f"{html.escape(rel_path)}:{i}</a>"
                        snippet = html.escape(line.strip())

                        hits.append(
                            f"{link} – <strong style='color:#dc2626;'>Insecure ObjectInputStream deserialization</strong><br>"
                            f"<code>{snippet}</code><br>"
                            f"<em>Risk: Remote Code Execution via malicious serialized objects</em>"
                        )

            if has_custom_read_object:
                # Found custom readObject implementation
                for i, line in enumerate(lines, 1):
                    if custom_read_object_pattern.search(line):
                        link = f'<a href="file://{html.escape(path)}">' \
                               f"{html.escape(rel_path)}:{i}</a>"
                        snippet = html.escape(line.strip())

                        hits.append(
                            f"{link} – <strong style='color:#d97706;'>WARNING: Custom readObject implementation</strong><br>"
                            f"<code>{snippet}</code><br>"
                            f"<em>Review for unsafe deserialization logic</em>"
                        )

            # Check if file uses the new safe API (getSerializable with Class parameter)
            has_new_api = new_api_pattern.search(content)
            # Check if file has API version checks
            has_version_check = version_check_pattern.search(content)

            # If both new API and version checks are present, the code is handling it properly
            if has_new_api and has_version_check:
                continue  # Skip - properly implemented

            # Now check for old API usage
            for i, line in enumerate(lines, 1):
                if old_api_pattern.search(line):
                    # Additional context: check surrounding lines for method name
                    method_context = ""
                    for j in range(max(0, i-10), i):
                        if '.method' in lines[j]:
                            method_context = lines[j].strip()
                            break

                    link = f'<a href="file://{html.escape(path)}">' \
                           f"{html.escape(rel_path)}:{i}</a>"
                    snippet = html.escape(line.strip())

                    # Add contextual information
                    if has_version_check:
                        context = "WARNING: Has version check but missing type-safe API"
                    else:
                        context = "FAIL: No version check or type safety"

                    hits.append(
                        f"{link} – {context}<br>"
                        f"<code>{snippet}</code>"
                    )

    if not hits:
        return True, "None" + mastg_ref

    # Add summary information
    summary = f"<strong>Found {len(hits)} insecure deserialization issue(s)</strong><br>"
    summary += "Includes: ObjectInputStream.readObject(), Bundle.getSerializable() without type safety<br><br>"

    return False, summary + "<br>\n".join(hits) + mastg_ref

def check_browsable_deeplinks(manifest):
    """
    Comprehensive deep link security check for BROWSABLE intent-filters.
    Detects:
    1. http/https schemes with no host restriction in the ENTIRE intent-filter
    2. Missing android:autoVerify on App Links
    3. Wildcard path patterns (* or .*)
    4. BROWSABLE filters with no <data> tags

    CRITICAL: A host restriction in ANY <data> tag applies to the ENTIRE intent-filter.
    Only flags vulnerability when NO host is specified in ANY data tag.

    Resolves @string references from res/values/strings.xml for accurate assessment.
    Skips MainActivity as expected launch entry point.
    """
    ANDROID_NS = 'http://schemas.android.com/apk/res/android'
    def ns(a): return f'{{{ANDROID_NS}}}{a}'

    def resolve_string(value, manifest_path):
        """Resolve @string/... references from res/values/strings.xml"""
        if not value or not value.startswith('@string/'):
            return value, False  # Return (value, was_resolved)

        string_name = value.replace('@string/', '')
        base_dir = os.path.dirname(manifest_path)
        strings_path = os.path.join(base_dir, 'res', 'values', 'strings.xml')

        if not os.path.exists(strings_path):
            return value, False  # Can't resolve

        try:
            strings_tree = ET.parse(strings_path)
            for string_elem in strings_tree.findall('.//string'):
                if string_elem.get('name') == string_name:
                    resolved = string_elem.text or value
                    return resolved, True
        except:
            pass

        return value, False  # Resolution failed

    try:
        tree = ET.parse(manifest)
        root = tree.getroot()
        pkg = root.attrib.get('package', '')
    except:
        return True, "Unable to parse manifest", 0

    issues = []

    for activity in root.findall('.//activity'):
        name = activity.get(ns('name'), 'unknown')

        # Skip MainActivity by simple class name
        if name.split('.')[-1] == 'MainActivity':
            continue

        for ifilter in activity.findall('intent-filter'):
            actions = {a.get(ns('name')) for a in ifilter.findall('action')}
            cats = {c.get(ns('name')) for c in ifilter.findall('category')}

            # Only check BROWSABLE intent filters
            if not ('android.intent.action.VIEW' in actions and
                    'android.intent.category.DEFAULT' in cats and
                    'android.intent.category.BROWSABLE' in cats):
                continue

            data_elems = ifilter.findall('data')

            # Issue 1: BROWSABLE filter with no <data> tags
            if not data_elems:
                url = 'http://example.com/'
                cmd = f'adb shell am start -a android.intent.action.VIEW -n {pkg}/{name} -d "{url}"'
                issues.append(
                    f'<strong>{name}</strong>: BROWSABLE filter with no &lt;data&gt; → matches everything<br>'
                    f'<strong>Test with:</strong><br><pre>{cmd}</pre>'
                    f'<strong>Fix:</strong> Add specific &lt;data&gt; tags with scheme and host restrictions<br><br>'
                )
                continue

            # CRITICAL: Check if ANY data tag has a host
            # If ANY host exists, the ENTIRE intent-filter is restricted to that host
            all_hosts = []
            all_hosts_raw = []
            for d in data_elems:
                host = d.get(ns('host'))
                if host:
                    all_hosts_raw.append(host)
                    resolved_host, _ = resolve_string(host, manifest)
                    all_hosts.append(resolved_host)

            # Get schemes and paths for reporting
            schemes = set()
            paths = []
            for d in data_elems:
                scheme = d.get(ns('scheme'))
                if scheme:
                    schemes.add(scheme)
                path = (d.get(ns('pathPattern')) or
                       d.get(ns('pathPrefix')) or
                       d.get(ns('path')))
                if path:
                    resolved_path, _ = resolve_string(path, manifest)
                    paths.append(resolved_path)

            # Issue 2: http/https schemes with NO host restriction in ENTIRE filter
            has_http_schemes = any(s in ('http', 'https') for s in schemes)
            if has_http_schemes and not all_hosts:
                example_path = paths[0] if paths else '/example'
                example_scheme = 'https' if 'https' in schemes else 'http'
                url = f"{example_scheme}://attacker.com{example_path}"
                cmd = f'adb shell am start -a android.intent.action.VIEW -n {pkg}/{name} -d "{url}"'
                issues.append(
                    f'<strong>{name}</strong>: <code>{example_scheme}://</code> with NO host restriction → matches any domain<br>'
                    f'<strong>Schemes:</strong> {", ".join(sorted(schemes))}<br>'
                    f'<strong>Paths:</strong> {", ".join(paths) if paths else "none"}<br>'
                    f'<strong>Test with:</strong><br><pre>{cmd}</pre>'
                    f'<em>If your app opens, vulnerability confirmed</em><br>'
                    f'<strong>Fix:</strong> Add <code>android:host="your-domain.com"</code> to at least one &lt;data&gt; tag<br><br>'
                )
                continue  # Skip other checks for this filter

            # Issue 3: Missing android:autoVerify on App Links with host
            if has_http_schemes and all_hosts:
                auto_verify = ifilter.get(ns('autoVerify'), 'false')
                if auto_verify.lower() != 'true':
                    example_path = paths[0] if paths else '/example'
                    example_scheme = 'https' if 'https' in schemes else 'http'

                    # Build test commands for EACH host
                    test_commands = []
                    for host in all_hosts:
                        url = f"{example_scheme}://{host}{example_path}"
                        cmd = f'adb shell am start -a android.intent.action.VIEW -n {pkg}/{name} -d "{url}"'
                        test_commands.append(f'<pre>{cmd}</pre>')

                    issues.append(
                        f'<strong>{name}</strong>: missing <code>android:autoVerify</code> on App Link<br>'
                        f'<strong>Hosts:</strong> {", ".join(all_hosts)}<br>'
                        f'<strong>Test with:</strong><br>{"".join(test_commands)}'
                        f'<strong>Fix:</strong> Add <code>android:autoVerify="true"</code> to the &lt;intent-filter&gt; tag<br>'
                        f'<strong>Note:</strong> Enables App Links verification - ensures only your verified domain opens the app<br><br>'
                    )

            # Issue 4: Wildcard paths
            wildcard_paths = [p for p in paths if '*' in p or '.*' in p]
            if wildcard_paths:
                example_scheme = list(schemes)[0] if schemes else 'http'
                example_host = all_hosts[0] if all_hosts else 'example.com'

                # Build test commands for EACH wildcard path
                test_commands = []
                for wildcard_path in wildcard_paths:
                    sample_path = wildcard_path.replace('.*', 'malicious').replace('*', 'malicious')
                    url = f"{example_scheme}://{example_host}{sample_path}"
                    cmd = f'adb shell am start -a android.intent.action.VIEW -n {pkg}/{name} -d "{url}"'
                    test_commands.append(f'<pre>{cmd}</pre>')

                issues.append(
                    f'<strong>{name}</strong>: pathPattern with wildcards: <code>{", ".join(wildcard_paths)}</code><br>'
                    f'<strong>Test with:</strong><br>{"".join(test_commands)}'
                    f'<strong>Fix:</strong> Use specific paths or validate all path parameters in code<br><br>'
                )

    total_issues = len(issues)
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0028/' target='_blank'>MASTG-TEST-0028: Testing Deep Links</a></div>"

    if not issues:
        return True, f"No overly-broad deep-link filters detected{mastg_ref}", 0

    result = (
        f"<div><strong>Found {total_issues} deep link security issue(s)</strong></div><br>"
        + "".join(issues) +
        "<div class='info-box'><em> These checks apply only to BROWSABLE intent-filters (externally accessible). "
        "Custom URI schemes (myapp://) without BROWSABLE category are not flagged. "
        "MainActivity is excluded from checks. "
        "<strong>Test commands use intent-filter resolution (no -n flag) to verify actual vulnerability.</strong></em></div>"
        + mastg_ref
    )

    return False, result, total_issues


def check_deep_link_misconfiguration(manifest):
    """
    Detect intent filters with multiple separate <data> tags that create
    unintended URL patterns via Cartesian product.

    CRITICAL: Each <data> tag creates a SEPARATE URI pattern in Android.
    If ANY <data> tag lacks a host attribute, it accepts traffic from ANY domain.
    ALL <data> tags must have host restrictions for the intent filter to be secure.

    Also resolves @string references to accurately assess the configuration.
    """
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0028/' target='_blank'>MASTG-TEST-0028: Testing Deep Links</a></div>"

    ANDROID_NS = 'http://schemas.android.com/apk/res/android'
    def ns(a): return f'{{{ANDROID_NS}}}{a}'

    def resolve_string(value, manifest_path):
        """Resolve @string/... references from res/values/strings.xml"""
        if not value or not value.startswith('@string/'):
            return value

        string_name = value.replace('@string/', '')
        base_dir = os.path.dirname(manifest_path)
        strings_path = os.path.join(base_dir, 'res', 'values', 'strings.xml')

        if not os.path.exists(strings_path):
            return value  # Can't resolve, return original

        try:
            strings_tree = ET.parse(strings_path)
            for string_elem in strings_tree.findall('.//string'):
                if string_elem.get('name') == string_name:
                    return string_elem.text or value
        except:
            pass

        return value  # Resolution failed, return original

    tree = ET.parse(manifest)
    root = tree.getroot()
    pkg = root.attrib.get('package', '')
    issues = []

    for activity in root.findall('.//activity'):
        activity_name = activity.get(ns('name'), 'unknown')

        for intent_filter in activity.findall('intent-filter'):
            # Only check BROWSABLE intent filters
            categories = {c.get(ns('name')) for c in intent_filter.findall('category')}
            if 'android.intent.category.BROWSABLE' not in categories:
                continue

            data_tags = intent_filter.findall('data')

            # Need at least 2 separate <data> tags for potential Cartesian product
            if len(data_tags) < 2:
                continue

            # Extract and resolve all attributes from data tags
            schemes = []
            hosts = []
            hosts_raw = []  # Track original @string values
            paths = []
            paths_raw = []

            # Track which data tags have host restrictions
            data_tags_with_hosts = 0
            data_tags_without_hosts = []

            for idx, d in enumerate(data_tags):
                scheme = d.get(ns('scheme'))
                host = d.get(ns('host'))
                path = (d.get(ns('pathPrefix')) or
                       d.get(ns('path')) or
                       d.get(ns('pathPattern')))

                if scheme:
                    schemes.append(scheme)
                if host:
                    hosts_raw.append(host)
                    resolved_host = resolve_string(host, manifest)
                    hosts.append(resolved_host)
                    data_tags_with_hosts += 1
                else:
                    # This data tag has NO host - potential vulnerability
                    data_tags_without_hosts.append(idx)

                if path:
                    paths_raw.append(path)
                    resolved_path = resolve_string(path, manifest)
                    paths.append(resolved_path)

            # CRITICAL CHECK: Each <data> tag creates a separate URI pattern in Android.
            # If ANY <data> tag lacks a host attribute, it accepts traffic from ANY domain.
            # ALL <data> tags must have host restrictions for the intent filter to be secure.
            if not data_tags_without_hosts:
                # All data tags have host restrictions - SECURE
                continue

            # VULNERABILITY DETECTED: At least one <data> tag has no host restriction
            auto_verify = intent_filter.get(ns('autoVerify'), 'false')

            issue_msg = (
                f"<strong>{activity_name}</strong><br>"
                f"<strong>CRITICAL: Cartesian Product Vulnerability:</strong> Intent filter has "
                f"{len(data_tags)} &lt;data&gt; tags, but <strong>{len(data_tags_without_hosts)} "
                f"lack host restrictions</strong>.<br>"
            )

            if schemes:
                issue_msg += f"<strong>Schemes found:</strong> {', '.join(set(schemes))}<br>"

            if hosts:
                issue_msg += f"<strong>Hosts found:</strong> {', '.join(set(hosts))} (in {data_tags_with_hosts}/{len(data_tags)} tags)<br>"
                issue_msg += f"<strong>Vulnerable tags:</strong> <span style='color:#d32f2f;'>{len(data_tags_without_hosts)} &lt;data&gt; tags without host → accept ANY domain</span><br>"
            else:
                issue_msg += f"<strong>Hosts:</strong> <span style='color:#d32f2f;'>NONE (accepts any domain)</span><br>"
            if paths:
                issue_msg += f"<strong>Paths:</strong> {', '.join(paths)}<br>"

            example_path = paths[0] if paths else '/malicious'
            example_scheme = schemes[0] if schemes else 'https'
            issue_msg += (
                f"<br><strong>Impact:</strong> Each &lt;data&gt; tag without a host creates a separate URI pattern. "
                f"<strong>{len(data_tags_without_hosts)} tag(s) accept arbitrary domains</strong>. "
                f"An attacker can use <code>{example_scheme}://evil.com{example_path}</code> to trigger this activity.<br>"
                f"<strong>AutoVerify:</strong> {auto_verify}<br>"
                f"<br><strong>Fix:</strong> Combine all attributes in a SINGLE &lt;data&gt; tag (prevents Cartesian product):<br>"
                f"<code>&lt;data android:scheme=\"{example_scheme}\" "
                f"android:host=\"your-domain.com\" "
                f"android:pathPrefix=\"{paths[0] if paths else '/path'}\" /&gt;</code><br>"
                f"OR add host to EVERY &lt;data&gt; tag if you need multiple patterns.<br>"
                f"<br><strong>Test command (verify vulnerability):</strong><br>"
                f"<pre>adb shell am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -n {pkg}/{activity_name} -d '{example_scheme}://attacker.com{example_path}'</pre>"
                f"<em>If the app opens, vulnerability is confirmed.</em><br>"
                f"<br><strong>OWASP Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0028/' target='_blank'>MASTG-TEST-0028</a>"
            )

            issues.append(issue_msg)

    total_issues = len(issues)
    if not issues:
        return True, "No intent filter Cartesian product vulnerabilities detected (all have host restrictions)" + mastg_ref, 0

    return False, "<br><br>\n".join(issues) + mastg_ref, total_issues


def render_checksec_table(text):
    """
    Render checksec output into an HTML table with dropdown filters.
    1) Split on 2+ spaces to get 8 tokens per row.
    2) Treat token #8 as a combo string and regex‐split it into 4 fields.
    """

    # 1) Gather non-empty lines
    lines = [l for l in text.splitlines() if l.strip()]
    if len(lines) < 2:
        return f"<pre>{text}</pre>"

    # 2) Split header into its raw tokens (should be 8)
    raw_hdr = re.split(r"\s{2,}", lines[0].strip())
    if len(raw_hdr) < 8:
        return f"<pre>Unexpected header format:\n{lines[0]}</pre>"

    # Build our final column names: 
    # first 7 from raw_hdr, then the four we’re about to parse out, 
    # then ignore raw_hdr[7] (combined) entirely.
    filename_hdr = raw_hdr[-1]
    col_names = raw_hdr[:7] + ["FORTIFY", "Fortified", "Fortifiable", filename_hdr]

    rows = []
    combo_re = re.compile(r'^(Yes|No)(\d+)(\d+)(/.+)$')
    # 3) For each data line, split into 8 parts, then parse part 8
    for ln in lines[1:]:
        parts = re.split(r"\s{2,}", ln.strip(), maxsplit=7)
        if len(parts) != 8:
            continue
        first7, combo = parts[:7], parts[7]
        m = combo_re.match(combo)
        if not m:
            # fallback: stick everything into filename
            f_val, fort, fortif, fname = "", "", "", combo
        else:
            f_val, fort, fortif, fname = m.groups()
        rows.append(first7 + [f_val, fort, fortif, fname])

    # 4) Sort Partial RELRO first
    rows.sort(key=lambda r: 0 if "Partial RELRO" in r[0] else 1)

    # 5) Build unique filter options per column
    unique_vals = [sorted({r[i] for r in rows}) for i in range(len(col_names))]

    # 6) Assemble HTML with per-column dropdowns
    html = ['<table id="checksecTable"><thead><tr>']
    # filter row
    for vals in unique_vals:
        opts = "".join(f'<option value="{v}">{v}</option>' for v in vals)
        html.append(
            '<th><select class="filter-select" onchange="applyFilters()">'
            '<option value="">All</option>' + opts +
            '</select></th>'
        )
    html.append('</tr><tr>')
    # header labels with sort chevrons
    for idx, h in enumerate(col_names):
        html.append(
            f'<th class="sortable" onclick="sortTable({idx})">'
            f'{h} <span class="chevron"></span></th>'
        )
    html.append('</tr></thead><tbody>')
    # data rows
    for r in rows:
        html.append('<tr>')
        for cell in r:
            html.append(f'<td>{cell}</td>')
        html.append('</tr>')
    html.append('</tbody></table>')

    return "".join(html)
    
def check_task_hijack(manifest):
    """
    Scan AndroidManifest.xml for three classes of task-hijacking risk:
      1) Activities with NO taskAffinity AND NO launchMode (missing protection),
         unless they are launcher activities (MAIN + LAUNCHER).
         - FAIL: Exported activities (exploitable)
         - WARN: Non-exported activities (defense-in-depth)
      2) Exported activities with a custom taskAffinity ≠ package AND allowTaskReparenting="true".
      3) Any exported activity with NO android:permission attribute (unprotected export).
    Returns ('PASS'|'WARN'|'FAIL', details_html: str).
    """
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0029/' target='_blank'>MASTG-TEST-0029: Testing for Sensitive Functionality Exposure Through IPC</a></div>"

    ANDROID_NS = 'http://schemas.android.com/apk/res/android'
    def ns(a): return f'{{{ANDROID_NS}}}{a}'

    failures = []  # Exploitable issues
    warnings = []  # Defense-in-depth recommendations

    # Get package name first (needed for ADB commands)
    tree = ET.parse(manifest)
    root = tree.getroot()
    pkg = root.attrib.get('package', '')

    # ── PART 1: regex-based "missing protection" scan ──
    txt = open(manifest, errors='ignore').read()
    # Match both self-closing <activity .../> and <activity>...</activity> tags
    blocks = re.findall(r'(<activity\b(?:.*?/>|.*?>.*?</activity>))', txt, flags=re.DOTALL)

    # Library paths to exclude (not your app code)
    lib_paths = (
        '/com/google/android/gms/', '/com/google/firebase/', '/com/google/android/play/',
        '/androidx/', '/android/support/', '/com/facebook/', '/kotlin/', '/kotlinx/'
    )

    def is_library_activity(name):
        for lib in lib_paths:
            if lib.replace('/', '.') in name:
                return True
        return False

    for blk in blocks:
        name_m = re.search(r'android:name="([^"]+)"', blk)
        name = name_m.group(1) if name_m else "unknown"

        # Skip library activities
        if is_library_activity(name):
            continue

        # Skip launcher activities (any activity with MAIN action is an app entry point)
        if re.search(r'<action[^>]+android:name="android.intent.action.MAIN"', blk):
            continue

        # Check for explicit exported="true" OR presence of intent-filter (makes it exported)
        exported_m = re.search(r'android:exported="true"', blk)
        has_intent_filter = re.search(r'<intent-filter', blk)
        is_exported = exported_m is not None or has_intent_filter is not None

        # Check if taskAffinity attribute is missing
        ta_m = re.search(r'android:taskAffinity="([^"]*)"', blk)
        missing_affinity = not ta_m

        # Check if launchMode attribute is missing
        lm_m = re.search(r'android:launchMode="([^"]*)"', blk)
        missing_launch_mode = not lm_m

        if missing_affinity and missing_launch_mode:
            esc = html.escape(blk[:300] + ('...' if len(blk) > 300 else ''))

            # Generate full activity name and ADB command
            if name.startswith('.'):
                full_name = pkg + name
            elif '.' not in name:
                full_name = f"{pkg}.{name}"
            else:
                full_name = name

            adb_cmd = f"adb shell am start -n {pkg}/{full_name}"

            if is_exported:
                # FAIL: Exported activities are exploitable
                desc = (
                    f'<strong>Activity:</strong> <code>{name}</code><br>'
                    f'<strong>Exported:</strong> YES (externally launchable - EXPLOITABLE)<br>'
                    f'<strong>Issue:</strong> Missing <code>taskAffinity</code> and <code>launchMode</code> attributes<br>'
                    f'<strong>Risk:</strong> Vulnerable to task hijacking attacks<br>'
                    f'<strong>Fix:</strong> Add <code>android:launchMode="singleTask"</code> or set <code>android:taskAffinity=""</code><br>'
                    f'<strong>OWASP Reference:</strong> MSTG-PLATFORM-3<br>'
                    f'<strong>Test:</strong> <code>{adb_cmd}</code>'
                )
                failures.append(f"{desc}<br><pre>{esc}</pre>")
            else:
                # WARN: Non-exported activities (defense-in-depth)
                desc = (
                    f'<strong>Activity:</strong> <code>{name}</code><br>'
                    f'<strong>Exported:</strong> NO (internal only - not exploitable)<br>'
                    f'<strong>Issue:</strong> Missing <code>taskAffinity</code> and <code>launchMode</code> attributes<br>'
                    f'<strong>Recommendation:</strong> Add for defense-in-depth (best practice)<br>'
                    f'<strong>Fix:</strong> Add <code>android:launchMode="singleTask"</code> or set <code>android:taskAffinity=""</code>'
                )
                warnings.append(f"{desc}<br><pre>{esc}</pre>")

    # ── PART 2 + PART 3: XML-based scan ──
    tree = ET.parse(manifest)
    root = tree.getroot()
    pkg = root.attrib.get('package', '')

    for activity in root.findall('.//activity'):
        name = activity.get(ns('name'), 'unknown')

        # Skip library activities
        if is_library_activity(name):
            continue

        # Skip launcher activities (MAIN action)
        is_launcher_main = False
        for intent_filter in activity.findall('intent-filter'):
            has_main = any(action.get(ns('name')) == 'android.intent.action.MAIN'
                          for action in intent_filter.findall('action'))
            if has_main:
                is_launcher_main = True
                break

        if is_launcher_main:
            continue

        # Determine exported state
        exported_attr = activity.get(ns('exported'))
        has_if = activity.find('intent-filter') is not None
        is_exported = (exported_attr == 'true') or has_if

        # Generate full activity name and ADB command
        if name.startswith('.'):
            full_name = pkg + name
        elif '.' not in name:
            full_name = f"{pkg}.{name}"
        else:
            full_name = name

        adb_cmd = f"adb shell am start -n {pkg}/{full_name}"

        # Part 2: custom affinity + reparenting
        task_affinity = activity.get(ns('taskAffinity'), pkg)
        allow_reparent = activity.get(ns('allowTaskReparenting')) == 'true'
        if is_exported and task_affinity != pkg and allow_reparent:
            failures.append(
                f'<strong>Activity:</strong> <code>{name}</code><br>'
                f'<strong>Issue:</strong> taskAffinity="{task_affinity}" + allowTaskReparenting="true"<br>'
                f'<strong>Risk:</strong> Activity can be moved to attacker\'s task<br>'
                f'<strong>Fix:</strong> Remove allowTaskReparenting or set taskAffinity to package name<br>'
                f'<strong>OWASP Reference:</strong> MSTG-PLATFORM-3<br>'
                f'<strong>Test:</strong> <code>{adb_cmd}</code>'
            )

        # Part 3: unprotected export
        permission = activity.get(ns('permission'))

        # Note: Launcher activities are already skipped at the top of the loop
        # This check is redundant but kept for clarity
        if is_exported and not permission:
            failures.append(
                f'<strong>Activity:</strong> <code>{name}</code><br>'
                f'<strong>Issue:</strong> Exported with no android:permission attribute<br>'
                f'<strong>Risk:</strong> Any app can launch this activity<br>'
                f'<strong>Fix:</strong> Add android:permission attribute or set android:exported="false"<br>'
                f'<strong>OWASP Reference:</strong> MSTG-PLATFORM-3<br>'
                f'<strong>Test:</strong> <code>{adb_cmd}</code>'
            )

    # Determine status and build output
    total_activities = len(failures) + len(warnings)

    if failures and warnings:
        output = (
            f"<strong style='color:red'>CRITICAL ISSUES ({len(failures)}):</strong><br><br>" +
            "<br><br>\n".join(failures) +
            f"<br><br><hr><strong style='color:#d98e00'>RECOMMENDATIONS ({len(warnings)}):</strong><br><br>" +
            "<br><br>\n".join(warnings) +
            mastg_ref
        )
        return 'FAIL', output, total_activities
    elif failures:
        output = f"<strong style='color:red'>CRITICAL ISSUES ({len(failures)}):</strong><br><br>" + "<br><br>\n".join(failures) + mastg_ref
        return 'FAIL', output, total_activities
    elif warnings:
        output = f"<strong style='color:#d98e00'>DEFENSE-IN-DEPTH RECOMMENDATIONS ({len(warnings)}):</strong><br><br>" + "<br><br>\n".join(warnings) + mastg_ref
        return 'WARN', output, total_activities
    else:
        return 'PASS', "No task hijacking vulnerabilities detected" + mastg_ref, 0

def check_network_security_config(base):
    """
    Tests:
      • android:usesCleartextTraffic must be explicitly "false" (FAIL if missing/wrong)
      • Manifest reference @xml/network_security_config (WARN if missing)
      • res/xml/network_security_config.xml exists (WARN if missing)
      • No <debug-overrides> in the config (FAIL if found)
      • Every <domain-config> must have cleartextTrafficPermitted="false" and include a <pin-set> (FAIL if wrong)
    """
    manifest = os.path.join(base, 'AndroidManifest.xml')
    cfg_path = os.path.join(base, 'res', 'xml', 'network_security_config.xml')
    m_txt = open(manifest, errors='ignore').read()

    fail_issues = []  # Critical security issues
    warn_issues = []  # Recommendations

    # 1) Check usesCleartextTraffic on <application> - CRITICAL
    m = re.search(
        r'<application\b[^>]*\bandroid:usesCleartextTraffic="(true|false)"',
        m_txt
    )
    if not m:
        fail_issues.append("Missing android:usesCleartextTraffic")
    elif m.group(1).lower() != 'false':
        fail_issues.append(f"android:usesCleartextTraffic is set to {m.group(1)}")

    # 2) Check networkSecurityConfig reference - RECOMMENDATION
    if not re.search(
        r'android:networkSecurityConfig="@xml/network_security_config"',
        m_txt
    ):
        warn_issues.append("Missing android:networkSecurityConfig")

    # 3) Check config file existence - RECOMMENDATION
    if not os.path.exists(cfg_path):
        warn_issues.append("Missing res/xml/network_security_config.xml")
    else:
        # 4) Parse config for deeper issues
        try:
            tree = ET.parse(cfg_path)
            root = tree.getroot()
        except Exception as e:
            fail_issues.append(f"Failed to parse network_security_config.xml: {e}")
            root = None

        if root is not None:
            # 4a) debug-overrides - CRITICAL
            dob = root.find('debug-overrides')
            if dob is not None:
                snippet = html.escape(ET.tostring(dob, encoding='unicode'))
                fail_issues.append(f"Found insecure <debug-overrides>:<br><pre>{snippet}</pre>")

            # 4b) domain-config checks - CRITICAL
            dcs = root.findall('domain-config')
            if not dcs:
                warn_issues.append("No <domain-config> entries (no domain restrictions)")
            else:
                for dc in dcs:
                    domain = dc.findtext('domain') or "(unspecified)"
                    ctp = dc.get('cleartextTrafficPermitted')
                    if ctp != 'false':
                        fail_issues.append(
                            f"Domain `{domain}` allows cleartextTrafficPermitted={ctp}"
                        )
                    if dc.find('pin-set') is None:
                        warn_issues.append(
                            f"Domain `{domain}` missing <pin-set> (no certificate pinning)"
                        )

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0020/' target='_blank'>MASTG-TEST-0020: Testing the TLS Settings</a></div>"

    # 5) Final result
    if fail_issues:
        # Critical issues found - return FAIL
        all_issues = fail_issues + warn_issues
        all_issues.append(mastg_ref)
        return 'FAIL', "<br>\n".join(all_issues)
    elif warn_issues:
        # Only recommendations - return WARN
        warn_issues.append(mastg_ref)
        return 'WARN', "<br>\n".join(warn_issues)
    else:
        # Everything good
        return 'PASS', f"None{mastg_ref}"
    
def check_http_uris(base):
    """
    FAIL if any literal 'http://' URIs are found in .smali, .java or .xml files,
    except known safe namespaces (Android schema, W3C, Maven, Apache, etc.).
    Also filters out common false positives like localhost, example.com, test URLs,
    and URLs appearing in error messages or documentation strings.
    Returns (ok: bool, details_html: str).
    """

    hits = []
    http_re = re.compile(r'http://[^\s"\'<>]+')

    # Known safe namespaces and schema URLs
    ignore_prefixes = (
        "http://schemas.android.com",
        "http://www.w3.org",
        "http://maven.apache.org",
        "http://www.apache.org",
        "http://dashif.org",
        "http://ns.adobe.com",
        "http://github.com",
        "http://schemas.microsoft.com",
        "http://findbugs.sourceforge.net",
        "http://%s",
        "http://xmlpull.org",
        "http://xml.org",
        "http://www.android.com",
        "http://jsoup.org",
        # Test/placeholder URLs
        "http://localhost",
        "http://127.0.0.1",
        "http://0.0.0.0",
        "http://example.com",
        "http://example.org",
        "http://test.com",
        "http://undefined",
    )

    # Patterns that indicate the URL is in documentation/error messages (not actual code)
    false_positive_patterns = [
        r'(error|exception|warning|log|message|description|comment|make sure|example|e\.g\.|i\.e\.|see https?://)',
        r'(starts with|should be|must be|can be|try|instead)',
        r'(malformed|invalid|supplied.*url)',
    ]
    false_positive_re = re.compile('|'.join(false_positive_patterns), re.IGNORECASE)

    for root, _, files in os.walk(base):
        for fn in files:
            if not fn.endswith(('.smali', '.java', '.xml')):
                continue
            full = os.path.join(root, fn)
            rel  = os.path.relpath(full, base)
            try:
                for lineno, line in enumerate(open(full, errors='ignore'), 1):
                    for m in http_re.findall(line):
                        # Skip known safe prefixes
                        if any(m.startswith(pref) for pref in ignore_prefixes):
                            continue

                        # Skip if this appears to be in an error message or documentation
                        if false_positive_re.search(line):
                            continue

                        snippet = html.escape(line.strip())
                        link    = f'<a href="file://{html.escape(full)}">{html.escape(rel)}:{lineno}</a>'
                        hits.append(f"{link} ⟶ {snippet}")
            except:
                pass

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0233/' target='_blank'>MASTG-TEST-0233: Hardcoded HTTP URLs</a></div>"

    if not hits:
        return True, f"None{mastg_ref}", 0

    # Return explicit count as third value to avoid automatic counting of mastg_ref links
    result = "<br>\n".join(hits) + mastg_ref
    return False, result, len(hits)

def check_debuggable(manifest, base):
    """
    FAIL if:
      - android:debuggable="true" or android:testOnly="true" in <application> tag,
      - code contains debug-enabling calls including BuildConfig DEBUG field set true.
    PASS otherwise.
    """
    txt = open(manifest, errors='ignore').read()
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0039/' target='_blank'>MASTG-TEST-0039: Testing whether the App is Debuggable</a></div>"

    if re.search(r'<application\b[^>]*\bandroid:debuggable="true"', txt, re.IGNORECASE):
        return False, f"android:debuggable=\"true\" in manifest{mastg_ref}"
    if re.search(r'<application\b[^>]*\bandroid:testOnly="true"', txt, re.IGNORECASE):
        return False, f"android:testOnly=\"true\" in manifest{mastg_ref}"

    # patterns to check
    patterns = {
        r'\.setWebContentsDebuggingEnabled\(\s*true\s*\)': "WebView debugging enabled via setWebContentsDebuggingEnabled(true)",
        r'Debug\.isDebuggerConnected\s*\(': "Runtime debugger check via Debug.isDebuggerConnected()",
        r'Debug\.waitForDebugger\s*\(': "Forced debugger attach via Debug.waitForDebugger()",
        r'\\.field\\s+.*DEBUG:Z\\s*=\\s*true': "BuildConfig DEBUG field left true in smali"
    }
    # check code patterns and report file:line links for matches
    for pat, msg in patterns.items():
        hits = grep_code(base, pat)
        if hits:
            # find first occurrence with line number
            rel = hits[0]
            abs_path = os.path.abspath(os.path.join(base, rel))
            # open file to find line
            with open(os.path.join(base, rel), errors='ignore') as f:
                for idx, line in enumerate(f, 1):
                    if re.search(pat, line):
                        link = f'<a href="file://{abs_path}:{idx}">{rel}:{idx}</a>'
                        return False, f"{link} {msg}{mastg_ref}"
            # fallback if line not found
            link = f'<a href="file://{abs_path}">{rel}</a>'
            return False, f"{link} {msg}{mastg_ref}"

    return True, f"No debug flags or debug-enabling calls found{mastg_ref}"

def check_root_detection(manifest, base):
    """
    PASS if any root-detection code is present in smali or Java:
      • smali method signatures like L…;->isRoot()Z or L…;->isRooted()Z
      • RootBeer instantiation or isRooted()/isRoot() calls
      • RootChecker usage
      • checkRootFiles()/checkRootPackages()
      • Runtime.getRuntime().exec("su")
      • java.io.File("/system/bin/su")
      • Build.TAGS.contains("test-keys")
    FAIL otherwise. Reports ALL detection methods found, not just the first.
    """
    # Patterns tuned for smali and Java
    patterns = {
        # smali-style root checks
        r'->isRoot\(\)Z':                             'isRoot() smali method',
        r'->isRooted\(\)Z':                           'isRooted() smali method',
        r'RootBeer':                                  'RootBeer library reference',
        r'RootChecker':                               'RootChecker class reference',
        r'->checkRootFiles\(\)Z':                     'checkRootFiles() smali call',
        r'->checkRootPackages\(\)Z':                  'checkRootPackages() smali call',
        # Java-style calls in smali or Java sources
        r'\.isRoot\(\)':                              'isRoot() Java call',
        r'\.isRooted\(\)':                            'isRooted() Java call',
        r'\.checkRootFiles\(':                        'checkRootFiles() Java call',
        r'\.checkRootPackages\(':                     'checkRootPackages() Java call',
        r'Runtime\.getRuntime\(\)\.exec\(\s*".*su.*"\)': 'Shell exec "su" call',
        r'new\s+java\.io\.File\(\s*".*/system/(x)?bin/su"': 'su binary file check',
        r'Build\.TAGS\s*\.contains\(\s*"test-keys"\)': 'Build.TAGS test-keys check',
    }

    findings = {}

    for pat, msg in patterns.items():
        hits = grep_code(base, pat)
        if hits:
            findings[msg] = hits

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0045/' target='_blank'>MASTG-TEST-0045: Testing Root Detection</a></div>"

    if not findings:
        return False, f'No root detection code found{mastg_ref}'

    # Report all detection methods found with line numbers and snippets
    lines = []
    lines.append(f"<div> Root detection mechanisms found: {len(findings)} method(s)</div>")

    for desc, hits in findings.items():
        lines.append(f'<details open>')
        lines.append(f'<summary class="pass">')
        lines.append(f'<span class="bullet"></span><span class="check-name"> {desc} ({len(hits)} file(s))</span>')
        lines.append('</summary>')

        # Show first 5 files with line numbers and code snippets
        for rel in sorted(hits)[:5]:
            full_path = os.path.join(base, rel)
            full_abs = os.path.abspath(full_path)
            filename = os.path.basename(rel)

            # Find the matching pattern in the file
            pattern = [pat for pat, msg in patterns.items() if msg == desc][0]
            try:
                with open(full_path, 'r', errors='ignore') as f:
                    file_lines = f.readlines()
                    for line_num, line in enumerate(file_lines, 1):
                        if re.search(pattern, line):
                            # Get context (1 line before and after)
                            start = max(0, line_num - 2)
                            end = min(len(file_lines), line_num + 1)
                            context_lines = file_lines[start:end]

                            lines.append(
                                f'<div class="finding-detail">'
                                f'<a href="file://{html.escape(full_abs)}:{line_num}">{html.escape(filename)}:{line_num}</a> '
                            )

                            # Show code snippet inline (clickable to expand)
                            snippet = ''.join(context_lines)
                            lines.append(' <a href="#" onclick="this.nextSibling.style.display=this.nextSibling.style.display==\'none\'?\'block\':\'none\';return false" class="code-toggle">[+]</a>')
                            lines.append('<pre class="code-snippet" style="display:none">')
                            for i, ctx_line in enumerate(context_lines):
                                if start + i + 1 == line_num:
                                    lines.append(f'<span class="highlight">{html.escape(ctx_line.rstrip())}</span>')
                                else:
                                    lines.append(html.escape(ctx_line.rstrip()))
                            lines.append('</pre>')
                            lines.append('</div>')
                            break  # Only show first match per file
            except Exception:
                # Fallback if file can't be read
                lines.append(
                    f'<div class="finding-detail">'
                    f'<a href="file://{html.escape(full_abs)}">{html.escape(rel)}</a>'
                    f'</div>'
                )

        if len(hits) > 5:
            lines.append(f'<div class="finding-detail"><em>...and {len(hits) - 5} more files</em></div>')

        lines.append('</details>')

    lines.append(mastg_ref)
    return True, "\n".join(lines)

def check_allow_backup(manifest):
    """
    Check if app has properly disabled backup functionality for security.
    PASS if android:allowBackup="false" (backups disabled - secure).
    FAIL if android:allowBackup="true" or missing (backups enabled - insecure).
    """
    txt = open(manifest, errors='ignore').read()
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0009/' target='_blank'>MASTG-TEST-0009: Testing Backups for Sensitive Data</a></div>"

    m = re.search(r'<application\b[^>]*\bandroid:allowBackup="(true|false)"', txt)
    if not m:
        return False, f"android:allowBackup is missing (defaults to true - backups enabled). Set to false to prevent backup extraction.{mastg_ref}"
    if m.group(1).lower() != 'false':
        return False, f"android:allowBackup=\"{m.group(1)}\" - backups are enabled. Change to false to prevent data extraction via adb backup.{mastg_ref}"
    return True, f"android:allowBackup=\"false\" - backups properly disabled{mastg_ref}"
    
def check_safe_browsing(manifest, base):
    """
    PASS if:
      • No WebView usage, or
      • No explicit opt-out found (default ON on API 26+), or
      • Code explicitly enables Safe Browsing.
    FAIL if:
      • Manifest sets android.webkit.WebView.EnableSafeBrowsing=false, or
      • Code calls setSafeBrowsingEnabled(false), or
      • App calls SafeBrowsingResponse.proceed(...) inside its own onSafeBrowsingHit(...).
    INFO-ish PASS note if target/min < 26.
    Special handling for React Native apps (setSafeBrowsingEnabled not available).
    """
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0031/' target='_blank'>MASTG-TEST-0031: Testing JavaScript Execution in WebViews</a></div>"

    # --- detect any WebView usage (SMALI patterns for decompiled APK) ---
    webview_patterns = [
        r'Landroid/webkit/WebView;',                  # Standard Android WebView
        r'Landroidx/webkit/WebViewCompat;',           # AndroidX WebView compat
        r'Landroid/webkit/WebSettings;',              # WebView settings
        r'com/reactnativecommunity/webview',          # RN smali path
        r'RNCWebView',                                # React Native WebView
        r'MauiWebViewClient',                         # MAUI framework
    ]

    # Detect React Native usage (SMALI patterns)
    rn_patterns = [
        r'com/facebook/react/ReactActivity',
        r'com/facebook/react/ReactApplication',
        r'com/reactnativecommunity/webview',
        r'RNCWebView',
    ]
    rn_hits = []
    for pat in rn_patterns:
        rn_hits += grep_code(base, pat)
    is_react_native = bool(rn_hits)

    webview_hits = []
    for pat in webview_patterns:
        webview_hits += grep_code(base, pat)
    if not webview_hits:
        return True, "No WebView usage detected" + mastg_ref

    # --- manifest explicit opt-out? ---
    try:
        manifest_txt = open(manifest, errors='ignore').read()
    except Exception:
        manifest_txt = ""
    m = re.search(
        r'<meta-data\s+android:name="android\.webkit\.WebView\.EnableSafeBrowsing"'
        r'\s+android:value="(true|false)"',
        manifest_txt, re.IGNORECASE
    )
    if m and m.group(1).lower() == 'false':
        return False, "Safe Browsing explicitly disabled via manifest meta-data" + mastg_ref

    # --- SDK applicability quick note ---
    def _sdk(txt):
        ms = re.search(r'<uses-sdk[^>]*android:minSdkVersion="(\d+)"', txt)
        ts = re.search(r'<uses-sdk[^>]*android:targetSdkVersion="(\d+)"', txt)
        return (int(ms.group(1)) if ms else None,
                int(ts.group(1)) if ts else None)
    min_sdk, target_sdk = _sdk(manifest_txt)

    # --- code explicit enable/disable (Java/Kotlin & smali) ---
    enable_hits = []
    disable_hits = []

    # direct framework API in source
    enable_hits += grep_code(base, r'\.setSafeBrowsingEnabled\s*\(\s*true\s*\)')
    disable_hits += grep_code(base, r'\.setSafeBrowsingEnabled\s*\(\s*false\s*\)')

    # AndroidX compat helper
    enable_hits += grep_code(base, r'WebSettingsCompat\.setSafeBrowsingEnabled\([^,]+,\s*true\s*\)')
    disable_hits += grep_code(base, r'WebSettingsCompat\.setSafeBrowsingEnabled\([^,]+,\s*false\s*\)')

    # smali boundary calls -> look back for const 0x0 / 0x1 near the call
    call_files = grep_code(base, r'->setSafeBrowsingEnabled\(Z\)V')
    for rel in call_files:
        path = os.path.join(base, rel)
        try:
            lines = open(path, errors='ignore').read().splitlines()
        except Exception:
            continue
        for i, line in enumerate(lines, 1):
            if '->setSafeBrowsingEnabled(Z)V' not in line:
                continue
            window = "\n".join(lines[max(0, i-8):i+1])
            if re.search(r'const/(4|16)\s+[vp]\d+,\s*0x0\b', window):
                disable_hits.append(f"{rel}:{i}")
            elif re.search(r'const/(4|16)\s+[vp]\d+,\s*0x1\b', window):
                enable_hits.append(f"{rel}:{i}")

    # --- helper to build file:// anchors with line numbers ---
    def _first_anchor(rel, pat):
        full = os.path.join(base, rel)
        try:
            with open(full, errors='ignore') as f:
                for idx, ln in enumerate(f, 1):
                    if re.search(pat, ln):
                        return f'<a href="file://{os.path.abspath(full)}:{idx}">{html.escape(rel)}:{idx}</a>'
        except Exception:
            pass
        return f'<a href="file://{os.path.abspath(full)}">{html.escape(rel)}</a>'

    # if any explicit disables → FAIL
    if disable_hits:
        links = []
        for rel in sorted(set(disable_hits)):
            file_rel = rel.split(':', 1)[0]
            links.append(_first_anchor(file_rel, r'setSafeBrowsingEnabled'))
        return False, "Safe Browsing disabled at runtime via code:<br>" + "<br>".join(links) + mastg_ref

    # 3) Suppressing the interstitial? Only if proceed() is called from the app's onSafeBrowsingHit(...)
    #    Ignore library namespaces to avoid false positives (androidx, chromium, RN, etc.)
    lib_ns = (
        '/androidx/', '/org/chromium/', '/com/google/', '/com/facebook/',
        '/com/reactnativecommunity/', '/kotlin/', '/kotlinx/', '/okhttp3/', '/retrofit2/'
    )

    # files that reference SafeBrowsingResponse.proceed(...)
    proceed_files = set()
    proceed_files.update(grep_code(base, r'Landroid/webkit/SafeBrowsingResponse;->proceed\(Z\)V'))
    proceed_files.update(grep_code(base, r'\bSafeBrowsingResponse\.proceed\s*\('))

    # drop library files
    proceed_files = {rel for rel in proceed_files if not any(ns in rel for ns in lib_ns)}

    # confirm proceed() is inside an onSafeBrowsingHit(...) method *in the same file*
    real_suppress = []
    for rel in sorted(proceed_files):
        path = os.path.join(base, rel)
        try:
            lines = open(path, errors='ignore').read().splitlines()
        except Exception:
            continue

        i = 0
        while i < len(lines):
            line = lines[i]
            if line.startswith('.method') and 'onSafeBrowsingHit' in line:
                j = i + 1
                body = []
                while j < len(lines) and not lines[j].startswith('.end method'):
                    body.append(lines[j]); j += 1
                body_text = "\n".join(body)
                if ('SafeBrowsingResponse;->proceed' in body_text) or re.search(r'\bSafeBrowsingResponse\.proceed\s*\(', body_text):
                    real_suppress.append((rel, i + 1))
                i = j
            else:
                i += 1

    if real_suppress:
        links = []
        for rel, start_ln in real_suppress:
            full = os.path.join(base, rel)
            links.append(f'<a href="file://{os.path.abspath(full)}:{start_ln}">{html.escape(rel)}:{start_ln}</a>')
        return False, "App suppresses Safe Browsing interstitial (proceed() inside onSafeBrowsingHit):<br>" + "<br>".join(links) + mastg_ref

    # explicit enable → PASS
    if enable_hits:
        return True, "Safe Browsing enabled at runtime via code" + mastg_ref

    # API applicability note
    if (min_sdk and min_sdk < 26) or (target_sdk and target_sdk < 26):
        return True, "Targets < API 26; default enablement may not apply. No opt-out found." + mastg_ref

    # React Native special case
    if is_react_native:
        return True, "React Native app detected. Safe Browsing control limited in RN WebView. No opt-out found; default is ENABLED on API 26+" + mastg_ref

    # default PASS (no opt-out found)
    return True, "No Safe Browsing opt-out detected; default is ENABLED on API 26+" + mastg_ref


def check_exported_components(manifest, base=None):
    """
    FAIL if any <activity|service|receiver|provider android:exported="true">
    (or implicitly exported via intent-filter) lacks a permission, or if its
    permission has only 'normal' protection level. Reports count and details.

    Filters out:
    - Library components (Google Play Services, AndroidX, Firebase, etc.)
    - Launcher activities (MAIN + LAUNCHER)
    - App widgets (required to be exported)
    """
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0029/' target='_blank'>MASTG-TEST-0029: Testing for Sensitive Functionality Exposure Through IPC</a></div>"

    tree = ET.parse(manifest)
    root = tree.getroot()
    pkg  = root.attrib.get('package', '')
    ANDROID_NS = 'http://schemas.android.com/apk/res/android'
    def ns(attr): return f'{{{ANDROID_NS}}}{attr}'

    # Library component prefixes to exclude
    library_prefixes = [
        'com.google.android.gms.',      # Google Play Services
        'com.google.firebase.',          # Firebase
        'com.google.android.play.',      # Play Core
        'androidx.',                     # AndroidX
        'android.support.',              # Old support library
        'com.facebook.',                 # Facebook SDK
        'com.android.billingclient.',    # Billing library
        'com.google.android.datatransport.',
        'com.google.android.libraries.',
    ]

    def is_library_component(name):
        """Check if component is from a third-party library"""
        if not name:
            return False
        # Resolve relative names
        if name.startswith('.'):
            full_name = pkg + name
        elif '.' not in name:
            full_name = f"{pkg}.{name}"
        else:
            full_name = name

        return any(full_name.startswith(prefix) for prefix in library_prefixes)

    def is_widget_component(elem, tag):
        """Check if receiver is an app widget"""
        if tag != 'receiver':
            return False

        name = elem.get(ns('name'), '')
        # Check component name for widget indicators
        if 'widget' in name.lower() or 'appwidget' in name.lower():
            # Verify it has APPWIDGET_UPDATE action
            for intent_filter in elem.findall('intent-filter'):
                for action in intent_filter.findall('action'):
                    action_name = action.get(ns('name'), '')
                    if 'APPWIDGET_UPDATE' in action_name:
                        return True
        return False

    # 1) Build a map of declared permissions → protectionLevel
    perm_protection = {}
    for perm in root.findall('permission'):
        name = perm.get(ns('name'))
        level = perm.get(ns('protectionLevel'), 'normal')
        perm_protection[name] = level

    issues = []
    # 2) Check each exported component type
    for tag in ('activity', 'service', 'receiver', 'provider'):
        for elem in root.findall(f'.//{tag}'):
            name = elem.get(ns('name'), '(unknown)')

            # Skip library components
            if is_library_component(name):
                continue

            exp_attr = elem.get(ns('exported'))
            has_if   = elem.find('intent-filter') is not None

            # Determine exported status:
            if   exp_attr == 'true':   is_exported = True
            elif exp_attr == 'false':  is_exported = False
            else:  # no explicit exported
                # Android <12: any intent-filter → exported
                # Android ≥12: must explicitly opt-in, but for static we assume intent-filter still means export
                is_exported = has_if

            if not is_exported:
                continue

            # Skip launcher activities (MAIN + LAUNCHER) as they're expected to be exported
            is_launcher = False
            if tag == 'activity':
                for intent_filter in elem.findall('intent-filter'):
                    has_main = any(action.get(ns('name')) == 'android.intent.action.MAIN'
                                  for action in intent_filter.findall('action'))
                    has_launcher = any(category.get(ns('name')) == 'android.intent.category.LAUNCHER'
                                      for category in intent_filter.findall('category'))
                    if has_main and has_launcher:
                        is_launcher = True
                        break

            if is_launcher:
                continue

            # Skip app widgets (required to be exported)
            if is_widget_component(elem, tag):
                continue

            # 3) Check permission attribute
            perm = elem.get(ns('permission'))
            if not perm:
                # no protection at all
                issues.append((tag, name, None, has_if))
            else:
                prot = perm_protection.get(perm, 'normal')
                if prot == 'normal':
                    # protection too weak
                    issues.append((tag, name, perm, has_if))

    if not issues:
        return True, "None" + mastg_ref, 0

    # 4) Format details
    lines = []
    for tag, name, perm, implicit in issues:
        # Resolve full component name
        if name.startswith('.'):
            full = pkg + name
        elif '.' not in name:
            full = f"{pkg}.{name}"
        else:
            full = name

        # Pick an adb command (providers don’t have a generic ADB launch)
        if tag == 'activity':
            cmd = f"adb shell am start -n {pkg}/{full}"
        elif tag == 'service':
            cmd = f"adb shell am start-service -n {pkg}/{full}"
        elif tag == 'receiver':
            cmd = f"adb shell am broadcast -n {pkg}/{full} -a <ACTION>"
        else:
            cmd = "# no generic adb command for providers"

        detail = f"<strong>{tag}</strong> <code>{html.escape(name)}</code>"
        if perm is None:
            detail += " <span class='fail'>(no permission)</span>"
        else:
            detail += f" <span class='warn'>(permission '{perm}' is normal-level)</span>"
        if implicit:
            detail += " <span class='info'>(implicit via intent-filter)</span>"
        detail += f"<br><code>{html.escape(cmd)}</code>"

        lines.append(detail)

    return False, "<br><br>\n".join(lines) + mastg_ref, len(issues)


def check_sql_injection(base, manifest):
    """
    MASTG-TEST-0025 (Injection flaws):
      • Grep for appendWhere(…) usages
      • Grep for rawQuery(…) without args
      • For each hit, show a placeholder `adb shell content query` command
    """
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0025/' target='_blank'>MASTG-TEST-0025: Testing for Injection Flaws</a></div>"

    AND_NS   = "http://schemas.android.com/apk/res/android"
    auth_attr = f"{{{AND_NS}}}authorities"
    exp_attr  = f"{{{AND_NS}}}exported"

    # first, build a list of all exported provider authorities
    tree = ET.parse(manifest)
    root = tree.getroot()
    auths = []
    for prov in root.findall("provider"):
        exported = prov.get(exp_attr)
        if exported is not None and exported.lower() == "false":
            continue
        raw = prov.get(auth_attr, "")
        for a in raw.split(";"):
            a = a.strip()
            if a:
                auths.append(a)

    issues = []

    # helper to emit a suggestion for each authority
    def suggest():
        cmds = []
        for a in auths:
            cmds.append(
                f'<code>adb shell content query '
                f'--uri content://{html.escape(a)}/&lt;PATH&gt; '
                f'--where "1=1) OR 1=1--"</code>'
            )
        return "<br>".join(cmds) if cmds else "<em>(no exported providers found to test)</em>"

    # 1) appendWhere
    for rel in grep_code(base, r'appendWhere\('):
        full = os.path.join(base, rel)
        issues.append(
            f'<a href="file://{full}">{html.escape(rel)}</a> uses <code>appendWhere(...)</code><br>'
            f'<em>try:</em> {suggest()}'
        )

    # 2) rawQuery without args
    for rel in grep_code(base, r'\.rawQuery\('):
        full = os.path.join(base, rel)
        issues.append(
            f'<a href="file://{full}">{html.escape(rel)}</a> uses <code>rawQuery(...)</code> without args<br>'
            f'<em>try:</em> {suggest()}'
        )

    if not issues:
        return True, "None" + mastg_ref

    return False, "<br>\n".join(issues) + mastg_ref


def check_raw_sql_queries(base):
    """
    Detects raw SQL query usage with potential injection risks.

    Checks for:
    1. SQLite API calls (rawQuery, execSQL, query, insert, update, delete)
    2. String concatenation/formatting near SQL calls
    3. StringBuilder/StringBuffer usage for SQL construction
    4. String.format() usage with SQL

    Maps to MASVS-STORAGE and MASVS-CODE injection controls.
    """
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0304/' target='_blank'>MASTG-TEST-0304: Sensitive Data Stored Unencrypted via SQLite</a></div>"

    findings = {
        'Critical': [],  # rawQuery/execSQL with obvious concatenation
        'High': [],      # SQL methods with StringBuilder
        'Medium': [],    # query/insert/update with potential issues
        'Info': []       # Safe usage with parameterization
    }

    # SQLite API patterns to search for
    sql_api_patterns = {
        'rawQuery': r'Landroid/database/sqlite/SQLiteDatabase;->rawQuery',
        'execSQL': r'Landroid/database/sqlite/SQLiteDatabase;->execSQL',
        'query': r'Landroid/database/sqlite/SQLiteDatabase;->query',
        'insert': r'Landroid/database/sqlite/SQLiteDatabase;->insert',
        'update': r'Landroid/database/sqlite/SQLiteDatabase;->update',
        'delete': r'Landroid/database/sqlite/SQLiteDatabase;->delete',
        'rawQueryWithFactory': r'Landroid/database/sqlite/SQLiteDatabase;->rawQueryWithFactory',
    }

    scanned_files = 0

    for root, _, files in os.walk(base):
        for f in files:
            if not f.endswith('.smali'):
                continue

            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, base)

            # Skip library files
            if any(lib in rel_path for lib in ['androidx/', 'android/support/', 'com/google/']):
                continue

            scanned_files += 1

            try:
                with open(full_path, errors='ignore') as file:
                    lines = file.readlines()

                # Search for SQL API calls
                for line_num, line in enumerate(lines, 1):
                    for api_name, pattern in sql_api_patterns.items():
                        if re.search(pattern, line):
                            # Found SQL API call - analyze context
                            # Increased from 20 to 80 to catch StringBuilder patterns further back
                            # (AndroGoat has StringBuilder at line 71, rawQuery at line 139 = 68 lines apart)
                            context_start = max(0, line_num - 80)
                            context_end = min(len(lines), line_num + 5)
                            context = lines[context_start:context_end]

                            # Analyze the context for injection risks
                            risk_level, reason, indicators = analyze_sql_context(
                                api_name, context, line_num - context_start
                            )

                            if risk_level == 'Safe':
                                continue  # Skip safe usage

                            # Build finding
                            finding = {
                                'file': rel_path,
                                'line': line_num,
                                'api': api_name,
                                'reason': reason,
                                'indicators': indicators,
                                'snippet': ''.join(context[max(0, line_num - context_start - 3):line_num - context_start + 2])
                            }

                            findings[risk_level].append(finding)

            except Exception as e:
                continue

    # Build HTML report with collapsible sections
    total = sum(len(findings[k]) for k in ['Critical', 'High', 'Medium'])

    if total == 0:
        return 'PASS', f"<div>No raw SQL injection risks detected</div><div>Scanned {scanned_files} files</div>" + mastg_ref

    lines = []
    lines.append(f"<div style='margin:2px 0'><strong>Scanned:</strong> {scanned_files} smali files • <strong>Total:</strong> {total} findings</div>")

    # Show findings by severity with collapsible sections
    severity_config = {
        'Critical': ('', '#dc3545', True),
        'High': ('', '#fd7e14', True),
        'Medium': ('', '#ffc107', False),
    }

    for severity, (emoji, color, is_open) in severity_config.items():
        items = findings[severity]
        if not items:
            continue

        open_attr = 'open' if is_open else ''
        lines.append(f'<details {open_attr}>')
        lines.append(f'<summary>')
        lines.append(f'<span class="bullet"></span><span class="check-name">{emoji} {severity} Risk ({len(items)})</span>')
        lines.append('</summary>')

        for i, finding in enumerate(items, 1):
            full = os.path.abspath(os.path.join(base, finding['file']))
            filename = os.path.basename(finding['file'])

            lines.append(
                f'<div class="finding-detail" style="border-left-color:{color}">'
                f'<strong>#{i}</strong> '
                f'<a href="file://{html.escape(full)}:{finding["line"]}">{html.escape(filename)}:{finding["line"]}</a>'
                f'<br><code>{html.escape(finding["api"])}</code> '
                f'<span class="text-muted">{html.escape(finding["reason"])}</span>'
            )

            if finding['indicators']:
                lines.append('<br><span class="text-muted">WARNING: ')
                lines.append(', '.join(html.escape(ind) for ind in finding['indicators']))
                lines.append('</span>')

            if finding['snippet']:
                lines.append('<details class="code-details"><summary class="code-toggle">Show code</summary>')
                lines.append('<pre class="code-snippet">')
                lines.append(html.escape(finding['snippet']))
                lines.append('</pre></details>')

            lines.append('</div>')

        lines.append('</details>')

    lines.append(
        '<div class="info-box"><em> Recommendation: Use parameterized queries with ? placeholders '
        'and selectionArgs[] to prevent SQL injection. Avoid string concatenation for SQL.</em></div>'
    )

    # Determine overall status
    has_critical_high = len(findings['Critical']) + len(findings['High']) > 0

    if has_critical_high:
        return 'FAIL', '\n'.join(lines) + mastg_ref
    else:
        return 'WARN', '\n'.join(lines) + mastg_ref


def analyze_sql_context(api_name, context, api_line_index):
    """
    Analyze code context around SQL API call to determine injection risk.

    Returns: (risk_level, reason, indicators)
    """
    context_str = ''.join(context)
    indicators = []

    # Check for string concatenation patterns
    has_string_builder = 'Ljava/lang/StringBuilder;' in context_str
    has_string_buffer = 'Ljava/lang/StringBuffer;' in context_str
    has_string_concat = '->append(' in context_str
    has_string_format = 'Ljava/lang/String;->format' in context_str

    # Check for parameterization (good practice)
    has_selection_args = 'selectionArgs' in context_str or '[Ljava/lang/String;' in context_str
    has_placeholders = '?' in context_str or '\\?' in context_str

    # Check for user input sources
    has_intent_extra = 'getStringExtra' in context_str or 'getIntExtra' in context_str
    has_edittext = 'EditText' in context_str or 'getText()' in context_str
    has_bundle = 'Bundle;->get' in context_str
    has_uri = 'Uri;' in context_str or 'getQueryParameter' in context_str

    # Detect const-string SQL patterns
    sql_keywords_in_const = False
    for line in context[:api_line_index]:
        if 'const-string' in line and any(kw in line.upper() for kw in ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE']):
            sql_keywords_in_const = True
            break

    # Risk assessment logic
    risk_level = 'Info'
    reason = "SQL query usage detected"

    # Critical risk: rawQuery/execSQL with concatenation and no parameterization
    if api_name in ['rawQuery', 'execSQL', 'rawQueryWithFactory']:
        if (has_string_builder or has_string_concat or has_string_format):
            if not has_selection_args and not has_placeholders:
                indicators.append("String concatenation/StringBuilder detected")
                indicators.append("No parameterization (? placeholders) found")

                if has_intent_extra or has_edittext or has_bundle or has_uri:
                    risk_level = 'Critical'
                    reason = f"{api_name}() with string concatenation and potential user input"
                    indicators.append("Potential user input source detected")
                else:
                    risk_level = 'High'
                    reason = f"{api_name}() with string concatenation - potential injection"
            else:
                risk_level = 'Medium'
                reason = f"{api_name}() with concatenation but has parameterization"
                indicators.append("Parameterization detected (verify correct usage)")
        elif has_selection_args or has_placeholders:
            risk_level = 'Safe'
            reason = "Properly parameterized query"
        elif sql_keywords_in_const:
            risk_level = 'Medium'
            reason = f"{api_name}() with static SQL string (verify no dynamic parts)"
            indicators.append("Static SQL detected - verify no user input is concatenated")

    # High risk: query/insert/update/delete with suspicious patterns
    elif api_name in ['query', 'insert', 'update', 'delete']:
        if has_string_builder or has_string_concat or has_string_format:
            if has_intent_extra or has_edittext or has_bundle or has_uri:
                risk_level = 'High'
                reason = f"{api_name}() with string operations and potential user input"
                indicators.append("String manipulation detected")
                indicators.append("Potential user input source detected")
            else:
                risk_level = 'Medium'
                reason = f"{api_name}() with string operations - review for safety"
                indicators.append("String manipulation detected - verify SQL construction")
        elif not has_selection_args and sql_keywords_in_const:
            risk_level = 'Medium'
            reason = f"{api_name}() without explicit parameterization"
            indicators.append("Consider using ? placeholders and selectionArgs")
        else:
            risk_level = 'Safe'

    return risk_level, reason, indicators


def check_insecure_webview(base):
    """
    Comprehensive WebView security check based on OWASP MASTG-KNOW-0018.

    Checks for:
      • JavaScript enabled (setJavaScriptEnabled)
      • JavaScript interfaces (addJavascriptInterface)
      • File access configurations (setAllowFileAccess, setAllowUniversalAccessFromFileURLs, etc.)
      • Content provider access (setAllowContentAccess)
      • WebView debugging (setWebContentsDebuggingEnabled)
      • SSL/TLS error bypassing (onReceivedSslError with proceed())
      • URL loading from user input (XSS risks)
      • Mixed content mode (setMixedContentMode ALWAYS_ALLOW)
      • Storage and geolocation permissions
      • Custom protocol handlers without validation
      • Missing WebView cleanup

    MASVS: MASVS-PLATFORM-2
    MASTG: MASTG-KNOW-0018, MASTG-TEST-0027, MASTG-TEST-0031, MASTG-TEST-0032,
           MASTG-TEST-0033, MASTG-TEST-0037, MASTG-TEST-0250-253, MASTG-TEST-0284
    """

    hits = []

    # WebView configuration patterns to check
    patterns = {
        "setJavaScriptEnabled(true)": r'Landroid/webkit/WebSettings;->setJavaScriptEnabled\(Z\)V',
        "addJavascriptInterface": r'Landroid/webkit/WebView;->addJavascriptInterface\(',
        "setAllowUniversalAccessFromFileURLs(true)": r'Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs\(Z\)V',
        "setAllowFileAccessFromFileURLs(true)": r'Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs\(Z\)V',
        "setAllowFileAccess(true)": r'Landroid/webkit/WebSettings;->setAllowFileAccess\(Z\)V',
        "setAllowContentAccess(true)": r'Landroid/webkit/WebSettings;->setAllowContentAccess\(Z\)V',
        "setWebContentsDebuggingEnabled(true)": r'Landroid/webkit/WebView;->setWebContentsDebuggingEnabled\(Z\)V',
        "setMixedContentMode(ALWAYS_ALLOW)": r'Landroid/webkit/WebSettings;->setMixedContentMode\(I\)V',
        "setGeolocationEnabled(true)": r'Landroid/webkit/WebSettings;->setGeolocationEnabled\(Z\)V',
        "setDomStorageEnabled(true)": r'Landroid/webkit/WebSettings;->setDomStorageEnabled\(Z\)V',
        "setDatabaseEnabled(true)": r'Landroid/webkit/WebSettings;->setDatabaseEnabled\(Z\)V',
        "setSavePassword(true)": r'Landroid/webkit/WebSettings;->setSavePassword\(Z\)V',
        "setSaveFormData(true)": r'Landroid/webkit/WebSettings;->setSaveFormData\(Z\)V',
    }

    for desc, pat in patterns.items():
        for rel in grep_code(base, pat):
            hits.append(f"<code>{rel}</code> {desc}")

    # XSS Risks: loadUrl/loadData/evaluateJavascript with user input
    xss_files = []
    for root, _, files in os.walk(base):
        for fn in files:
            if not fn.endswith('.smali'):
                continue
            path = os.path.join(root, fn)
            try:
                content = open(path, errors='ignore').read()
                # Check for WebView loading methods
                has_load_method = any(method in content for method in [
                    'WebView;->loadUrl',
                    'WebView;->loadData',
                    'WebView;->loadDataWithBaseURL',
                    'WebView;->evaluateJavascript'
                ])

                if has_load_method:
                    # Check for user input sources in same file
                    user_input_patterns = [
                        'getText()',           # EditText user input
                        'getStringExtra',      # Intent extras
                        'getQueryParameter',   # URI parameters
                        'getExtras',           # Bundle data
                        'getDataString',       # Intent data
                        'getAction',           # Intent action
                        'readLine',            # File/stream input
                        'receive',             # Broadcast/network input
                    ]
                    has_user_input = any(pattern in content for pattern in user_input_patterns)

                    if has_user_input:
                        rel = os.path.relpath(path, base)
                        xss_files.append(rel)
            except:
                continue

    if xss_files:
        hits.append(f"<strong>{len(xss_files)} file(s) load WebView content from user input (XSS risk):</strong>")
        for rel in xss_files[:10]:
            hits.append(f"<code style='margin-left:20px;'>{rel}</code>")
        if len(xss_files) > 10:
            hits.append(f"<span style='margin-left:20px;'>...and {len(xss_files) - 10} more</span>")

    # SSL/TLS Error Bypassing (onReceivedSslError with proceed())
    ssl_bypass_files = []
    override_re = re.compile(r'\.method.*onReceivedSslError')
    proceed_re = re.compile(r'\bproceed\(')

    for root, _, files in os.walk(base):
        for fn in files:
            if not fn.endswith('.smali'):
                continue
            path = os.path.join(root, fn)
            try:
                lines = open(path, errors='ignore').read().splitlines()
                for i, line in enumerate(lines):
                    if override_re.search(line):
                        # Check next 30 lines for proceed() call
                        for j in range(i, min(i + 30, len(lines))):
                            if proceed_re.search(lines[j]):
                                rel = os.path.relpath(path, base)
                                hits.append(f"<code>{rel}:{j+1}</code> onReceivedSslError calls proceed()")
                                break
            except:
                pass

    # Protocol Handler Issues (shouldOverrideUrlLoading)
    protocol_handlers = []
    protocol_re = re.compile(r'\.method.*(shouldOverrideUrlLoading|shouldInterceptRequest)')

    for root, _, files in os.walk(base):
        for fn in files:
            if not fn.endswith('.smali'):
                continue
            path = os.path.join(root, fn)
            try:
                content = open(path, errors='ignore').read()
                if protocol_re.search(content):
                    # Check for unsafe URL handling (intent://, file://, javascript:, etc.)
                    unsafe_schemes = ['intent://', 'file://', 'javascript:', 'data:', 'content://']
                    has_unsafe_scheme = any(scheme in content.lower() for scheme in unsafe_schemes)

                    # Check for URL validation
                    has_validation = bool(re.search(r'(startsWith|contains|matches|whitelist|allow)', content, re.IGNORECASE))

                    if has_unsafe_scheme and not has_validation:
                        rel = os.path.relpath(path, base)
                        hits.append(f"<code>{rel}</code> Custom protocol handler without URL validation")
            except:
                pass

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0031/' target='_blank'>MASTG-TEST-0031: Testing JavaScript Execution in WebViews</a></div>"

    if not hits:
        return True, f"None{mastg_ref}"

    details = "<br>\n".join(hits)
    details += mastg_ref

    return False, details


def check_keyboard_cache(base, manifest):
    """
    Detects keyboard cache vulnerabilities where sensitive input gets stored by the keyboard.

    VULNERABILITY: EditText fields without proper inputType flags allow keyboard to cache
    sensitive data (passwords, credit cards, SSNs, etc.) in autocomplete dictionaries.

    Keyboard cache locations:
    - System: /data/data/com.android.providers.userdictionary/databases/user_dict.db
    - Google Keyboard: /data/data/com.google.android.inputmethod.latin/databases/
    - Samsung Keyboard: /data/data/com.samsung.android.honeyboard/databases/
    - App-specific: May vary by keyboard app

    Checks for:
    1. EditText fields without android:inputType attribute
    2. EditText fields without textNoSuggestions flag
    3. Password fields without textPassword flag
    4. Sensitive field patterns (password, credit card, SSN, PIN, CVV, etc.)

    MASVS: MASVS-STORAGE-2 (Sensitive Data Disclosure)
    MASTG: MASTG-TEST-0001 (Testing Local Storage for Sensitive Data)
    """
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0006/' target='_blank'>MASTG-TEST-0006: Determining Whether the Keyboard Cache Is Disabled for Text Input Fields</a></div>"

    issues = []

    # Get package name for ADB commands
    try:
        tree = ET.parse(manifest)
        root = tree.getroot()
        pkg = root.attrib.get('package', 'com.example.app')
    except:
        pkg = 'com.example.app'

    # Sensitive field patterns (in id, hint, or label)
    sensitive_patterns = [
        ('password', 'Password'),
        ('passwd', 'Password'),
        ('pwd', 'Password'),
        ('pin', 'PIN'),
        ('cvv', 'CVV'),
        ('cvc', 'CVC'),
        ('ssn', 'SSN'),
        ('social', 'Social Security'),
        ('creditcard', 'Credit Card'),
        ('cardnumber', 'Card Number'),
        ('cardholder', 'Cardholder'),
        ('account', 'Account Number'),
        ('routing', 'Routing Number'),
        ('security', 'Security Code'),
        ('secret', 'Secret'),
        ('otp', 'OTP'),
        ('token', 'Token'),
    ]

    # Library layout paths to exclude
    lib_layout_patterns = [
        'androidx/', 'android/support/', 'com/google/', 'com/facebook/',
        'material/', 'appcompat/', 'design/', 'res-auto/'
    ]

    def is_library_layout(path):
        """Check if layout is from a library"""
        normalized = path.replace('\\', '/')
        return any(lib in normalized for lib in lib_layout_patterns)

    # Walk through all layout XML files
    for root_dir, _, files in os.walk(os.path.join(base, 'res')):
        for fn in files:
            if not fn.endswith('.xml'):
                continue
            if 'layout' not in root_dir:  # Only check layout files
                continue

            xml_path = os.path.join(root_dir, fn)
            rel_path = os.path.relpath(xml_path, base)

            # Skip library layouts
            if is_library_layout(rel_path):
                continue

            try:
                xml_tree = ET.parse(xml_path)
                xml_root = xml_tree.getroot()

                # Find all EditText elements
                for edit_text in xml_root.iter():
                    if 'EditText' not in edit_text.tag:
                        continue

                    # Get field attributes
                    attribs = edit_text.attrib
                    field_id = attribs.get('{http://schemas.android.com/apk/res/android}id', 'unknown')
                    field_hint = attribs.get('{http://schemas.android.com/apk/res/android}hint', '')
                    input_type = attribs.get('{http://schemas.android.com/apk/res/android}inputType', '')

                    # Clean up field ID
                    if '/' in field_id:
                        field_id = field_id.split('/')[-1]

                    # Check if field is sensitive
                    is_sensitive = False
                    sensitive_type = ''
                    field_text = f"{field_id} {field_hint}".lower()

                    for pattern, desc in sensitive_patterns:
                        if pattern in field_text:
                            is_sensitive = True
                            sensitive_type = desc
                            break

                    # Check for vulnerabilities
                    vulnerability_found = False
                    vulnerability_desc = []

                    # Check ALL fields for keyboard caching vulnerability
                    if is_sensitive:
                        # Sensitive field - strict checking
                        if not input_type:
                            vulnerability_found = True
                            vulnerability_desc.append("FAIL: NO android:inputType attribute (keyboard cache ENABLED)")
                            severity = "CRITICAL"
                        elif 'textNoSuggestions' not in input_type:
                            vulnerability_found = True
                            vulnerability_desc.append("WARNING: Missing 'textNoSuggestions' flag (autocomplete/cache enabled)")
                            severity = "HIGH"

                        # Password field without textPassword
                        if 'password' in sensitive_type.lower():
                            if 'textPassword' not in input_type and 'numberPassword' not in input_type:
                                vulnerability_found = True
                                vulnerability_desc.append("FAIL: Password field without 'textPassword' flag (VISIBLE password)")
                                severity = "CRITICAL"
                    else:
                        # Non-sensitive field - flag if missing inputType OR missing textNoSuggestions
                        if not input_type:
                            vulnerability_found = True
                            vulnerability_desc.append("FAIL: NO android:inputType attribute (keyboard cache ENABLED)")
                            severity = "MEDIUM"
                        elif 'textNoSuggestions' not in input_type:
                            vulnerability_found = True
                            vulnerability_desc.append("WARNING: Missing 'textNoSuggestions' flag (keyboard cache/autocomplete enabled)")
                            severity = "MEDIUM"

                    if vulnerability_found:
                        # Build sensitive field indicator outside f-string to avoid backslash issues
                        sensitive_indicator = f'<span style="color:#dc3545">(SENSITIVE: {sensitive_type})</span>' if is_sensitive else ''

                        issue = (
                            f"<div style='border-left: 4px solid #dc3545; padding-left: 10px; margin: 10px 0;'>"
                            f"<strong>File:</strong> <code>{rel_path}</code><br>"
                            f"<strong>Field:</strong> <code>{field_id}</code> {sensitive_indicator}<br>"
                            f"<strong>Severity:</strong> <span style='color:#dc3545'>{severity}</span><br>"
                            f"<strong>Issues:</strong><br>"
                        )

                        for desc in vulnerability_desc:
                            issue += f"&nbsp;&nbsp;• {desc}<br>"

                        if input_type:
                            issue += f"<strong>Current inputType:</strong> <code>{input_type}</code><br>"
                        else:
                            issue += f"<strong>Current inputType:</strong> <span style='color:#dc3545'>MISSING</span><br>"

                        # Generate fix recommendation
                        if is_sensitive and 'password' in sensitive_type.lower():
                            recommended_type = "textPassword|textNoSuggestions"
                        elif is_sensitive:
                            recommended_type = "text|textNoSuggestions"
                        else:
                            recommended_type = "text|textNoSuggestions"

                        issue += (
                            f"<strong>Fix:</strong> Add <code>android:inputType=\"{recommended_type}\"</code><br>"
                            f"</div>"
                        )

                        issues.append((severity, issue))

            except Exception as e:
                continue

    if not issues:
        return True, "No keyboard cache vulnerabilities detected" + mastg_ref, 0

    # Sort by severity (CRITICAL > HIGH > MEDIUM)
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}
    issues.sort(key=lambda x: severity_order.get(x[0], 999))

    # Compact report: just the vulnerable fields
    lines = []
    lines.append(
        f"<div><strong>Keyboard cache issues:</strong> {len(issues)} vulnerable EditText field(s)</div>"
    )

    for severity, issue_html in issues:
        lines.append(issue_html)

    return False, "<br>\n".join(lines) + mastg_ref, len(issues)


def check_os_command_injection(base):
    """
    Detects OS Command Injection vulnerabilities.

    VULNERABILITY: User input passed to Runtime.exec(), ProcessBuilder, or shell commands
    can allow attackers to execute arbitrary OS commands.

    Checks for:
    1. Runtime.getRuntime().exec() with user input (EditText, Intent extras, etc.)
    2. ProcessBuilder with user input
    3. String concatenation building shell commands
    4. Common command patterns: ping, sh, bash, cmd, su

    MASVS: MASVS-CODE-4 (Injection Flaws)
    MASTG: MASTG-TEST-0025
    """
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0025/' target='_blank'>MASTG-TEST-0025: Testing for Injection Flaws</a></div>"

    # Use dict to deduplicate by activity class (group inner classes with parent)
    vulnerable_activities = {}

    # Library paths to exclude
    lib_paths = (
        '/androidx/', '/android/support/',
        '/com/google/android/gms/', '/com/google/firebase/',
        '/kotlin/', '/kotlinx/', '/okhttp3/', '/retrofit2/'
    )

    def is_library_path(path):
        normalized = '/' + path.replace('\\', '/')
        return any(lib in normalized for lib in lib_paths)

    def get_activity_base_name(filename):
        """
        Extract base activity name, removing inner class suffixes.
        Example: SomeActivity$onCreate$1.smali -> SomeActivity.smali
        """
        # Remove inner class suffix (everything after $)
        if '$' in filename:
            return filename.split('$')[0] + '.smali'
        return filename

    # Search for Runtime.exec() and ProcessBuilder usage
    exec_patterns = [
        r'Ljava/lang/Runtime;->exec\(',
        r'Ljava/lang/ProcessBuilder;-><init>\(',
    ]

    for root, _, files in os.walk(base):
        for fn in files:
            if not fn.endswith('.smali'):
                continue
            path = os.path.join(root, fn)
            rel = os.path.relpath(path, base)

            # Skip library code
            if is_library_path(rel):
                continue

            try:
                lines = open(path, errors='ignore').read()

                # Check for Runtime.exec() or ProcessBuilder
                has_exec = any(re.search(pat, lines) for pat in exec_patterns)
                if not has_exec:
                    continue

                # Check for user input sources
                user_input_patterns = [
                    'EditText;->getText',  # User input from EditText
                    'TextView;->getText',  # User input from TextView
                    'Intent;->getStringExtra',  # Intent extras
                    'Uri;->getQueryParameter',  # URI parameters
                    'Bundle;->getString',  # Bundle data
                ]

                has_user_input = any(pattern in lines for pattern in user_input_patterns)

                # Check for command string patterns (ping, sh, bash, etc.)
                command_patterns = [
                    r'const-string.*"ping\s',
                    r'const-string.*"sh\s',
                    r'const-string.*"bash\s',
                    r'const-string.*"cmd\s',
                    r'const-string.*"su\s',
                    r'const-string.*"/system/bin/',
                ]

                has_command = any(re.search(pat, lines, re.IGNORECASE) for pat in command_patterns)

                # Check for string concatenation (StringBuilder/StringBuffer)
                has_string_concat = 'StringBuilder;-><init>' in lines or 'StringBuffer;-><init>' in lines

                # Determine risk level
                if has_exec and (has_user_input or (has_command and has_string_concat)):
                    severity = "CRITICAL" if has_user_input else "HIGH"

                    indicators = []
                    if has_user_input:
                        indicators.append("User input detected (EditText/Intent/URI)")
                    if has_command:
                        indicators.append("Shell command pattern detected (ping/sh/bash/cmd)")
                    if has_string_concat:
                        indicators.append("String concatenation detected (potential command injection)")

                    # Get base activity name for deduplication
                    base_name = get_activity_base_name(fn)
                    activity_key = os.path.join(os.path.dirname(rel), base_name)

                    # Only keep highest severity for each activity
                    if activity_key not in vulnerable_activities or severity == "CRITICAL":
                        vulnerable_activities[activity_key] = {
                            'severity': severity,
                            'file': rel,
                            'indicators': indicators
                        }

            except:
                continue

    if not vulnerable_activities:
        return True, "No OS command injection risks detected" + mastg_ref, 0

    # Build output from deduplicated results
    hits = []
    for activity_key, data in vulnerable_activities.items():
        hit = (
            f"<strong>{data['severity']}:</strong> <code>{data['file']}</code><br>"
            f"<strong>Issue:</strong> Runtime.exec() or ProcessBuilder with potential command injection<br>"
            f"<strong>Indicators:</strong> {', '.join(data['indicators'])}<br>"
            f"<strong>Risk:</strong> Attacker can execute arbitrary OS commands<br>"
            f"<strong>Fix:</strong> Avoid Runtime.exec() with user input. Use allowlist validation or safer alternatives.<br>"
            f"<strong>MASVS:</strong> MASVS-CODE-4<br>"
        )
        hits.append(hit)

    return False, "<br><br>\n".join(hits) + mastg_ref, len(vulnerable_activities)


def check_weak_crypto(base):
    """
    FAIL if any use of weak crypto is detected:
      • Any literal "MD5" | "SHA-1" | "SHA1" | "HmacMD5" | "HmacSHA1"
      • Any Cipher.getInstance(...DES...) or (...ECB...)
    Emits clickable file:// links with line numbers and the matching snippet.
    Filters out library code to show only app code issues.
    """
    # Library paths to exclude (same pattern as other checks)
    lib_paths = (
        '/androidx/', '/android/support/',
        '/com/google/android/gms/', '/com/google/firebase/', '/com/google/android/play/',
        '/com/google/common/', '/com/google/crypto/', '/okhttp3/', '/okio/', '/retrofit2/', '/com/squareup/',
        '/com/facebook/', '/kotlin/', '/kotlinx/',
        '/io/reactivex/', '/rx/', '/dagger/',
        '/com/airbnb/', '/org/bson/', '/io/jsonwebtoken/',
        '/lib/', '/jetified-'
    )

    def is_library_path(path):
        """Check if path is library code"""
        normalized = '/' + path.replace('\\', '/')
        return any(lib in normalized for lib in lib_paths)

    # single big regex that covers:
    #  - any of those algorithm names in quotes (smali or Java)
    #  - Cipher.getInstance DES/ECB
    combined = re.compile(
        r'("MD5"|"SHA-1"|"SHA1"|"HmacMD5"|"HmacSHA1")'
        r'|Cipher->getInstance\(\s*"[^"]*(DES|ECB)[^"]*"\s*\)'
    )

    issues = []
    for root, _, files in os.walk(base):
        for fn in files:
            if not fn.endswith(('.smali', '.java')):
                continue
            path = os.path.join(root, fn)
            rel = os.path.relpath(path, base)

            # Skip library code
            if is_library_path(rel):
                continue

            try:
                lines = open(path, errors='ignore').read().splitlines()
            except:
                continue

            for lineno, line in enumerate(lines, 1):
                m = combined.search(line)
                if not m:
                    continue
                snippet = html.escape(line.strip())
                link = (
                    f'<a href="file://{html.escape(path)}">'
                    f'{html.escape(rel)}:{lineno}</a>'
                )
                issues.append(f"{link} – <code>{snippet}</code>")
                break  # one hit per file

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0221/' target='_blank'>MASTG-TEST-0221: Broken Symmetric Encryption Algorithms</a></div>"

    if not issues:
        return True, f"None{mastg_ref}"

    return False, "<br>\n".join(issues) + mastg_ref

    
def check_kotlin_metadata(base):
    """
    Scan for classes annotated with kotlin.Metadata.
    Returns (ok, details_html, total_hits).
    Only the first 100 hits are shown; total_hits is the real count.
    Filters out library code to show only app code issues.
    """
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0040/' target='_blank'>MASTG-TEST-0040: Testing for Debugging Symbols</a></div>"

    # Library paths to exclude (same pattern as other checks)
    lib_paths = (
        '/androidx/', '/android/support/',
        '/com/google/android/gms/', '/com/google/firebase/', '/com/google/android/play/',
        '/okhttp3/', '/retrofit2/', '/com/squareup/',
        '/com/facebook/', '/kotlin/', '/kotlinx/',
        '/io/reactivex/', '/rx/', '/dagger/',
        '/lib/', '/jetified-'
    )

    def is_library_path(path):
        """Check if path is library code"""
        normalized = '/' + path.replace('\\', '/')
        return any(lib in normalized for lib in lib_paths)

    pattern = r"Lkotlin/Metadata;"
    hits = []
    for root, _, files in os.walk(base):
        for f in files:
            if not f.endswith(('.smali', '.java')):
                continue
            full = os.path.join(root, f)
            rel = os.path.relpath(full, base)

            # Skip library code
            if is_library_path(rel):
                continue

            try:
                for line in open(full, errors='ignore'):
                    if re.search(pattern, line):
                        snippet = line.strip()
                        hits.append((rel, snippet))
                        break  # Only first match per file
            except:
                pass

    total = len(hits)
    if total == 0:
        return True, "None" + mastg_ref, 0

    # only show first 100
    display = hits[:100]
    lines = []
    for rel, snippet in display:
        full = os.path.abspath(os.path.join(base, rel))
        lines.append(
            f'<a href="file://{html.escape(full)}">{html.escape(rel)}</a>: '
            f'<code>{html.escape(snippet)}</code>'
        )
    if total > 100:
        lines.append(f"...and {total-100} more")

    return False, "<br>\n".join(lines) + mastg_ref, total


def check_file_permissions(base):
    """
    FAIL if MODE_WORLD_READABLE or MODE_WORLD_WRITABLE is used,
    or if code sets file perms to 0666/0777.
    Links each .smali/.java file found.
    """
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0001/' target='_blank'>MASTG-TEST-0001: Testing Local Storage for Sensitive Data</a></div>"

    patterns = [
        # openFileOutput(..., MODE_WORLD_READABLE)
        r'openFileOutput\([\w, ]*,\s*MODE_WORLD_READABLE\)',
        # openFileOutput(..., MODE_WORLD_WRITEABLE)
        r'openFileOutput\([\w, ]*,\s*MODE_WORLD_WRITEABLE\)',
        # File.setPermissions(..., 0666, ...)
        r'\.setPermissions\([^,]+,\s*0+6+6+,[^)]*\)',
        # File.setPermissions(..., 0777, ...)
        r'\.setPermissions\([^,]+,\s*0+7+7+7+,[^)]*\)',
    ]

    hits = set()
    for pat in patterns:
        for rel in grep_code(base, pat):
            hits.add(rel)
    if not hits:
        return True, "None" + mastg_ref
    lines = []
    for rel in sorted(hits):
        full = os.path.join(base, rel)
        lines.append(f'<a href="file://{full}">{rel}</a>')
    return False, "<br>\n".join(lines) + mastg_ref

def check_package_context(base):
    """
    FAIL if Context.createPackageContext() is used with both
    CONTEXT_INCLUDE_CODE and CONTEXT_IGNORE_SECURITY flags.
    This combination allows loading code from another package without
    security checks, which can lead to code injection vulnerabilities.

    Filters out third-party library code (Google Play Services, etc.)
    as these legitimately use this for dynamic module loading.
    """
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0002/' target='_blank'>MASTG-TEST-0002: Testing Local Storage for Input Validation</a></div>"

    # Library paths to exclude (these use createPackageContext legitimately)
    lib_paths = (
        '/com/google/android/gms/',  # Google Play Services (DynamiteModule, etc.)
        '/com/google/firebase/',
        '/androidx/', '/android/support/',
        '/com/facebook/', '/kotlin/', '/kotlinx/',
        '/okhttp3/', '/retrofit2/',
        '/lib/', '/jetified-'
    )

    def is_library_path(path):
        """Check if path is library code"""
        normalized = '/' + path.replace('\\', '/')
        return any(lib in normalized for lib in lib_paths)

    # SMALI pattern for createPackageContext call
    create_context_pattern = r'Landroid/content/Context;->createPackageContext'
    candidate_files = grep_code(base, create_context_pattern)

    # Filter out library code
    candidate_files = [f for f in candidate_files if not is_library_path(f)]

    if not candidate_files:
        return ('PASS', "No createPackageContext usage detected" + mastg_ref)

    # Check each file for insecure flag combination (value 3 = CONTEXT_INCLUDE_CODE | CONTEXT_IGNORE_SECURITY)
    hits = []
    for rel in candidate_files:
        path = os.path.join(base, rel)
        try:
            lines = open(path, errors='ignore').read().splitlines()
            for i, line in enumerate(lines):
                if 'createPackageContext' in line:
                    # Check previous 5 lines for const/4 or const/16 with value 3 or 0x3
                    context_start = max(0, i - 5)
                    context = '\n'.join(lines[context_start:i+1])
                    # Look for const/4 vX, 0x3 or const/4 vX, 3
                    if re.search(r'const/4\s+v\d+,\s*(?:0x3|3)\b', context):
                        hits.append((rel, i+1))
                        break
        except:
            pass

    if not hits:
        return ('PASS', f"createPackageContext usage found in {len(candidate_files)} file(s), but no insecure flag combinations detected" + mastg_ref)

    # Build report with line numbers and code snippets
    lines = []
    lines.append("<div><strong>Insecure createPackageContext usage detected:</strong></div>")
    lines.append("<div style='margin:5px 0; color:#dc2626;'>Using CONTEXT_INCLUDE_CODE | CONTEXT_IGNORE_SECURITY allows loading code without security checks</div>")
    for rel, line_num in sorted(hits):
        full = os.path.abspath(os.path.join(base, rel))
        lines.append(f'<a href="file://{full}:{line_num}">{html.escape(rel)}:{line_num}</a>')

        # Read and show the code snippet
        try:
            with open(os.path.join(base, rel), errors='ignore') as f:
                file_lines = f.readlines()
                if 0 <= line_num - 1 < len(file_lines):
                    snippet = file_lines[line_num - 1].strip()
                    lines.append(f'<pre><code>{html.escape(snippet)}</code></pre>')
        except:
            pass

    return ('FAIL', "<br>\n".join(lines) + mastg_ref)

def check_certificate_pinning(base):
    """
    Certificate pinning detection (static only), with:
      • PASS if known-library APIs or SSLSocketFactory overrides are found
      • WARN if only manual/resource patterns or HostnameVerifier stubs are found
      • FAIL if nothing is found
    Emits clickable links, line numbers, and snippets.
    """

    # 1) Known-library APIs
    lib_patterns = [
        # OkHttp pinning
        r'Lokhttp3/CertificatePinner\$Builder;->add\(',
        r'Lokhttp3/CertificatePinner\$Builder;->build\(',
        r'Lokhttp3/CertificatePinner;',
        r'CertificatePinner->pin\(',
        r'\.certificatePinner\(',
        r'->check\(Ljava/lang/String;Ljava/util/List;\)',

        # TrustKit
        r'io\.github\.trustkit',
        r'com\.datatheorem\.android\.trustkit',
        r'TrustKit;->getInstance',

        # Custom PinningTrustManager
        r'PinningTrustManager',

        # Retrofit with pinning
        r'Retrofit\$Builder;->client',

        # Apache HTTP Client pinning
        r'SSLConnectionSocketFactory',

        # Network Security Config
        r'network_security_config',
    ]
    lib_hits = set()
    for pat in lib_patterns:
        lib_hits.update(grep_code(base, pat))

    # Check Network Security Config XML for <pin-set>
    network_config_path = os.path.join(base, 'res', 'xml', 'network_security_config.xml')
    if os.path.exists(network_config_path):
        try:
            with open(network_config_path, errors='ignore') as f:
                config_content = f.read()
                if '<pin-set>' in config_content or 'pin-set' in config_content:
                    lib_hits.add('res/xml/network_security_config.xml')
        except Exception:
            pass

    # 2) Manual/resource patterns
    manual_patterns = [
        # Certificate digest/hash checking
        r'MessageDigest->getInstance\(\s*"SHA-?256"\s*\)',
        r'MessageDigest->getInstance\(\s*"SHA-?1"\s*\)',
        r'(?i)sha256/[A-Za-z0-9+/=]{24,}=*',
        r'(?i)sha-?1/[A-Za-z0-9+/=]{24,}=*',

        # X.509 certificate handling
        r'CertificateFactory->getInstance\(\s*"X\.509"\s*\)',
        r'generateCertificate\(',
        r'X509Certificate',
        r'->getPublicKey\(\)',
        r'->getEncoded\(\)',

        # Certificate loading from resources
        r'openRawResource\(\s*R\.raw\.[a-z0-9_]*(?:cer|crt|pem)\b',
        r'AssetManager;->open',

        # Public key pinning
        r'PublicKey',
        r'KeyFactory',
        r'X509EncodedKeySpec',

        # Certificate comparison
        r'equals\(.*Certificate',
        r'Arrays;->equals',

        # SSL Context with custom trust
        r'SSLContext;->init',
        r'TrustManagerFactory',
        r'X509TrustManager',

        # Certificate chain validation
        r'checkServerTrusted',
        r'->getTrustedIssuers',
    ]
    manual_hits = set()
    for pat in manual_patterns:
        manual_hits.update(grep_code(base, pat))

    # 3) SSLSocketFactory overrides
    sslfactory_patterns = [
        r'->setSSLSocketFactory\(',
        r'\.sslSocketFactory\(',
        r'new-instance\s+[vp]\d+,\s+L[^;]+SSLSocketFactory;',
    ]
    sslfactory_hits = set()
    for pat in sslfactory_patterns:
        sslfactory_hits.update(grep_code(base, pat))

    # 4) HostnameVerifier stubs
    hv_re = re.compile(
        r'\.method[^\n]*verify\([^\)]*\)[\s\S]*?const/4\s+\S+,\s+0x1[\s\S]*?return',
        re.MULTILINE
    )
    hv_hits = set()
    for rel in grep_code(base, r'->verify\('):
        path = os.path.join(base, rel)
        try:
            for i, ln in enumerate(open(path, errors='ignore'), 1):
                if hv_re.search(ln):
                    hv_hits.add(rel)
                    break
        except:
            continue

    sections = []

    # Helper to render clickable entries with optional snippet
    def render_hits(hit_set, extract_snippet=False, patterns=None):
        out = []
        for rel in sorted(hit_set):
            path = os.path.join(base, rel)
            href = f'file://{html.escape(path)}'
            # snippet logic
            snippet = None
            if extract_snippet and patterns:
                lines = open(path, errors='ignore').read().splitlines()
                for pat in patterns:
                    rx = re.compile(pat, re.IGNORECASE)
                    for idx, ln in enumerate(lines, 1):
                        if rx.search(ln):
                            snippet = html.escape(ln.strip())
                            link = f'<a href="{href}">{html.escape(rel)}:{idx}</a>'
                            out.append(f"{link} – <code>{snippet}</code>")
                            break
                    if snippet:
                        break
                if not snippet:
                    out.append(f'<a href="{href}">{html.escape(rel)}</a>')
            else:
                out.append(f'<a href="{href}">{html.escape(rel)}</a>')
        return out

    # Render each section
    if lib_hits:
        entries = render_hits(lib_hits)
        sections.append(
            "<strong>Library pinning APIs:</strong><br>" + "<br>".join(entries)
        )
    if sslfactory_hits:
        entries = render_hits(sslfactory_hits)
        sections.append(
            "<strong>SSLSocketFactory overrides:</strong><br>" + "<br>".join(entries)
        )

    if manual_hits:
        entries = render_hits(manual_hits, extract_snippet=True, patterns=manual_patterns)
        sections.append(
            "<strong>Manual pinning/resource patterns:</strong><br>" + "<br>".join(entries)
        )

    if hv_hits:
        entries = render_hits(hv_hits)
        sections.append(
            "<strong>Unsafe HostnameVerifier stubs:</strong><br>" + "<br>".join(entries)
        )

    # Add summary at the top
    summary_parts = []
    if lib_hits:
        summary_parts.append(f" <strong>Library pinning APIs found:</strong> {len(lib_hits)} file(s)")
    if sslfactory_hits:
        summary_parts.append(f" <strong>SSLSocketFactory overrides found:</strong> {len(sslfactory_hits)} file(s)")
    if manual_hits:
        summary_parts.append(f"WARNING: <strong>Manual patterns found:</strong> {len(manual_hits)} file(s)")
    if hv_hits:
        summary_parts.append(f"WARNING: <strong>HostnameVerifier stubs found:</strong> {len(hv_hits)} file(s)")

    summary_html = "<div>" + "</div><div>".join(summary_parts) + "</div><br>" if summary_parts else ""

    detail_html = summary_html + "<br>\n".join(sections)
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0022/' target='_blank'>MASTG-TEST-0022: Testing Custom Certificate Stores and Certificate Pinning</a></div>"

    # Decide PASS / WARN / FAIL
    if lib_hits or sslfactory_hits:
        # definitive pinning found
        confidence_note = (
            "<br><div><em> Definitive certificate pinning detected. "
            "Dynamic testing recommended to verify pinning is active for all connections.</em></div>"
        )
        return True, detail_html + confidence_note + mastg_ref
    if manual_hits or hv_hits:
        # only heuristics found -> warn
        warn_banner = (
            "<em class='warn'>"
            "No definitive pinning API found; heuristic patterns detected — "
            "please review above.</em><br><br>"
        )
        return True, warn_banner + detail_html + mastg_ref
    # nothing found -> fail
    return False, f"<strong>No certificate pinning detected.</strong>{mastg_ref}"

def check_sharedprefs_encryption(base):
    """
    Check if SharedPreferences usage implements encryption (EncryptedSharedPreferences).
    FAIL if plain SharedPreferences found without encryption.
    Shows actual API calls with context for better understanding.
    """
    # Exclude library/framework files - comprehensive list
    exclude_patterns = [
        r'androidx/',
        r'android/support/',
        r'com/google/android/gms/',
        r'com/google/firebase/',
        r'com/google/crypto/tink/',
        r'com/google/android/play/',
        r'androidx/work/',
        r'mono/android/',
        r'com/google/android/exoplayer',
        r'/core/content/',
        r'/internal/',
        r'kotlin/',
        r'kotlinx/',
        r'okhttp3/',
        r'retrofit2/',
        r'com/squareup/',
        r'com/facebook/',
        # Popular third-party libraries
        r'com/skydoves/balloon/',      # Balloon tooltip library
        r'com/yariksoffice/lingver/',   # Lingver localization library
        r'com/github/mikephil/charting/',  # MPAndroidChart
        r'com/permissionx/guolindev/',     # PermissionX
        r'com/bumptech/glide/',            # Glide
        r'com/airbnb/lottie/',             # Lottie
        r'io/reactivex/',                  # RxJava
        r'com/jakewharton/',               # JakeWharton libraries
        r'/lib/',
        r'/jetified-',
    ]

    def is_library_file(path):
        """Check if path is library code"""
        return any(re.search(pattern, path) for pattern in exclude_patterns)

    # Find actual SharedPreferences calls with context
    findings = {
        'encrypted': [],
        'unencrypted': []
    }

    # Patterns to search for
    encrypted_pattern = r'(EncryptedSharedPreferences|androidx/security/crypto/EncryptedSharedPreferences)'
    unencrypted_patterns = [
        r'invoke-\w+.*getSharedPreferences\(',
        r'invoke-\w+.*getDefaultSharedPreferences\(',
    ]

    scanned_files = 0

    for root, _, files in os.walk(base):
        for f in files:
            if not f.endswith('.smali'):
                continue

            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, base)

            # Skip library files
            if is_library_file(rel_path):
                continue

            scanned_files += 1

            try:
                with open(full_path, errors='ignore') as file:
                    lines = file.readlines()

                # Check for encrypted usage
                for line_num, line in enumerate(lines, 1):
                    if re.search(encrypted_pattern, line):
                        findings['encrypted'].append({
                            'file': rel_path,
                            'line': line_num,
                            'snippet': line.strip()
                        })

                # Check for unencrypted usage
                for line_num, line in enumerate(lines, 1):
                    for pattern in unencrypted_patterns:
                        if re.search(pattern, line):
                            # Get preference name from context
                            pref_name = extract_preference_name(lines, line_num)

                            findings['unencrypted'].append({
                                'file': rel_path,
                                'line': line_num,
                                'snippet': line.strip(),
                                'pref_name': pref_name
                            })
                            break

            except Exception:
                continue

    # Build report
    encrypted_count = len(findings['encrypted'])
    unencrypted_count = len(findings['unencrypted'])

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0287/' target='_blank'>MASTG-TEST-0287: Sensitive Data Stored Unencrypted via the SharedPreferences API</a></div>"

    if unencrypted_count == 0 and encrypted_count == 0:
        return 'PASS', f"<div>No SharedPreferences usage detected in app code</div><div>Scanned {scanned_files} app code files</div>{mastg_ref}"

    if unencrypted_count == 0:
        return 'PASS', f"<div>All SharedPreferences usage in app code is encrypted</div><div>Found {encrypted_count} encrypted usage(s)</div>{mastg_ref}"

    # Build detailed report with collapsible sections
    lines = []
    lines.append(f"<div><strong>Scanned:</strong> {scanned_files} app code files (libraries excluded)</div>")

    if encrypted_count > 0:
        lines.append(f"<div><strong>Encrypted usage found:</strong> {encrypted_count} instance(s)</div>")

    lines.append(f"<div><strong>WARNING: Unencrypted usage found in app code:</strong> {unencrypted_count} instance(s)</div><br>")

    # Group by file for better organization
    files_with_unencrypted = {}
    for finding in findings['unencrypted']:
        file_path = finding['file']
        if file_path not in files_with_unencrypted:
            files_with_unencrypted[file_path] = []
        files_with_unencrypted[file_path].append(finding)

    # Collapsible section for unencrypted findings
    lines.append('<details open>')
    lines.append('<summary class="warning">')
    lines.append(f'WARNING: Unencrypted SharedPreferences in App Code ({len(files_with_unencrypted)} files) - Click to expand/collapse')
    lines.append('</summary>')
    lines.append('<div>')

    for file_path in sorted(files_with_unencrypted.keys()):
        full = os.path.abspath(os.path.join(base, file_path))
        file_findings = files_with_unencrypted[file_path]

        lines.append(
            f'<div class="finding-card">'
            f'<a href="file://{html.escape(full)}">{html.escape(file_path)}</a><br>'
            f'<strong>Unencrypted calls:</strong> {len(file_findings)}<br>'
        )

        for finding in file_findings[:3]:  # Show first 3 per file
            lines.append(f'<div class="finding-detail">')
            lines.append(f'<strong>Line {finding["line"]}:</strong>')
            if finding['pref_name']:
                lines.append(f'<br>Preference name: <code>{html.escape(finding["pref_name"])}</code>')
            lines.append(f'<br><code>{html.escape(finding["snippet"])}</code>')
            lines.append('</div>')

        if len(file_findings) > 3:
            lines.append(f'<div class="finding-detail"><em>...and {len(file_findings) - 3} more in this file</em></div>')

        lines.append('</div>')

    lines.append('</div></details>')

    lines.append(
        '<div class="info-box"><em> Recommendation: Use EncryptedSharedPreferences from '
        'androidx.security:security-crypto to encrypt sensitive preferences. '
        'See: <a href="https://developer.android.com/reference/androidx/security/crypto/EncryptedSharedPreferences" '
        'target="_blank">Android Security Crypto</a></em></div>'
    )

    lines.append(mastg_ref)

    return 'FAIL', '\n'.join(lines)


def extract_preference_name(lines, call_line_num):
    """
    Try to extract the SharedPreferences name from the context.
    Looks backwards for const-string that might be the preference name.
    """
    # Look at previous 10 lines
    start = max(0, call_line_num - 10)
    context = lines[start:call_line_num]

    # Look for const-string with a name
    for line in reversed(context):
        match = re.search(r'const-string\s+[vp]\d+,\s*"([^"]+)"', line)
        if match:
            name = match.group(1)
            # Filter out obviously wrong matches
            if len(name) < 50 and not name.startswith('android.') and not name.startswith('java.'):
                return name

    return None

def check_external_storage(base):
    """
    Check for usage of external storage APIs that may expose sensitive data.
    Separates risky patterns from legitimate use cases.
    """
    # High-risk patterns (direct public storage access)
    risky_patterns = {
        'getExternalStorageDirectory': 'Direct external storage access (deprecated)',
        'getExternalStoragePublicDirectory': 'Public external directory',
    }

    # Lower-risk patterns (scoped/app-specific storage)
    safe_patterns = {
        'getExternalFilesDir': 'App-specific external files (scoped)',
        'getExternalCacheDir': 'App-specific external cache (scoped)',
    }

    # Permission checks
    permission_patterns = {
        'WRITE_EXTERNAL_STORAGE': 'Write permission',
        'READ_EXTERNAL_STORAGE': 'Read permission',
    }

    # Library exclusions - comprehensive list
    exclude_patterns = [
        r'androidx/',
        r'android/support/',
        r'com/google/android/gms/',
        r'com/google/firebase/',
        r'com/google/android/exoplayer',
        r'com/google/android/play/',
        r'com/google/common/',
        r'io/sentry/',
        r'/core/content/',
        r'kotlin/',
        r'kotlinx/',
        r'okhttp3/',
        r'retrofit2/',
        r'com/squareup/',
        r'com/facebook/',
        # Popular third-party libraries
        r'com/github/mikephil/charting/',  # MPAndroidChart
        r'com/permissionx/guolindev/',      # PermissionX
        r'com/bumptech/glide/',             # Glide image loading
        r'com/airbnb/lottie/',              # Lottie animations
        r'io/reactivex/',                   # RxJava
        r'com/jakewharton/',                # JakeWharton libraries
        r'/lib/',
        r'/jetified-',
    ]

    def is_library_file(path):
        """Check if path is library code"""
        return any(re.search(pattern, path) for pattern in exclude_patterns)

    def find_matching_lines(base, pattern):
        """Find files and their matching lines for a pattern"""
        results = {}
        for root, _, files in os.walk(base):
            for f in files:
                if f.endswith(('.smali', '.xml', '.java')):
                    try:
                        full_path = os.path.join(root, f)
                        rel_path = os.path.relpath(full_path, base)
                        if is_library_file(rel_path):
                            continue

                        with open(full_path, errors='ignore') as file:
                            lines = file.readlines()
                            for line_num, line in enumerate(lines, 1):
                                if re.search(pattern, line):
                                    if rel_path not in results:
                                        results[rel_path] = []
                                    results[rel_path].append((line_num, line.strip()))
                                    break  # Only first match per file
                    except:
                        pass
        return results

    risky_findings = {}
    safe_findings = {}
    permission_findings = {}

    for pattern, desc in risky_patterns.items():
        results = find_matching_lines(base, pattern)
        if results:
            risky_findings[desc] = results

    for pattern, desc in safe_patterns.items():
        results = find_matching_lines(base, pattern)
        if results:
            safe_findings[desc] = results

    for pattern, desc in permission_patterns.items():
        results = find_matching_lines(base, pattern)
        if results:
            permission_findings[desc] = results

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0200/' target='_blank'>MASTG-TEST-0200: Files Written to External Storage</a></div>"

    if not (risky_findings or safe_findings or permission_findings):
        return 'PASS', f"<div>No external storage usage detected in app code</div>{mastg_ref}"

    lines = []
    has_risk = bool(risky_findings)

    # Show risky usage
    if risky_findings:
        lines.append(f"<div><strong>WARNING: High-risk external storage usage in app code:</strong></div>")
        for desc, hits in risky_findings.items():
            lines.append(f"<div><strong>{desc}:</strong> {len(hits)} file(s)</div>")
            for rel in sorted(hits)[:10]:
                full = os.path.abspath(os.path.join(base, rel))
                lines.append(f'<a href="file://{html.escape(full)}">{html.escape(rel)}</a>')
                # Show code snippet
                for line_num, code_line in hits[rel]:
                    lines.append(f'<pre><code>{html.escape(code_line)}</code></pre>')
            if len(hits) > 10:
                lines.append(f"<div>...and {len(hits) - 10} more</div>")

    # Show safe usage
    if safe_findings:
        lines.append(f"<br><div><em>ℹ Scoped storage in app code (lower risk):</em></div>")
        for desc, hits in safe_findings.items():
            lines.append(f"<div>{desc}: {len(hits)} file(s)</div>")
            for rel in sorted(hits)[:5]:
                full = os.path.abspath(os.path.join(base, rel))
                lines.append(f'<a href="file://{html.escape(full)}">{html.escape(rel)}</a>')
                # Show code snippet
                for line_num, code_line in hits[rel]:
                    lines.append(f'<pre><code>{html.escape(code_line)}</code></pre>')
            if len(hits) > 5:
                lines.append(f"<div>...and {len(hits) - 5} more</div>")

    # Show permissions
    if permission_findings:
        lines.append(f"<br><div><em>Storage permissions in app code:</em></div>")
        for desc, hits in permission_findings.items():
            for rel in sorted(hits)[:5]:
                full = os.path.abspath(os.path.join(base, rel))
                lines.append(f"<div>{desc} in <a href=\"file://{html.escape(full)}\">{html.escape(rel)}</a></div>")
                # Show code snippet
                for line_num, code_line in hits[rel]:
                    lines.append(f'<pre><code>{html.escape(code_line)}</code></pre>')
            if len(hits) > 5:
                lines.append(f"<div>...and {len(hits) - 5} more</div>")

    lines.append(mastg_ref)

    # Only FAIL if risky patterns found in app code
    if has_risk:
        return 'FAIL', "<br>\n".join(lines)
    elif safe_findings or permission_findings:
        return 'WARN', "<br>\n".join(lines)
    else:
        return 'PASS', "<br>\n".join(lines)

def check_hardcoded_keys(base):
    """
    Detect hardcoded cryptographic keys, secrets, and API keys in code.
    Uses entropy analysis, pattern matching, and sensitive keyword detection.
    Filters out common false positives from constants, test data, and libraries.
    """
    # Library/framework exclusions
    exclude_patterns = [
        r'androidx/',
        r'android/support/',
        r'com/google/android/gms/',
        r'com/google/firebase/',
        r'com/google/crypto/tink/',
        r'com/google/common/',
        r'androidx/work/',
        r'/test/',
        r'/debug/',
        r'/BuildConfig',
        r'/R\.',
        r'res/color/',
        r'res/drawable/',
        r'res/layout/',
        r'res/menu/',
        r'res/anim/',
        r'res/animator/',
    ]

    def is_library_file(path):
        return any(re.search(pattern, path) for pattern in exclude_patterns)

    # Enhanced patterns with more comprehensive detection
    # Format: (pattern, capture_group_for_value, capture_group_for_key_name)
    string_patterns = [
        # Smali .field static final declarations (Kotlin/Java constants)
        # Example: .field public static final HARDCODED_API_KEY:Ljava/lang/String; = "sk_live_..."
        (r'\.field[^=]*(HARDCODED[^:]*|API[_-]?KEY|SECRET[^:]*|ENCRYPTION[_-]?KEY|AES[_-]?KEY|CRYPTO[_-]?KEY|MASTER[_-]?KEY|PRIVATE[_-]?KEY|AUTH[_-]?TOKEN|ACCESS[_-]?TOKEN)[^=]*=\s*"([^"]{8,})"', 2, 1),

        # Smali const-string declarations (most common in decompiled code)
        (r'const-string\s+[vp]\d+,\s*"([^"]{16,})"', 1, None),

        # Key-value patterns with sensitive keywords (captures both key and value)
        # Enhanced to catch more variations: key, Key, KEY, api_key, apiKey, API_KEY, etc.
        (r'(?i)(api[_-]?key|apikey|api_secret|secret[_-]?key|private[_-]?key|access[_-]?token|client[_-]?secret|auth[_-]?token|bearer[_-]?token|encryption[_-]?key|master[_-]?key|crypto[_-]?key|hardcoded[_-]?key|hardcoded[_-]?secret)["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', 2, 1),

        # XML string resources (for strings.xml files) - Enhanced to catch keys with specific names
        (r'<string[^>]*name=["\']([^"\']*(?:key|secret|token|password|auth|credential|api)[^"\']*)["\'][^>]*>([^<]{8,})</string>', 2, 1),
        (r'<string[^>]*name=["\']([^"\']*)["\'][^>]*>([^<]{8,})</string>', 2, 1),  # Generic XML string

        # Known secret patterns (high confidence) - for both code and XML
        (r'(AKIA[0-9A-Z]{16})', 1, None),  # AWS Access Key
        (r'(AIza[0-9A-Za-z\-_]{35})', 1, None),  # Google API Key
        (r'(ya29\.[0-9A-Za-z\-_\.]+)', 1, None),  # Google OAuth Access Token (more flexible)
        (r'([0-9]+-[0-9A-Za-z_]+\.apps\.googleusercontent\.com)', 1, None),  # Google OAuth Client ID

        # Stripe keys - RELAXED length requirements to catch test/example keys
        (r'(sk_live_[0-9a-zA-Z]{10,})', 1, None),  # Stripe Secret Key (reduced from 24+)
        (r'(sk_test_[0-9a-zA-Z]{10,})', 1, None),  # Stripe Test Secret Key
        (r'(pk_live_[0-9a-zA-Z]{10,})', 1, None),  # Stripe Publishable Key
        (r'(rk_live_[0-9a-zA-Z]{10,})', 1, None),  # Stripe Restricted Key
        (r'(sq0atp-[0-9A-Za-z\-_]{22})', 1, None),  # Square Access Token
        (r'(sq0csp-[0-9A-Za-z\-_]{43})', 1, None),  # Square OAuth Secret
        (r'(ghp_[0-9a-zA-Z]{36})', 1, None),  # GitHub Personal Access Token
        (r'(gho_[0-9a-zA-Z]{36})', 1, None),  # GitHub OAuth Access Token
        (r'(github_pat_[0-9a-zA-Z_]{82})', 1, None),  # GitHub Fine-grained PAT
        (r'(glpat-[0-9a-zA-Z\-_]{20})', 1, None),  # GitLab Personal Access Token
        (r'(xox[pboa]-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-z0-9]{32})', 1, None),  # Slack Token
        (r'(sk-[a-zA-Z0-9]{48})', 1, None),  # OpenAI API Key
        (r'(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})', 1, None),  # SendGrid API Key

        # JWT tokens
        (r'(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})', 1, None),

        # Private keys (PEM format)
        (r'(-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----)', 1, None),
        (r'(-----BEGIN\s+ENCRYPTED\s+PRIVATE\s+KEY-----)', 1, None),
        (r'(-----BEGIN\s+EC\s+PRIVATE\s+KEY-----)', 1, None),

        # Quoted versions for code files (more patterns)
        (r'"(AKIA[0-9A-Z]{16})"', 1, None),
        (r'"(AIza[0-9A-Za-z\-_]{35})"', 1, None),
        (r'"(ya29\.[0-9A-Za-z\-_\.]+)"', 1, None),  # More flexible ya29 pattern
        (r'"([0-9]+-[0-9A-Za-z_]+\.apps\.googleusercontent\.com)"', 1, None),
        (r'"(sk-[a-zA-Z0-9]{48})"', 1, None),  # OpenAI API Key quoted
        (r'"(sk_live_[0-9a-zA-Z]{10,})"', 1, None),  # Stripe key quoted (relaxed)
        (r'"(sk_test_[0-9a-zA-Z]{10,})"', 1, None),  # Stripe test key quoted

        # OBVIOUS hardcoded secret patterns (catch training/example apps)
        (r'"(super_secret[_a-zA-Z0-9]+)"', 1, None),  # super_secret_*
        (r'"(my_secret[_a-zA-Z0-9]+)"', 1, None),     # my_secret_*
        (r'"(test_secret[_a-zA-Z0-9]+)"', 1, None),   # test_secret_*
        (r'"(hardcoded_[a-zA-Z0-9_]{8,})"', 1, None), # hardcoded_*

        # Base64-like strings (must be quoted to avoid class names)
        (r'"([A-Za-z0-9+/=]{40,})"', 1, None),

        # Hex strings (must be quoted) - common for encryption keys
        (r'"([0-9a-fA-F]{32,})"', 1, None),

        # Generic string assignments with = operator
        (r'=\s*"([A-Za-z0-9+/=_-]{32,})"', 1, None),

        # Firebase/Google service JSON keys (look for specific field names)
        (r'"(private_key_id)"\s*:\s*"([^"]{20,})"', 2, 1),
        (r'"(private_key)"\s*:\s*"([^"]{100,})"', 2, 1),
    ]

    findings_by_confidence = {
        'Critical': [],  # >0.8 confidence
        'High': [],      # 0.6-0.8
        'Medium': [],    # 0.4-0.6
        'Low': []        # <0.4 (filtered out unless has sensitive keyword)
    }

    scanned_files = 0
    for root, _, files in os.walk(base):
        for f in files:
            if not f.endswith(('.smali', '.xml', '.java', '.json', '.properties')):
                continue

            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, base)

            # Skip library files
            if is_library_file(rel_path):
                continue

            # Skip certain Android resource XML files that don't contain secrets
            # BUT SCAN strings.xml as developers often mistakenly put API keys there!
            if f.endswith('.xml'):
                # Normalize path separators for cross-platform compatibility
                normalized_path = rel_path.replace('\\', '/').lower()
                # Skip non-secret XML files (but NOT strings.xml!)
                if ('androidmanifest' in normalized_path.lower() or
                    'colors.xml' in f.lower() or
                    'dimens.xml' in f.lower() or
                    'styles.xml' in f.lower() or
                    'attrs.xml' in f.lower()):
                    continue

            scanned_files += 1

            try:
                content = open(full_path, errors='ignore').read()

                # Search for patterns
                for pattern_tuple in string_patterns:
                    pattern, value_group, key_group = pattern_tuple

                    for match in re.finditer(pattern, content, re.MULTILINE):
                        try:
                            # Extract value from specified capture group
                            value = match.group(value_group) if value_group else match.group(0)

                            # Extract key name if specified
                            key_name = match.group(key_group) if key_group else ""

                            # Clean up value
                            value = value.strip('"\'')

                            # Skip common false positives
                            if len(value) < 8:
                                continue
                            if value.lower() in ['example', 'test', 'default', 'placeholder', 'undefined', 'null']:
                                continue
                            if re.match(r'^[0-9]+$', value):  # Pure numbers
                                continue

                            # Skip Android/Material Design component library strings (by name prefix)
                            # m3c_ = Material 3 Components, abc_ = AppCompat, mtrl_ = Material Design, exo_ = ExoPlayer
                            if key_name and re.match(r'^(m3c_|abc_|mtrl_|exo_|mr_|cast_|design_|cardview_|recyclerview_)', key_name):
                                continue

                            # Skip strings containing Android format placeholders (UI localization strings)
                            # %s, %d, %1$s, %2$d, etc. are used in translated UI strings
                            if re.search(r'%[0-9]*\$?[sdxfn]', value):
                                continue

                            # Skip Android resource references
                            if value.startswith('@') or value.startswith('?'):
                                continue

                            # Skip if it looks like XML tag/attribute names (underscores and alphanumeric only)
                            if re.match(r'^[a-z_][a-z0-9_]*[0-9]*$', value, re.I):  # Simple identifiers with optional trailing numbers
                                continue

                            # Skip common boolean strings
                            if value in ['true', 'false', 'enabled', 'disabled']:
                                continue

                            # IMPORTANT: Skip internationalization/localization strings (non-ASCII Unicode)
                            # These are UI text in various languages (Russian, Chinese, Thai, Arabic, etc.)
                            # Count non-ASCII characters
                            non_ascii_count = sum(1 for c in value if ord(c) > 127)
                            # If more than 30% of the string is non-ASCII Unicode, it's likely i18n text
                            if non_ascii_count > 0 and (non_ascii_count / len(value)) > 0.3:
                                # Check if it contains known secret patterns (base64, hex, known prefixes)
                                # These should NOT be skipped even if they have some Unicode
                                is_known_secret_pattern = (
                                    re.match(r'^[A-Za-z0-9+/=]{40,}$', value) or  # Base64
                                    re.match(r'^[0-9a-fA-F]{32,}$', value) or      # Hex
                                    value.startswith(('AKIA', 'AIza', 'sk_', 'pk_', 'ghp_', 'glpat-', 'ya29.')) or
                                    '.apps.googleusercontent.com' in value
                                )
                                if not is_known_secret_pattern:
                                    continue  # Skip internationalization strings

                            # Skip numeric values with units
                            if re.match(r'^[0-9]+\.?[0-9]*(dip|dp|sp|px|pt|mm|in)$', value):
                                continue

                            # Skip SQL queries (will be checked in a separate SQL security test)
                            value_upper = value.upper()
                            sql_keywords = ['SELECT ', 'INSERT ', 'UPDATE ', 'DELETE ', 'CREATE ', 'DROP ', 'ALTER ', 'FROM ', 'WHERE ', 'JOIN ']
                            if any(keyword in value_upper for keyword in sql_keywords):
                                continue

                            # Skip PRAGMA statements (SQLite configuration)
                            if value_upper.startswith('PRAGMA '):
                                continue

                            # Skip Java/Kotlin package and class names (contain dots and look like com.package.Class)
                            # BUT DON'T skip known secret patterns like *.apps.googleusercontent.com
                            if '.' in value and not value.startswith('.'):
                                # Check if it's a known secret pattern first
                                known_secret_patterns = [
                                    r'AKIA[0-9A-Z]{16}',
                                    r'AIza[0-9A-Za-z\-_]{35}',
                                    r'ya29\.[0-9A-Za-z\-_]+',
                                    r'[0-9]+-[0-9A-Za-z_]+\.apps\.googleusercontent\.com',
                                    r'sk_live_[0-9a-zA-Z]{24,}',
                                    r'pk_live_[0-9a-zA-Z]{24,}',
                                    r'.*\.apps\.googleusercontent\.com$',  # Any Google OAuth Client ID
                                ]
                                is_known_secret = any(re.match(pattern, value) for pattern in known_secret_patterns)

                                if not is_known_secret:
                                    # Check if it looks like a fully qualified class name
                                    parts = value.split('.')
                                    # If it has multiple parts and most are lowercase (package structure), skip it
                                    if len(parts) >= 3:
                                        lowercase_parts = sum(1 for p in parts if p and p[0].islower())
                                        if lowercase_parts >= len(parts) - 2:  # Most parts are lowercase (package names)
                                            continue

                            # Skip strings that look like error messages or natural language
                            # (contain spaces and common English words, not just identifiers)
                            if ' ' in value and len(value) > 30:
                                # Count spaces - error messages typically have many
                                space_count = value.count(' ')
                                if space_count >= 3:  # Likely a sentence/error message
                                    continue

                            # Skip strings with parentheses that look like function signatures or debug output
                            if '(' in value and '=' in value:
                                # Looks like "FunctionName(param=value)" - debug output
                                continue

                            # Skip if it looks like a class name, package path, or identifier
                            if '/' in value:
                                # But allow known secret prefixes
                                secret_prefixes = ['AKIA', 'AIza', 'Bearer']
                                if not any(value.startswith(prefix) for prefix in secret_prefixes):
                                    continue

                            # Skip common Android/UI patterns
                            if value.startswith('#') or value.endswith(('dip', 'dp', 'sp', 'px')):
                                continue

                            # Skip if it's a camelCase identifier (but allow base64/hex patterns)
                            if re.match(r'^[a-z][a-zA-Z0-9]*[A-Z]', value):  # camelCase
                                # Unless it's base64/hex which might just happen to look like camelCase
                                if not (re.match(r'^[A-Za-z0-9+/=]+$', value) or re.match(r'^[0-9a-fA-F]+$', value)):
                                    continue

                            # Analyze if it's likely a secret
                            is_secret, confidence, reason = is_likely_secret(value, key_name)

                            # Skip low-confidence findings that only match weak indicators
                            # (e.g., just having "database" in a class name)
                            if confidence < 0.5:
                                # Check if this is only flagged due to generic keywords in the value
                                has_sensitive_val, val_categories = is_sensitive_keyword(value)
                                if has_sensitive_val:
                                    # Only flagged because of weak keywords like "database", "encryption"
                                    weak_categories = {'database', 'encryption', 'secrets'}
                                    if all(cat in weak_categories for cat in val_categories):
                                        # Skip unless there's also a sensitive key name
                                        has_sensitive_key, _ = is_sensitive_keyword(key_name)
                                        if not has_sensitive_key:
                                            continue

                            # Categorize by confidence (raised thresholds)
                            if confidence >= 0.8:
                                category = 'Critical'
                            elif confidence >= 0.65:
                                category = 'High'
                            elif confidence >= 0.5:
                                category = 'Medium'
                            else:
                                # Only include low confidence if it has very specific sensitive keywords
                                has_sensitive, sensitive_cats = is_sensitive_keyword(key_name + " " + value)
                                # Require high-value keywords for low confidence (not just "database" or "encryption")
                                high_value_cats = {'credentials', 'tokens', 'keys', 'financial', 'pii', 'oauth', 'signing'}
                                if has_sensitive and any(cat in high_value_cats for cat in sensitive_cats):
                                    category = 'Low'
                                else:
                                    continue  # Skip

                            # Get context (surrounding lines with actual code)
                            lines_list = content.splitlines()
                            line_num = content[:match.start()].count('\n')
                            context_start = max(0, line_num - 2)
                            context_end = min(len(lines_list), line_num + 3)
                            context_lines = lines_list[context_start:context_end]

                            # Highlight the matching line
                            match_line_in_context = line_num - context_start
                            if 0 <= match_line_in_context < len(context_lines):
                                context_lines[match_line_in_context] = '>>> ' + context_lines[match_line_in_context]

                            finding = {
                                'file': rel_path,
                                'line': line_num + 1,
                                'value': value,
                                'value_preview': value[:80] + ('...' if len(value) > 80 else ''),
                                'key_name': key_name,
                                'confidence': confidence,
                                'reason': reason,
                                'context': context_lines,
                                'full_match': match.group(0)[:100],
                            }

                            # Avoid duplicates based on file + value
                            dup_key = (rel_path, value[:50])
                            if dup_key not in [((f['file'], f['value'][:50])) for f in findings_by_confidence[category]]:
                                findings_by_confidence[category].append(finding)

                        except (IndexError, AttributeError):
                            continue  # Skip malformed matches

            except Exception as e:
                pass

    # Build report
    total_findings = sum(len(findings_by_confidence[cat]) for cat in findings_by_confidence)

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0212/' target='_blank'>MASTG-TEST-0212: Use of Hardcoded Cryptographic Keys in Code</a></div>"

    if total_findings == 0:
        return True, f"<div>No hardcoded keys detected</div><div>Scanned {scanned_files} app files</div>{mastg_ref}"

    # Generate unique ID for this table instance
    import random
    table_id = f"hardcoded_keys_table_{random.randint(1000, 9999)}"

    lines = []
    lines.append(f"<div style='margin:10px 0'><strong>Scanned:</strong> {scanned_files} app files • <strong>Total:</strong> {total_findings} findings</div>")

    # Add filter and search controls
    lines.append(f'''
<div style="margin:15px 0; padding:12px; background:#f8f9fa; border-radius:4px;">
    <div style="display:flex; gap:15px; align-items:center; flex-wrap:wrap;">
        <div style="display:flex; gap:8px; align-items:center;">
            <label style="font-weight:600; margin-right:5px;">Filter by Confidence:</label>
            <label style="cursor:pointer;"><input type="checkbox" id="{table_id}_filter_critical" checked onchange="filterTable_{table_id}()"> <span style="color:#dc3545; font-weight:600;">Critical</span></label>
            <label style="cursor:pointer;"><input type="checkbox" id="{table_id}_filter_high" checked onchange="filterTable_{table_id}()"> <span style="color:#fd7e14; font-weight:600;">High</span></label>
            <label style="cursor:pointer;"><input type="checkbox" id="{table_id}_filter_medium" checked onchange="filterTable_{table_id}()"> <span style="color:#ffc107; font-weight:600;">Medium</span></label>
            <label style="cursor:pointer;"><input type="checkbox" id="{table_id}_filter_low" checked onchange="filterTable_{table_id}()"> <span style="color:#6c757d; font-weight:600;">Low</span></label>
        </div>
        <div style="display:flex; gap:8px; align-items:center; flex-grow:1;">
            <label style="font-weight:600;">Search:</label>
            <input type="text" id="{table_id}_search" placeholder="Search location, content, or reason..."
                   style="flex-grow:1; max-width:400px; padding:6px 10px; border:1px solid #ced4da; border-radius:4px;"
                   onkeyup="filterTable_{table_id}()">
        </div>
        <div>
            <button onclick="expandAllCode_{table_id}()" style="padding:6px 12px; border:1px solid #007bff; background:#007bff; color:white; border-radius:4px; cursor:pointer; margin-right:5px;">Expand All</button>
            <button onclick="collapseAllCode_{table_id}()" style="padding:6px 12px; border:1px solid #6c757d; background:#6c757d; color:white; border-radius:4px; cursor:pointer;">Collapse All</button>
        </div>
    </div>
</div>
''')

    # Start table with scrollable container
    lines.append(f'''
<div style="overflow-x:auto; margin:10px 0; border:1px solid #dee2e6; border-radius:4px;">
<table id="{table_id}" style="width:100%; min-width:900px; border-collapse:collapse; font-size:13px; background:white;">
    <thead>
        <tr style="background:#343a40; color:white; text-align:left;">
            <th style="padding:10px; width:40px; border:1px solid #dee2e6; white-space:nowrap;">#</th>
            <th style="padding:10px; min-width:200px; border:1px solid #dee2e6;">Location</th>
            <th style="padding:10px; min-width:100px; border:1px solid #dee2e6;">Confidence</th>
            <th style="padding:10px; min-width:250px; border:1px solid #dee2e6;">Content</th>
            <th style="padding:10px; min-width:200px; border:1px solid #dee2e6;">Reason</th>
            <th style="padding:10px; min-width:100px; text-align:center; border:1px solid #dee2e6;">Code</th>
        </tr>
    </thead>
    <tbody>
''')

    # Add all findings to table
    row_num = 0
    for category in ['Critical', 'High', 'Medium', 'Low']:
        findings = findings_by_confidence[category]
        if not findings:
            continue

        # Color coding by category
        color_map = {
            'Critical': '#dc3545',
            'High': '#fd7e14',
            'Medium': '#ffc107',
            'Low': '#6c757d'
        }
        badge_color = color_map[category]

        for finding in findings:
            row_num += 1
            full_path = os.path.abspath(os.path.join(base, finding['file']))
            filename = os.path.basename(finding['file'])

            # Create unique row ID
            row_id = f"{table_id}_row_{row_num}"
            code_id = f"{table_id}_code_{row_num}"

            # Build code context HTML
            code_html = ""
            if finding.get('context'):
                code_html = '<pre style="margin:0; padding:8px; background:#f8f9fa; border-radius:4px; font-size:11px; overflow-x:auto; color:#212529; font-family:Consolas,Monaco,monospace;">'
                for ctx_line in finding['context']:
                    escaped = html.escape(ctx_line)
                    if ctx_line.startswith('>>> '):
                        code_html += f'<span style="background:#fff3cd; display:block; color:#000; font-weight:600;">{escaped}</span>'
                    else:
                        code_html += f'{escaped}\n'
                code_html += '</pre>'

            # Build table row
            lines.append(f'''
        <tr id="{row_id}" data-category="{category.lower()}" style="border:1px solid #dee2e6;">
            <td style="padding:8px; border:1px solid #dee2e6; text-align:center; font-weight:600;">{row_num}</td>
            <td style="padding:8px; border:1px solid #dee2e6; word-break:break-word;">
                <a href="file://{html.escape(full_path)}" style="color:#007bff; text-decoration:none;" title="{html.escape(finding['file'])}">{html.escape(filename)}</a>
                <div style="font-size:11px; color:#6c757d;">Line {finding['line']}</div>
                {f'<div style="font-size:11px; color:#6c757d; font-style:italic;">{html.escape(finding["key_name"])}</div>' if finding['key_name'] else ''}
            </td>
            <td style="padding:8px; border:1px solid #dee2e6;">
                <span style="display:inline-block; padding:4px 8px; border-radius:3px; background:{badge_color}; color:white; font-weight:600; font-size:11px;">{category}</span>
                <div style="font-size:11px; color:#6c757d; margin-top:3px;">{finding['confidence']:.0%}</div>
            </td>
            <td style="padding:8px; border:1px solid #dee2e6; word-break:break-all;">
                <code style="background:#e9ecef; padding:2px 4px; border-radius:3px; font-size:11px; color:#000; font-family:Consolas,Monaco,monospace; font-weight:500;">{html.escape(finding['value_preview'])}</code>
            </td>
            <td style="padding:8px; border:1px solid #dee2e6; font-size:12px; word-wrap:break-word; overflow-wrap:break-word;">
                {html.escape(finding['reason'])}
            </td>
            <td style="padding:8px; border:1px solid #dee2e6; text-align:center; white-space:nowrap;">
                <button onclick="toggleCode_{table_id}('{code_id}')"
                        style="padding:4px 10px; border:1px solid #007bff; background:#007bff; color:white; border-radius:3px; cursor:pointer; font-size:11px;">
                    View
                </button>
                <div id="{code_id}" style="display:none; margin-top:8px; text-align:left; max-width:400px; overflow-x:auto;">
                    {code_html}
                </div>
            </td>
        </tr>
''')

    # Close table and scrollable container
    lines.append('''
    </tbody>
</table>
</div>
''')

    # Add JavaScript for filtering and search
    lines.append(f'''
<script>
function filterTable_{table_id}() {{
    const searchInput = document.getElementById('{table_id}_search').value.toLowerCase();
    const showCritical = document.getElementById('{table_id}_filter_critical').checked;
    const showHigh = document.getElementById('{table_id}_filter_high').checked;
    const showMedium = document.getElementById('{table_id}_filter_medium').checked;
    const showLow = document.getElementById('{table_id}_filter_low').checked;

    const table = document.getElementById('{table_id}');
    const rows = table.getElementsByTagName('tbody')[0].getElementsByTagName('tr');

    let visibleCount = 0;
    for (let row of rows) {{
        const category = row.getAttribute('data-category');
        const text = row.textContent.toLowerCase();

        // Check category filter
        let categoryMatch = false;
        if (category === 'critical' && showCritical) categoryMatch = true;
        if (category === 'high' && showHigh) categoryMatch = true;
        if (category === 'medium' && showMedium) categoryMatch = true;
        if (category === 'low' && showLow) categoryMatch = true;

        // Check search filter
        const searchMatch = searchInput === '' || text.includes(searchInput);

        // Show/hide row
        if (categoryMatch && searchMatch) {{
            row.style.display = '';
            visibleCount++;
        }} else {{
            row.style.display = 'none';
        }}
    }}
}}

function toggleCode_{table_id}(codeId) {{
    const codeDiv = document.getElementById(codeId);
    if (codeDiv.style.display === 'none') {{
        codeDiv.style.display = 'block';
    }} else {{
        codeDiv.style.display = 'none';
    }}
}}

function expandAllCode_{table_id}() {{
    const table = document.getElementById('{table_id}');
    const rows = table.getElementsByTagName('tbody')[0].getElementsByTagName('tr');
    for (let row of rows) {{
        if (row.style.display !== 'none') {{
            const codeDiv = row.querySelector('[id^="{table_id}_code_"]');
            if (codeDiv) {{
                codeDiv.style.display = 'block';
            }}
        }}
    }}
}}

function collapseAllCode_{table_id}() {{
    const table = document.getElementById('{table_id}');
    const rows = table.getElementsByTagName('tbody')[0].getElementsByTagName('tr');
    for (let row of rows) {{
        const codeDiv = row.querySelector('[id^="{table_id}_code_"]');
        if (codeDiv) {{
            codeDiv.style.display = 'none';
        }}
    }}
}}
</script>
''')

    lines.append(
        f"<div style='margin-top:10px;'><em>Tip: Focus on Critical and High confidence findings first. "
        f"Use filters and search to narrow down results. Entropy analysis and pattern matching used to reduce false positives.</em></div>"
    )

    lines.append(mastg_ref)

    # FAIL if critical or high confidence findings
    has_critical_or_high = len(findings_by_confidence['Critical']) + len(findings_by_confidence['High']) > 0

    return (not has_critical_or_high), "\n".join(lines)

def check_key_sizes(base):
    """
    Check for insufficient cryptographic key sizes.
    Uses SMALI patterns for decompiled APK analysis.
    """
    issues = []

    # SMALI patterns for RSA key generation
    # Matches: Ljava/security/KeyPairGenerator;->getInstance
    rsa_pattern = r'Ljava/security/KeyPairGenerator;->getInstance'
    rsa_files = grep_code(base, rsa_pattern)

    for rel in rsa_files:
        full = os.path.join(base, rel)
        try:
            content = open(full, errors='ignore').read()
            lines = content.splitlines()

            # In SMALI, initialize() looks like:
            # invoke-virtual {vX, vY}, Ljava/security/KeyPairGenerator;->initialize(I)V
            # The key size is loaded with const/16 or const instructions before the invoke
            for i, line in enumerate(lines):
                if '->initialize' in line and 'KeyPairGenerator' in line:
                    # Look for const/16 or const in previous 3 lines (key size parameter)
                    for j in range(max(0, i-3), i):
                        size_match = re.search(r'const(?:/16)?\s+v\d+,\s*(?:0x)?(\d+)', lines[j])
                        if size_match:
                            size = int(size_match.group(1), 16 if '0x' in lines[j] else 10)
                            if 256 <= size < 2048:  # Reasonable range for RSA key size
                                issues.append((rel, f"RSA key size {size} < 2048 bits", i+1))
                                break
        except:
            pass

    # SMALI patterns for AES key generation
    # Matches: Ljavax/crypto/KeyGenerator;->getInstance
    aes_pattern = r'Ljavax/crypto/KeyGenerator;->getInstance'
    aes_files = grep_code(base, aes_pattern)

    for rel in aes_files:
        full = os.path.join(base, rel)
        try:
            content = open(full, errors='ignore').read()
            lines = content.splitlines()

            # In SMALI, init() looks like:
            # invoke-virtual {vX, vY}, Ljavax/crypto/KeyGenerator;->init(I)V
            for i, line in enumerate(lines):
                if '->init' in line and 'KeyGenerator' in line:
                    # Look for const/16 or const in previous 3 lines (key size parameter)
                    for j in range(max(0, i-3), i):
                        size_match = re.search(r'const(?:/16)?\s+v\d+,\s*(?:0x)?(\d+)', lines[j])
                        if size_match:
                            size = int(size_match.group(1), 16 if '0x' in lines[j] else 10)
                            if size < 128 and size > 0:  # Valid AES key sizes: 128, 192, 256
                                issues.append((rel, f"AES key size {size} < 128 bits", i+1))
                                break
        except:
            pass

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0208/' target='_blank'>MASTG-TEST-0208: Insufficient Key Sizes</a></div>"

    if not issues:
        if rsa_files or aes_files:
            return True, f"Key generation found in {len(rsa_files) + len(aes_files)} files, sizes appear adequate{mastg_ref}"
        return True, f"No key generation detected{mastg_ref}"

    lines = []
    for rel, msg, line_num in issues[:50]:
        full = os.path.abspath(os.path.join(base, rel))
        lines.append(f'<a href="file://{html.escape(full)}">{html.escape(rel)}:{line_num}</a>: {html.escape(msg)}')

    if len(issues) > 50:
        lines.append(f"...and {len(issues) - 50} more")

    lines.append(mastg_ref)

    return False, "<br>\n".join(lines)

def check_biometric_auth(base):
    """
    MASTG-TEST-0018: Testing Biometric Authentication

    Check for proper biometric authentication implementation in APP CODE.
    Verifies biometric auth is bound to cryptographic operations via CryptoObject.

    CRITICAL: Detects BiometricPrompt.authenticate() without CryptoObject (allows Frida bypass).

    MASTG: https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0018/
    Reference: https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0001/
    """
    # Library paths to exclude
    lib_paths = (
        '/androidx/', '/android/support/',
        '/com/google/android/gms/', '/com/google/firebase/', '/com/google/android/play/',
        '/com/google/common/', '/okhttp3/', '/okio/', '/retrofit2/', '/com/squareup/',
        '/com/facebook/', '/kotlin/', '/kotlinx/',
        '/io/reactivex/', '/rx/', '/dagger/',
        '/lib/', '/jetified-'
    )

    def is_library_path(path):
        """Check if path is library code"""
        normalized = '/' + path.replace('\\', '/')
        return any(lib in normalized for lib in lib_paths)

    # CRITICAL: BiometricPrompt.authenticate() without CryptoObject
    # authenticate(PromptInfo) = VULNERABLE (one param, no CryptoObject)
    null_crypto_biometric = re.compile(
        r'invoke-virtual.*Landroidx/biometric/BiometricPrompt;->authenticate'
        r'\(Landroidx/biometric/BiometricPrompt\$PromptInfo;\)V'
    )

    # SECURE: BiometricPrompt.authenticate() with CryptoObject
    # authenticate(PromptInfo, CryptoObject) = SECURE (two params)
    secure_crypto_biometric = re.compile(
        r'invoke-virtual.*Landroidx/biometric/BiometricPrompt;->authenticate'
        r'\(Landroidx/biometric/BiometricPrompt\$PromptInfo;Landroidx/biometric/BiometricPrompt\$CryptoObject;\)'
    )

    # Detect general BiometricPrompt usage
    biometric_prompt_pat = re.compile(r'Landroidx/biometric/BiometricPrompt;')

    # Secure patterns - CryptoObject + KeyStore binding
    crypto_object_pattern = re.compile(r'Landroidx/biometric/BiometricPrompt\$CryptoObject;')
    keystore_patterns = [
        re.compile(r'setUserAuthenticationRequired'),
        re.compile(r'setInvalidatedByBiometricEnrollment'),
    ]

    # Categorize findings
    biometric_files = set()
    null_crypto_files = []  # CRITICAL - allows Frida bypass
    secure_crypto_files = set()  # SECURE - uses CryptoObject
    crypto_object_files = set()
    keystore_files = set()

    for root, _, files in os.walk(base):
        for fn in files:
            if not fn.endswith('.smali'):
                continue

            path = os.path.join(root, fn)
            rel_path = os.path.relpath(path, base)

            # Skip library code - only check APP CODE
            if is_library_path(rel_path):
                continue

            try:
                content = open(path, errors='ignore').read()
                lines = content.splitlines()
            except:
                continue

            # Check for BiometricPrompt usage (general)
            if biometric_prompt_pat.search(content):
                biometric_files.add(rel_path)

            # Check for CryptoObject usage (secure)
            if crypto_object_pattern.search(content):
                crypto_object_files.add(rel_path)

            # Check for KeyStore integration (secure)
            for pat in keystore_patterns:
                if pat.search(content):
                    keystore_files.add(rel_path)
                    break

            # Check for CRITICAL vulnerability: authenticate() without CryptoObject
            for i, line in enumerate(lines, 1):
                if null_crypto_biometric.search(line):
                    snippet = html.escape(line.strip()[:120])
                    link = f'<a href="file://{html.escape(path)}">{html.escape(rel_path)}:{i}</a>'
                    null_crypto_files.append((link, snippet))
                    break

            # Check for secure usage: authenticate() with CryptoObject
            if secure_crypto_biometric.search(content):
                secure_crypto_files.add(rel_path)

    # No BiometricPrompt API usage detected in app code
    if not biometric_files:
        return 'PASS', "<div>No BiometricPrompt usage detected in app code</div>"

    # CRITICAL: BiometricPrompt.authenticate() without CryptoObject - allows Frida bypass
    if null_crypto_files:
        lines = [
            f"<div><strong>Vulnerable Code ({len(null_crypto_files)} instance(s)):</strong></div>"
        ]

        for link, snippet in null_crypto_files[:15]:
            # e.g. smali_classes3/.../BiometricPromptManager.smali:256 → invoke-virtual {...}
            lines.append(f"{link} → <code>{snippet}</code>")

        # Link to the MASTG test case
        lines.append(
            "<br><div><strong>Reference:</strong> "
            "<a href='https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0017/' "
            "target='_blank'>MASTG-TEST-0017: Testing Biometric Authentication</a></div>"
        )

        return 'FAIL', "<br>\n".join(lines)

    # BiometricPrompt found with secure usage (CryptoObject + KeyStore)
    if secure_crypto_files or (crypto_object_files and keystore_files):
        lines = [
            f"<div>BiometricPrompt with cryptographic binding detected</div>",
            f"<div>Found in {len(biometric_files)} file(s)</div>",
            "<div><strong>Secure patterns detected:</strong></div>",
            "<ul style='margin-left:20px;'>"
        ]
        if secure_crypto_files:
            lines.append(f"<li>BiometricPrompt.authenticate() with CryptoObject: {len(secure_crypto_files)} file(s)</li>")
        if crypto_object_files:
            lines.append(f"<li>CryptoObject usage: {len(crypto_object_files)} file(s)</li>")
        if keystore_files:
            lines.append(f"<li>KeyStore integration (setUserAuthenticationRequired): {len(keystore_files)} file(s)</li>")
        lines.append("</ul>")

        lines.append("<div><strong>App code files implementing biometric auth:</strong></div>")
        for rel in sorted(biometric_files)[:10]:
            full = os.path.abspath(os.path.join(base, rel))
            lines.append(f'<a href="file://{html.escape(full)}">{html.escape(rel)}</a>')

        lines.append("<br><div><strong>Recommendations:</strong></div>")
        lines.append("<ul style='margin-left:20px;'>")
        lines.append("<li>Verify setInvalidatedByBiometricEnrollment(true) is used</li>")
        lines.append("<li>Ensure sensitive operations require biometric re-authentication</li>")
        lines.append("<li>Check for proper error handling in onAuthenticationError()</li>")
        lines.append("</ul>")

        return 'PASS', "<br>\n".join(lines)

    # BiometricPrompt used but cannot confirm secure implementation
    lines = [
        f"<div><strong style='color:#d97706;'>WARNING: BiometricPrompt usage detected, security unclear</strong></div>",
        f"<div style='margin-top:8px;'>Found BiometricPrompt in {len(biometric_files)} file(s)</div>",
        "<div style='margin-top:8px;'><strong>Status:</strong> Could not detect authenticate() calls with or without CryptoObject.</div>",
        "<div><strong>Manual Review Required:</strong></div>",
        "<ul style='margin-left:20px;'>",
        "<li>Verify authenticate() is called WITH CryptoObject parameter</li>",
        "<li>Ensure CryptoObject wraps a KeyStore-bound key</li>",
        "<li>Check setUserAuthenticationRequired(true) is used</li>",
        "</ul>",
        "<div><strong>Files using BiometricPrompt:</strong></div>"
    ]
    for rel in sorted(biometric_files)[:15]:
        full = os.path.abspath(os.path.join(base, rel))
        lines.append(f'<a href="file://{html.escape(full)}">{html.escape(rel)}</a>')

    return 'WARN', "<br>\n".join(lines)

def check_flag_secure(base, manifest):
    """
    Check if FLAG_SECURE is used to prevent screenshots on sensitive screens.
    """
    flag_secure_patterns = [
        r'FLAG_SECURE',
        r'addFlags\s*\(\s*WindowManager\.LayoutParams\.FLAG_SECURE',
        r'setFlags\s*\([^)]*FLAG_SECURE',
    ]

    hits = set()
    for pat in flag_secure_patterns:
        hits.update(grep_code(base, pat))

    # Count activities in manifest
    try:
        tree = ET.parse(manifest)
        root = tree.getroot()
        activities = root.findall('.//{http://schemas.android.com/apk/res/android}activity')
        activity_count = len(activities)
    except:
        activity_count = 0

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0010/' target='_blank'>MASTG-TEST-0010: Finding Sensitive Information in Auto-Generated Screenshots</a></div>"

    if hits:
        lines = [
            f"<div> FLAG_SECURE usage detected in {len(hits)} file(s)</div>"
        ]
        for rel in sorted(hits)[:15]:
            full = os.path.abspath(os.path.join(base, rel))
            lines.append(f'<a href="file://{html.escape(full)}">{html.escape(rel)}</a>')
        lines.append(mastg_ref)
        return 'PASS', "<br>\n".join(lines)

    return 'WARN', f"<div>No FLAG_SECURE usage detected</div><div>Total activities: {activity_count}</div><div class='info-box'><em> Recommendation: Consider using FLAG_SECURE for activities that display sensitive data (payment info, credentials, personal data) to prevent screenshots and screen recording.</em></div>{mastg_ref}"

def check_webview_javascript_bridge(base):
    """
    Check for insecure WebView JavaScript interfaces.

    VULNERABILITY: addJavascriptInterface() + remote content loading allows
    any JavaScript from the internet to call exposed Android methods.

    This checks:
    1. Whether @JavascriptInterface annotations are present (API 17+ requirement)
    2. Whether WebViews with JS interfaces load REMOTE content (http/https URLs)
    3. Whether proper URL validation is implemented

    FAIL if: addJavascriptInterface + loading remote/network URLs
    PASS if: addJavascriptInterface + only local assets (file:// or loadData)
    """
    # JavaScript interface patterns
    js_interface_patterns = [
        r'addJavascriptInterface\(',
        r'->addJavascriptInterface\(',
    ]

    hits = set()
    for pat in js_interface_patterns:
        hits.update(grep_code(base, pat))

    if not hits:
        return True, "No JavaScript interfaces detected"

    # Analyze each file that adds JavaScript interface
    interface_classes = set()
    vulnerable_interfaces = []
    files_with_remote_loading = []

    for rel in hits:
        full_path = os.path.join(base, rel)
        try:
            with open(full_path, 'r', errors='ignore') as f:
                content = f.read()

            # Check if this file loads REMOTE content (vulnerability indicator)
            remote_loading_patterns = [
                r'loadUrl.*"https?://',           # loadUrl("http://...")
                r'loadUrl.*Ljava/lang/String;',   # loadUrl(stringVar) - might be remote
                r'loadDataWithBaseURL.*"https?://', # loadDataWithBaseURL with remote base
            ]

            loads_remote = False
            for pattern in remote_loading_patterns:
                if re.search(pattern, content):
                    loads_remote = True
                    break

            # Check for URL validation (security control)
            has_url_validation = bool(re.search(r'(startsWith|contains|matches|equals).*"(https?://|file://)', content))

            if loads_remote:
                files_with_remote_loading.append({
                    'file': rel,
                    'has_validation': has_url_validation
                })

            # Find addJavascriptInterface calls and extract the object being passed
            # Pattern: invoke-virtual {vX, vY}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
            add_js_matches = re.finditer(
                r'invoke-virtual\s+\{([^}]+)\}.*addJavascriptInterface',
                content
            )

            for match in add_js_matches:
                # Get the lines before this invocation to find what object is being passed
                lines_before = content[:match.start()].split('\n')

                # Look backwards for field access or new-instance that loads the interface object
                for i in range(len(lines_before) - 1, max(0, len(lines_before) - 30), -1):
                    line = lines_before[i]

                    # Match patterns like: iget-object v2, p0, Lcom/example/MyClass;->jsInterface:Lcom/example/MyInterface;
                    field_match = re.search(r'L([^;]+);->\w+:L([^;]+);', line)
                    if field_match:
                        interface_classes.add(field_match.group(2))
                        continue

                    # Match patterns like: new-instance v0, Lcom/example/MyInterface;
                    new_match = re.search(r'new-instance\s+\w+,\s*L([^;]+);', line)
                    if new_match:
                        interface_classes.add(new_match.group(1))
                        break

        except Exception as e:
            pass

    # Now check each interface class for @JavascriptInterface annotations
    secure_count = 0
    for class_path in interface_classes:
        # Convert class path to file path (replace / with os separator)
        class_file_patterns = [
            os.path.join(base, "smali", class_path + ".smali"),
            os.path.join(base, "smali_classes2", class_path + ".smali"),
            os.path.join(base, "smali_classes3", class_path + ".smali"),
            os.path.join(base, "smali_classes4", class_path + ".smali"),
            os.path.join(base, "smali_classes5", class_path + ".smali"),
            os.path.join(base, "smali_classes6", class_path + ".smali"),
            os.path.join(base, "smali_classes7", class_path + ".smali"),
        ]

        found_annotation = False
        for class_file in class_file_patterns:
            if os.path.exists(class_file):
                try:
                    with open(class_file, 'r', errors='ignore') as f:
                        class_content = f.read()

                    # Check if this class has @JavascriptInterface annotations on public methods
                    if re.search(r'\.annotation\s+runtime\s+Landroid/webkit/JavascriptInterface;', class_content):
                        found_annotation = True
                        secure_count += 1
                        break
                except:
                    pass

        if not found_annotation and class_path:
            vulnerable_interfaces.append(class_path)

    # Build report
    lines = []
    lines.append(f"<div><strong>JavaScript interfaces detected:</strong> {len(hits)} file(s)</div>")

    if interface_classes:
        lines.append(f"<div>Interface classes identified: {len(interface_classes)}</div>")

    if secure_count > 0:
        lines.append(f"<div>@JavascriptInterface annotations properly implemented</div>")

    if vulnerable_interfaces:
        lines.append(f"<div>WARNING: {len(vulnerable_interfaces)} interface(s) may lack @JavascriptInterface annotations:</div>")
        for vuln_class in vulnerable_interfaces[:10]:
            lines.append(f"<div style='margin-left:20px;'>{vuln_class}</div>")

    # Check for remote content loading
    if files_with_remote_loading:
        lines.append(f"<div><br><strong>{len(files_with_remote_loading)} file(s) expose JavaScript interfaces while loading REMOTE content:</strong></div>")
        lines.append("<div style='margin-left:20px;'>This allows ANY JavaScript from the internet to call exposed Android methods!</div>")
        for item in files_with_remote_loading[:10]:
            full = os.path.abspath(os.path.join(base, item['file']))
            validation_note = " (has some URL validation)" if item['has_validation'] else " (NO URL validation detected)"
            lines.append(f"<div style='margin-left:20px;'><a href=\"file://{html.escape(full)}\">{html.escape(item['file'])}</a>{validation_note}</div>")

    # Show files that use addJavascriptInterface
    lines.append("<div><br><strong>All files using addJavascriptInterface:</strong></div>")
    for rel in sorted(hits)[:20]:
        full = os.path.abspath(os.path.join(base, rel))
        lines.append(f'<div style="margin-left:20px;"><a href="file://{html.escape(full)}">{html.escape(rel)}</a></div>')

    if len(hits) > 20:
        lines.append(f"<div style='margin-left:20px;'>...and {len(hits) - 20} more</div>")

    # FAIL if remote content loading detected, regardless of annotations
    is_secure = len(files_with_remote_loading) == 0 and len(vulnerable_interfaces) == 0

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0033/' target='_blank'>MASTG-TEST-0033: Testing for Java Objects Exposed Through WebViews</a></div>"
    lines.append(mastg_ref)

    return is_secure, "<br>\n".join(lines)

def check_clipboard_security(base):
    """
    Check for sensitive data exposure via clipboard.
    Detects when sensitive data (OTP, passwords, credit cards, tokens) is copied to clipboard.

    VULNERABILITY: Clipboard data can be accessed by any app with clipboard access.
    Sensitive authentication data (OTP, passwords) should never be copied to clipboard.

    MASVS: MASVS-STORAGE-2 (Sensitive Data Disclosure)
    MASTG: MASTG-TEST-0001
    """
    # Clipboard API patterns to detect (SMALI patterns for decompiled APK)
    clipboard_api_patterns = {
        'setPrimaryClip': r'Landroid/content/ClipboardManager;->setPrimaryClip',
        'getPrimaryClip': r'Landroid/content/ClipboardManager;->getPrimaryClip',
        'ClipboardManager_getSystemService': r'getSystemService.*Landroid/content/ClipboardManager;',
        'ClipData': r'Landroid/content/ClipData;->newPlainText',
    }

    # Sensitive data indicators (what should NEVER be copied to clipboard)
    sensitive_indicators = [
        'password', 'passwd', 'pwd',
        'otp', 'token', 'auth',
        'creditcard', 'credit_card', 'cc',
        'cvv', 'cvc', 'pin',
        'secret', 'key', 'private',
        'ssn', 'social',
    ]

    # Security controls to look for
    prevention_patterns = [
        r'setTextIsSelectable\s*\(\s*false',
        r'textIsSelectable\s*=\s*["\']false',
        r'InputType\.TYPE_TEXT_VARIATION_PASSWORD',
        r'InputType\.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD',
    ]

    critical_findings = []  # setPrimaryClip with sensitive data
    findings = []           # Other clipboard usage
    prevention_hits = set()
    scanned_files = 0

    # Scan for clipboard usage
    for root, _, files in os.walk(base):
        for f in files:
            if not f.endswith('.smali'):
                continue

            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, base)

            # Skip library files
            if any(lib in rel_path for lib in ['androidx/', 'android/support/', 'com/google/']):
                continue

            scanned_files += 1

            try:
                with open(full_path, errors='ignore') as file:
                    content = file.read()
                    lines = content.splitlines()

                # Look for clipboard API calls
                for line_num, line in enumerate(lines, 1):
                    for api_name, pattern in clipboard_api_patterns.items():
                        if re.search(pattern, line, re.IGNORECASE):
                            # Get broader context to check for sensitive data indicators
                            context_start = max(0, line_num - 30)
                            context_end = min(len(lines), line_num + 5)
                            context_lines = lines[context_start:context_end]
                            context_text = '\n'.join(context_lines).lower()

                            # Check if sensitive data is involved
                            is_sensitive = any(indicator in context_text for indicator in sensitive_indicators)

                            finding = {
                                'file': rel_path,
                                'line': line_num,
                                'api': api_name,
                                'snippet': line.strip(),
                                'context': '\n'.join(lines[max(0, line_num - 3):min(len(lines), line_num + 2)]),
                                'sensitive': is_sensitive
                            }

                            # Critical if setPrimaryClip with sensitive data
                            if 'setPrimaryClip' in api_name and is_sensitive:
                                critical_findings.append(finding)
                            else:
                                findings.append(finding)
                            break

                # Look for prevention mechanisms
                for pat in prevention_patterns:
                    if re.search(pat, content):
                        prevention_hits.add(rel_path)
                        break

            except Exception:
                continue

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0001/' target='_blank'>MASTG-TEST-0001: Testing Local Storage for Sensitive Data</a></div>"

    if not critical_findings and not findings:
        return 'PASS', f"<div>No clipboard usage detected</div><div>Scanned {scanned_files} files</div>{mastg_ref}", 0

    # Build detailed report
    report_lines = []

    # Critical findings first (FAIL)
    if critical_findings:
        report_lines.append(
            f"<div style='background:#f8d7da; border-left:4px solid #dc3545; padding:10px; margin:10px 0;'>"
            f"<strong>Sensitive Data Copied to Clipboard</strong><br>"
            f"Found {len(critical_findings)} instance(s) of sensitive data (OTP, passwords, tokens) being copied to clipboard<br>"
            f"<strong>Risk:</strong> Any app can read clipboard and steal sensitive authentication data"
            f"</div><br>"
        )

        for finding in critical_findings:
            full = os.path.abspath(os.path.join(base, finding['file']))
            report_lines.append(
                f"<div style='border-left:4px solid #dc3545; padding-left:10px; margin:10px 0;'>"
                f"<strong>File:</strong> <a href='file://{html.escape(full)}'>{html.escape(finding['file'])}:{finding['line']}</a><br>"
                f"<strong>API:</strong> <code>{finding['api']}</code> (COPIES TO CLIPBOARD)<br>"
                f"<strong>WARNING: Sensitive data detected in context</strong> (OTP/password/token/credit card)<br>"
                f"<strong>Code:</strong><br>"
                f"<pre>{html.escape(finding['context'])}</pre>"
                f"<strong>Fix:</strong> Never copy sensitive authentication data to clipboard. Use secure alternatives:<br>"
                f"• For OTP: Display on screen only, don't allow copy<br>"
                f"• For passwords: Use password managers with autofill<br>"
                f"• For tokens: Pass directly via secure Intent extras<br>"
                f"<strong>MASVS:</strong> MASVS-STORAGE-2<br>"
                f"</div><br>"
            )

    # Non-critical findings (WARN)
    if findings:
        report_lines.append(f"<div><strong>Other Clipboard Usage:</strong> {len(findings)} instance(s)</div>")
        if prevention_hits:
            report_lines.append(f"<div><strong> Files with clipboard prevention:</strong> {len(prevention_hits)} file(s)</div>")
        report_lines.append("<br>")

        files_with_clipboard = {}
        for finding in findings:
            file_path = finding['file']
            if file_path not in files_with_clipboard:
                files_with_clipboard[file_path] = []
            files_with_clipboard[file_path].append(finding)

        report_lines.append('<details>')
        report_lines.append('<summary>')
        report_lines.append(f'WARNING: Non-Critical Clipboard Usage ({len(files_with_clipboard)} files)')
        report_lines.append('</summary>')

        for file_path in sorted(files_with_clipboard.keys()):
            full = os.path.abspath(os.path.join(base, file_path))
            file_findings = files_with_clipboard[file_path]

            has_prevention = file_path in prevention_hits
            border_color = '#28a745' if has_prevention else '#ffc107'
            status_icon = '' if has_prevention else 'WARNING:'

            report_lines.append(
                f'<div style="border-left:4px solid {border_color}; padding-left:10px; margin:10px 0;">'
                f'{status_icon} <a href="file://{html.escape(full)}">{html.escape(file_path)}</a><br>'
                f'<strong>Clipboard calls:</strong> {len(file_findings)}'
            )

            if has_prevention:
                report_lines.append(' | <span style="color:#28a745">Has prevention mechanisms</span>')

            for finding in file_findings[:3]:
                report_lines.append(
                    f'<br><strong>Line {finding["line"]}:</strong> <code>{finding["api"]}</code> - '
                    f'<code>{html.escape(finding["snippet"][:80])}</code>'
                )

            if len(file_findings) > 3:
                report_lines.append(f'<br><em>...and {len(file_findings) - 3} more</em>')

            report_lines.append('</div>')

        report_lines.append('</details>')

    report_lines.append(
        '<div class="info-box"><em> Clipboard data can be accessed by other apps. '
        'Avoid copying sensitive data (OTP, passwords, tokens, credit cards) to clipboard.</em></div>'
    )

    report_lines.append(mastg_ref)

    # Return FAIL if critical findings, WARN otherwise
    if critical_findings:
        return False, '\n'.join(report_lines), len(critical_findings)
    else:
        return 'WARN', '\n'.join(report_lines)

def check_pii_location_info(base):
    """
    Check if app code uses Location.getLatitude()/getLongitude().

    Filters out:
    - Third-party library code (androidx, google, etc.)
    - Expected usage in fitness/navigation apps

    Only flags suspicious usage in non-location-based apps.
    """

    # Library paths to exclude
    lib_paths = (
        '/androidx/', '/android/support/',
        '/com/google/android/gms/', '/com/google/firebase/',
        '/okhttp3/', '/retrofit2/', '/com/squareup/',
        '/com/facebook/', '/kotlin/', '/kotlinx/',
        '/org/chromium/', '/io/reactivex/',
        '/lib/', '/jetified-'
    )

    def is_library_path(path):
        """Check if path is library code"""
        normalized = '/' + path.replace('\\', '/')
        return any(lib in normalized for lib in lib_paths)

    patterns = [
        # Java calls
        r'Location\.getLatitude\(',
        r'Location\.getLongitude\(',
        # Smali calls
        r'Landroid/location/Location;->getLatitude',
        r'Landroid/location/Location;->getLongitude'
    ]

    issues = []
    for root, _, files in os.walk(base):
        for fn in files:
            if not fn.endswith(('.smali', '.java')):
                continue
            path = os.path.join(root, fn)

            # Filter out library code
            rel_path = os.path.relpath(path, base)
            if is_library_path(rel_path):
                continue

            try:
                lines = open(path, errors='ignore').read().splitlines()
            except:
                continue

            for i, line in enumerate(lines, 1):
                for pat in patterns:
                    if re.search(pat, line):
                        snippet = html.escape(line.strip())
                        link = (
                            f'<a href="file://{html.escape(path)}">'
                            f'{html.escape(rel_path)}:{i}</a>'
                        )
                        issues.append(f"{link} – <code>{snippet}</code>")
                        break
                else:
                    continue
                break  # stop after first match in this file

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0254/' target='_blank'>MASTG-TEST-0254: Dangerous App Permissions</a></div>"

    if not issues:
        return True, f"None{mastg_ref}"

    # Add context note for informational purposes
    note = "<strong>Note:</strong> Location usage detected in app code. "
    note += "Verify this is disclosed in privacy policy and necessary for app functionality.<br><br>"

    return False, note + "<br>\n".join(issues) + mastg_ref


def check_pii_wifi_info(base):
    """
    FAIL if any code calls WifiManager.getConnectionInfo(), which can leak
    personally identifiable network info.
    Emits clickable file:// links with line numbers and code snippets.
    """

    patterns = [
        # Wi-Fi MAC / SSID
        r'WifiManager\.getConnectionInfo\(',
        r'Landroid/net/wifi/WifiManager;->getConnectionInfo',
        # Bluetooth MAC
        r'BluetoothDevice\.getAddress\(',
        r'Landroid/bluetooth/BluetoothDevice;->getAddress'
        # Bluetooth device name
        r'BluetoothDevice\.getName\(',
        r'Landroid/bluetooth/BluetoothDevice;->getName'
    ]

    issues = []
    for root, _, files in os.walk(base):
        for fn in files:
            if not fn.endswith(('.smali', '.java')):
                continue
            path = os.path.join(root, fn)
            try:
                lines = open(path, errors='ignore').read().splitlines()
            except:
                continue

            for i, line in enumerate(lines, 1):
                for pat in patterns:
                    if re.search(pat, line):
                        rel = os.path.relpath(path, base)
                        snippet = html.escape(line.strip())
                        link = (
                            f'<a href="file://{html.escape(path)}">'
                            f'{html.escape(rel)}:{i}</a>'
                        )
                        issues.append(f"{link} – <code>{snippet}</code>")
                        break
                else:
                    continue
                break  # stop after first match in this file

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0254/' target='_blank'>MASTG-TEST-0254: Dangerous App Permissions</a></div>"

    if not issues:
        return True, f"None{mastg_ref}"
    return False, "<br>\n".join(issues) + mastg_ref

def check_signature_schemes(apk_path):
    """
    Runs `apksigner verify --verbose --print-certs` on the APK and reports:
      • which schemes (v1, v2, v3) are present/missing
      • checks for weak hash algorithms (SHA1withRSA - vulnerable to collisions)
      • flags Janus (CVE-2017-13156) correctly:
         - v1 ONLY: CRITICAL - vulnerable on all Android 5.0-8.0
         - v1 + v2/v3: WARNING - still vulnerable on Android 5.0-7.x
         - v2/v3 only (no v1): SECURE - but breaks Android < 7.0 compatibility
      • Android 5.0-7.x do NOT properly enforce v2/v3, so v1 presence = vulnerability
    """
    out = run_cmd(f"apksigner verify --verbose --print-certs {apk_path}")
    clean = re.sub(r"\x1b\[[0-9;]*m", "", out)
    clean = re.sub(r"[^\x20-\x7E\n]", "", clean)

    # Detect schemes
    present = []
    for ver, marker in [
        ("v1", r"Verified using v1 scheme.*: true"),
        ("v2", r"Verified using v2 scheme.*: true"),
        ("v3", r"Verified using v3 scheme.*: true")
    ]:
        if re.search(marker, clean):
            present.append(ver)

    all_schemes = ["v1", "v2", "v3"]
    missing = [v for v in all_schemes if v not in present]

    # Build base report with clear structure
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0224/' target='_blank'>MASTG-TEST-0224: Usage of Insecure Signature Version</a></div>"

    if not present:
        return False, f"No signature schemes found{mastg_ref}"

    report_lines = []
    has_failures = False

    # INFO: Signature scheme versions
    info_parts = []
    info_parts.append(f"<strong>Present:</strong> {', '.join(present)}")
    if missing:
        info_parts.append(f"<strong>Missing:</strong> {', '.join(missing)}")
    report_lines.append("<div style='color:#0d6efd;'>INFO: " + " | ".join(info_parts) + "</div>")

    # Check certificate hash algorithm (SHA1 vs SHA256)
    sha1_detected = False
    if re.search(r'(SHA1withRSA|SHA-1)', clean, re.IGNORECASE):
        sha1_detected = True
        has_failures = True
        report_lines.append(
            "<div style='margin-top:10px;'><strong style='color:#dc3545;'>FAIL: Weak Signature Algorithm</strong></div>"
            "<div style='margin-left:20px;'>Certificate uses <code>SHA1withRSA</code>. "
            "SHA-1 is cryptographically broken and vulnerable to collision attacks.</div>"
            "<div style='margin-left:20px;'><strong>Recommendation:</strong> Re-sign with <code>SHA256withRSA</code> or stronger.</div>"
        )

    # Janus vulnerability logic (CVE-2017-13156)
    # CORRECT vulnerability assessment:
    # - v1 ONLY: Vulnerable on ALL Android versions (5.0-8.0)
    # - v1 + v2/v3: STILL vulnerable on Android 5.0-7.x (OS doesn't enforce v2/v3 properly)
    # - v2/v3 without v1: Secure (but breaks compatibility with Android < 7.0)

    if "v1" in present:
        has_failures = True
        if present == ["v1"]:
            # v1 only → CRITICAL: vulnerable on ALL Android versions
            report_lines.append(
                "<div style='margin-top:10px;'><strong style='color:#dc3545;'>FAIL: Janus Vulnerability (CVE-2017-13156)</strong></div>"
                "<div style='margin-left:20px;'><strong>Severity:</strong> CRITICAL</div>"
                "<div style='margin-left:20px;'>APK signed only with v1 (JAR signature), vulnerable on Android 5.0-8.0.</div>"
                "<div style='margin-left:20px;'>v1 does not validate the entire APK, allowing malicious DEX prepending.</div>"
                "<div style='margin-left:20px;'><strong>Recommendation:</strong> Add v2 or v3 signing to mitigate.</div>"
            )
        else:
            # v1 + v2/v3 → WARNING: still vulnerable on Android 5.0-7.x
            report_lines.append(
                "<div style='margin-top:10px;'><strong style='color:#fd7e14;'>FAIL: Janus Vulnerability (CVE-2017-13156)</strong></div>"
                "<div style='margin-left:20px;'><strong>Severity:</strong> Partial (Android 5.0-7.x affected)</div>"
                "<div style='margin-left:20px;'>APK signed with v1 + v2/v3. While v2/v3 provide protection on Android 8.0+, "
                "Android 5.0-7.x devices do NOT properly enforce v2/v3 validation and remain vulnerable.</div>"
                "<div style='margin-left:20px;'><strong>Recommendation:</strong> Consider dropping support for Android < 7.0 and removing v1 signing entirely.</div>"
            )

    # Final verdict
    report_lines.append(mastg_ref)
    if has_failures:
        return False, "<br>\n".join(report_lines)

    # If we have v2/v3 WITHOUT v1, we're fully protected
    if "v2" in present or "v3" in present:
        report_lines.append("<div style='margin-top:10px;color:#198754;'>Secure signature configuration</div>")
        return True, "<br>\n".join(report_lines)

    # No proper signatures
    return False, "<br>\n".join(report_lines)
    
def check_insecure_randomness(base):
    """
    FAIL if any code uses predictable randomness:
      • java.util.Random (especially with predictable seed like currentTimeMillis)
      • kotlin.random.Random (especially with predictable seed)
      • Math.random()
      • ThreadLocalRandom (insecure for crypto)
    Reports clickable file:// links with line numbers and code snippets.
    Filters out library code to show only app code issues.
    """
    # Library paths to exclude
    lib_paths = (
        '/androidx/', '/android/support/',
        '/com/google/android/gms/', '/com/google/firebase/', '/com/google/android/play/',
        '/com/google/common/', '/com/google/crypto/tink/',  # Google Tink cryptographic library
        '/okhttp3/', '/okio/', '/retrofit2/', '/com/squareup/',
        '/com/facebook/', '/kotlin/', '/kotlinx/',
        '/io/reactivex/', '/rx/', '/dagger/',
        '/com/airbnb/', '/org/bson/', '/io/jsonwebtoken/',
        '/org/jsoup/',  # jsoup library
        '/j$/',  # Java 8+ backport library (j$ prefix)
        '/lib/', '/jetified-'
    )

    def is_library_path(path):
        """Check if path is library code"""
        normalized = '/' + path.replace('\\', '/')
        return any(lib in normalized for lib in lib_paths)

    # SMALI patterns for decompiled code
    patterns = {
        "java.util.Random":         re.compile(r'new-instance.*Ljava/util/Random;'),
        "kotlin.random.Random":     re.compile(r'Lkotlin/random/RandomKt;->Random\('),
        "Math.random()":            re.compile(r'Ljava/lang/Math;->random\(\)'),
        "ThreadLocalRandom":        re.compile(r'ThreadLocalRandom'),
    }

    issues = []
    for root, _, files in os.walk(base):
        for fn in files:
            if not fn.endswith('.smali'):
                continue
            path = os.path.join(root, fn)
            rel = os.path.relpath(path, base)

            # Skip library code
            if is_library_path(rel):
                continue

            try:
                content = open(path, errors='ignore').read()
                lines = content.splitlines()
            except:
                continue

            for i, line in enumerate(lines, 1):
                for label, pat in patterns.items():
                    if pat.search(line):
                        # Check if seeded with currentTimeMillis (CRITICAL vulnerability)
                        is_predictable_seed = False
                        context_start = max(0, i - 5)
                        context_end = min(len(lines), i + 5)
                        context = '\n'.join(lines[context_start:context_end])

                        if 'currentTimeMillis' in context:
                            is_predictable_seed = True
                            label = f"{label} with currentTimeMillis seed (CRITICAL)"

                        snippet = html.escape(line.strip())
                        link = (
                            f'<a href="file://{html.escape(path)}">'
                            f'{html.escape(rel)}:{i}</a>'
                        )

                        # Add severity indicator
                        severity = " * " if is_predictable_seed else "HIGH"
                        severity_color = "#dc3545" if is_predictable_seed else "#fd7e14"

                        issues.append(
                            f"{link} – "
                            f'<span style="display:inline-block; padding:2px 6px; background:{severity_color}; color:white; border-radius:3px; font-size:10px; font-weight:600; margin-right:5px;">{severity}</span>'
                            f"<code>{label} → {snippet}</code>"
                        )
                        break
                else:
                    continue
                break  # only first hit per file

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0204/' target='_blank'>MASTG-TEST-0204: Insecure Random API Usage</a></div>"

    if not issues:
        return True, f"None{mastg_ref}"

    # Sort issues: CRITICAL first, then HIGH
    issues_critical = [i for i in issues if 'CRITICAL' in i]
    issues_high = [i for i in issues if 'HIGH' in i]
    issues = issues_critical + issues_high

    result = []
    result.append(f"<div style='margin:5px 0'><strong>Insecure random usage found:</strong> {len(issues)}</div>")
    result.extend(issues)
    result.append(mastg_ref)

    return False, "<br>\n".join(result)
    
def check_insecure_fingerprint_api(base):
    """
    MASTG-TEST: Testing Insecure Biometric Authentication Implementation

    Checks for critical biometric vulnerabilities according to OWASP MASTG:

    CRITICAL: authenticate() with null CryptoObject - allows Frida bypass attacks
    FAIL: Deprecated FingerprintManager API usage
    WARN: BiometricPrompt/FingerprintManager without crypto binding detected

    Checks BOTH deprecated FingerprintManager AND modern BiometricPrompt APIs.

    MASTG Reference: https://github.com/OWASP/owasp-mastg/blob/master/Document/0x05f-Testing-Local-Authentication.md
    """
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0018/' target='_blank'>MASTG-TEST-0018: Testing Biometric Authentication</a></div>"

    # Library paths to exclude (only well-maintained framework libraries)
    # NOTE: For FingerprintManager detection, we want to catch deprecated API usage
    # even in third-party libraries since it affects the app's security posture
    lib_paths = (
        '/androidx/biometric/',  # Modern biometric library (safe)
        '/org/conscrypt/', '/lib/arm', '/lib/x86',  # Native libraries
    )

    def is_library_path(path):
        """Check if path is framework library code (androidx biometric only - NOT FingerprintManagerCompat)"""
        normalized = '/' + path.replace('\\', '/')
        return any(lib in normalized for lib in lib_paths)

    # Detection patterns for FingerprintManager (deprecated API) - includes BOTH platform AND compat wrapper
    # IMPORTANT: FingerprintManagerCompat is just a wrapper around the same insecure deprecated API
    fingerprint_manager_pat = re.compile(
        r'(Landroid/hardware/fingerprint/FingerprintManager;|'
        r'Landroidx/core/hardware/fingerprint/FingerprintManagerCompat;|'
        r'Landroid/support/v4/hardware/fingerprint/FingerprintManagerCompat;)'
    )

    # Any authenticate() call pattern - matches BOTH platform and compat
    authenticate_call_pattern = re.compile(
        r'invoke-virtual.*(Landroid/hardware/fingerprint/FingerprintManager;->authenticate|'
        r'Landroidx/core/hardware/fingerprint/FingerprintManagerCompat;->authenticate|'
        r'Landroid/support/v4/hardware/fingerprint/FingerprintManagerCompat;->authenticate)'
    )

    # Null parameter pattern (const/4 vX, 0x0 before authenticate call)
    null_pattern = re.compile(r'const/4\s+v\d+,\s*0x0')

    # Secure: CryptoObject used - matches BOTH platform and compat
    crypto_object_pattern = re.compile(
        r'(Landroid/hardware/fingerprint/FingerprintManager\$CryptoObject;|'
        r'Landroidx/core/hardware/fingerprint/FingerprintManagerCompat\$CryptoObject;|'
        r'Landroid/support/v4/hardware/fingerprint/FingerprintManagerCompat\$CryptoObject;)'
    )

    # KeyStore integration patterns (secure implementation)
    keystore_patterns = [
        re.compile(r'setUserAuthenticationRequired'),
        re.compile(r'setInvalidatedByBiometricEnrollment'),
    ]

    # Categorize findings
    fingerprint_files = set()
    null_crypto_files = []  # CRITICAL - allows Frida bypass
    crypto_files = set()  # SECURE - uses CryptoObject
    keystore_files = set()  # SECURE - KeyStore integration

    for root, _, files in os.walk(base):
        for fn in files:
            if not fn.endswith('.smali'):
                continue
            path = os.path.join(root, fn)
            rel_path = os.path.relpath(path, base)

            # Skip library code
            if is_library_path(rel_path):
                continue

            try:
                content = open(path, errors='ignore').read()
                lines = content.splitlines()
            except:
                continue

            # Check for FingerprintManager usage (deprecated)
            if fingerprint_manager_pat.search(content):
                fingerprint_files.add(rel_path)

            # Check for CryptoObject usage (secure)
            if crypto_object_pattern.search(content):
                crypto_files.add(rel_path)

            # Check for KeyStore integration (secure)
            for pat in keystore_patterns:
                if pat.search(content):
                    keystore_files.add(rel_path)
                    break

            # Check for null CryptoObject vulnerability (CRITICAL)
            # Look for authenticate() calls and check if null is passed (look back 10 lines for const/4 vX, 0x0)
            for i, line in enumerate(lines, 1):
                if authenticate_call_pattern.search(line):
                    # Check previous lines (up to 10 lines back) for null assignment
                    context_start = max(0, i - 10)
                    context = lines[context_start:i]
                    has_null = any(null_pattern.search(ctx_line) for ctx_line in context)

                    # If we find null in context OR no CryptoObject construction, flag it
                    # Check if CryptoObject is constructed in this file
                    file_has_crypto_obj = rel_path in crypto_files

                    if has_null or not file_has_crypto_obj:
                        snippet = html.escape(line.strip()[:120])
                        link = f'<a href="file://{html.escape(path)}">{html.escape(rel_path)}:{i}</a>'
                        null_crypto_files.append((link, snippet))
                        break

    # No FingerprintManager API usage detected
    if not fingerprint_files:
        return 'PASS', "<div>No FingerprintManager API usage detected (deprecated API not found)</div>" + mastg_ref

    # CRITICAL: null CryptoObject detected - allows Frida bypass
    if null_crypto_files:
        lines = [
            "<div><strong style='color:#dc2626;'>FingerprintManager.authenticate() with NULL CryptoObject</strong></div>",
            f"<div style='margin-top:8px;'><strong>Vulnerable Code ({len(null_crypto_files)} file(s)):</strong></div>"
        ]
        for link, snippet in null_crypto_files[:15]:
            lines.append(f"{link} → <code>{snippet}</code>")

        lines.append("<br><div><strong>OWASP Reference:</strong> ")
        lines.append("<a href='https://mas.owasp.org/MASTG/knowledge/android/MASVS-AUTH/MASTG-KNOW-0002/' target='_blank'>")
        lines.append("MASTG-KNOW-0002: FingerprintManager Security</a></div>")

        return 'FAIL', "<br>\n".join(lines) + mastg_ref

    # FingerprintManager used - check for crypto binding
    if crypto_files or keystore_files:
        # Potentially secure - but still using deprecated API
        lines = [
            f"<div><strong style='color:#d97706;'>WARNING: Deprecated FingerprintManager API with crypto binding detected</strong></div>",
            f"<div style='margin-top:8px;'>Found in {len(fingerprint_files)} file(s)</div>",
            "<div style='margin-top:8px;'><strong>Status:</strong></div>",
            "<ul style='margin-left:20px;'>"
        ]

        if crypto_files:
            lines.append(f"<li>CryptoObject usage detected in {len(crypto_files)} file(s)</li>")
        if keystore_files:
            lines.append(f"<li>KeyStore integration detected in {len(keystore_files)} file(s)</li>")

        lines.append("</ul>")
        lines.append("<div style='margin-top:8px;'><strong>Issue:</strong> FingerprintManager is deprecated since Android 9.0 (API 28)</div>")
        lines.append("<div><strong>Recommendation:</strong> Migrate to androidx.biometric.BiometricPrompt</div>")

        lines.append("<div style='margin-top:8px;'><strong>Files using FingerprintManager:</strong></div>")
        for rel in sorted(fingerprint_files)[:15]:
            full = os.path.abspath(os.path.join(base, rel))
            lines.append(f'<a href="file://{html.escape(full)}">{html.escape(rel)}</a>')

        lines.append("<br><div><strong>Migration Guide:</strong></div>")
        lines.append("<ul style='margin-left:20px;'>")
        lines.append("<li>Replace FingerprintManager with BiometricPrompt</li>")
        lines.append("<li>Use BiometricPrompt.CryptoObject instead</li>")
        lines.append("<li>Maintain KeyStore crypto binding (setUserAuthenticationRequired)</li>")
        lines.append("</ul>")

        return 'WARN', "<br>\n".join(lines) + mastg_ref

    # FingerprintManager used without crypto binding - potentially vulnerable
    lines = [
        f"<div><strong style='color:#dc2626;'>FAIL: FingerprintManager without cryptographic binding</strong></div>",
        f"<div style='margin-top:8px;'>Found in {len(fingerprint_files)} file(s)</div>",
        "<div style='margin-top:8px;'><strong>Security Risks:</strong></div>",
        "<ul style='margin-left:20px;'>",
        "<li>Likely using null CryptoObject (allows Frida bypass)</li>",
        "<li>Deprecated API since Android 9.0 (API 28)</li>",
        "<li>No KeyStore crypto binding detected</li>",
        "</ul>",
        "<div style='margin-top:8px;'><strong>Files:</strong></div>"
    ]

    for rel in sorted(fingerprint_files)[:15]:
        full = os.path.abspath(os.path.join(base, rel))
        lines.append(f'<a href="file://{html.escape(full)}">{html.escape(rel)}</a>')

    lines.append("<br><div><strong>Required Actions:</strong></div>")
    lines.append("<ol style='margin-left:20px;'>")
    lines.append("<li>Manual review required - check if authenticate() uses CryptoObject or null</li>")
    lines.append("<li>If null: VULNERABILITY - implement CryptoObject with KeyStore</li>")
    lines.append("<li>Migrate to androidx.biometric.BiometricPrompt</li>")
    lines.append("</ol>")

    return 'FAIL', "<br>\n".join(lines) + mastg_ref

    
def check_tls_versions(base):
    """
    FAIL only if app code (non-library) explicitly:
      • SSLContext.getInstance("TLSv1" or "TLSv1.1"), or
      • enables TLSv1/1.1 via setEnabledProtocols(...) / SSLParameters.setProtocols(...)
    PASS (Info) if matches are only in library code (okhttp/conscrypt/react/etc.).
    PASS if no suspicious usage found.
    """
    lib_ns = (
        '/androidx/', '/org/chromium/', '/com/google/', '/com/facebook/',
        '/com/reactnativecommunity/', '/kotlin/', '/kotlinx/',
        '/okhttp3/', '/retrofit2/', '/org/conscrypt/', '/lib/', '/jetified-'
    )

    # Quick file-level filters
    files_tls10 = set(grep_code(base, r'"TLSv1"'))
    files_tls11 = set(grep_code(base, r'"TLSv1\.1"'))
    candidates = (files_tls10 | files_tls11)

    if not candidates:
        return True, "None"

    def is_library_path(rel):
        rp = '/' + rel.replace('\\', '/')
        return any(ns in rp for ns in lib_ns)

    hard_hits = []   # direct risky usage in app code
    soft_hits = []   # library-only mentions

    # Patterns that imply real use, not just enum/constants
    use_patterns = [
        r'SSLContext\.getInstance\s*\(\s*"TLSv1(\.1)?"\s*\)',                      # Java
        r'Ljavax/net/ssl/SSLContext;->getInstance\(Ljava/lang/String;\)',          # smali call
        r'\.setEnabledProtocols\s*\(',                                             # Java SSLSocket/SSLEngine
        r'Ljavax/net/ssl/SSLEngine;->setEnabledProtocols\(\[Ljava/lang/String;\)',# smali
        r'Ljavax/net/ssl/SSLParameters;->setProtocols\(\[Ljava/lang/String;\)',   # smali
        r'SSLParameters\.setProtocols\s*\(',
    ]

    for rel in sorted(candidates):
        path = os.path.join(base, rel)
        try:
            txt = open(path, errors='ignore').read()
        except Exception:
            txt = ""

        # Decide library vs app first
        is_lib = is_library_path(rel)

        # Heuristic: only call it "use" if a TLSv1/1.1 string appears in the SAME FILE
        # as an SSLContext.getInstance(...) or *EnabledProtocols/SSLParameters.setProtocols call.
        suspicious = any(re.search(p, txt) for p in use_patterns)

        if suspicious and not is_lib:
            # find a line number to link
            line_no = None
            for i, line in enumerate(txt.splitlines(), 1):
                if ('TLSv1' in line) or ('TLSv1.1' in line) or re.search(r'setEnabledProtocols|setProtocols|SSLContext\.getInstance', line):
                    line_no = i; break
            href = f'file://{os.path.abspath(path)}' + (f':{line_no}' if line_no else '')
            hard_hits.append(f'<a href="{href}">{html.escape(rel)}{":" + str(line_no) if line_no else ""}</a>')
        else:
            soft_hits.append(rel)

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0020/' target='_blank'>MASTG-TEST-0020: Testing the TLS Settings</a></div>"

    if hard_hits:
        return False, (
            "App code may use legacy TLS:\n"
            "• " + "<br>• ".join(hard_hits) + mastg_ref
        )

    # No app-owned risky usage; only library mentions or nothing
    if soft_hits:
        # Trim to a few examples to keep the report tidy
        examples = [h for h in soft_hits if not is_library_path(h)]
        libs_only = len(examples) == 0
        note = "Only library constants/enums mention TLSv1/1.1 (e.g., OkHttp/Conscrypt/React Native)." \
               if libs_only else "Mentions found, but no enabling/initialization detected."
        return True, note + mastg_ref

    return True, f"None{mastg_ref}"

def check_frida_tls_negotiation(base, wait_secs=12):
    """
    Dynamic TLS negotiation monitoring via USB+Frida CLI.
    Returns INFO status with observational data about TLS usage during the test session.

    This test passively observes TLS negotiation - it does NOT force the app to use legacy TLS.
    Results are informational only and depend on which network features were triggered.

    Reports:
      • If TLS 1.0/1.1 was actually negotiated (red alert)
      • If TLS 1.0/1.1 was enabled by app but not used (orange warning)
      • If only modern TLS was observed (or no activity)

    Hooks:
      • OkHttp RealConnection.connectTls* (reports negotiated TLS)
      • JSSE/Conscrypt SSLSocket.startHandshake & setEnabledProtocols
      • Native BoringSSL SSL_do_handshake / SSL_connect (WebView/Chromium/Cronet)
    """
    # 1) resolve installed package from manifest prefix
    manifest = os.path.join(base, 'AndroidManifest.xml')
    pkg_prefix = ET.parse(manifest).getroot().attrib.get('package', '')
    out = subprocess.check_output(['adb','shell','pm','list','packages', pkg_prefix], text=True)
    pkgs = [l.split(':',1)[1] for l in out.splitlines() if l.startswith('package:')]
    if not pkgs:
        raise RuntimeError(f"No installed package matching {pkg_prefix!r}")
    spawn_name = pkgs[0]

    # 2) force-stop before instrumentation
    subprocess.run(['adb','shell','am','force-stop', spawn_name],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 3) Frida JS – prints "VERDICT: …" lines we parse below
    jscode = r"""
    (function () {
      // ---- Java layer -------------------------------------------------
      function safe(fn) { try { fn(); } catch (e) {} }

      safe(function () {
        Java.perform(function () {

          // SSLContext.getInstance logging (visibility)
          safe(function () {
            var SC = Java.use('javax.net.ssl.SSLContext');
            SC.getInstance.overload('java.lang.String').implementation = function (alg) {
              console.log('[TLS-INIT] SSLContext.getInstance("' + alg + '")');
              return this.getInstance(alg);
            };
          });

          // OkHttp negotiated TLS (3.x/4.x)
          safe(function () {
            var RC = Java.use('okhttp3.internal.connection.RealConnection');
            function hook(ov) {
              ov.implementation = function () {
                var ret = ov.apply(this, arguments);
                try {
                  var hs = this.handshake();
                  if (hs) {
                    var tv = hs.tlsVersion();
                    var cs = hs.cipherSuite();
                    var tname = tv ? tv.javaName() : '(null)';
                    var cname = cs ? cs.javaName() : '(null)';
                    console.log('[OKHTTP] tls=' + tname + ' cipher=' + cname);
                    if (tname === 'TLSv1' || tname === 'TLSv1.1') {
                      console.log('VERDICT: LEGACY_NEGOTIATED (OkHttp)');
                    }
                  }
                } catch (e) {}
                return ret;
              };
            }
            if (RC['connectTls$okhttp']) RC['connectTls$okhttp'].overloads.forEach(hook);
            else if (RC.connectTls)      RC.connectTls.overloads.forEach(hook);
          });

          // Helpers for JSSE/Conscrypt sockets
          function hookEnabledProtocols(className) {
            safe(function () {
              var C = Java.use(className);
              if (!C.setEnabledProtocols || !C.setEnabledProtocols.overloads) return;
              C.setEnabledProtocols.overloads.forEach(function (ov) {
                ov.implementation = function (arr) {
                  try {
                    // Read String[] -> JS list safely
                    var bad = false, listed = [];
                    for (var i = 0; i < arr.length; i++) {
                      var v = arr[i] + '';
                      listed.push(v);
                      if (v === 'TLSv1' || v === 'TLSv1.1') bad = true;
                    }
                    if (bad) {
                      console.log('VERDICT: LEGACY_ENABLED_BY_APP (' + className + ') ' + listed.join(','));
                    }
                  } catch (e) {}
                  return ov.call(this, arr);
                };
              });
              console.log('[TLS-INIT] hook ' + className + '.setEnabledProtocols');
            });
          }

          function hookStartHandshake(className) {
            safe(function () {
              var C = Java.use(className);
              if (!C.startHandshake) return;
              var orig = C.startHandshake;
              C.startHandshake.implementation = function () {
                var ret = orig.call(this);
                try {
                  var sess = this.getSession();
                  var proto = sess.getProtocol();
                  var cipher = sess.getCipherSuite();
                  console.log('[JSSE] ' + className + ' tls=' + proto + ' cipher=' + cipher);
                  if (proto === 'TLSv1' || proto === 'TLSv1.1') {
                    console.log('VERDICT: LEGACY_NEGOTIATED (' + className + ')');
                  }
                } catch (e) {}
                return ret;
              };
              console.log('[JSSE] hooked ' + className + '.startHandshake()');
            });
          }

          var impls = [
            'com.android.org.conscrypt.ConscryptFileDescriptorSocket',
            'com.android.org.conscrypt.OpenSSLSocketImpl',
            'com.android.org.conscrypt.Java8EngineSocket',
            'org.conscrypt.ConscryptFileDescriptorSocket',
            'com.google.android.gms.org.conscrypt.ConscryptFileDescriptorSocket'
          ];
          impls.forEach(hookEnabledProtocols);
          impls.forEach(hookStartHandshake);
        });
      });

      // ---- Native (BoringSSL) layer -----------------------------------
      safe(function () {
        var resolver = new ApiResolver('module');
        function str(p) { return (p && !p.isNull()) ? Memory.readUtf8String(p) : '(null)'; }
        var gvMap = {}, gcMap = {}, gcnMap = {};
        function cache(mod) {
          if (!gvMap[mod]) { var f = Module.findExportByName(mod, 'SSL_get_version'); if (f) gvMap[mod] = new NativeFunction(f, 'pointer', ['pointer']); }
          if (!gcMap[mod]) { var f = Module.findExportByName(mod, 'SSL_get_current_cipher'); if (f) gcMap[mod] = new NativeFunction(f, 'pointer', ['pointer']); }
          if (!gcnMap[mod]){ var f = Module.findExportByName(mod, 'SSL_CIPHER_get_name'); if (f) gcnMap[mod] = new NativeFunction(f, 'pointer', ['pointer']); }
        }
        function attach(sym) {
          cache(sym.moduleName);
          Interceptor.attach(sym.address, {
            onEnter: function (args) { this.ssl = args[0]; this.mod = sym.moduleName; },
            onLeave: function () {
              try {
                var ver = gvMap[this.mod] ? str(gvMap[this.mod](this.ssl)) : '(unknown)';
                if (ver === 'TLSv1' || ver === 'TLSv1.1') {
                  console.log('VERDICT: LEGACY_NEGOTIATED (native:' + this.mod + ')');
                }
              } catch (e) {}
            }
          });
        }
        function arm() {
          ['exports:*!SSL_do_handshake', 'exports:*!SSL_connect'].forEach(function (pat) {
            try { resolver.enumerateMatches(pat, { onMatch: attach, onComplete: function () {} }); } catch (e) {}
          });
          console.log('[NATIVE TLS] hooks armed');
        }
        arm();
        var dlopen = Module.findExportByName(null, 'android_dlopen_ext') || Module.findExportByName(null, 'dlopen');
        if (dlopen) {
          Interceptor.attach(dlopen, {
            onEnter: function (args) {
              this.path = args[0].isNull() ? null : Memory.readUtf8String(args[0]);
            },
            onLeave: function () {
              if (this.path && /ssl|boringssl|cronet|webview/i.test(this.path)) arm();
            }
          });
        }
      });
    })();
    """

    # 4) write JS, launch frida (send Enter to resume the spawned app)
    tmp = tempfile.NamedTemporaryFile(suffix=".js", delete=False)
    tmp.write(jscode.encode()); tmp.flush(); tmp.close()

    proc = subprocess.Popen(
        ['frida', '-l', tmp.name, '-U', '-f', spawn_name],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    try:
        proc.stdin.write('\n')
        proc.stdin.flush()
    except Exception:
        pass

    # 5) Interactive mode - wait for user to finish testing
    instructions = [
        f"App '{spawn_name}' is now running with Frida instrumentation",
        "Use the app and trigger network connections",
        "Navigate to features that use HTTPS/TLS (login, API calls, etc.)",
        "Watch the Frida output below for TLS activity"
    ]
    logs = interactive_frida_monitor(proc, "TLS NEGOTIATION", instructions)

    # Parse collected logs for verdicts
    legacy_neg = any('VERDICT: LEGACY_NEGOTIATED' in line for line in logs)
    legacy_enabled = any('VERDICT: LEGACY_ENABLED_BY_APP' in line for line in logs)

    # 6) cleanup
    proc.terminate()
    subprocess.run(['adb','shell','am','force-stop', spawn_name],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.unlink(tmp.name)

    # 7) Count different types of activity
    if logs:
        tls_inits = sum(1 for l in logs if '[TLS-INIT]' in l)
        okhttp_calls = sum(1 for l in logs if '[OKHTTP]' in l)
        jsse_calls = sum(1 for l in logs if '[JSSE]' in l)
        native_calls = sum(1 for l in logs if '[NATIVE TLS]' in l or 'VERDICT: LEGACY_NEGOTIATED (native' in l)
    else:
        tls_inits = okhttp_calls = jsse_calls = native_calls = 0

    # 8) Build informational report
    summary_parts = []

    if legacy_neg:
        summary_parts.append("<div style='color:#dc3545'><strong>TLS 1.0/1.1 WAS NEGOTIATED</strong></div>")
        summary_parts.append("<div>The app successfully connected using legacy TLS during this test session!</div>")
    elif legacy_enabled:
        summary_parts.append("<div style='color:#ff8c00'><strong>TLS 1.0/1.1 IS ENABLED</strong></div>")
        summary_parts.append("<div>The app explicitly enables legacy TLS versions (via setEnabledProtocols) but didn't negotiate them during this session</div>")
    else:
        # Check if actual network connections happened
        if okhttp_calls > 0 or jsse_calls > 0 or native_calls > 0:
            summary_parts.append("<div><strong>No legacy TLS detected</strong></div>")
            summary_parts.append("<div>App made network connections using modern TLS during this test session</div>")
        elif tls_inits > 0:
            summary_parts.append("<div><strong>TLS initialized but no network activity</strong></div>")
            summary_parts.append("<div>TLS context was created but no actual network handshakes occurred - trigger more network features in the app</div>")
        else:
            summary_parts.append("<div><strong>No TLS activity detected</strong></div>")
            summary_parts.append("<div>App may not use network, or no connections were triggered during this test session</div>")

    summary_parts.append(f"<div style='margin-top:8px; font-size:11px; color:#666'>")
    summary_parts.append(f"Captured: {tls_inits} TLS inits")
    if okhttp_calls: summary_parts.append(f", {okhttp_calls} OkHttp connections")
    if jsse_calls: summary_parts.append(f", {jsse_calls} JSSE handshakes")
    if native_calls: summary_parts.append(f", {native_calls} native SSL calls")
    summary_parts.append("</div>")

    # Instructions if no network connections detected
    if not legacy_neg and not legacy_enabled and okhttp_calls == 0 and jsse_calls == 0 and native_calls == 0:
        summary_parts.append(
            "<div style='margin-top:8px; padding:8px; background:#fff3cd; border-left:3px solid #ffc107; font-size:11px'>"
            "<strong>Test Incomplete:</strong> No network connections detected during monitoring.<br>"
            "<strong>Action Required:</strong> While the app is running in Frida, manually trigger actions that make network requests:<br>"
            "• Login/logout<br>"
            "• Load content/refresh feeds<br>"
            "• Sync data<br>"
            "• Any API calls<br>"
            "Then check if any VERDICT lines appear in the output."
            "</div>"
        )

    # MASTG reference
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0020/' target='_blank'>MASTG-TEST-0020: Testing the TLS Settings</a></div>"
    summary_parts.append(mastg_ref)

    if logs:
        detail = (
            "<div>" + "".join(summary_parts) + "</div>" +
            "<details style='margin-top:8px'><summary style='cursor:pointer; font-size:11px; color:#0066cc'>View full Frida output</summary>" +
            "<pre style='white-space:pre-wrap; font-size:9px; max-height:300px; overflow-y:auto; background:#f5f5f5; padding:6px'>\n" +
            "\n".join(logs[-600:]) +  # cap output
            "\n</pre></details>"
        )
    else:
        detail = (
            "<div style='padding:8px; background:#f8d7da; border-left:3px solid #dc3545; font-size:11px'>"
            "<strong>No output captured</strong><br>"
            "Possible issues:<br>"
            "• Frida hooks didn't attach (check if app uses native SSL)<br>"
            "• App crashed on startup<br>"
            "• ADB/USB connection issues<br>"
            "<br><strong>Try:</strong> Increase wait time or check Frida/ADB setup"
            "</div>" + mastg_ref
        )

    # Return INFO status (not PASS/FAIL) - this is observational data
    return ('INFO', detail)

def check_frida_pinning(base, wait_secs=15):
    """
    Dynamic pinning *detection* via USB+Frida CLI (inline JS):
      • Discovers installed package
      • Force-stops, writes JS to temp file, launches `frida -l tmp.js -U -f pkg`
      • Collects send({ev:…, class:…, method:…, host:…}) messages for wait_secs
      • Monitors ALL network requests (pinned and non-pinned)
      • Terminates Frida, stops app, returns ('INFO', HTML-report)
    """
    # 1) pkg from manifest
    manifest = os.path.join(base, 'AndroidManifest.xml')
    pkg_prefix = ET.parse(manifest).getroot().attrib.get('package','')

    # 2) find installed package
    out = subprocess.check_output(
        ['adb','shell','pm','list','packages', pkg_prefix], text=True
    )
    pkgs = [l.split(':',1)[1] for l in out.splitlines() if l.startswith('package:')]
    if not pkgs:
        raise RuntimeError(f"No package matching {pkg_prefix}")
    spawn_name = pkgs[0]

    # 3) force-stop
    subprocess.run(
        ['adb','shell','am','force-stop', spawn_name],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    # 4) inline JS detection script with hostname extraction
    jscode = r"""
    setImmediate(function install(){
      if (!Java.available) return setTimeout(install,100);
      Java.perform(function(){
        send("🔗 Pinning detection + network monitoring hooks installed");

        // Extract hostname from URL string
        function extractHost(urlString) {
          try {
            if (!urlString) return null;
            if (urlString.indexOf('://') > 0) {
              var host = urlString.split('://')[1].split('/')[0].split(':')[0];
              return host;
            }
            return urlString.split('/')[0].split(':')[0];
          } catch(e) {
            return null;
          }
        }

        // Hook pinning methods WITH hostname extraction
        function hookPinWithHost(className, method, sig, hostArgIdx){
          try {
            var C = Java.use(className);
            C[method].overload.apply(C[method], sig).implementation = function(){
              var host = null;
              try {
                if (hostArgIdx !== undefined && arguments[hostArgIdx]) {
                  var arg = arguments[hostArgIdx];
                  if (typeof arg === 'string') {
                    host = arg;
                  } else if (arg && arg.getPeerHost) {
                    host = arg.getPeerHost();
                  } else if (arg && arg.toString) {
                    host = arg.toString();
                  }
                }
              } catch(e) {}

              send({ev:"PIN", class:className, method:method, host:host});
              return this[method].apply(this, arguments);
            };
          } catch(e){}
        }

        // Simple hook without hostname (for methods that don't expose it easily)
        function hookPin(className, method, sig){
          try {
            var C = Java.use(className);
            C[method].overload.apply(C[method], sig).implementation = function(){
              send({ev:"PIN", class:className, method:method, host:null});
              return this[method].apply(this, arguments);
            };
          } catch(e){}
        }

        // 1) X509TrustManager (no hostname in signature)
        hookPin("javax.net.ssl.X509TrustManager","checkServerTrusted",["[Ljava.security.cert.X509Certificate;","java.lang.String"]);
        hookPin("javax.net.ssl.X509TrustManager","checkClientTrusted",["[Ljava.security.cert.X509Certificate;","java.lang.String"]);

        // 2) CertificateFactory.generateCertificate
        hookPin("java.security.cert.CertificateFactory","generateCertificate",["java.io.InputStream"]);

        // 3) SSLContext.init
        hookPin("javax.net.ssl.SSLContext","init",["[Ljavax.net.ssl.KeyManager;","[Ljavax.net.ssl.TrustManager;","java.security.SecureRandom"]);

        // 4) okhttp3.CertificatePinner.check - hostname is first arg!
        hookPinWithHost("okhttp3.CertificatePinner","check",["java.lang.String","java.util.List"], 0);
        hookPinWithHost("okhttp3.CertificatePinner","check",["java.lang.String","java.security.cert.Certificate"], 0);
        hookPinWithHost("okhttp3.CertificatePinner","check",["java.lang.String","[Ljava.security.cert.Certificate;"], 0);
        hookPinWithHost("okhttp3.CertificatePinner","check$okhttp",["java.lang.String","kotlin.jvm.functions.Function0"], 0);

        // 5) Trustkit - hostname is first arg
        hookPinWithHost("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier","verify",["java.lang.String","javax.net.ssl.SSLSession"], 0);
        hookPinWithHost("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier","verify",["java.lang.String","java.security.cert.X509Certificate"], 0);
        hookPin("com.datatheorem.android.trustkit.pinning.PinningTrustManager","checkServerTrusted",["[Ljava.security.cert.X509Certificate;","java.lang.String"]);

        // 6) Conscrypt TrustManagerImpl - authType (3rd arg) may contain hostname
        hookPinWithHost("com.android.org.conscrypt.TrustManagerImpl","checkTrustedRecursive",["java.util.List","[B","[B","java.lang.String","boolean","java.util.List","java.util.List","java.util.List"], 3);
        hookPinWithHost("com.android.org.conscrypt.TrustManagerImpl","verifyChain",["java.util.List","java.util.List","java.lang.String","boolean","[B","[B"], 2);

        // 7) HostnameVerifier.verify - hostname is first arg
        hookPinWithHost("javax.net.ssl.HostnameVerifier","verify",["java.lang.String","javax.net.ssl.SSLSession"], 0);

        // 8) HttpsURLConnection.setDefaultHostnameVerifier
        hookPin("javax.net.ssl.HttpsURLConnection","setDefaultHostnameVerifier",["javax.net.ssl.HostnameVerifier"]);

        // 9) Apache & Cordova WebViewClient
        hookPin("android.webkit.WebViewClient","onReceivedSslError",["android.webkit.WebView","android.webkit.SslErrorHandler","android.net.http.SslError"]);
        hookPin("android.webkit.WebViewClient","onReceivedError",["android.webkit.WebView","android.webkit.WebResourceRequest","android.webkit.WebResourceError"]);

        // 10) PhoneGap sslCertificateChecker
        hookPin("nl.xservices.plugins.sslCertificateChecker","execute",["java.lang.String","org.json.JSONArray","org.apache.cordova.CallbackContext"]);

        // 11) IBM Worklight & MobileFirst - hostname is first arg
        hookPinWithHost("com.worklight.wlclient.api.WLClient","pinTrustedCertificatePublicKey",["java.lang.String"], 0);
        hookPin("com.worklight.wlclient.api.WLClient","pinTrustedCertificatePublicKey",["[Ljava.lang.String;"]);
        hookPinWithHost("com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning","verify",["java.lang.String","javax.net.ssl.SSLSocket"], 0);
        hookPinWithHost("com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning","verify",["java.lang.String","java.security.cert.X509Certificate"], 0);
        hookPinWithHost("com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning","verify",["java.lang.String","[Ljava.lang.String;","[Ljava.lang.String;"], 0);
        hookPinWithHost("com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning","verify",["java.lang.String","javax.net.ssl.SSLSession"], 0);

        // 12) Netty FingerprintTrustManagerFactory - hostname is first arg
        hookPinWithHost("io.netty.handler.ssl.util.FingerprintTrustManagerFactory","checkTrusted",["java.lang.String","java.util.List"], 0);

        // 13) Squareup (pre-3.x) - hostname is first arg
        hookPinWithHost("com.squareup.okhttp.CertificatePinner","check",["java.lang.String","java.security.cert.Certificate"], 0);
        hookPinWithHost("com.squareup.okhttp.CertificatePinner","check",["java.lang.String","java.util.List"], 0);
        hookPinWithHost("com.squareup.okhttp.internal.tls.OkHostnameVerifier","verify",["java.lang.String","java.security.cert.X509Certificate"], 0);
        hookPinWithHost("com.squareup.okhttp.internal.tls.OkHostnameVerifier","verify",["java.lang.String","javax.net.ssl.SSLSession"], 0);

        // 14) Chromium Cronet - hostname is first arg
        hookPinWithHost("org.chromium.net.impl.CronetEngineBuilderImpl","addPublicKeyPins",["java.lang.String","java.util.Set","boolean","java.util.Date"], 0);

        // 15) Flutter plugins - hostname is first arg
        hookPinWithHost("diefferson.http_certificate_pinning.HttpCertificatePinning","checkConnexion",["java.lang.String","java.util.List","java.util.Map","int","java.lang.String"], 0);
        hookPinWithHost("com.macif.plugin.sslpinningplugin.SslPinningPlugin","checkConnexion",["java.lang.String","java.util.List","java.util.Map","int","java.lang.String"], 0);

        // === NETWORK REQUEST MONITORING (for non-pinned domains) ===

        // OkHttp3 Request execution
        try {
          var RealCall = Java.use("okhttp3.internal.connection.RealCall");
          RealCall.execute.implementation = function() {
            try {
              var req = this.request();
              if (req) {
                var url = req.url();
                if (url) {
                  var host = url.host();
                  send({ev:"NET", lib:"OkHttp3", host:host});
                }
              }
            } catch(e) {}
            return this.execute();
          };
        } catch(e) {}

        // OkHttp (old version)
        try {
          var Call = Java.use("com.squareup.okhttp.Call");
          Call.execute.implementation = function() {
            try {
              var req = this.request();
              if (req) {
                var url = req.httpUrl();
                if (url) {
                  var host = url.host();
                  send({ev:"NET", lib:"OkHttp", host:host});
                }
              }
            } catch(e) {}
            return this.execute();
          };
        } catch(e) {}

        // HttpURLConnection
        try {
          var URL = Java.use("java.net.URL");
          var HttpURLConnection = Java.use("java.net.HttpURLConnection");
          URL.openConnection.overload().implementation = function() {
            var conn = this.openConnection();
            try {
              var host = this.getHost();
              if (host) {
                send({ev:"NET", lib:"HttpURLConnection", host:host});
              }
            } catch(e) {}
            return conn;
          };
        } catch(e) {}

        // Apache HttpClient (legacy)
        try {
          var DefaultHttpClient = Java.use("org.apache.http.impl.client.DefaultHttpClient");
          DefaultHttpClient.execute.overload("org.apache.http.client.methods.HttpUriRequest").implementation = function(req) {
            try {
              var uri = req.getURI();
              if (uri) {
                var host = uri.getHost();
                if (host) {
                  send({ev:"NET", lib:"ApacheHttp", host:host});
                }
              }
            } catch(e) {}
            return this.execute(req);
          };
        } catch(e) {}

        // Retrofit (uses OkHttp, but track separately)
        try {
          var ServiceMethod = Java.use("retrofit2.ServiceMethod");
          ServiceMethod.invoke.implementation = function(args) {
            try {
              var requestFactory = this.requestFactory.value;
              if (requestFactory && requestFactory.baseUrl) {
                var host = extractHost(requestFactory.baseUrl.toString());
                if (host) {
                  send({ev:"NET", lib:"Retrofit", host:host});
                }
              }
            } catch(e) {}
            return this.invoke(args);
          };
        } catch(e) {}
      });
    });
    """

    # 5) spawn Frida CLI with our script
    tmp = tempfile.NamedTemporaryFile(suffix=".js", delete=False)
    tmp.write(jscode.encode()); tmp.flush(); tmp.close()

    proc = subprocess.Popen(
      ['frida','-l', tmp.name, '-U','-f', spawn_name],
      stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )

    # 6) Interactive collection with user prompt
    instructions = [
        f"App '{spawn_name}' is running with certificate pinning + network monitoring",
        "Use the app and trigger HTTPS/network connections",
        "Try features that connect to servers (login, sync, API calls)",
        "Collecting both pinned and non-pinned network activity..."
    ]
    all_output = interactive_frida_monitor(proc, "CERTIFICATE PINNING ANALYSIS", instructions)

    # Parse collected logs
    pinned_hosts = set()  # Hosts with cert pinning
    non_pinned_hosts = set()  # Hosts without cert pinning
    pinning_methods = set()
    logs = []  # Store all output for collapsible section

    for line in all_output:
        logs.append(line)  # Collect all output for later display

        if 'message:' not in line:
            continue
        part = line.split('message:',1)[1].split('data:',1)[0].strip()
        try:
            msg = ast.literal_eval(part)
            payload = msg.get('payload', {})

            # Pinning detection
            if payload.get('ev') == 'PIN':
                cls = payload.get('class', '')
                mth = payload.get('method', '')
                host = payload.get('host')

                pinning_methods.add(f"{cls}.{mth}()")
                if host and host != 'null':
                    pinned_hosts.add(host)

            # Network request detection (non-pinned)
            elif payload.get('ev') == 'NET':
                host = payload.get('host')
                if host and host != 'null':
                    non_pinned_hosts.add(host)

        except:
            pass

    # Remove pinned hosts from non-pinned set (they were categorized as pinned)
    non_pinned_hosts = non_pinned_hosts - pinned_hosts

    # 7) cleanup
    proc.terminate()
    subprocess.run(['adb','shell','am','force-stop', spawn_name],
                   stdout=subprocess.DEVNULL)
    os.unlink(tmp.name)

    # 8) Build detailed report
    detail_parts = []

    # Pinned domains section
    if pinned_hosts:
        detail_parts.append("<div><strong>Domains WITH Certificate Pinning:</strong></div>")
        detail_parts.append("<div class='detail-list-item'>")
        for host in sorted(pinned_hosts):
            detail_parts.append(f"▹ <code style='color:#28a745'>{html.escape(host)}</code><br>")
        detail_parts.append("</div><br>")

    # Non-pinned domains section
    if non_pinned_hosts:
        detail_parts.append("<div><strong>Domains WITHOUT Certificate Pinning:</strong></div>")
        detail_parts.append("<div class='detail-list-item'>")
        for host in sorted(non_pinned_hosts):
            detail_parts.append(f"▹ <code style='color:#dc3545'>{html.escape(host)}</code><br>")
        detail_parts.append("</div><br>")

    # Pinning methods detected
    if pinning_methods:
        detail_parts.append("<div><strong>Pinning Methods Detected:</strong></div>")
        detail_parts.append("<div class='detail-list-item'>")
        for h in sorted(pinning_methods):
            detail_parts.append(f"▹ <code>{html.escape(h)}</code><br>")
        detail_parts.append("</div>")

    # MASTG reference
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0019/' target='_blank'>MASTG-TEST-0019: Testing Custom Certificate Stores and Certificate Pinning</a></div>"
    detail_parts.append(mastg_ref)

    # Add collapsible Frida output section (like Dynamic SharedPreferences)
    if logs:
        detail_parts.append("<br>")
        detail_parts.append(
            "<details style='margin-top:8px'><summary style='cursor:pointer; font-size:11px; color:#0066cc'>View full Frida output</summary>"
            "<pre style='white-space:pre-wrap; font-size:9px; max-height:300px; overflow-y:auto; background:#f5f5f5; padding:6px'>\n"
        )
        detail_parts.append("\n".join(logs[-600:]))  # cap output to last 600 lines
        detail_parts.append("\n</pre></details>")

    if not pinned_hosts and not non_pinned_hosts and not pinning_methods:
        return 'INFO', "No network activity or pinning methods observed during test."

    detail = "".join(detail_parts)

    # Return INFO status (not Pass/Fail) like Dynamic SharedPreferences
    return 'INFO', detail

def check_frida_file_reads(base, wait_secs=7):
    """
    Dynamic File-read audit via USB+Frida CLI (inline JS):
      • Discovers installed package
      • Force-stops, writes JS to temp file, launches `frida -l tmp.js -U -f pkg`
      • Collects send({path:…}) messages for wait_secs
      • Terminates Frida, stops app, returns (ok, HTML-report)
    """
    # 1) pkg prefix from manifest
    manifest = os.path.join(base, 'AndroidManifest.xml')
    pkg_prefix = ET.parse(manifest).getroot().attrib.get('package','')

    # 2) find real package
    out = subprocess.check_output(['adb','shell','pm','list','packages', pkg_prefix], text=True)
    candidates = [l.split(':',1)[1].strip()
                  for l in out.splitlines() if l.startswith('package:')]
    if not candidates:
        raise RuntimeError(f"No installed package matching {pkg_prefix!r}")
    spawn_name = candidates[0]

    # 3) force-stop
    subprocess.run(['adb','shell','am','force-stop', spawn_name],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 4) inline JS
    jscode = r"""
    setImmediate(function(){
      if (Java.available) {
        Java.perform(function(){
          function report(p){ send({path:p}); }
          // FileInputStream
          var FIS = Java.use("java.io.FileInputStream");
          FIS.$init.overload("java.io.File").implementation = function(f){
            report(f.getAbsolutePath()); return this.$init(f);
          };
          FIS.$init.overload("java.lang.String").implementation = function(p){
            report(p); return this.$init(p);
          };
          // FileReader
          try {
            var FR = Java.use("java.io.FileReader");
            FR.$init.overload("java.io.File").implementation = function(f){
              report(f.getAbsolutePath()); return this.$init(f);
            };
            FR.$init.overload("java.lang.String").implementation = function(p){
              report(p); return this.$init(p);
            };
          } catch(e){}
          send("🔗 File-read hooks installed");
        });
      } else {
        setTimeout(arguments.callee, 100);
      }
    });
    """

    # 5) write to temp file and launch frida CLI
    tmp = tempfile.NamedTemporaryFile(suffix=".js", delete=False)
    tmp.write(jscode.encode()); tmp.flush(); tmp.close()
    proc = subprocess.Popen(
        ['frida','-l', tmp.name, '-U','-f', spawn_name],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )

    # 6) interactive monitoring with user prompt
    instructions = [
        f"App '{spawn_name}' is running with file read monitoring",
        "Use app features that may read files (settings, data loading, etc.)",
        "Watch for file read operations below"
    ]
    logs = interactive_frida_monitor(proc, "FILE READS", instructions)

    # Parse collected logs for file reads
    reads = []
    for line in logs:
        if 'message:' in line:
            try:
                part = line.split('message:',1)[1].split('data:',1)[0].strip()
                msg = ast.literal_eval(part)
                if msg.get('type')=='send' and isinstance(msg.get('payload'),dict):
                    p = msg['payload'].get('path')
                    if p:
                        reads.append(p)
            except:
                pass

    # 7) cleanup
    proc.terminate()
    subprocess.run(['adb','shell','am','force-stop', spawn_name],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.unlink(tmp.name)

    unique = sorted(set(reads))
    if not unique:
        return 'INFO', "<strong> No file-read attempts observed.</strong>"
    # File reads detected - this is informational, not necessarily a failure
    # Return INFO to show what was read
    return 'INFO', f"<strong>File reads detected ({len(unique)}):</strong><br>" + "<br>\n".join(f"- <code>{html.escape(p)}</code>" for p in unique)

def check_frida_strict_mode(base, wait_secs=7):
    """
    Dynamic StrictMode usage check via USB+Frida CLI (inline JS):
      • Discovers installed package
      • Force-stops, writes JS to temp file, launches `frida -l tmp.js -U -f pkg`
      • Sends Enter to resume spawned app
      • Monitors StrictMode calls with interactive user prompt
      • Terminates Frida, stops app, returns (ok, HTML-report)
    """
    # 1) find the real package name
    manifest = os.path.join(base, 'AndroidManifest.xml')
    pkg_prefix = ET.parse(manifest).getroot().attrib.get('package','')
    out = subprocess.check_output(
        ['adb','shell','pm','list','packages', pkg_prefix], text=True
    )
    pkgs = [l.split(':',1)[1] for l in out.splitlines() if l.startswith('package:')]
    if not pkgs:
        raise RuntimeError(f"No installed package matching {pkg_prefix!r}")
    spawn_name = pkgs[0]

    # 2) force-stop any running instance
    subprocess.run(
        ['adb','shell','am','force-stop', spawn_name],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    # 3) write our Frida JS to a temp file
    jscode = r"""
    Java.perform(function(){
      // Helper to get full backtrace using Thread API
      function getFullBacktrace() {
        var trace = [];
        try {
          var Thread = Java.use("java.lang.Thread");
          var currentThread = Thread.currentThread();
          var stackElements = currentThread.getStackTrace();
          for (var i = 0; i < stackElements.length; i++) {
            trace.push("  " + stackElements[i].toString());
          }
        } catch (e) {
          // Fallback: use Exception-based approach
          try {
            var Exception = Java.use("java.lang.Exception");
            var exc = Exception.$new();
            var stackElements = exc.getStackTrace();
            for (var i = 0; i < stackElements.length; i++) {
              trace.push("  " + stackElements[i].toString());
            }
          } catch (e2) {
            trace.push("  [Could not get backtrace: " + e2 + "]");
          }
        }
        return trace.join("\n");
      }

      var SM = Java.use("android.os.StrictMode");

      // Hook setThreadPolicy
      SM.setThreadPolicy.overload("android.os.StrictMode$ThreadPolicy").implementation = function(p){
        console.log("\n[*] StrictMode.setThreadPolicy() called\nBacktrace:\n" + getFullBacktrace() + "\nPolicy: " + p + "\n");
        return this.setThreadPolicy(p);
      };

      // Hook setVmPolicy
      SM.setVmPolicy.overload("android.os.StrictMode$VmPolicy").implementation = function(p){
        console.log("\n[*] StrictMode.setVmPolicy() called\nBacktrace:\n" + getFullBacktrace() + "\nPolicy: " + p + "\n");
        return this.setVmPolicy(p);
      };

      // Hook builder penaltyLog methods
      try {
        var VmBuilder = Java.use("android.os.StrictMode$VmPolicy$Builder");
        VmBuilder.penaltyLog.implementation = function(){
          console.log("\n[*] StrictMode.VmPolicy.Builder.penaltyLog() called\nBacktrace:\n" + getFullBacktrace() + "\n");
          return this.penaltyLog();
        };
      } catch (e) {}

      try {
        var ThreadBuilder = Java.use("android.os.StrictMode$ThreadPolicy$Builder");
        ThreadBuilder.penaltyLog.implementation = function(){
          console.log("\n[*] StrictMode.ThreadPolicy.Builder.penaltyLog() called\nBacktrace:\n" + getFullBacktrace() + "\n");
          return this.penaltyLog();
        };
      } catch (e) {}

      send("StrictMode hooks installed");
    });
    """
    tmp = tempfile.NamedTemporaryFile(suffix=".js", delete=False)
    tmp.write(jscode.encode()); tmp.flush(); tmp.close()

    # 4) launch Frida CLI
    proc = subprocess.Popen(
        ['frida', '-l', tmp.name, '-U', '-f', spawn_name],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    # 5) wait up to 5s for our "hooks installed" banner
    start_time = time.time()
    while True:
        line = proc.stdout.readline()
        if not line:
            proc.terminate()
            os.unlink(tmp.name)
            raise RuntimeError("Frida died before installing hooks")
        if "StrictMode hooks installed" in line:
            break
        if time.time() - start_time > 5:
            proc.terminate()
            os.unlink(tmp.name)
            raise RuntimeError("Timed out waiting for hooks installation")

    # 6) Interactive monitoring with user prompt
    # Note: Frida with -f automatically resumes the spawned app
    instructions = [
        f"App '{spawn_name}' is running with StrictMode monitoring",
        "Navigate through app features and settings",
        "Watch for StrictMode policy violations below"
    ]
    logs = interactive_frida_monitor(proc, "STRICTMODE", instructions, send_exit_on_stop=True)

    # 7) cleanup
    # Frida should already be terminated by interactive_frida_monitor
    # but ensure it's dead and stop the app
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except:
            proc.kill()

    subprocess.run(
        ['adb','shell','am','force-stop', spawn_name],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    os.unlink(tmp.name)

    # 8) analyze and format the report
    if not logs:
        return 'PASS', "No StrictMode activity observed."

    # Check if StrictMode calls are from app code or libraries
    app_package = pkg_prefix if pkg_prefix else spawn_name
    library_packages = [
        'com.google.android.gms',
        'com.google.firebase',
        'androidx.',
        'android.support.',
        'com.facebook.',
        'io.fabric.',
    ]

    app_strictmode_calls = []
    library_strictmode_calls = []

    def is_app_originated(call_lines):
        """
        Check if StrictMode call originated from app code by finding the first
        non-framework/non-library frame in the backtrace.
        """
        for line in call_lines:
            # Skip until we find backtrace lines
            if 'Backtrace:' not in line and not any(x in line for x in ['.java:', '.kt:', 'Native Method', 'Unknown Source']):
                continue

            # Found a stack frame - check if it's app code
            # Skip pure framework calls (android.os, android.app, java.*, com.android.*, dalvik.*)
            if any(fw in line for fw in ['android.os.', 'android.app.', 'java.lang.', 'java.util.', 'com.android.internal.', 'dalvik.']):
                continue

            # Check if this frame is from app package
            if app_package and app_package in line:
                return True

            # Check if this frame is from a known library
            if any(lib in line for lib in library_packages):
                return False

        return False

    current_call = []
    for line in logs:
        if '[*] StrictMode' in line:
            # Start of new StrictMode call
            if current_call:
                # Analyze previous call
                if is_app_originated(current_call):
                    app_strictmode_calls.append('\n'.join(current_call))
                else:
                    library_strictmode_calls.append('\n'.join(current_call))

            current_call = [line]
        else:
            current_call.append(line)

    # Don't forget the last call
    if current_call:
        if is_app_originated(current_call):
            app_strictmode_calls.append('\n'.join(current_call))
        else:
            library_strictmode_calls.append('\n'.join(current_call))

    # MASTG reference
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0264/' target='_blank'>MASTG-TEST-0264: Memory Corruption Bugs</a></div>"

    # Build report
    report_lines = []

    if app_strictmode_calls:
        report_lines.append("<div style='background:#ffe6e6; padding:8px; border-left:4px solid #dc3545; margin-bottom:10px;'><strong style='color:#721c24;'>⚠ StrictMode in App Code: {} call(s) detected</strong></div>".format(len(app_strictmode_calls)))
        report_lines.append("<details open><summary style='cursor:pointer; font-size:12px; color:#0066cc; font-weight:bold;'>📋 App StrictMode Calls - Click to expand/collapse</summary>")

        # Format each call with clear separation and highlighting
        formatted_calls = []
        for i, call in enumerate(app_strictmode_calls, 1):
            call_html = f"<div style='margin-bottom:15px; padding:10px; background:#fff; border:1px solid #ddd;'>"
            call_html += f"<div style='background:#dc3545; color:white; padding:5px; margin-bottom:5px; font-weight:bold;'>Call #{i}</div>"

            # Highlight app package lines in the backtrace
            lines = call.split('\n')
            highlighted_lines = []
            for line in lines:
                if app_package and app_package in line:
                    # Highlight the app code line
                    highlighted_lines.append(f"<span style='background:#ffeb3b; color:#000; font-weight:bold;'>→ {html.escape(line)}</span>")
                else:
                    highlighted_lines.append(html.escape(line))

            call_html += '<pre style="margin:0; font-size:10px; line-height:1.4;">' + '\n'.join(highlighted_lines) + '</pre>'
            call_html += "</div>"
            formatted_calls.append(call_html)

        report_lines.append('\n'.join(formatted_calls))
        report_lines.append("</details>")

    if library_strictmode_calls:
        report_lines.append("<br><div><strong>ℹ StrictMode in Library Code:</strong> {} call(s) (Google/Firebase/Framework)</div><br>".format(len(library_strictmode_calls)))
        report_lines.append("<details><summary style='cursor:pointer; font-size:11px; color:#0066cc'>Library StrictMode Calls - Click to expand/collapse</summary>")
        report_lines.append("<pre style='white-space:pre-wrap; font-size:9px; max-height:300px; overflow-y:auto; background:#f5f5f5; padding:6px'>\n" + "\n\n".join(library_strictmode_calls) + "\n</pre>")
        report_lines.append("</details>")

    report_lines.append(
        "<br><div style='font-size:11px; color:#666'><em>Note: StrictMode in library code (Google Play Services, Firebase) is managed by the library vendor "
        "and is generally not a concern. Focus on StrictMode calls originating from your app's package.</em></div>"
    )

    detail = "\n".join(report_lines) + mastg_ref

    # Return FAIL ONLY if StrictMode detected in APP CODE
    # Per MASTG-TEST-0264/0263/0265: StrictMode in production is an information leakage risk
    # Library/framework StrictMode calls are out of the developer's control and should not cause failure
    if app_strictmode_calls:
        severity_note = "<div style='background:#fff3cd; padding:15px; border-left:5px solid #ffc107; font-size:12px; margin-bottom:15px;'>"
        severity_note += f"<div style='font-size:16px; font-weight:bold; color:#856404; margin-bottom:10px;'>WARNING: StrictMode in App Code ({len(app_strictmode_calls)} call{'s' if len(app_strictmode_calls) > 1 else ''})</div>"
        severity_note += "<strong>MASTG Guidance (MASTG-TEST-0264, MASTG-TEST-0263, MASTG-TEST-0265):</strong><br>"
        severity_note += "StrictMode detected in <strong>APP CODE</strong> at runtime in production build.<br><br>"
        severity_note += "<strong>Risk:</strong> Information leakage - StrictMode logs implementation details and internal state that attackers can exploit.<br><br>"
        severity_note += "<strong>Remediation:</strong><br>"
        severity_note += "• Wrap app StrictMode calls with <code>if (BuildConfig.DEBUG)</code> guards<br>"
        severity_note += "• Ensure StrictMode is completely disabled in release builds<br>"
        severity_note += "</div>"

        return 'FAIL', severity_note + detail
    elif library_strictmode_calls:
        # Library StrictMode is present but not from app - WARN instead of FAIL
        info_note = "<div style='background:#e3f2fd; padding:10px; border-left:3px solid #2196F3; font-size:11px'>"
        info_note += "<strong>ℹ Information:</strong><br>"
        info_note += "StrictMode calls detected in library/framework code only (Google Play Services, Firebase, Android Framework).<br>"
        info_note += "These are managed by the library vendor and are generally not a security concern.<br>"
        info_note += "<strong>Optional:</strong> If you want to suppress these, configure ProGuard/R8:<br>"
        info_note += "<code>-assumenosideeffects class android.os.StrictMode { *; }</code><br>"
        info_note += "</div><br>"

        return 'WARN', info_note + detail
    else:
        return 'PASS', detail


import subprocess, tempfile, time, ast, os, threading, xml.etree.ElementTree as ET

def check_frida_task_hijack(base, manifest,
                            per_launch_pause=1.5,
                            final_wait=7):
    """
    Dynamic Exported-Activity check via USB+Frida CLI (inline JS + Python timeout):
      • Parses manifest for exported+unprotected activities
      • Writes JS to temp file, launches `frida -l tmp.js -U -f pkg`
      • Waits for "hooks installed" banner, then adb-starts each candidate
      • Collects send({ev:'life',…}) messages for final_wait seconds
      • Terminates Frida, stops app, returns (ok, HTML-report)
    """
    # ── 0) package name ─────────────────────────────────────────────
    pkg = ET.parse(manifest).getroot().attrib.get('package','')

    # ── 1) find unprotected exported activities ─────────────────────
    AND_NS = 'http://schemas.android.com/apk/res/android'
    def ns(a): return f'{{{AND_NS}}}{a}'
    tree = ET.parse(manifest); root = tree.getroot()
    perm_level = {
        p.get(ns('name')): p.get(ns('protectionLevel'),'normal')
        for p in root.findall('permission')
    }
    bad = []
    for act in root.findall('.//activity'):
        name = act.get(ns('name'),'')
        if not name: continue
        # resolve to FQCN
        if name.startswith('.'):       fq = pkg + name
        elif '.' in name:              fq = name
        else:                          fq = pkg + '.' + name

        exp   = act.get(ns('exported'))
        has_if= act.find('intent-filter') is not None
        exported = (exp=='true') or (exp is None and has_if)
        if not exported: continue

        perm = act.get(ns('permission'))
        weak = (perm is None) or (perm_level.get(perm)=='normal')

        # skip MAIN/LAUNCHER
        if has_if:
            acts = [a.get(ns('name')) for a in act.findall('.//action')]
            cats = [c.get(ns('name')) for c in act.findall('.//category')]
            if 'android.intent.action.MAIN' in acts and 'android.intent.category.LAUNCHER' in cats:
                continue

        if weak:
            bad.append(fq)

    if not bad:
        return True, "No exported, unprotected activities detected."

    # ── 2) inline Frida JS ───────────────────────────────────────────
    jscode = r"""
    Java.perform(function(){
      var A = Java.use("android.app.Activity");
      function hook(name){
        return function(){
          send({ev:"life",cls:this.getClass().getName(),m:name});
          return this[name].apply(this,arguments);
        }
      }
      ["onCreate","onStart","onResume"].forEach(function(m){
        try { A[m].overload().implementation = hook(m); } catch(e){}
        try { A[m].overload("android.os.Bundle").implementation = hook(m); } catch(e){}
      });
      send("Task-hijack hooks installed");
    });
    """

    # ── 3) write JS to temp file ────────────────────────────────────
    tmp = tempfile.NamedTemporaryFile(suffix=".js", delete=False)
    tmp.write(jscode.encode()); tmp.flush(); tmp.close()

    # ── 4) launch Frida CLI ────────────────────────────────────────
    proc = subprocess.Popen(
        ['frida', '-l', tmp.name, '-U', '-f', pkg],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    # ── 5) wait up to 5s for our "hooks installed" banner ──────────
    start = time.time()
    while True:
        line = proc.stdout.readline()
        if not line:
            proc.terminate()
            raise RuntimeError("Frida died before installing hooks")
        if "Task-hijack hooks installed" in line:
            break
        if time.time() - start > 5:
            proc.terminate()
            raise RuntimeError("Timed out waiting for hooks installation")

    # ── 6) Launch activities and collect logs simultaneously ──────
    print(f"\n[*] Launching {len(bad)} exported activities and monitoring...")
    print("="*70)

    logs = []

    # Launch each activity and collect logs in real-time
    for i, comp in enumerate(bad, 1):
        print(f"[*] Launching activity {i}/{len(bad)}: {comp.split('.')[-1]}")

        # Launch activity
        subprocess.run(
            ['adb','shell','am','start','-W','-n', f"{pkg}/{comp}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Collect Frida output for a short period after launch
        start_time = time.time()
        while time.time() - start_time < per_launch_pause:
            try:
                # Non-blocking read with select (Unix) or polling (Windows)
                import platform
                is_windows = platform.system() == 'Windows'

                if is_windows:
                    # Windows: Use threading with timeout
                    import threading
                    import queue

                    def read_line(q):
                        try:
                            line = proc.stdout.readline()
                            if line:
                                q.put(line)
                        except:
                            pass

                    q = queue.Queue()
                    t = threading.Thread(target=read_line, args=(q,))
                    t.daemon = True
                    t.start()
                    t.join(timeout=0.1)

                    try:
                        line = q.get_nowait()
                        print(line.rstrip())
                        logs.append(line.rstrip())
                    except queue.Empty:
                        pass
                else:
                    # Unix: Use select
                    import select
                    import fcntl

                    fd = proc.stdout.fileno()
                    r, _, _ = select.select([fd], [], [], 0.1)
                    if r:
                        line = proc.stdout.readline()
                        if line:
                            print(line.rstrip())
                            logs.append(line.rstrip())

            except:
                time.sleep(0.1)

    print("\n[*] All activities launched. Collecting final logs...")

    # Wait for any remaining logs
    final_wait_start = time.time()
    while time.time() - final_wait_start < final_wait:
        try:
            import platform
            is_windows = platform.system() == 'Windows'

            if is_windows:
                import threading
                import queue

                def read_line(q):
                    try:
                        line = proc.stdout.readline()
                        if line:
                            q.put(line)
                    except:
                        pass

                q = queue.Queue()
                t = threading.Thread(target=read_line, args=(q,))
                t.daemon = True
                t.start()
                t.join(timeout=0.1)

                try:
                    line = q.get_nowait()
                    print(line.rstrip())
                    logs.append(line.rstrip())
                except queue.Empty:
                    pass
            else:
                import select

                fd = proc.stdout.fileno()
                r, _, _ = select.select([fd], [], [], 0.1)
                if r:
                    line = proc.stdout.readline()
                    if line:
                        print(line.rstrip())
                        logs.append(line.rstrip())
        except:
            time.sleep(0.1)

    print("="*70)

    # ── 7) parse collected logs for lifecycle events ───────────────
    seen = {}
    for out_line in logs:
        if 'message:' in out_line:
            try:
                part = out_line.split('message:',1)[1].split('data:',1)[0].strip()
                msg  = ast.literal_eval(part)
                if msg.get('type')=='send' and msg['payload'].get('ev')=='life':
                    seen[msg['payload']['cls']] = msg['payload']['m']
            except Exception:
                pass

    # ── 8) cleanup ─────────────────────────────────────────────────
    proc.terminate()
    subprocess.run(['adb','shell','am','force-stop', pkg],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.unlink(tmp.name)

    # ── 9) build HTML report ───────────────────────────────────────
    rows, launches = [], 0
    for comp in bad:
        simple = comp.split('.')[-1]
        if comp in seen:
            launches += 1
            rows.append(f"- <code>{simple}</code> → <code>{seen[comp]}()</code>")
        else:
            rows.append(f"- <code>{simple}</code> not observed")

    detail = "<br>\n".join(rows)
    # FAIL if any activity launched
    return (False if launches else True), detail


def check_frida_sharedprefs(base, wait_secs=10):
    """
    Dynamic SharedPreferences monitoring via Frida:
    - Hooks getSharedPreferences() to detect usage
    - Intercepts putString/putInt/etc to capture stored data
    - Checks if EncryptedSharedPreferences is used
    - Returns findings with file names and key-value pairs
    """
    manifest = os.path.join(base, 'AndroidManifest.xml')
    pkg_prefix = ET.parse(manifest).getroot().attrib.get('package', '')

    out = subprocess.check_output(['adb', 'shell', 'pm', 'list', 'packages', pkg_prefix], text=True)
    candidates = [l.split(':', 1)[1].strip() for l in out.splitlines() if l.startswith('package:')]
    if not candidates:
        raise RuntimeError(f"No installed package matching {pkg_prefix!r}")
    spawn_name = candidates[0]

    subprocess.run(['adb', 'shell', 'am', 'force-stop', spawn_name],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    jscode = r"""
    setImmediate(function(){
      if (Java.available) {
        Java.perform(function(){
          // Convert a byte[] to UTF-8 string
            function bytesToUtf8(bytes, off, len) {
            try {
                var JavaString = Java.use("java.lang.String");
                return JavaString.$new(bytes, off, len, "UTF-8").toString();
            } catch (e) {
                // Fallback – do a crude conversion if JavaString fails
                var s = "";
                for (var i = off; i < off + len; i++) {
                s += String.fromCharCode(bytes[i] & 0xff);
                }
                return s;
            }
            }

            // Extract key/value pairs from SharedPreferences XML
            function parseSharedPrefsXml(xmlString) {
            var results = [];
            if (!xmlString) return results;

            // <string name="foo">bar</string>
            var reString = /<string\s+name="([^"]*)">([^<]*)<\/string>/g;
            // <boolean name="foo" value="true" />
            var reBool   = /<boolean\s+name="([^"]*)"\s+value="([^"]*)"\s*\/>/g;
            // <int name="foo" value="123" />
            var reInt    = /<int\s+name="([^"]*)"\s+value="([^"]*)"\s*\/>/g;
            // <long name="foo" value="123" />
            var reLong   = /<long\s+name="([^"]*)"\s+value="([^"]*)"\s*\/>/g;

            var m;
            while ((m = reString.exec(xmlString)) !== null) {
                results.push({ key: m[1], value: m[2] });
            }
            while ((m = reBool.exec(xmlString)) !== null) {
                results.push({ key: m[1], value: m[2] });
            }
            while ((m = reInt.exec(xmlString)) !== null) {
                results.push({ key: m[1], value: m[2] });
            }
            while ((m = reLong.exec(xmlString)) !== null) {
                results.push({ key: m[1], value: m[2] });
            }

            return results;
        }                  

          // Hook SQLite for database storage (with noise filtering)
          try {
            var SQLiteDB = Java.use("android.database.sqlite.SQLiteDatabase");
            SQLiteDB.insert.overload("java.lang.String", "java.lang.String", "android.content.ContentValues").implementation = function(table, nullColumnHack, values) {
              // Filter out noisy analytics tables
              var noiseFilter = ['events', 'event_metadata', 'crashlytics', 'analytics', 'firebase', 'log'];
              var isNoise = false;
              for (var i = 0; i < noiseFilter.length; i++) {
                if (table.toLowerCase().indexOf(noiseFilter[i]) >= 0) {
                  isNoise = true;
                  break;
                }
              }
              if (!isNoise) {
                console.log("💾 SQLite insert into table: " + table + " values: " + values);
              }
              return this.insert(table, nullColumnHack, values);
            };
            SQLiteDB.update.overload("java.lang.String", "android.content.ContentValues", "java.lang.String", "[Ljava.lang.String;").implementation = function(table, values, whereClause, whereArgs) {
              var noiseFilter = ['events', 'event_metadata', 'crashlytics', 'analytics', 'firebase', 'log'];
              var isNoise = false;
              for (var i = 0; i < noiseFilter.length; i++) {
                if (table.toLowerCase().indexOf(noiseFilter[i]) >= 0) {
                  isNoise = true;
                  break;
                }
              }
              if (!isNoise) {
                console.log("💾 SQLite update table: " + table + " values: " + values);
              }
              return this.update(table, values, whereClause, whereArgs);
            };
          } catch(e) { console.log("SQLite hooks skipped"); }

          // Hook DataStore (newer preference API)
          try {
            var DataStore = Java.use("androidx.datastore.preferences.core.PreferencesKt");
            console.log("🔍 DataStore detected");

            // Hook DataStore edit/write operations
            try {
              var MutablePreferences = Java.use("androidx.datastore.preferences.core.MutablePreferences");

              // Hook set() for string values
              var stringKey = Java.use("androidx.datastore.preferences.core.Preferences$Key");
              MutablePreferences.set.overload("androidx.datastore.preferences.core.Preferences$Key", "java.lang.Object").implementation = function(key, value) {
                var keyName = key.getName ? key.getName() : String(key);
                var valueStr = String(value);
                console.log("[*] DataStore.set: " + keyName + " = " + valueStr.substring(0, 50));

                // Check for sensitive data
                var sensitive = false;
                var keywords = ['password', 'passwd', 'pwd', 'token', 'secret', 'key', 'auth', 'pin', 'code'];
                var lowerKey = String(keyName).toLowerCase();
                var lowerVal = valueStr.toLowerCase();
                for (var i = 0; i < keywords.length; i++) {
                  if (lowerKey.indexOf(keywords[i]) >= 0 || lowerVal.indexOf(keywords[i]) >= 0) {
                    sensitive = true;
                    break;
                  }
                }

                send({
                  type: "datastore_write",
                  key: keyName,
                  value: valueStr.substring(0, 100),
                  sensitive: sensitive,
                  valueLength: valueStr.length
                });

                return this.set(key, value);
              };
              console.log("[+] DataStore hooks installed");
            } catch(e) {
              console.log("DataStore hook error: " + e);
            }
          } catch(e) {}

          // Hook direct File writes to shared_prefs directory
          var currentFileStream = null;
          try {
            var FileOutputStream = Java.use("java.io.FileOutputStream");
            FileOutputStream.$init.overload("java.io.File", "boolean").implementation = function(file, append) {
              var path = file.getAbsolutePath();
              if (path.indexOf("shared_prefs") >= 0) {
                var filename = path.substring(path.lastIndexOf("/") + 1);
                var timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
                console.log("📁 [" + timestamp + "] FileOutputStream writing to: " + filename);

                // Store current file context for write tracking
                currentFileStream = {
                  filename: filename,
                  path: path,
                  timestamp: timestamp
                };

                send({
                  type: "file_write",
                  filename: filename,
                  path: path,
                  timestamp: timestamp
                });
              }
              return this.$init(file, append);
            };

            // Hook all write overloads to capture actual data
            try {
              var originalWrite1 = FileOutputStream.write.overload("[B");
              FileOutputStream.write.overload("[B").implementation = function(bytes) {
                captureWrite(bytes);
                return originalWrite1.call(this, bytes);
              };
            } catch(e) {}

            try {
              var originalWrite2 = FileOutputStream.write.overload("[B", "int", "int");
              FileOutputStream.write.overload("[B", "int", "int").implementation = function(bytes, off, len) {
                if (currentFileStream && off === 0) {
                  captureWrite(bytes);
                }
                return originalWrite2.call(this, bytes, off, len);
              };
            } catch(e) {}

            try {
              var originalWrite3 = FileOutputStream.write.overload("int");
              FileOutputStream.write.overload("int").implementation = function(b) {
                return originalWrite3.call(this, b);
              };
            } catch(e) {}

            function captureWrite(bytes) {
            if (currentFileStream && bytes && bytes.length > 0 && bytes.length < 50000) {
                try {
                // Convert to a plain JS string
                var jsStr = bytesToUtf8(bytes, 0, bytes.length);

                // Check if it's XML preference data
                if (jsStr.indexOf("<?xml") >= 0 ||
                    jsStr.indexOf("<map>") >= 0 ||
                    jsStr.indexOf("<string name=") >= 0) {

                    console.log("  └─ Writing preference data (" + bytes.length + " bytes)");

                    var allMatches = [];

                    // String values
                    var stringMatches = jsStr.match(/<string name="([^"]+)">([^<]*)<\/string>/g);
                    if (stringMatches) {
                    for (var i = 0; i < stringMatches.length; i++) {
                        var match = stringMatches[i].match(/<string name="([^"]+)">([^<]*)<\/string>/);
                        if (match) {
                        allMatches.push({key: match[1], value: match[2], type: "string"});
                        }
                    }
                    }

                    // Boolean values
                    var boolMatches = jsStr.match(/<boolean name="([^"]+)" value="([^"]+)" \/>/g);
                    if (boolMatches) {
                    for (var i = 0; i < boolMatches.length; i++) {
                        var match = boolMatches[i].match(/<boolean name="([^"]+)" value="([^"]+)" \/>/);
                        if (match) {
                        allMatches.push({key: match[1], value: match[2], type: "boolean"});
                        }
                    }
                    }

                    // Int values
                    var intMatches = jsStr.match(/<int name="([^"]+)" value="([^"]+)" \/>/g);
                    if (intMatches) {
                    for (var i = 0; i < intMatches.length; i++) {
                        var match = intMatches[i].match(/<int name="([^"]+)" value="([^"]+)" \/>/);
                        if (match) {
                        allMatches.push({key: match[1], value: match[2], type: "int"});
                        }
                    }
                    }

                    // Long values
                    var longMatches = jsStr.match(/<long name="([^"]+)" value="([^"]+)" \/>/g);
                    if (longMatches) {
                    for (var i = 0; i < longMatches.length; i++) {
                        var match = longMatches[i].match(/<long name="([^"]+)" value="([^"]+)" \/>/);
                        if (match) {
                        allMatches.push({key: match[1], value: match[2], type: "long"});
                        }
                    }
                    }

                    // Float values
                    var floatMatches = jsStr.match(/<float name="([^"]+)" value="([^"]+)" \/>/g);
                    if (floatMatches) {
                    for (var i = 0; i < floatMatches.length; i++) {
                        var match = floatMatches[i].match(/<float name="([^"]+)" value="([^"]+)" \/>/);
                        if (match) {
                        allMatches.push({key: match[1], value: match[2], type: "float"});
                        }
                    }
                    }

                    // Log and send first 10 entries
                    for (var i = 0; i < Math.min(allMatches.length, 10); i++) {
                    var entry = allMatches[i];
                    var valuePreview = entry.value.substring(0, 50);
                    console.log("     " + entry.key + " = " + valuePreview + (entry.value.length > 50 ? "..." : ""));

                    send({
                        type: "file_write_detail",
                        filename: currentFileStream.filename,
                        timestamp: currentFileStream.timestamp,
                        key: entry.key,
                        value: entry.value,
                        value_type: entry.type,
                        value_length: entry.value.length
                    });
                    }

                    if (allMatches.length > 10) {
                    console.log("     ...and " + (allMatches.length - 10) + " more entries");
                    }
                }
                } catch(e) {
                console.log("  └─ Error parsing write: " + e);
                }
            }
            }
          } catch(e) { console.log("FileOutputStream hook error: " + e); }

          // Entropy calculation function
          function calculateEntropy(str) {
            if (!str || str.length === 0) return 0;
            var freq = {};
            for (var i = 0; i < str.length; i++) {
              var char = str[i];
              freq[char] = (freq[char] || 0) + 1;
            }
            var entropy = 0;
            var len = str.length;
            for (var char in freq) {
              var p = freq[char] / len;
              entropy -= p * Math.log2(p);
            }
            return entropy;
          }

          // Sensitive keyword detection
          function hasSensitiveKeyword(text) {
            if (!text) return false;
            var keywords = ['password', 'passwd', 'pwd', 'token', 'secret', 'key', 'auth',
                           'bearer', 'credential', 'api', 'private', 'credit', 'card', 'ssn',
                           'session', 'oauth', 'jwt', 'cipher', 'encrypt', 'pin', 'code', 'passcode'];
            var lower = text.toLowerCase();
            for (var i = 0; i < keywords.length; i++) {
              if (lower.indexOf(keywords[i]) >= 0) return true;
            }
            return false;
          }

          // Hook Context.getSharedPreferences
          var Context = Java.use("android.content.Context");
          Context.getSharedPreferences.overload("java.lang.String", "int").implementation = function(name, mode) {
            var encrypted = false;
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            if (stack.indexOf("EncryptedSharedPreferences") >= 0) {
              encrypted = true;
            }
            console.log("📁 getSharedPreferences: " + name + " (encrypted: " + encrypted + ")");
            send({
              type: "prefs_access",
              name: name,
              encrypted: encrypted,
              mode: mode
            });
            return this.getSharedPreferences(name, mode);
          };

          // Hook EncryptedSharedPreferences.create (androidx.security.crypto)
          try {
            var EncPrefs = Java.use("androidx.security.crypto.EncryptedSharedPreferences");
            EncPrefs.create.overload("java.lang.String", "java.lang.String", "android.content.Context",
                                     "androidx.security.crypto.EncryptedSharedPreferences$PrefKeyEncryptionScheme",
                                     "androidx.security.crypto.EncryptedSharedPreferences$PrefValueEncryptionScheme")
                           .implementation = function(fileName, masterKeyAlias, context, keyScheme, valueScheme) {
              console.log("🔐 EncryptedSharedPreferences.create: " + fileName);
              send({
                type: "prefs_access",
                name: fileName,
                encrypted: true,
                mode: 0
              });
              return this.create(fileName, masterKeyAlias, context, keyScheme, valueScheme);
            };
          } catch(e) { console.log("EncryptedSharedPreferences hook skipped (not available)"); }

          // Hook PreferenceManager.getDefaultSharedPreferences (common for settings)
          try {
            var PrefManager = Java.use("android.preference.PreferenceManager");
            PrefManager.getDefaultSharedPreferences.overload("android.content.Context").implementation = function(context) {
              console.log("📁 PreferenceManager.getDefaultSharedPreferences called");
              var prefs = this.getDefaultSharedPreferences(context);
              send({
                type: "prefs_access",
                name: "default_prefs",
                encrypted: false,
                mode: 0
              });
              return prefs;
            };
          } catch(e) { console.log("PreferenceManager hook skipped: " + e); }

          // Hook getString to see reads
          try {
            var SharedPrefs = Java.use("android.content.SharedPreferences");
            SharedPrefs.getString.overload("java.lang.String", "java.lang.String").implementation = function(key, defValue) {
              var result = this.getString(key, defValue);
              console.log("📖 getString: " + key + " = " + (result ? result.substring(0, 30) : "null"));
              return result;
            };
          } catch(e) { console.log("getString hook error: " + e); }

          // Hook edit() to see when editing starts
          try {
            var SharedPrefs = Java.use("android.content.SharedPreferences");
            SharedPrefs.edit.implementation = function() {
              console.log("📝 SharedPreferences.edit() called - starting edit session");
              return this.edit();
            };
          } catch(e) { console.log("edit() hook error: " + e); }

          // Hook Editor methods to catch stored data
          var Editor = Java.use("android.content.SharedPreferences$Editor");

          // Hook putString
          try {
            Editor.putString.overload("java.lang.String", "java.lang.String").implementation = function(key, value) {
              var valueStr = String(value);
              var entropy = calculateEntropy(valueStr);
              var sensitive = hasSensitiveKeyword(key) || hasSensitiveKeyword(valueStr);
              var highEntropy = entropy > 4.5;
              var isBase64 = /^[A-Za-z0-9+\/]+=*$/.test(valueStr) && valueStr.length >= 16;
              var isHex = /^[0-9a-fA-F]+$/.test(valueStr) && valueStr.length >= 32;
              var isJWT = /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(valueStr);

              console.log("[*] putString: " + key + " = " + valueStr.substring(0, 30) + (valueStr.length > 30 ? "..." : ""));
              send({
                type: "prefs_write",
                method: "putString",
                key: key,
                value: valueStr.substring(0, 100),
                entropy: entropy.toFixed(2),
                sensitive: sensitive,
                highEntropy: highEntropy,
                isBase64: isBase64,
                isHex: isHex,
                isJWT: isJWT,
                valueLength: valueStr.length
              });
              return this.putString(key, value);
            };
          } catch(e) { console.log("putString hook error: " + e); }

          // Hook putInt
          try {
            Editor.putInt.overload("java.lang.String", "int").implementation = function(key, value) {
              console.log("[*] putInt: " + key + " = " + value);
              send({
                type: "prefs_write",
                method: "putInt",
                key: key,
                value: String(value),
                entropy: 0,
                sensitive: hasSensitiveKeyword(key),
                highEntropy: false,
                isBase64: false,
                isHex: false,
                isJWT: false,
                valueLength: String(value).length
              });
              return this.putInt(key, value);
            };
          } catch(e) { console.log("putInt hook error: " + e); }

          // Hook putBoolean
          try {
            Editor.putBoolean.overload("java.lang.String", "boolean").implementation = function(key, value) {
              console.log("[*] putBoolean: " + key + " = " + value);
              send({
                type: "prefs_write",
                method: "putBoolean",
                key: key,
                value: String(value),
                entropy: 0,
                sensitive: hasSensitiveKeyword(key),
                highEntropy: false,
                isBase64: false,
                isHex: false,
                isJWT: false,
                valueLength: String(value).length
              });
              return this.putBoolean(key, value);
            };
          } catch(e) { console.log("putBoolean hook error: " + e); }

          // Hook putLong
          try {
            Editor.putLong.overload("java.lang.String", "long").implementation = function(key, value) {
              console.log("[*] putLong: " + key + " = " + value);
              send({
                type: "prefs_write",
                method: "putLong",
                key: key,
                value: String(value),
                entropy: 0,
                sensitive: hasSensitiveKeyword(key),
                highEntropy: false,
                isBase64: false,
                isHex: false,
                isJWT: false,
                valueLength: String(value).length
              });
              return this.putLong(key, value);
            };
          } catch(e) { console.log("putLong hook error: " + e); }

          // Hook putFloat
          try {
            Editor.putFloat.overload("java.lang.String", "float").implementation = function(key, value) {
              console.log("[*] putFloat: " + key + " = " + value);
              send({
                type: "prefs_write",
                method: "putFloat",
                key: key,
                value: String(value),
                entropy: 0,
                sensitive: hasSensitiveKeyword(key),
                highEntropy: false,
                isBase64: false,
                isHex: false,
                isJWT: false,
                valueLength: String(value).length
              });
              return this.putFloat(key, value);
            };
          } catch(e) { console.log("putFloat hook error: " + e); }

          // Hook putStringSet
          try {
            Editor.putStringSet.overload("java.lang.String", "java.util.Set").implementation = function(key, values) {
              console.log("[*] putStringSet: " + key + " = " + values);
              send({
                type: "prefs_write",
                method: "putStringSet",
                key: key,
                value: String(values),
                entropy: 0,
                sensitive: hasSensitiveKeyword(key),
                highEntropy: false,
                isBase64: false,
                isHex: false,
                isJWT: false,
                valueLength: String(values).length
              });
              return this.putStringSet(key, values);
            };
          } catch(e) { console.log("putStringSet hook error: " + e); }

          // Hook commit and apply to see when data is actually persisted
          try {
            Editor.commit.implementation = function() {
              console.log("💾 Editor.commit() called - saving to disk");
              return this.commit();
            };
          } catch(e) { console.log("commit hook error: " + e); }

          try {
            Editor.apply.implementation = function() {
              console.log("💾 Editor.apply() called - saving to disk async");
              this.apply();
            };
          } catch(e) { console.log("apply hook error: " + e); }

          // Hook getInt, getBoolean, getLong, getFloat to see other reads
          try {
            var SharedPrefs = Java.use("android.content.SharedPreferences");
            SharedPrefs.getInt.overload("java.lang.String", "int").implementation = function(key, defValue) {
              var result = this.getInt(key, defValue);
              console.log("📖 getInt: " + key + " = " + result);
              return result;
            };
          } catch(e) {}

          try {
            var SharedPrefs = Java.use("android.content.SharedPreferences");
            SharedPrefs.getBoolean.overload("java.lang.String", "boolean").implementation = function(key, defValue) {
              var result = this.getBoolean(key, defValue);
              console.log("📖 getBoolean: " + key + " = " + result);
              return result;
            };
          } catch(e) {}

          try {
            var SharedPrefs = Java.use("android.content.SharedPreferences");
            SharedPrefs.getLong.overload("java.lang.String", "long").implementation = function(key, defValue) {
              var result = this.getLong(key, defValue);
              console.log("📖 getLong: " + key + " = " + result);
              return result;
            };
          } catch(e) {}

          console.log("[+] SharedPreferences/DataStore hooks installed successfully");
          send({type: "ready", msg: "SharedPreferences hooks installed"});
        });
      } else {
        setTimeout(arguments.callee, 100);
      }
    });
    """

    tmp = tempfile.NamedTemporaryFile(suffix=".js", delete=False)
    tmp.write(jscode.encode())
    tmp.flush()
    tmp.close()

    proc = subprocess.Popen(
        ['frida', '-l', tmp.name, '-U', '-f', spawn_name],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )

    # Interactive monitoring with user prompt
    instructions = [
        f"App '{spawn_name}' is running with SharedPreferences/DataStore monitoring",
        "Use app features that save/load settings or data (PINs, passwords, tokens)",
        "Watch for preference write operations below"
    ]
    logs = interactive_frida_monitor(proc, "SHAREDPREFERENCES/DATASTORE", instructions)

    # Parse collected logs and organize by storage type
    prefs_accessed = {}  # {filename: {'encrypted': bool, 'reads': [], 'writes': []}}
    datastore_ops = []
    file_writes = {}  # {filename: {'timestamp': str, 'details': [...]}}

    for line in logs:
        if 'message:' in line:
            try:
                part = line.split('message:', 1)[1].split('data:', 1)[0].strip()
                msg = ast.literal_eval(part)
                if msg.get('type') == 'send':
                    payload = msg.get('payload', {})

                    if payload.get('type') == 'prefs_access':
                        name = payload.get('name', 'unknown')
                        encrypted = payload.get('encrypted', False)
                        if name not in prefs_accessed:
                            prefs_accessed[name] = {
                                'encrypted': encrypted,
                                'reads': [],
                                'writes': []
                            }

                    elif payload.get('type') == 'datastore_write':
                        key = payload.get('key', '')
                        value = payload.get('value', '')
                        sensitive = payload.get('sensitive', False)
                        datastore_ops.append({
                            'operation': 'WRITE',
                            'key': key,
                            'value': value,
                            'sensitive': sensitive
                        })

                    elif payload.get('type') == 'file_write':
                        filename = payload.get('filename', '')
                        timestamp = payload.get('timestamp', 'unknown')
                        if 'gms.measurement' not in filename and 'firebase' not in filename:
                            if filename not in file_writes:
                                file_writes[filename] = {
                                    'timestamp': timestamp,
                                    'details': []
                                }

                    elif payload.get('type') == 'file_write_detail':
                        filename = payload.get('filename', '')
                        timestamp = payload.get('timestamp', 'unknown')
                        key = payload.get('key', '')
                        value = payload.get('value', '')

                        if filename in file_writes:
                            file_writes[filename]['details'].append({
                                'key': key,
                                'value': value
                            })

                    elif payload.get('type') == 'prefs_write':
                        # Track which prefs file was written to (we need to match context)
                        key = payload.get('key', '')
                        value = payload.get('value', '')
                        method = payload.get('method', 'put')
                        sensitive = payload.get('sensitive', False)

                        # Add to most recent prefs access or create entry
                        if prefs_accessed:
                            last_prefs = list(prefs_accessed.keys())[-1]
                            prefs_accessed[last_prefs]['writes'].append({
                                'method': method,
                                'key': key,
                                'value': value,
                                'sensitive': sensitive
                            })
            except:
                pass

    proc.terminate()
    subprocess.run(['adb', 'shell', 'am', 'force-stop', spawn_name],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.unlink(tmp.name)

    # Build clean report
    if not prefs_accessed and not datastore_ops and not file_writes:
        mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0001/' target='_blank'>MASTG-TEST-0001: Testing Local Storage for Sensitive Data</a></div>"
        return 'INFO', f"<strong>No SharedPreferences/DataStore usage observed during runtime</strong>{mastg_ref}"

    detail = []

    # DataStore operations
    if datastore_ops:
        detail.append("<div><strong>DataStore Operations:</strong></div>")
        for op in datastore_ops[:20]:
            raw_value = unescape(op['value'])
            value_preview = raw_value[:50] + ('...' if len(raw_value) > 50 else '')
            sensitive_note = " <em>(sensitive)</em>" if op['sensitive'] else ""
            detail.append(
                f"<div style='margin-left:15px'>{op['operation']}: "
                f"<code>{escape(op['key'])}</code> = "
                f"<code>{escape(value_preview, quote=False)}</code>"
                f"{sensitive_note}</div>"
            )
        if len(datastore_ops) > 20:
            detail.append(f"<div style='margin-left:15px'><em>...and {len(datastore_ops) - 20} more operations</em></div>")
        detail.append("<br>")

    # SharedPreferences operations
    if prefs_accessed:
        detail.append("<div><strong>SharedPreferences Files Accessed:</strong></div>")
        for prefs_name, data in prefs_accessed.items():
            encryption_status = "Encrypted" if data['encrypted'] else "Plain"
            detail.append(
                f"<div style='margin-left:15px'><strong>{escape(prefs_name)}</strong> "
                f"<em>({encryption_status})</em></div>"
            )

            if data['writes']:
                for write in data['writes'][:10]:
                    raw_value = unescape(write['value'])
                    value_preview = raw_value[:50] + ('...' if len(raw_value) > 50 else '')
                    sensitive_note = " <em>(sensitive)</em>" if write['sensitive'] else ""
                    detail.append(
                        f"<div style='margin-left:30px'>WRITE: "
                        f"<code>{escape(write['key'])}</code> = "
                        f"<code>{escape(value_preview, quote=False)}</code>"
                        f"{sensitive_note}</div>"
                    )
                if len(data['writes']) > 10:
                    detail.append(f"<div style='margin-left:30px'><em>...and {len(data['writes']) - 10} more writes</em></div>")
        detail.append("<br>")

    if file_writes:
        detail.append("<div><strong>Direct File Writes to shared_prefs/:</strong></div>")
        MAX_FILE_WRITE_ENTRIES = 30  # per file

        for filename in sorted(file_writes.keys())[:10]:
            write_data = file_writes[filename]
            details = write_data['details']

            # Just show the file name – no date/time
            detail.append(
                f"<div style='margin-left:15px'><strong>{escape(filename)}</strong></div>"
            )

            if details:
                # Build an ordered list of UNIQUE (key, value) pairs
                unique_entries = []
                seen = set()
                for item in details:
                    raw_value = unescape(item['value'])
                    sig = (item['key'], raw_value)
                    if sig in seen:
                        continue
                    seen.add(sig)
                    unique_entries.append((item['key'], raw_value))

                to_show = min(len(unique_entries), MAX_FILE_WRITE_ENTRIES)

                for key, raw_value in unique_entries[:to_show]:
                    # For MASTG, show full value but wrap long JSON so it doesn't run off the page
                    value_preview = raw_value
                    detail.append(
                        "<div style='margin-left:30px; "
                        "white-space:pre-wrap; word-break:break-all;'>"
                        f"WRITE: <code>{escape(key)}</code> = "
                        f"<code>{escape(value_preview, quote=False)}</code></div>"
                    )

                if len(unique_entries) > to_show:
                    detail.append(
                        f"<div style='margin-left:30px'><em>.and {len(unique_entries) - to_show} more unique writes</em></div>"
                    )
            else:
                # Write observed, but we couldn't parse XML content
                detail.append(
                    "<div style='margin-left:30px'><em>Write observed, XML content not parsed</em></div>"
                )

        if len(file_writes) > 10:
            detail.append(
                f"<div style='margin-left:15px'><em>...and {len(file_writes) - 10} more files</em></div>"
            )
        detail.append("<br>")

    # MASTG reference
    mastg_ref = "<div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0001/' target='_blank'>MASTG-TEST-0001: Testing Local Storage for Sensitive Data</a></div>"
    detail.append(mastg_ref)

    # Add collapsible Frida output section
    if logs:
        detail.append("<br>")
        detail.append(
            "<details style='margin-top:8px'><summary style='cursor:pointer; font-size:11px; color:#0066cc'>View full Frida output</summary>"
            "<pre style='white-space:pre-wrap; font-size:9px; max-height:300px; overflow-y:auto; background:#f5f5f5; padding:6px'>\n"
        )
        detail.append("\n".join(logs[-600:]))  # cap output to last 600 lines
        detail.append("\n</pre></details>")

    return 'INFO', "<br>\n".join(detail)


def check_frida_external_storage(base, wait_secs=10):
    """
    Dynamic external storage monitoring via Frida:
    - Hooks File constructor to detect external storage paths
    - Monitors FileOutputStream for write operations
    - Identifies sensitive file types being written
    """
    manifest = os.path.join(base, 'AndroidManifest.xml')
    pkg_prefix = ET.parse(manifest).getroot().attrib.get('package', '')

    out = subprocess.check_output(['adb', 'shell', 'pm', 'list', 'packages', pkg_prefix], text=True)
    candidates = [l.split(':', 1)[1].strip() for l in out.splitlines() if l.startswith('package:')]
    if not candidates:
        raise RuntimeError(f"No installed package matching {pkg_prefix!r}")
    spawn_name = candidates[0]

    subprocess.run(['adb', 'shell', 'am', 'force-stop', spawn_name],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    jscode = r"""
    setImmediate(function install(){
      if (!Java.available) return setTimeout(install, 100);
      Java.perform(function(){
        send({type: "ready", msg: "External storage hooks installing..."});

        // Helper to check if path is external storage
        function isExternalPath(path) {
          if (!path) return false;
          return (path.indexOf("/sdcard") === 0 ||
                  path.indexOf("/storage/emulated") === 0 ||
                  path.indexOf("/mnt/sdcard") === 0 ||
                  path.indexOf(externalDir) === 0);
        }

        // Helper to get file extension
        function getExtension(path) {
          var lastDot = path.lastIndexOf(".");
          return (lastDot > 0) ? path.substring(lastDot) : "";
        }

        // Get external storage paths
        var externalDir = "/storage/emulated/0";
        try {
          var Environment = Java.use("android.os.Environment");
          externalDir = Environment.getExternalStorageDirectory().getAbsolutePath();
        } catch(e) {}

        // 1. Hook File constructor
        try {
          var File = Java.use("java.io.File");
          File.$init.overload("java.lang.String").implementation = function(path) {
            if (isExternalPath(path)) {
              send({type: "external_file", path: path, action: "access"});
            }
            return this.$init(path);
          };
        } catch(e) {}

        // 2. Hook FileOutputStream (write operations)
        try {
          var FileOutputStream = Java.use("java.io.FileOutputStream");
          FileOutputStream.$init.overload("java.io.File").implementation = function(file) {
            try {
              var path = file.getAbsolutePath();
              if (isExternalPath(path)) {
                send({type: "external_write", path: path, extension: getExtension(path)});
              }
            } catch(e) {}
            return this.$init(file);
          };

          FileOutputStream.$init.overload("java.lang.String").implementation = function(path) {
            if (isExternalPath(path)) {
              send({type: "external_write", path: path, extension: getExtension(path)});
            }
            return this.$init(path);
          };
        } catch(e) {}

        // 3. Hook FileInputStream (read operations)
        try {
          var FileInputStream = Java.use("java.io.FileInputStream");
          FileInputStream.$init.overload("java.io.File").implementation = function(file) {
            try {
              var path = file.getAbsolutePath();
              if (isExternalPath(path)) {
                send({type: "external_read", path: path, extension: getExtension(path)});
              }
            } catch(e) {}
            return this.$init(file);
          };

          FileInputStream.$init.overload("java.lang.String").implementation = function(path) {
            if (isExternalPath(path)) {
              send({type: "external_read", path: path, extension: getExtension(path)});
            }
            return this.$init(path);
          };
        } catch(e) {}

        // 4. Hook FileWriter (write operations)
        try {
          var FileWriter = Java.use("java.io.FileWriter");
          FileWriter.$init.overload("java.io.File").implementation = function(file) {
            try {
              var path = file.getAbsolutePath();
              if (isExternalPath(path)) {
                send({type: "external_write", path: path, extension: getExtension(path)});
              }
            } catch(e) {}
            return this.$init(file);
          };

          FileWriter.$init.overload("java.lang.String").implementation = function(path) {
            if (isExternalPath(path)) {
              send({type: "external_write", path: path, extension: getExtension(path)});
            }
            return this.$init(path);
          };
        } catch(e) {}

        // 5. Hook FileReader (read operations)
        try {
          var FileReader = Java.use("java.io.FileReader");
          FileReader.$init.overload("java.io.File").implementation = function(file) {
            try {
              var path = file.getAbsolutePath();
              if (isExternalPath(path)) {
                send({type: "external_read", path: path, extension: getExtension(path)});
              }
            } catch(e) {}
            return this.$init(file);
          };

          FileReader.$init.overload("java.lang.String").implementation = function(path) {
            if (isExternalPath(path)) {
              send({type: "external_read", path: path, extension: getExtension(path)});
            }
            return this.$init(path);
          };
        } catch(e) {}

        // 6. Hook RandomAccessFile (read/write operations)
        try {
          var RandomAccessFile = Java.use("java.io.RandomAccessFile");
          RandomAccessFile.$init.overload("java.io.File", "java.lang.String").implementation = function(file, mode) {
            try {
              var path = file.getAbsolutePath();
              if (isExternalPath(path)) {
                var op = (mode.indexOf("w") >= 0) ? "external_write" : "external_read";
                send({type: op, path: path, extension: getExtension(path)});
              }
            } catch(e) {}
            return this.$init(file, mode);
          };

          RandomAccessFile.$init.overload("java.lang.String", "java.lang.String").implementation = function(path, mode) {
            if (isExternalPath(path)) {
              var op = (mode.indexOf("w") >= 0) ? "external_write" : "external_read";
              send({type: op, path: path, extension: getExtension(path)});
            }
            return this.$init(path, mode);
          };
        } catch(e) {}

        send({type: "ready", msg: "External storage hooks installed successfully"});
      });
    });
    """

    tmp = tempfile.NamedTemporaryFile(suffix=".js", delete=False)
    tmp.write(jscode.encode())
    tmp.flush()
    tmp.close()

    proc = subprocess.Popen(
        ['frida', '-l', tmp.name, '-U', '-f', spawn_name],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )

    # Interactive monitoring with user prompt
    instructions = [
        f"App '{spawn_name}' is running with external storage monitoring",
        "Use features that might save files (photos, downloads, exports)",
        "Watch for external storage access below"
    ]
    all_output = interactive_frida_monitor(proc, "EXTERNAL STORAGE", instructions)

    # Parse collected logs
    write_operations = []  # Files written to external storage
    read_operations = []   # Files read from external storage
    access_operations = []  # Files accessed on external storage
    logs = []  # Store all output for collapsible section

    for line in all_output:
        logs.append(line)  # Collect all output for later display

        if 'message:' in line:
            try:
                part = line.split('message:', 1)[1].split('data:', 1)[0].strip()
                msg = ast.literal_eval(part)
                if msg.get('type') == 'send':
                    payload = msg.get('payload', {})
                    if payload.get('type') == 'external_write':
                        path = payload.get('path', '')
                        ext = payload.get('extension', '')
                        # Flag sensitive extensions
                        sensitive_exts = ['.db', '.sqlite', '.sql', '.key', '.pem', '.p12', '.jks', '.keystore']
                        is_sensitive = ext.lower() in sensitive_exts
                        write_operations.append({
                            'path': path,
                            'ext': ext,
                            'sensitive': is_sensitive
                        })
                    elif payload.get('type') == 'external_read':
                        path = payload.get('path', '')
                        ext = payload.get('extension', '')
                        sensitive_exts = ['.db', '.sqlite', '.sql', '.key', '.pem', '.p12', '.jks', '.keystore']
                        is_sensitive = ext.lower() in sensitive_exts
                        read_operations.append({
                            'path': path,
                            'ext': ext,
                            'sensitive': is_sensitive
                        })
                    elif payload.get('type') == 'external_file':
                        access_operations.append(payload.get('path', ''))
            except:
                pass

    proc.terminate()
    subprocess.run(['adb', 'shell', 'am', 'force-stop', spawn_name],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.unlink(tmp.name)

    # Build clean report
    if not write_operations and not read_operations and not access_operations:
        mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0002/' target='_blank'>MASTG-TEST-0002: Testing External Storage for Sensitive Data</a></div>"
        return 'INFO', f"<strong>No external storage usage observed during runtime</strong>{mastg_ref}"

    detail = []

    # Write operations section
    if write_operations:
        detail.append("<div><strong>Files Written to External Storage:</strong></div>")

        # Separate sensitive and regular files
        sensitive_files = [w for w in write_operations if w['sensitive']]
        regular_files = [w for w in write_operations if not w['sensitive']]

        if sensitive_files:
            detail.append("<div style='margin-left:15px; color:#dc3545'><strong>Sensitive Files:</strong></div>")
            for write in sensitive_files[:20]:
                detail.append(f"<div style='margin-left:30px'><code>{html.escape(write['path'])}</code> <em>(ext: {html.escape(write['ext'])})</em></div>")
            if len(sensitive_files) > 20:
                detail.append(f"<div style='margin-left:30px'><em>...and {len(sensitive_files) - 20} more sensitive files</em></div>")

        if regular_files:
            detail.append("<div style='margin-left:15px'><strong>Regular Files:</strong></div>")
            for write in regular_files[:20]:
                detail.append(f"<div style='margin-left:30px'><code>{html.escape(write['path'])}</code> <em>(ext: {html.escape(write['ext'])})</em></div>")
            if len(regular_files) > 20:
                detail.append(f"<div style='margin-left:30px'><em>...and {len(regular_files) - 20} more files</em></div>")

        detail.append("<br>")

    # Read operations section
    if read_operations:
        detail.append("<div><strong>Files Read from External Storage:</strong></div>")

        # Separate sensitive and regular files
        sensitive_reads = [r for r in read_operations if r['sensitive']]
        regular_reads = [r for r in read_operations if not r['sensitive']]

        if sensitive_reads:
            detail.append("<div style='margin-left:15px; color:#dc3545'><strong>Sensitive Files:</strong></div>")
            for read in sensitive_reads[:20]:
                detail.append(f"<div style='margin-left:30px'><code>{html.escape(read['path'])}</code> <em>(ext: {html.escape(read['ext'])})</em></div>")
            if len(sensitive_reads) > 20:
                detail.append(f"<div style='margin-left:30px'><em>...and {len(sensitive_reads) - 20} more sensitive files</em></div>")

        if regular_reads:
            detail.append("<div style='margin-left:15px'><strong>Regular Files:</strong></div>")
            for read in regular_reads[:20]:
                detail.append(f"<div style='margin-left:30px'><code>{html.escape(read['path'])}</code> <em>(ext: {html.escape(read['ext'])})</em></div>")
            if len(regular_reads) > 20:
                detail.append(f"<div style='margin-left:30px'><em>...and {len(regular_reads) - 20} more files</em></div>")

        detail.append("<br>")

    # Access operations section
    if access_operations:
        detail.append("<div><strong>External Storage Paths Accessed:</strong></div>")
        # Show unique paths only
        unique_paths = list(set(access_operations))
        for path in sorted(unique_paths)[:30]:
            detail.append(f"<div style='margin-left:15px'><code>{html.escape(path)}</code></div>")
        if len(unique_paths) > 30:
            detail.append(f"<div style='margin-left:15px'><em>...and {len(unique_paths) - 30} more paths</em></div>")
        detail.append("<br>")

    # MASTG reference
    mastg_ref = "<div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0002/' target='_blank'>MASTG-TEST-0002: Testing External Storage for Sensitive Data</a></div>"
    detail.append(mastg_ref)

    # Add collapsible Frida output section (like Dynamic SharedPreferences)
    if logs:
        detail.append("<br>")
        detail.append(
            "<details style='margin-top:8px'><summary style='cursor:pointer; font-size:11px; color:#0066cc'>View full Frida output</summary>"
            "<pre style='white-space:pre-wrap; font-size:9px; max-height:300px; overflow-y:auto; background:#f5f5f5; padding:6px'>\n"
        )
        detail.append("\n".join(logs[-600:]))  # cap output to last 600 lines
        detail.append("\n</pre></details>")

    return 'INFO', "<br>\n".join(detail)


def check_frida_crypto_keys(base, wait_secs=10):
    """
    Dynamic cryptographic key monitoring via Frida:
    - Hooks SecretKeySpec to detect key material
    - Monitors KeyGenerator for key sizes
    - Checks for hardcoded vs derived keys
    """
    manifest = os.path.join(base, 'AndroidManifest.xml')
    pkg_prefix = ET.parse(manifest).getroot().attrib.get('package', '')

    out = subprocess.check_output(['adb', 'shell', 'pm', 'list', 'packages', pkg_prefix], text=True)
    candidates = [l.split(':', 1)[1].strip() for l in out.splitlines() if l.startswith('package:')]
    if not candidates:
        raise RuntimeError(f"No installed package matching {pkg_prefix!r}")
    spawn_name = candidates[0]

    subprocess.run(['adb', 'shell', 'am', 'force-stop', spawn_name],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    jscode = r"""
    setImmediate(function(){
      if (Java.available) {
        Java.perform(function(){
          // Hook SecretKeySpec constructor
          var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
          SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function(keyBytes, algorithm) {
            var keyLen = keyBytes.length;
            var keyHex = "";
            for (var i = 0; i < Math.min(8, keyLen); i++) {
              keyHex += ("0" + (keyBytes[i] & 0xFF).toString(16)).slice(-2);
            }
            if (keyLen > 8) keyHex += "...";

            send({
              type: "secret_key",
              algorithm: algorithm,
              keyLength: keyLen * 8,
              keyPreview: keyHex
            });
            return this.$init(keyBytes, algorithm);
          };

          // Hook KeyGenerator
          var KeyGenerator = Java.use("javax.crypto.KeyGenerator");
          KeyGenerator.init.overload("int").implementation = function(keySize) {
            send({
              type: "key_generator",
              keySize: keySize
            });
            return this.init(keySize);
          };

          // Hook KeyPairGenerator
          try {
            var KeyPairGenerator = Java.use("java.security.KeyPairGenerator");
            KeyPairGenerator.initialize.overload("int").implementation = function(keySize) {
              send({
                type: "keypair_generator",
                keySize: keySize
              });
              return this.initialize(keySize);
            };
          } catch(e) {}

          send({type: "ready", msg: "Crypto hooks installed"});
        });
      } else {
        setTimeout(arguments.callee, 100);
      }
    });
    """

    tmp = tempfile.NamedTemporaryFile(suffix=".js", delete=False)
    tmp.write(jscode.encode())
    tmp.flush()
    tmp.close()

    proc = subprocess.Popen(
        ['frida', '-l', tmp.name, '-U', '-f', spawn_name],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )

    # Interactive monitoring with user prompt
    instructions = [
        f"App '{spawn_name}' is running with cryptographic key monitoring",
        "Use features that might use encryption (login, data storage, API calls)",
        "Watch for cryptographic key operations below"
    ]
    logs = interactive_frida_monitor(proc, "CRYPTO KEYS", instructions)

    # Parse collected logs
    findings = []
    weak_keys = []
    for line in logs:
        if 'message:' in line:
            try:
                part = line.split('message:', 1)[1].split('data:', 1)[0].strip()
                msg = ast.literal_eval(part)
                if msg.get('type') == 'send':
                    payload = msg.get('payload', {})
                    if payload.get('type') == 'secret_key':
                        algo = payload.get('algorithm', '')
                        keyLen = payload.get('keyLength', 0)
                        preview = payload.get('keyPreview', '')
                        marker = "" if keyLen < 128 else ""
                        findings.append(f"{marker} {algo} key ({keyLen} bits): {preview}")
                        if keyLen < 128:
                            weak_keys.append(f"{algo} with {keyLen} bits")
                    elif payload.get('type') == 'key_generator':
                        size = payload.get('keySize', 0)
                        marker = "" if size >= 128 else "WARNING:"
                        findings.append(f"{marker} Generated key: {size} bits")
                    elif payload.get('type') == 'keypair_generator':
                        size = payload.get('keySize', 0)
                        marker = "" if size >= 2048 else "WARNING:"
                        findings.append(f"{marker} Generated keypair: {size} bits")
                        if size < 2048:
                            weak_keys.append(f"RSA with {size} bits")
            except:
                pass

    proc.terminate()
    subprocess.run(['adb', 'shell', 'am', 'force-stop', spawn_name],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.unlink(tmp.name)

    if not findings:
        return 'PASS', "<strong>No cryptographic operations observed during runtime</strong>"

    detail = [f"<div><strong>Cryptographic operations detected:</strong></div>"]
    if weak_keys:
        detail.append(f"<div><strong>WARNING: Weak keys found:</strong> {', '.join(set(weak_keys))}</div><br>")

    detail.extend([f"<div>{html.escape(f)}</div>" for f in findings[:30]])
    if len(findings) > 30:
        detail.append(f"<div>...and {len(findings) - 30} more</div>")

    status = 'FAIL' if weak_keys else 'PASS'
    return status, "<br>\n".join(detail)


def check_frida_clipboard(base, wait_secs=10):
    """
    Dynamic clipboard monitoring via Frida:
    - Hooks ClipboardManager.setPrimaryClip
    - Captures clipboard content
    - Checks for sensitive data patterns
    """
    manifest = os.path.join(base, 'AndroidManifest.xml')
    pkg_prefix = ET.parse(manifest).getroot().attrib.get('package', '')

    out = subprocess.check_output(['adb', 'shell', 'pm', 'list', 'packages', pkg_prefix], text=True)
    candidates = [l.split(':', 1)[1].strip() for l in out.splitlines() if l.startswith('package:')]
    if not candidates:
        raise RuntimeError(f"No installed package matching {pkg_prefix!r}")
    spawn_name = candidates[0]

    subprocess.run(['adb', 'shell', 'am', 'force-stop', spawn_name],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    jscode = r"""
    setImmediate(function(){
      if (Java.available) {
        Java.perform(function(){
          var ClipboardManager = Java.use("android.content.ClipboardManager");

          ClipboardManager.setPrimaryClip.implementation = function(clip) {
            try {
              var item = clip.getItemAt(0);
              var text = item.getText();
              if (text) {
                var textStr = text.toString();
                var preview = textStr.substring(0, 100);

                // Check for sensitive patterns
                var sensitive = false;
                var patterns = ["password", "token", "key", "secret", "auth", "bearer", "credit"];
                for (var i = 0; i < patterns.length; i++) {
                  if (textStr.toLowerCase().indexOf(patterns[i]) >= 0) {
                    sensitive = true;
                    break;
                  }
                }

                send({
                  type: "clipboard",
                  preview: preview,
                  length: textStr.length,
                  sensitive: sensitive
                });
              }
            } catch(e) {}
            return this.setPrimaryClip(clip);
          };

          send({type: "ready", msg: "Clipboard hooks installed"});
        });
      } else {
        setTimeout(arguments.callee, 100);
      }
    });
    """

    tmp = tempfile.NamedTemporaryFile(suffix=".js", delete=False)
    tmp.write(jscode.encode())
    tmp.flush()
    tmp.close()

    proc = subprocess.Popen(
        ['frida', '-l', tmp.name, '-U', '-f', spawn_name],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )

    # Interactive monitoring with user prompt
    instructions = [
        f"App '{spawn_name}' is running with clipboard monitoring",
        "Use features that may copy data to clipboard (passwords, codes, etc.)",
        "Watch for clipboard operations below"
    ]
    logs = interactive_frida_monitor(proc, "CLIPBOARD", instructions)

    # Parse collected logs
    findings = []
    sensitive_count = 0
    clipboard_items = []  # Store individual clipboard operations with details

    for line in logs:
        if 'message:' in line:
            try:
                part = line.split('message:', 1)[1].split('data:', 1)[0].strip()
                msg = ast.literal_eval(part)
                if msg.get('type') == 'send':
                    payload = msg.get('payload', {})
                    if payload.get('type') == 'clipboard':
                        preview = payload.get('preview', '')
                        length = payload.get('length', 0)
                        sensitive = payload.get('sensitive', False)
                        marker = "[!]" if sensitive else "[ ]"
                        if sensitive:
                            sensitive_count += 1

                        findings.append(f"{marker} Copied {length} chars: {preview}")
                        clipboard_items.append({
                            'preview': preview,
                            'length': length,
                            'sensitive': sensitive
                        })
            except:
                pass

    proc.terminate()
    subprocess.run(['adb', 'shell', 'am', 'force-stop', spawn_name],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.unlink(tmp.name)

    # MASTG reference
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0001/' target='_blank'>MASTG-TEST-0001: Testing Local Storage for Sensitive Data</a></div>"

    if not findings:
        return 'PASS', f"<div><strong>No clipboard usage observed during runtime</strong></div>{mastg_ref}"

    # Build detailed report with summary
    summary_parts = []

    if sensitive_count > 0:
        summary_parts.append("<div style='background:#f8d7da; border-left:4px solid #dc3545; padding:10px; margin:10px 0;'>")
        summary_parts.append(f"<strong style='color:#dc2626;'>WARNING: Sensitive data copied to clipboard: {sensitive_count} time(s)</strong><br>")
        summary_parts.append("<strong>Risk:</strong> Any app with clipboard access can read this data<br>")
        summary_parts.append("<strong>Threat:</strong> Malicious keyboard apps, screen readers, or accessibility services can steal sensitive data")
        summary_parts.append("</div>")
    else:
        summary_parts.append(f"<div><strong>Clipboard operations detected:</strong> {len(findings)} item(s)</div>")
        summary_parts.append("<div style='margin-top:4px; color:#666; font-size:11px'>No sensitive data patterns detected</div>")

    # Show clipboard items with details
    summary_parts.append("<br><div><strong>Clipboard Contents:</strong></div>")
    for item in clipboard_items[:20]:
        marker = "[!]" if item['sensitive'] else "[ ]"
        sensitivity_label = "<span style='color:#dc2626; font-weight:bold;'>[SENSITIVE]</span>" if item['sensitive'] else ""
        summary_parts.append(
            f"<div style='padding:6px; margin:4px 0; background:#f9f9f9; border-left:3px solid {'#dc3545' if item['sensitive'] else '#ccc'};'>"
            f"{marker} <strong>{item['length']} chars</strong> {sensitivity_label}<br>"
            f"<code style='background:#e9ecef; padding:4px 6px; border:1px solid #adb5bd; color:#000; font-family:Consolas,Monaco,monospace; font-weight:500; border-radius:3px;'>{html.escape(item['preview'])}</code>"
            f"</div>"
        )

    if len(clipboard_items) > 20:
        summary_parts.append(f"<div style='color:#666; font-size:11px; margin-top:4px;'>...and {len(clipboard_items) - 20} more items</div>")

    # Add MASTG reference before Frida output
    summary_parts.append(mastg_ref)

    # Add collapsible full Frida output section (like Dynamic TLS test)
    if logs:
        detail = (
            "<div>" + "".join(summary_parts) + "</div>" +
            "<details style='margin-top:8px'><summary style='cursor:pointer; font-size:11px; color:#0066cc'>View full Frida output</summary>" +
            "<pre style='white-space:pre-wrap; font-size:9px; max-height:300px; overflow-y:auto; background:#f5f5f5; padding:6px; border:1px solid #ddd;'>\n" +
            html.escape("\n".join(logs[-600:])) +  # cap output to last 600 lines and escape HTML
            "\n</pre></details>"
        )
    else:
        detail = "<div>" + "".join(summary_parts) + "</div>"

    status = 'FAIL' if sensitive_count > 0 else 'WARN'
    return status, detail


def check_storage_analysis(base, package_name):
    """
    Comprehensive storage analysis:
    1. Capture initial storage state with adb shell su -c 'ls -laR /data/data/{package}'
    2. Clear app data
    3. Launch app to initialize
    4. Capture final storage state
    5. Compare and report differences (new files, directories created)

    Returns (status, detail) where status is 'PASS'|'WARN'|'FAIL'
    """
    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0001/' target='_blank'>MASTG-TEST-0001: Testing Local Storage for Sensitive Data</a></div>"

    import difflib

    def get_storage_listing(pkg):
        """Get detailed storage listing using adb shell su"""
        try:
            result = subprocess.run(
                ['adb', 'shell', 'su', '-c', f'ls -laR /data/data/{pkg}'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                return None, f"Error: {result.stderr}"
            return result.stdout, None
        except subprocess.TimeoutExpired:
            return None, "Timeout getting storage listing"
        except Exception as e:
            return None, f"Error: {str(e)}"

    def parse_storage_output(output):
        """Parse ls -laR output into structured data"""
        files = {}
        current_dir = None

        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue

            # Directory header: /data/data/com.example/files:
            if line.startswith('/data/data/') and line.endswith(':'):
                current_dir = line[:-1]
                files[current_dir] = []
            # File entry
            elif current_dir and line and not line.startswith('total '):
                files[current_dir].append(line)

        return files

    def check_db_encryption(db_path):
        """
        Check if a database file is encrypted by reading its header.
        SQLite databases start with "SQLite format 3" in plain text.
        Encrypted databases (SQLCipher) have encrypted headers.
        Returns: True if encrypted, False if not encrypted, None if can't determine
        """
        try:
            result = subprocess.run(
                ['adb', 'shell', 'su', '-c', f'head -c 16 {db_path}'],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                header = result.stdout
                # SQLite magic string: "SQLite format 3"
                if b'SQLite format 3' in header:
                    return False  # Not encrypted
                else:
                    return True  # Encrypted (no recognizable header)
            return None
        except:
            return None

    detail = []
    detail.append("<div class='storage-section'><strong>Storage Analysis Report</strong></div>")

    # Step 1: Get initial storage state
    initial_output, error = get_storage_listing(package_name)
    if error:
        return 'FAIL', f"<div>Failed to get initial storage state: {html.escape(error)}</div>" + mastg_ref
    initial_files = parse_storage_output(initial_output)

    # Step 2: Clear app data
    try:
        subprocess.run(['adb', 'shell', 'pm', 'clear', package_name],
                      capture_output=True, timeout=10, check=True)
    except Exception as e:
        return 'FAIL', f"<div>Failed to clear app data: {html.escape(str(e))}</div>" + mastg_ref

    # Step 3: Launch app
    try:
        subprocess.run(['adb', 'shell', 'monkey', '-p', package_name, '-c',
                       'android.intent.category.LAUNCHER', '1'],
                      capture_output=True, timeout=10)
        time.sleep(5)
    except Exception as e:
        return 'FAIL', f"<div>Failed to launch app: {html.escape(str(e))}</div>" + mastg_ref

    # Step 4: Get final storage state
    final_output, error = get_storage_listing(package_name)
    if error:
        return 'FAIL', f"<div>Failed to get final storage state: {html.escape(error)}</div>" + mastg_ref
    final_files = parse_storage_output(final_output)

    new_dirs = set(final_files.keys()) - set(initial_files.keys())
    new_files = {}
    modified_files = {}

    for dir_path in final_files:
        if dir_path in new_dirs:
            new_files[dir_path] = final_files[dir_path]
        elif dir_path in initial_files:
            # Compare file lists
            initial_set = set(initial_files[dir_path])
            final_set = set(final_files[dir_path])
            diff = final_set - initial_set
            if diff:
                modified_files[dir_path] = list(diff)

    # Generate report
    findings = []
    security_issues = []
    secure_dbs = []  # Track encrypted databases

    # Section 1: New directories (show all, no limits)
    if new_dirs:
        findings.append(f"<div class='storage-section'><strong> New Directories: {len(new_dirs)}</strong></div>")
        findings.append("<div class='storage-item'>")
        for dir_path in sorted(new_dirs):
            files_in_dir = new_files.get(dir_path, [])
            file_count = f" <span class='text-muted'>({len(files_in_dir)} files)</span>" if files_in_dir else ""
            findings.append(f"<div>{html.escape(dir_path)}{file_count}</div>")
        findings.append("</div>")

    # Section 2: New files in existing directories (show all, better formatting)
    if modified_files:
        total_new_files = sum(len(files) for files in modified_files.values())
        findings.append(f"<div class='storage-section'><strong>New Files: {total_new_files}</strong></div>")
        findings.append("<div class='storage-item'>")

        for dir_path, files in sorted(modified_files.items()):
            findings.append(f"<div><strong> {html.escape(dir_path)}</strong></div>")
            findings.append("<div class='file-list-box'>")

            for file_entry in files:
                findings.append(f"<div>{html.escape(file_entry)}</div>")

                # Security checks
                if '.xml' in file_entry and 'shared_prefs' in dir_path:
                    if '-rw-' in file_entry and '---' not in file_entry:
                        security_issues.append(f"WARNING: Shared preferences file with potentially insecure permissions: {file_entry}")

                if '.db' in file_entry:
                    # Extract the database filename from the ls output
                    db_filename = file_entry.split()[-1] if file_entry.split() else None

                    # Skip SQLite temporary/auxiliary files
                    if db_filename and any(db_filename.endswith(ext) for ext in ['.db-journal', '.db-shm', '.db-wal']):
                        continue

                    # Only check actual .db files
                    if not db_filename or not db_filename.endswith('.db'):
                        continue

                    db_full_path = f"{dir_path}/{db_filename}" if db_filename else None

                    # Check encryption status
                    is_encrypted = check_db_encryption(db_full_path) if db_full_path else None

                    if '-rw-rw-' in file_entry or '-rw-rw-rw-' in file_entry:
                        # World-readable database - security issue
                        if is_encrypted:
                            security_issues.append(f" Database file with world-readable permissions (encrypted): {file_entry}")
                        else:
                            security_issues.append(f" Database file with world-readable permissions: {file_entry}")
                    elif is_encrypted:
                        # Secure encrypted database
                        secure_dbs.append(f"{file_entry}")

                if any(ext in file_entry for ext in ['.key', '.pem', '.jks', '.p12']):
                    security_issues.append(f" Cryptographic key file detected: {file_entry}")

            findings.append("</div>")

        findings.append("</div>")

    # Section 3: Secure encrypted databases (show all)
    if secure_dbs:
        findings.append(f"<div class='storage-section'><strong>Secure Encrypted Databases: {len(secure_dbs)}</strong></div>")
        findings.append("<div class='storage-secure-box' style='background:#d4edda; border-left:4px solid #28a745; padding:10px; margin:10px 0;'>")
        for db in secure_dbs:
            findings.append(f"<div>{html.escape(db)}</div>")
        findings.append("</div>")

    # Section 4: Security issues (show all, with better formatting)
    if security_issues:
        findings.append(f"<div class='storage-section'><strong>Security Issues: {len(security_issues)}</strong></div>")
        findings.append("<div class='storage-issue-box'>")
        for issue in security_issues:
            findings.append(f"<div>{html.escape(issue)}</div>")
        findings.append("</div>")

    # Summary section
    findings.append("<div class='storage-section'><strong>Summary:</strong></div>")
    findings.append("<div class='storage-item'>")
    findings.append(f"<div>• New directories: <strong>{len(new_dirs)}</strong></div>")
    total_files = sum(len(files) for files in modified_files.values())
    findings.append(f"<div>• New files: <strong>{total_files}</strong></div>")
    if secure_dbs:
        findings.append(f"<div>• Secure encrypted databases: <strong class='text-success'>{len(secure_dbs)}</strong></div>")
    issue_color = 'text-danger' if security_issues else 'text-success'
    findings.append(f"<div>• Security issues: <strong class='{issue_color}'>{len(security_issues)}</strong></div>")
    findings.append("</div>")

    detail.extend(findings)

    # Determine status
    if security_issues:
        status = 'FAIL'
    elif new_dirs or modified_files:
        status = 'WARN'
    else:
        status = 'PASS'

    return status, "<br>\n".join(detail) + mastg_ref


def check_pending_intent_flags(base):
    """
    MASTG-TEST-0030: Vulnerable Implementation of PendingIntent

    Check for PendingIntent usage without FLAG_IMMUTABLE (Android 12+).
    Mutable PendingIntents can be hijacked by malicious apps.

    Reference: https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0030/
    """
    # SMALI patterns for decompiled APK
    pending_intent_patterns = [
        r'Landroid/app/PendingIntent;->getActivity',
        r'Landroid/app/PendingIntent;->getBroadcast',
        r'Landroid/app/PendingIntent;->getService',
        r'Landroid/app/PendingIntent;->getForegroundService',
    ]

    # Flag patterns - these are static final int constants (const/high16 or const)
    flag_immutable = r'0x4000000|67108864'  # FLAG_IMMUTABLE = 0x04000000 (67108864)
    flag_mutable = r'0x8000000|134217728'   # FLAG_MUTABLE = 0x08000000 (134217728)
    flag_update = r'0x8000000[08]|134217728'  # FLAG_UPDATE_CURRENT = 0x08000000 (134217728)

    vulnerable_files = []
    mutable_files = []
    update_current_files = []
    immutable_files = set()

    for root, _, files in os.walk(base):
        for fn in files:
            if not fn.endswith(('.smali', '.java')):
                continue
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, base)

            try:
                lines = open(full, errors='ignore').readlines()
                content = ''.join(lines)

                has_pending_intent = any(re.search(pat, content) for pat in pending_intent_patterns)
                if not has_pending_intent:
                    continue

                has_immutable = re.search(flag_immutable, content)
                has_mutable = re.search(flag_mutable, content)
                has_update_current = re.search(flag_update, content)

                # Find the line with PendingIntent call for snippet
                code_snippet = None
                line_num = 0
                for i, line in enumerate(lines, 1):
                    if any(re.search(pat, line) for pat in pending_intent_patterns):
                        code_snippet = line.strip()
                        line_num = i
                        break

                if has_immutable:
                    immutable_files.add(rel)
                elif has_mutable:
                    mutable_files.append((rel, line_num, code_snippet))
                elif has_update_current:
                    update_current_files.append((rel, line_num, code_snippet))
                else:
                    vulnerable_files.append((rel, line_num, code_snippet))
            except Exception:
                pass

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0030/' target='_blank'>MASTG-TEST-0030: Testing for Vulnerable Implementation of PendingIntent</a></div>"

    if not immutable_files and not vulnerable_files and not mutable_files and not update_current_files:
        return 'PASS', f"No PendingIntent usage detected{mastg_ref}"

    issues = []
    status = 'PASS'

    if vulnerable_files or mutable_files:
        status = 'FAIL'
        if vulnerable_files:
            issues.append(
                f"<div><strong>CRITICAL: {len(vulnerable_files)} file(s) create PendingIntent without FLAG_IMMUTABLE</strong></div>"
            )
            issues.append("<div>This is required on Android 12+ (API 31+) and prevents intent hijacking.</div>")
            for rel, line_num, code_snippet in vulnerable_files[:15]:
                full = os.path.abspath(os.path.join(base, rel))
                issues.append(f'<a href="file://{html.escape(full)}">{html.escape(rel)}</a>')
                if code_snippet:
                    issues.append(f'<pre><code>{html.escape(code_snippet)}</code></pre>')

        if mutable_files:
            issues.append(
                f"<div><strong>CRITICAL: {len(mutable_files)} file(s) explicitly use FLAG_MUTABLE</strong></div>"
            )
            issues.append("<div>Mutable PendingIntents allow the recipient to modify the underlying Intent.</div>")
            for rel, line_num, code_snippet in mutable_files[:15]:
                full = os.path.abspath(os.path.join(base, rel))
                issues.append(f'<a href="file://{html.escape(full)}">{html.escape(rel)}</a>')
                if code_snippet:
                    issues.append(f'<pre><code>{html.escape(code_snippet)}</code></pre>')

    if update_current_files:
        if status == 'PASS':
            status = 'WARN'
        issues.append(
            f"<div>WARNING: {len(update_current_files)} file(s) use FLAG_UPDATE_CURRENT</div>"
        )
        issues.append(
            "<div>On Android 12+, combine with FLAG_IMMUTABLE: <code>FLAG_UPDATE_CURRENT | FLAG_IMMUTABLE</code></div>"
        )
        for rel, line_num, code_snippet in update_current_files[:15]:
            full = os.path.abspath(os.path.join(base, rel))
            issues.append(f'<a href="file://{html.escape(full)}">{html.escape(rel)}</a>')
            if code_snippet:
                issues.append(f'<pre><code>{html.escape(code_snippet)}</code></pre>')

    if immutable_files and status == 'PASS':
        issues.append(f"<div>FLAG_IMMUTABLE found in {len(immutable_files)} file(s)</div>")

    if not issues:
        return 'PASS', f"All PendingIntents properly secured with FLAG_IMMUTABLE{mastg_ref}"

    issues.append(mastg_ref)
    return status, "<br>\n".join(issues)


def check_webview_ssl_error_handling(base):
    """
    MASTG-TEST-0284: Incorrect SSL Error Handling in WebViews

    Detect WebViewClient.onReceivedSslError() implementations that accept
    all certificates by calling proceed() without validation.

    Reference: https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0284/
    """
    vulnerable_files = []

    for root, _, files in os.walk(base):
        for fn in files:
            if not fn.endswith(('.smali', '.java')):
                continue
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, base)

            try:
                with open(full, errors='ignore') as f:
                    lines = f.readlines()

                in_ssl_error_method = False

                for i, line in enumerate(lines, 1):
                    if 'onReceivedSslError' in line and '.method' in line:
                        in_ssl_error_method = True

                    if in_ssl_error_method:
                        if 'invoke-' in line and 'proceed' in line and 'SslErrorHandler' in line:
                            snippet = html.escape(lines[i-1].strip()[:100])
                            link = f'<a href="file://{html.escape(full)}#L{i}">{html.escape(rel)}:{i}</a>'
                            vulnerable_files.append(f"{link} ⟶ <code>{snippet}</code>")
                            in_ssl_error_method = False
                            break

                        if '.end method' in line:
                            in_ssl_error_method = False
            except Exception:
                pass

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0284/' target='_blank'>MASTG-TEST-0284: Incorrect SSL Error Handling in WebViews</a></div>"

    if not vulnerable_files:
        return 'PASS', f"No insecure SSL error handling detected in WebViews{mastg_ref}"

    result = [
        f"<div><strong>CRITICAL: {len(vulnerable_files)} SSL error handler(s) bypass certificate validation</strong></div>",
        "<div>WebViewClient.onReceivedSslError() calls proceed(), accepting all certificates.</div>",
        "<div>This allows man-in-the-middle attacks. Use cancel() instead.</div>",
        "<br>".join(vulnerable_files[:20]),
        mastg_ref
    ]

    return 'FAIL', "<br>\n".join(result)


def check_recent_screenshot_disabled(base):
    """
    MASTG-TEST-0292: setRecentsScreenshotEnabled Not Used

    Check if setRecentsScreenshotEnabled(false) is used to prevent
    sensitive data in recent tasks screenshot (Android 13+).

    Reference: https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0292/
    """
    protection_patterns = [
        r'setRecentsScreenshotEnabled\s*\(\s*false',
        r'setExcludeFromRecents\s*\(\s*true',
        r'excludeFromRecents\s*=\s*["\']true',
    ]

    protected_files = set()

    for pat in protection_patterns:
        for root, _, files in os.walk(base):
            for fn in files:
                if not fn.endswith(('.smali', '.java', '.xml')):
                    continue
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, base)

                try:
                    if re.search(pat, open(full, errors='ignore').read()):
                        protected_files.add(rel)
                except Exception:
                    pass

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0292/' target='_blank'>MASTG-TEST-0292: setRecentsScreenshotEnabled Not Used to Prevent Screenshots When Backgrounded</a></div>"

    if protected_files:
        lines = [
            f"<div>Recent screenshot protection detected in {len(protected_files)} file(s)</div>",
            "<div>setRecentsScreenshotEnabled(false) prevents sensitive data in task switcher.</div>"
        ]
        for rel in sorted(protected_files)[:10]:
            full = os.path.abspath(os.path.join(base, rel))
            lines.append(f'<a href="file://{html.escape(full)}">{html.escape(rel)}</a>')
        lines.append(mastg_ref)
        return 'PASS', "<br>\n".join(lines)

    return 'WARN', (
        "<div>No recent screenshot protection detected</div>"
        "<div>Recommendation: Use <code>Activity.setRecentsScreenshotEnabled(false)</code> "
        "on activities displaying sensitive data (Android 13+).</div>"
        "<div>This prevents screenshots from appearing in the recent tasks overview.</div>"
        f"{mastg_ref}"
    )


def check_dangerous_permissions(manifest):
    """
    MASTG-TEST-0254/0255: Dangerous App Permissions Analysis

    Analyze all requested permissions and flag dangerous ones.

    Reference: https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0254/
    """
    dangerous_permissions = {
        'ACCESS_FINE_LOCATION': 'Location (Precise)', 'ACCESS_COARSE_LOCATION': 'Location (Approximate)',
        'ACCESS_BACKGROUND_LOCATION': 'Location (Background)', 'CAMERA': 'Camera',
        'RECORD_AUDIO': 'Microphone', 'READ_CONTACTS': 'Contacts (Read)',
        'WRITE_CONTACTS': 'Contacts (Write)', 'READ_PHONE_STATE': 'Phone (State)',
        'READ_PHONE_NUMBERS': 'Phone (Numbers)', 'CALL_PHONE': 'Phone (Make Calls)',
        'READ_CALL_LOG': 'Phone (Call Log)', 'WRITE_CALL_LOG': 'Phone (Call Log Write)',
        'SEND_SMS': 'SMS (Send)', 'RECEIVE_SMS': 'SMS (Receive)', 'READ_SMS': 'SMS (Read)',
        'READ_EXTERNAL_STORAGE': 'Storage (Read)', 'WRITE_EXTERNAL_STORAGE': 'Storage (Write)',
        'READ_MEDIA_IMAGES': 'Media (Images)', 'READ_MEDIA_VIDEO': 'Media (Video)',
        'READ_CALENDAR': 'Calendar (Read)', 'WRITE_CALENDAR': 'Calendar (Write)',
        'BODY_SENSORS': 'Body Sensors', 'ACTIVITY_RECOGNITION': 'Activity Recognition',
        'BLUETOOTH_SCAN': 'Bluetooth (Scan)', 'POST_NOTIFICATIONS': 'Notifications',
    }

    critical_permissions = {
        'ACCESS_BACKGROUND_LOCATION', 'RECORD_AUDIO', 'CAMERA', 'READ_SMS',
        'SEND_SMS', 'READ_CALL_LOG', 'WRITE_CALL_LOG',
    }

    try:
        tree = ET.parse(manifest)
        root = tree.getroot()
    except Exception as e:
        return 'WARN', f"<div>Failed to parse manifest: {html.escape(str(e))}</div>"

    permissions = []
    for perm in root.findall('.//{http://schemas.android.com/apk/res/android}uses-permission'):
        name = perm.get('{http://schemas.android.com/apk/res/android}name', '')
        if name.startswith('android.permission.'):
            permissions.append(name.replace('android.permission.', ''))

    if not permissions:
        return 'PASS', "<div>No dangerous permissions requested</div>"

    dangerous_found = []
    critical_found = []
    normal_found = []

    for perm in permissions:
        if perm in dangerous_permissions:
            if perm in critical_permissions:
                critical_found.append((perm, dangerous_permissions[perm]))
            else:
                dangerous_found.append((perm, dangerous_permissions[perm]))
        else:
            normal_found.append(perm)

    lines = []
    status = 'PASS'

    if critical_found:
        status = 'WARN'
        lines.append(f"<div><strong>WARNING: {len(critical_found)} CRITICAL permission(s) requested:</strong></div>")
        lines.append("<ul style='margin-left:20px;'>")
        for perm, desc in critical_found:
            lines.append(
                f"<li><code>{perm}</code> - {desc} <span style='color:#d97706;'>[High Privacy Risk]</span></li>"
            )
        lines.append("</ul>")
        lines.append("<div><strong>Verify:</strong> Are these absolutely necessary for core functionality?</div>")

    if dangerous_found:
        if status == 'PASS':
            status = 'WARN'
        lines.append(f"<div><strong>{len(dangerous_found)} dangerous permission(s):</strong></div>")
        lines.append("<ul style='margin-left:20px;'>")
        for perm, desc in dangerous_found:
            lines.append(f"<li><code>{perm}</code> - {desc}</li>")
        lines.append("</ul>")

    if normal_found:
        lines.append(f"<div>{len(normal_found)} normal permission(s): {', '.join(['<code>' + p + '</code>' for p in normal_found[:5]])}")
        if len(normal_found) > 5:
            lines.append(f" and {len(normal_found) - 5} more...")
        lines.append("</div>")

    lines.append("<br><div><strong>MASTG Recommendations:</strong></div>")
    lines.append("<ul style='margin-left:20px;'>")
    lines.append("<li>Request permissions at runtime, not installation</li>")
    lines.append("<li>Provide clear rationale before requesting</li>")
    lines.append("<li>Request only when needed</li>")
    lines.append("</ul>")

    lines.append("<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0254/' target='_blank'>MASTG-TEST-0254: Dangerous App Permissions</a></div>")

    return status, "<br>\n".join(lines)


def check_datastore_encryption(base):
    """
    MASTG-TEST-0305: Sensitive Data via DataStore

    Check for Jetpack DataStore usage IN APP CODE and verify encryption.
    Filters out androidx library files.

    Reference: https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0305/
    """
    # Library paths to exclude
    lib_paths = (
        '/androidx/', '/android/support/',
        '/com/google/android/gms/', '/com/google/firebase/', '/com/google/android/play/',
        '/com/google/common/', '/okhttp3/', '/okio/', '/retrofit2/', '/com/squareup/',
        '/com/facebook/', '/kotlin/', '/kotlinx/',
        '/io/reactivex/', '/rx/', '/dagger/',
        '/lib/', '/jetified-'
    )

    def is_library_path(path):
        """Check if path is library code"""
        normalized = '/' + path.replace('\\', '/')
        return any(lib in normalized for lib in lib_paths)

    # DataStore API usage patterns (SMALI patterns for decompiled APK)
    datastore_patterns = [
        r'Landroidx/datastore/core/DataStore;',
        r'Landroidx/datastore/preferences/core/Preferences;',
        r'Landroidx/datastore/core/DataStoreFactory;->create',
        r'Landroidx/datastore/preferences/PreferenceDataStoreFactory;',
    ]

    # Encryption patterns
    encryption_patterns = [
        r'Landroidx/security/crypto/EncryptedFile;',
        r'Landroidx/security/crypto/MasterKey;',
        r'Lcom/google/crypto/tink/',
    ]

    datastore_files = set()
    encrypted_files = set()

    # Scan for DataStore usage in APP CODE only
    for root, _, files in os.walk(base):
        for fn in files:
            if not fn.endswith('.smali'):
                continue

            full = os.path.join(root, fn)
            rel = os.path.relpath(full, base)

            # SKIP library files
            if is_library_path(rel):
                continue

            try:
                content = open(full, errors='ignore').read()

                # Check for DataStore usage
                for pat in datastore_patterns:
                    if re.search(pat, content):
                        datastore_files.add(rel)
                        break

                # Check for encryption
                for pat in encryption_patterns:
                    if re.search(pat, content):
                        encrypted_files.add(rel)
                        break

            except Exception:
                pass

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0305/' target='_blank'>MASTG-TEST-0305: Sensitive Data Stored Unencrypted via DataStore</a></div>"

    if not datastore_files:
        return 'PASS', f"<div>No Jetpack DataStore usage detected in app code</div>{mastg_ref}"

    if encrypted_files:
        lines = [
            f"<div>DataStore encryption detected in {len(encrypted_files)} file(s)</div>",
            "<div>App code uses EncryptedFile or Tink with DataStore.</div>"
        ]
        for rel in sorted(encrypted_files)[:5]:
            full = os.path.abspath(os.path.join(base, rel))
            lines.append(f'<a href="file://{html.escape(full)}">{html.escape(rel)}</a>')
        lines.append(mastg_ref)
        return 'PASS', "<br>\n".join(lines)

    lines = [
        f"<div><strong>WARNING: {len(datastore_files)} file(s) in app code use DataStore without encryption</strong></div>",
        "<div>DataStore stores data in plaintext by default.</div>",
        "<div>Recommendation: Use <code>EncryptedFile</code> with Tink or <code>MasterKey</code>.</div>",
        "<br><div><strong>App code files using DataStore:</strong></div>"
    ]
    for rel in sorted(datastore_files)[:15]:
        full = os.path.abspath(os.path.join(base, rel))
        lines.append(f'<a href="file://{html.escape(full)}">{html.escape(rel)}</a>')

    lines.append(mastg_ref)
    return 'WARN', "<br>\n".join(lines)


def check_room_encryption(base):
    """
    MASTG-TEST-0306: Sensitive Data via Android Room DB

    Check for Room database usage IN APP CODE and verify SQLCipher encryption.
    Filters out androidx library files.

    Reference: https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0306/
    """
    # Library paths to exclude
    lib_paths = (
        '/androidx/', '/android/support/',
        '/com/google/android/gms/', '/com/google/firebase/', '/com/google/android/play/',
        '/com/google/common/', '/okhttp3/', '/okio/', '/retrofit2/', '/com/squareup/',
        '/com/facebook/', '/kotlin/', '/kotlinx/',
        '/io/reactivex/', '/rx/', '/dagger/',
        '/lib/', '/jetified-'
    )

    def is_library_path(path):
        """Check if path is library code"""
        normalized = '/' + path.replace('\\', '/')
        return any(lib in normalized for lib in lib_paths)

    # Room API usage patterns (SMALI patterns for decompiled APK)
    room_patterns = [
        r'Landroidx/room/RoomDatabase;',
        r'Landroidx/room/Room;->databaseBuilder',
        r'\.annotation.*Landroidx/room/Database;',  # SMALI annotation syntax
        r'Landroidx/room/Dao;',
    ]

    # SQLCipher encryption patterns (SMALI patterns)
    encryption_patterns = [
        r'Lnet/sqlcipher/',
        r'Lnet/sqlcipher/database/SQLiteDatabase;',
        r'Landroidx/sqlite/db/SupportSQLiteOpenHelper\$Factory;',
        r'openOrCreateDatabase.*sqlcipher',
    ]

    room_files = set()
    encrypted_files = set()

    # Scan for Room usage in APP CODE only
    for root, _, files in os.walk(base):
        for fn in files:
            if not fn.endswith('.smali'):
                continue

            full = os.path.join(root, fn)
            rel = os.path.relpath(full, base)

            # SKIP library files
            if is_library_path(rel):
                continue

            try:
                content = open(full, errors='ignore').read()

                # Check for Room usage
                for pat in room_patterns:
                    if re.search(pat, content):
                        room_files.add(rel)
                        break

                # Check for encryption
                for pat in encryption_patterns:
                    if re.search(pat, content):
                        encrypted_files.add(rel)
                        break

            except Exception:
                pass

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0306/' target='_blank'>MASTG-TEST-0306: Sensitive Data Stored Unencrypted via Android Room DB</a></div>"

    if not room_files:
        return 'PASS', f"<div>No Room database usage detected in app code</div>{mastg_ref}"

    if encrypted_files:
        lines = [
            f"<div>Room database encryption detected in {len(encrypted_files)} file(s)</div>",
            "<div>App code uses SQLCipher with Room.</div>"
        ]
        for rel in sorted(encrypted_files)[:5]:
            full = os.path.abspath(os.path.join(base, rel))
            lines.append(f'<a href="file://{html.escape(full)}">{html.escape(rel)}</a>')
        lines.append(mastg_ref)
        return 'PASS', "<br>\n".join(lines)

    lines = [
        f"<div><strong>WARNING: {len(room_files)} file(s) in app code use Room database without encryption</strong></div>",
        "<div>Room databases are stored in plaintext by default.</div>",
        "<div>Recommendation: Use SQLCipher with Room via <code>SupportFactory</code>.</div>",
        "<br><div><strong>App code files using Room:</strong></div>"
    ]
    for rel in sorted(room_files)[:15]:
        full = os.path.abspath(os.path.join(base, rel))
        lines.append(f'<a href="file://{html.escape(full)}">{html.escape(rel)}</a>')

    lines.append(mastg_ref)
    return 'WARN', "<br>\n".join(lines)


def check_anti_debugging(base):
    """
    MASTG-TEST-0046: Testing Anti-Debugging Detection

    Detect anti-debugging mechanisms.

    Reference: https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0046/
    """
    anti_debug_patterns = [
        (r'Debug\.isDebuggerConnected', 'isDebuggerConnected()'),
        (r'Debug\.waitingForDebugger', 'waitingForDebugger()'),
        (r'ApplicationInfo\.FLAG_DEBUGGABLE', 'FLAG_DEBUGGABLE check'),
        (r'TracerPid', 'TracerPid check (native)'),
    ]

    detections = defaultdict(list)

    for pat, desc in anti_debug_patterns:
        for rel in grep_code(base, pat):
            detections[desc].append(rel)

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0046/' target='_blank'>MASTG-TEST-0046: Testing Anti-Debugging Detection</a></div>"

    if not detections:
        return 'WARN', (
            "<div>No anti-debugging mechanisms detected</div>"
            "<div>Acceptable for most apps. Only implement for sensitive apps requiring anti-reverse-engineering.</div>"
            f"{mastg_ref}"
        )

    lines = [f"<div>{len(detections)} anti-debugging mechanism(s) detected:</div>", "<ul style='margin-left:20px;'>"]

    for mechanism, files in sorted(detections.items()):
        lines.append(f"<li><strong>{mechanism}</strong> in {len(files)} file(s)</li>")
        for rel in sorted(files)[:3]:
            full = os.path.abspath(os.path.join(base, rel))
            lines.append(f"  <a href='file://{html.escape(full)}'>{html.escape(rel)}</a>")
        if len(files) > 3:
            lines.append(f"  ... and {len(files) - 3} more")

    lines.append("</ul>")
    lines.append(mastg_ref)
    return 'PASS', "<br>\n".join(lines)


def check_gms_security_provider(base):
    """
    MASTG-TEST-0023/0295: Testing the Security Provider

    Check if GMS ProviderInstaller is used to update security provider.

    Reference: https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0023/
    """
    provider_patterns = [
        r'ProviderInstaller\.installIfNeeded',
        r'ProviderInstaller\.installIfNeededAsync',
        r'com/google/android/gms/security/ProviderInstaller',
    ]

    provider_files = set()
    for pat in provider_patterns:
        for rel in grep_code(base, pat):
            provider_files.add(rel)

    mastg_ref = "<br><div><strong>Reference:</strong> <a href='https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0295/' target='_blank'>MASTG-TEST-0295: GMS Security Provider Not Updated</a></div>"

    if provider_files:
        lines = [
            f"<div>GMS ProviderInstaller usage detected in {len(provider_files)} file(s)</div>",
            "<div>Security provider will be updated with latest crypto patches.</div>"
        ]
        for rel in sorted(provider_files)[:5]:
            full = os.path.abspath(os.path.join(base, rel))
            lines.append(f'<a href="file://{html.escape(full)}">{html.escape(rel)}</a>')
        lines.append(mastg_ref)
        return 'PASS', "<br>\n".join(lines)

    return 'WARN', (
        "<div>No GMS ProviderInstaller usage detected</div>"
        "<div>Recommendation: Call <code>ProviderInstaller.installIfNeeded(context)</code> at app startup.</div>"
        "<div>This updates the security provider with fixes for Heartbleed, POODLE, etc.</div>"
        f"{mastg_ref}"
    )


def print_banner():
    banner = r"""
     ___   ____  _____ _____
    / _ \ / ___|| ____| ____|
   | | | |\___ \|  _| | |
   | |_| | ___) | |___| |___
    \___/ |____/|_____|_____|

    AppSec 4.2.2 – Automated Mobile App Security Test Script

    Options:
      -f, --file       APK file to decompile into smali
      -d, --dir        Decompiled directory containing smali
      -u, --usb        Run dynamic Frida USB checks
      -a, --all-tests  Run all tests without interactive selection

    Notes:
     the -u requires Frida to be running on rooted android device connected via usb
     verify frida-ps -Uai finds the app before using this option

    Usage:
      python3 securitytest.py -f app.apk -u -a
      python3 securitytest.py -d /path/to/decompiled -u -a
      python3 securitytest.py --help

    Requirements:  These must be on your $PATH
      [Frida],[apktool],[adb],[checksec],[apksigner],[readelf],[aapt],[curl]

    """
    print(banner)
    
# Main logic

def main():
    # Check for updates before running
    check_for_updates()

    print_banner()
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help='APK to decompile')
    group.add_argument('-d', '--dir',  help='Decompiled directory')
    parser.add_argument('-u','--usb', action='store_true', help='Run dynamic Frida USB pinning presence check')
    parser.add_argument('-a','--all-tests', action='store_true', help='Run all tests without interactive selection')
    args = parser.parse_args()

    # Track start time
    start_timestamp = datetime.now()
    start_time_str = start_timestamp.strftime("%B %d, %Y, %H:%M:%S")

    apk_path = None
    if args.file:
        base = os.path.splitext(args.file)[0]
        apk_path = args.file
        if os.path.exists(base):
            shutil.rmtree(base)
        os.makedirs(base)
        print(f"[+] Decompiling {apk_path} → {base}")

        # Detect available memory and set appropriate heap size
        try:
            if sys.platform.startswith('linux') or sys.platform == 'darwin':
                # Get available memory in GB
                mem_info = subprocess.check_output(['free', '-g'], text=True)
                available_gb = int([line.split()[6] for line in mem_info.split('\n') if 'Mem:' in line][0])
            elif sys.platform == 'win32':
                # Windows: use wmic or assume 4GB default
                try:
                    mem_info = subprocess.check_output(['wmic', 'OS', 'get', 'FreePhysicalMemory'], text=True)
                    available_kb = int([line.strip() for line in mem_info.split('\n') if line.strip().isdigit()][0])
                    available_gb = available_kb // (1024 * 1024)
                except:
                    available_gb = 4  # Default fallback
            else:
                available_gb = 4  # Default fallback

            # Set heap size to 75% of available memory (max 8GB, min 2GB)
            heap_size = max(2, min(8, int(available_gb * 0.75)))
            print(f"[*] Available memory: {available_gb}GB, using {heap_size}GB for decompilation")

            # Set JAVA_OPTS (works on some systems)
            os.environ['JAVA_OPTS'] = f'-Xmx{heap_size}G'

        except Exception as e:
            print(f"[!] Could not detect memory, using default 4GB heap: {e}")
            os.environ['JAVA_OPTS'] = '-Xmx4G'

        # Use single-threaded decompilation (-j 1) for large APKs to avoid OOM errors
        # Note: If apktool still fails with OOM, manually edit apktool wrapper:
        #   sudo sed -i 's/exec java /exec java -Xmx6G /' $(which apktool)
        run_cmd(f"apktool d {apk_path} -o {base} -f -j 1")
        with open(os.path.join(base, '.apk_source'), 'w') as m:
            m.write(apk_path)
    else:
        base = args.dir
        print(f"[+] Using existing directory `{base}`")
        marker = os.path.join(base, '.apk_source')
        if os.path.exists(marker):
            apk_path = open(marker).read().strip()

    # Define MASVS categories
    MASVS_CATEGORIES = {
        "MASVS-STORAGE": {
            "title": "Storage",
            "url":   "https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0001/",
            "checks": [
                "Dynamic File Read",
                "FileProvider Paths",
                "SharedPreferences Encryption",
                "External Storage Usage",
                "Keyboard Cache",
                "Storage Analysis",
                "DataStore Encryption",
                "Room Database Encryption",
            ]
        },
        "MASVS-CRYPTO": {
            "title": "Cryptography",
            "url":   "https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0013/",
            "checks": [
                "APK Signature Schemes",
                "Weak Crypto Algorithms",
                "Hardcoded Keys",
            ]
        },
        "MASVS-AUTH": {
            "title": "Authentication and Authorization",
            "url":   "https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0017/",
            "checks": [
                "Custom URI Schemes",
                "Browsable DeepLinks",
                "Deep Link Intent Filter Misconfiguration",
                "Biometric Authentication",
            ]
        },
        "MASVS-NETWORK": {
            "title": "Network Communication",
            "url":   "https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0019/",
            "checks": [
                "Certificate Pinning",
                "SSL/TLS Security (TrustManager, HostnameVerifier, Endpoint ID)",
                "Network Security Config",
                "Insecure HTTP URIs",
                "Use of TLS 1.0 or 1.1",
                "WebView SSL Error Handling",
                "GMS Security Provider",
                "Dynamic Cert Pinning",
                "Dynamic Use of TLS 1.0 or 1.1",
            ]
        },
        "MASVS-PLATFORM": {
            "title": "Platform Interaction",
            "url":   "https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0007/",
            "checks": [
                "SQLi via ContentProvider",
                "Task Hijacking",
                "Exported Components",
                "Min SDK Version",
                "In-App Updates",
                "Allow Backup",
                "StrictMode APIs",
                "FLAG_SECURE Usage",
                "Recent Screenshot Protection",
                "WebView JavaScript Bridges",
                "Clipboard Security",
                "PendingIntent Flags",
            ]
        },
        "MASVS-CODE": {
            "title": "Code Quality",
            "url":   "https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0002/",
            "checks": [
                "Debuggable APK",
                "Debug Symbols",
                "Allow Backup",
                "Memory Tagging",
                "Insecure Serialize API",
                "Insecure WebView Usage",
                "OS Command Injection",
                "Safe Browsing Enabled",
                "Insecure Randomness",
                "Insecure Fingerprint API",
                "Raw SQL Queries",
                "Insecure Package Context",
            ]
        },
        "MASVS-RESILIENCE": {
            "title": "Resilience Against Reverse Engineering and Tampering",
            "url":   "https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0038/",
            "checks": [
                "Kotlin Assertions",
                "Kotlin Metadata",
                "Logging Statements",
                "Dynamic StrictMode",
                "StrictMode APIs",
                "Root Detection",
                "Anti-Debugging",
            ]
        },
        "MASVS-PRIVACY": {
            "title": "Privacy",
            "url":   "https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/MASTG-TEST-0206/",
            "checks": [
                "PII via Ble Wi-Fi Info",
                "PII via Location Info",
                "Kotlin Metadata",
                "Logging Statements",
                "Clipboard Security",
                "Dangerous Permissions",
            ]
        },
    }
    grouped   = { cat: [] for cat in MASVS_CATEGORIES }
    ungrouped = []

    # 1) Initial static checks - checksec at the very top
    print("[*] Running checksec…")
    _, css = check_checksec(os.path.join(base, 'lib'))
    checksec_block = (
        "<h4>Checksec Results</h4>"
        "<details open>"  # open by default
        f"<summary>Details</summary>"
        f"<div style='overflow-x:auto;'>{render_checksec_table(css)}</div>"
        "</details>\n"
    )

    # 2) APK signature schemes
    if apk_path:
        print("[*] Checking APK signature schemes…")
        ok, det = check_signature_schemes(apk_path)
        cls    = 'pass' if ok else 'fail'
        status = 'PASS' if ok else 'FAIL'
        block = (
            "<details>"
            f"<summary class='{cls}'><span class='bullet'></span> "
            f"<span class='check-name'>APK Signature Schemes:</span> "
            f"<span class='check-status'>{status}</span></summary>"
            f"<div style='padding:8px'>{det}</div>"
            "</details>\n"
        )
        for cat, info in MASVS_CATEGORIES.items():
            if "APK Signature Schemes" in info['checks']:
                grouped[cat].append(block)
                break
        else:
            ungrouped.append(block)
    else:
        print("[*] Skipping signature check (no APK source)")

 # 3) Manifest load
    print("[*] Loading AndroidManifest.xml…")
    manifest = os.path.join(base, 'AndroidManifest.xml')

    # Helper to run Storage Analysis as a selectable dynamic test
    def run_storage_analysis():
        pkg_name = None
        if manifest and os.path.exists(manifest):
            try:
                root = ET.parse(manifest).getroot()
                pkg_name = root.get('package')
            except Exception as e:
                return 'WARN', f"<div>Failed to parse manifest for storage analysis: {html.escape(str(e))}</div>"

        if not pkg_name:
            return 'WARN', "<div>Could not extract package name for storage analysis</div>"

        return check_storage_analysis(base, pkg_name)

    # 4) Main checks list
    checks = [
        ("Debug Symbols",           lambda: check_debug_symbols(os.path.join(base,'lib'))),
        ("StrictMode APIs",         lambda: check_strict_mode(base)),
        ("Debuggable APK",          lambda: check_debuggable(manifest, base)),
        ("Allow Backup",            lambda: check_allow_backup(manifest)),
        ("SSL/TLS Security (TrustManager, HostnameVerifier, Endpoint ID)",lambda: check_x509(base)),
        ("Certificate Pinning",     lambda: check_certificate_pinning(base)),
        ("Network Security Config", lambda: check_network_security_config(base)),
        ("Insecure HTTP URIs",      lambda: check_http_uris(base)),
        ("Kotlin Assertions",       lambda: check_kotlin_assert(base)),
        ("Kotlin Metadata",         lambda: check_kotlin_metadata(base)),
        ("Logging Statements",      lambda: check_logging(base)),
        ("In-App Updates",          lambda: check_updates(base)),
        ("Memory Tagging",          lambda: check_memtag(manifest)),
        ("Min SDK Version",         lambda: check_min_sdk(manifest, apk_path)),
        ("FileProvider Paths",      lambda: check_file_provider(os.path.join(base,'res'))),
        ("Insecure Serialize API",  lambda: check_serialize(base)),
        ("Custom URI Schemes",      lambda: check_uri_scheme(manifest)),
        ("Browsable DeepLinks",     lambda: check_browsable_deeplinks(manifest)),
        ("Deep Link Intent Filter Misconfiguration", lambda: check_deep_link_misconfiguration(manifest)),
        ("SQLi via ContentProvider",lambda: check_sql_injection(base, manifest)),
        ("Task Hijacking",          lambda: check_task_hijack(manifest)),
        ("Exported Components",     lambda: check_exported_components(manifest, base)),
        ("Insecure WebView Usage",  lambda: check_insecure_webview(base)),
        ("OS Command Injection",    lambda: check_os_command_injection(base)),
        ("Safe Browsing Enabled",   lambda: check_safe_browsing(manifest, base)),
        ("Weak Crypto Algorithms",  lambda: check_weak_crypto(base)),
        ("PII via Ble Wi-Fi Info",  lambda: check_pii_wifi_info(base)),
        ("PII via Location Info",   lambda: check_pii_location_info(base)),
        ("Insecure Randomness",     lambda: check_insecure_randomness(base)),
        ("Insecure Fingerprint API",lambda: check_insecure_fingerprint_api(base)),
        ("Use of TLS 1.0 or 1.1",   lambda: check_tls_versions(base)),
        ("Root Detection",          lambda: check_root_detection(manifest, base)),
        ("SharedPreferences Encryption", lambda: check_sharedprefs_encryption(base)),
        ("External Storage Usage",  lambda: check_external_storage(base)),
        ("Hardcoded Keys",          lambda: check_hardcoded_keys(base)),
        ("Biometric Authentication",lambda: check_biometric_auth(base)),
        ("FLAG_SECURE Usage",       lambda: check_flag_secure(base, manifest)),
        ("WebView JavaScript Bridges", lambda: check_webview_javascript_bridge(base)),
        ("Clipboard Security",      lambda: check_clipboard_security(base)),
        ("Keyboard Cache",          lambda: check_keyboard_cache(base, manifest)),
        ("Raw SQL Queries",         lambda: check_raw_sql_queries(base)),
        ("Insecure Package Context", lambda: check_package_context(base)),
        # NEW MASTG TESTS (2025-11-26)
        ("PendingIntent Flags",     lambda: check_pending_intent_flags(base)),
        ("WebView SSL Error Handling", lambda: check_webview_ssl_error_handling(base)),
        ("Recent Screenshot Protection", lambda: check_recent_screenshot_disabled(base)),
        ("Dangerous Permissions",   lambda: check_dangerous_permissions(manifest)),
        ("DataStore Encryption",    lambda: check_datastore_encryption(base)),
        ("Room Database Encryption", lambda: check_room_encryption(base)),
        ("Anti-Debugging",          lambda: check_anti_debugging(base)),
        ("GMS Security Provider",   lambda: check_gms_security_provider(base)),
        ("S3 Bucket Security",      lambda: check_s3_bucket_security(base)),
    ]
    html_special = {
        "X509TrustManager Methods", "Kotlin Assertions",
        "Custom URI Schemes",       "Logging Statements",
        "FileProvider Paths",       "Insecure Serialize API",
        "Task Hijacking",           "Network Security Config",
        "Debuggable APK",           "Allow Backup",
        "Exported Components",      "Insecure WebView Usage",
        "Weak Crypto Algorithms",
        "APK Signature Schemes",    "Insecure Randomness",
        "Insecure Fingerprint API", "Use of TLS 1.0 or 1.1",
        "Certificate Pinning",      "Kotlin Metadata",
        "Insecure HTTP URIs",       "SQLi via ContentProvider",
        "Safe Browsing Enabled",    "StrictMode APIs",
        "Browsable DeepLinks",      "Deep Link Intent Filter Misconfiguration",
        "Root Detection",
        # New checks
        "SharedPreferences Encryption", "External Storage Usage",
        "Hardcoded Keys",
        "Biometric Authentication", "FLAG_SECURE Usage",
        "WebView JavaScript Bridges", "Clipboard Security",
        "Keyboard Cache",
        "Raw SQL Queries",          "Insecure Package Context",
        "PII via Ble Wi-Fi Info",   "PII via Location Info",
        # NEW MASTG TESTS
        "PendingIntent Flags",      "WebView SSL Error Handling",
        "Recent Screenshot Protection", "Dangerous Permissions",
        "DataStore Encryption",     "Room Database Encryption",
        "Anti-Debugging",
        "GMS Security Provider",
        "S3 Bucket Security",       "SSL/TLS Security (TrustManager, HostnameVerifier, Endpoint ID)",
    }

    # Interactive test selection
    if not args.all_tests:
        print("\n" + "="*70)
        print("TEST SELECTION")
        print("="*70)

        try:
            print("\nRun all tests or select specific tests?")
            print("  a - Run ALL tests")
            print("  s - SELECT specific tests")
            print("  q - Quit")

            choice = input("\nYour choice (a/s/q): ").strip().lower()

            if choice == 'q':
                print("[*] Exiting...")
                sys.exit(0)
            elif choice == 'a' or choice == '':
                print("[*] Running all tests...")
            elif choice == 's':
                # Interactive curses-based test selection
                selected = curses.wrapper(curses_select_menu, checks, "SELECT TESTS (Use arrows, SPACE to toggle)")

                if selected is None:
                    print("\n[*] Exiting...")
                    sys.exit(0)

                if selected:
                    checks = [checks[i] for i in sorted(selected)]
                    print(f"\n[*] Running {len(checks)} selected test(s)...")
                else:
                    print("\n[!] No tests selected. Exiting...")
                    sys.exit(0)
            else:
                print("[!] Invalid choice. Running all tests...")

        except (KeyboardInterrupt, EOFError):
            print("\n[*] Exiting...")
            sys.exit(0)

        print("="*70 + "\n")

    # 5) Execute main checks
    print("[*] Executing individual checks:")
    for name, fn in checks:
        print(f"    - {name}…", flush=True)
        try:
            if name in ("Exported Components", "Kotlin Assertions", "Logging Statements", "Kotlin Metadata",
                       "Browsable DeepLinks", "Deep Link Intent Filter Misconfiguration",
                       "Custom URI Schemes", "Keyboard Cache", "OS Command Injection", "Insecure HTTP URIs"):
                ok, det, cnt = fn()
            elif name == "Task Hijacking":
                # Task Hijacking returns ('PASS'|'WARN'|'FAIL', details, count)
                ok, det, cnt = fn()
            elif name == "Clipboard Security":
                # Clipboard Security can return 2 or 3 values depending on findings
                res = fn()
                if len(res) == 3:
                    ok, det, cnt = res
                else:
                    ok, det = res
                    cnt = None
            else:
                res = fn()
                # Back-compat: handle both (bool, detail) and ('PASS'|'WARN'|'FAIL', detail)
                if isinstance(res[0], str):
                    # New format: ('PASS'|'WARN'|'FAIL', detail)
                    ok, det = res[0], res[1]
                else:
                    # Old format: (bool, detail)
                    ok, det = res
        except Exception as e:
            ok, det = False, f"<strong>Error: {html.escape(str(e))}</strong>"

        # Determine status and class
        if name in ("Exported Components", "Kotlin Assertions", "Logging Statements", "Kotlin Metadata",
                    "Browsable DeepLinks", "Deep Link Intent Filter Misconfiguration",
                    "Custom URI Schemes", "Keyboard Cache", "OS Command Injection", "Insecure HTTP URIs"):
            status = "PASS" if ok else f"FAIL ({cnt})"
            cls = 'pass' if ok else 'fail'

        elif name == "Clipboard Security":
            # Can be PASS, WARN, or FAIL with count
            if ok == 'PASS' or ok is True:
                status = "PASS"
                cls = 'pass'
            elif ok == 'WARN':
                status = "WARN"
                cls = 'warn'
            elif ok is False and cnt is not None:
                # FAIL with count (critical findings)
                status = f"FAIL ({cnt})"
                cls = 'fail'
            else:
                status = "WARN"
                cls = 'warn'

        elif name == "Task Hijacking":
            # Task Hijacking uses status string + count
            if ok == 'PASS':
                status = "PASS"
                cls = 'pass'
            elif ok == 'WARN':
                status = f"WARN ({cnt})" if cnt > 0 else "WARN"
                cls = 'warn'
            else:  # FAIL
                status = f"FAIL ({cnt})" if cnt > 0 else "FAIL"
                cls = 'fail'

        elif name in ("Biometric Authentication", "Insecure Package Context"):
            # Explicit FAIL (1), no automatic counting from HTML
            if ok == 'PASS':
                status = "PASS"
                cls = 'pass'
            elif ok == 'WARN':
                status = "WARN"
                cls = 'warn'
            else:  # FAIL
                status = "FAIL (1)"
                cls = 'fail'

        elif isinstance(ok, str):
            # New format with explicit status string
            status = ok
            if ok == 'PASS':
                cls = 'pass'
            elif ok == 'WARN':
                cls = 'warn'
                count = det.count('<a href=') or (det.count('<br>') + 1)
                if count > 1:
                    status = f"WARN ({count})"
            elif ok == 'INFO':
                cls = 'info'
            else:  # FAIL (string)
                cls = 'fail'
                count = det.count('<a href=') or (det.count('<br>') + 1)
                status = f"FAIL ({count})" if count > 1 else "FAIL"

        else:
            # ok is a bool, generic handling + S3 override
            if name == "S3 Bucket Security":
                if ok:
                    status = "PASS"
                    cls = "pass"
                else:
                    # One misconfigured bucket → treat as a single finding
                    status = "FAIL (1)"
                    cls = "fail"
            elif ok:
                status = "PASS"
                cls = 'pass'
            else:
                count = det.count('<a href=') or (det.count('<br>') + 1)
                status = f"FAIL ({count})" if count > 1 else "FAIL"
                cls = 'fail'
        if name in html_special:
            html_block = (
                "<details>"
                f"<summary class='{cls}'><span class='bullet'></span> "
                f"<span class='check-name'>{name}:</span> "
                f"<span class='check-status'>{status}</span></summary>"
                f"<div class='detail-content'>{det}</div>"
                "</details>\n"
            )
        else:
            html_block = (
                "<details>"
                f"<summary class='{cls}'><span class='bullet'></span> "
                f"<span class='check-name'>{name}:</span> "
                f"<span class='check-status'>{status}</span></summary>"
                f"<pre>{det}</pre>"
                "</details>\n"
            )
        placed = False
        for cat, info in MASVS_CATEGORIES.items():
            if name in info['checks']:
                grouped[cat].append(html_block)
                placed = True
                break
        if not placed:
            ungrouped.append(html_block)

    # 6) Dynamic Frida checks
    dynamic_results = []  # Track dynamic check results for summary
    if args.usb:
        frida_checks = [
            ("Dynamic Cert Pinning",         lambda: check_frida_pinning(base)),
            ("Dynamic File Read",            lambda: check_frida_file_reads(base)),
            ("Dynamic Exported Activity",    lambda: check_frida_task_hijack(base, manifest, 2, 8)),
            ("Dynamic StrictMode",           lambda: check_frida_strict_mode(base)),
            ("Dynamic Use of TLS 1.0 or 1.1",lambda: check_frida_tls_negotiation(base)),
            # New dynamic verification checks
            ("Dynamic SharedPreferences",    lambda: check_frida_sharedprefs(base)),
            ("Dynamic External Storage",     lambda: check_frida_external_storage(base)),
            ("Dynamic Crypto Keys",          lambda: check_frida_crypto_keys(base)),
            ("Dynamic Clipboard",            lambda: check_frida_clipboard(base)),
            ("Storage Analysis",             run_storage_analysis),
        ]
        DYNAMIC_TO_STATIC = {
         "Dynamic Cert Pinning":          "Certificate Pinning",
         "Dynamic File Read":             "Dynamic File Read",
         "Dynamic Exported Activity":     "Exported Components",
         "Dynamic StrictMode":            "Dynamic StrictMode",
         "Dynamic Use of TLS 1.0 or 1.1": "Use of TLS 1.0 or 1.1",
         # Map new dynamic checks to their static equivalents
         "Dynamic SharedPreferences":     "SharedPreferences Encryption",
         "Dynamic External Storage":      "External Storage Usage",
         "Dynamic Crypto Keys":           "Hardcoded Keys",
         "Dynamic Clipboard":             "Clipboard Security",
        }

        # Interactive dynamic test selection
        if not args.all_tests:
            print("\n" + "="*70)
            print("DYNAMIC TEST SELECTION (Frida)")
            print("="*70)

            try:
                print("\nRun all dynamic tests or select specific tests?")
                print("  a - Run ALL dynamic tests")
                print("  s - SELECT specific dynamic tests")
                print("  n - Skip dynamic tests")

                choice = input("\nYour choice (a/s/n): ").strip().lower()

                if choice == 'n':
                    print("[*] Skipping all dynamic tests...")
                    frida_checks = []
                elif choice == 'a' or choice == '':
                    print("[*] Running all dynamic tests...")
                elif choice == 's':
                    # Interactive curses-based test selection
                    selected = curses.wrapper(curses_select_menu, frida_checks, "SELECT DYNAMIC TESTS (Use arrows, SPACE to toggle)")

                    if selected is None:
                        print("\n[*] Skipping all dynamic tests...")
                        frida_checks = []
                    elif selected:
                        frida_checks = [frida_checks[i] for i in sorted(selected)]
                        print(f"\n[*] Running {len(frida_checks)} selected dynamic test(s)...")
                    else:
                        print("\n[*] No dynamic tests selected. Skipping...")
                        frida_checks = []
                else:
                    print("[!] Invalid choice. Running all dynamic tests...")

            except (KeyboardInterrupt, EOFError):
                print("\n[*] Skipping all dynamic tests...")
                frida_checks = []

            print("="*70 + "\n")

        for name, fn in frida_checks:
            print(f"[*] Running {name}…")
            try:
                res = fn()
            except Exception as e:
                res = ('FAIL', f"<strong>Error: {html.escape(str(e))}</strong>")

            # Back-compat: existing fns return (bool, detail); new fns return ('PASS'|'WARN'|'FAIL', detail)
            if isinstance(res[0], str):
                status, det = res[0], res[1]
                cls = {'PASS':'pass', 'WARN':'warn', 'FAIL':'fail', 'INFO':'info'}.get(status, 'fail')
            else:
                ok, det = res
                status  = 'PASS' if ok else 'FAIL'
                cls     = 'pass' if ok else 'fail'

            # Track result for summary
            dynamic_results.append((name, status, cls))

            # Add visual indicator for dynamic checks
            dynamic_badge = "<span style='background:#4CAF50;color:white;padding:2px 6px;border-radius:3px;font-size:10px;margin-left:5px;'>DYNAMIC</span>"

            html_block = (
                "<details>"
                f"<summary class='{cls}'><span class='bullet'></span> "
                f"<span class='check-name'>{name}:</span> {dynamic_badge} "
                f"<span class='check-status'>{status}</span></summary>"
                f"<div class='detail-content'>{det}</div>"
                "</details>\n"
            )

            key = DYNAMIC_TO_STATIC.get(name, name)
            placed = False
            for cat, info in MASVS_CATEGORIES.items():
                if key in info['checks']:
                    grouped[cat].append(html_block)
                    placed = True
                    break
            if not placed:
                ungrouped.append(html_block)

    # 7) Extract APK metadata for report header
    manifest = os.path.join(base, 'AndroidManifest.xml')
    metadata = extract_apk_metadata(apk_path, manifest)

    # 8) Track finish time
    finish_timestamp = datetime.now()
    finish_time_str = finish_timestamp.strftime("%B %d, %Y, %H:%M:%S")

    # 9) Assemble final report
    sections = checksec_block  # ensure checksec is at top

    # Add MASVS category sections
    for cat, info in MASVS_CATEGORIES.items():
        sections += (
            f"<h4><a href=\"{info['url']}\" target=\"_blank\">{cat}: {info['title']}"  \
            f"</a></h4>\n"
        )
        sections += ''.join(grouped[cat]) + '\n'
    if ungrouped:
        sections += "<h4>Other Checks</h4>\n" + ''.join(ungrouped)

    # 10) Write out HTML report with metadata
    # Create report filename with package name
    report_filename = f"{metadata['package']}.report.html" if metadata['package'] else 'report.html'

    with open(report_filename, 'w') as f:
        f.write(HTML_TEMPLATE.format(
            package=metadata['package'],
            version_name=metadata['version_name'],
            version_code=metadata['version_code'],
            size_mb=metadata['size_mb'],
            start_time=start_time_str,
            finish_time=finish_time_str,
            sections=sections
        ))
    print(f'[+] Report generated: {report_filename}')

    # Display summary
    duration = finish_timestamp - start_timestamp
    duration_str = str(duration).split('.')[0]  # Remove microseconds
    print(f'[+] Scan completed in {duration_str}')
    print(f'[+] Package: {metadata["package"]}')
    print(f'[+] Version: {metadata["version_name"]} ({metadata["version_code"]})')

if __name__ == '__main__':
    main()
