import sys
import time

output_lines = []

def format_time(seconds):
    m = int(seconds // 60)
    s = int(seconds % 60)
    return f"{m:02d}:{s:02d}"

def print_status_line(silent_mode):
    from .core import progress
    if silent_mode:
        return
    elapsed = time.time() - progress["start_time"]
    percent = (progress["checked"] / progress["total"]) * 100 if progress["total"] else 0
    sys.stdout.write(
        f"\r[⏱️ {format_time(elapsed)}] Checked: {progress['checked']}/{progress['total']} ({percent:.1f}%) | Found: {progress['found']}"
    )
    sys.stdout.flush()

def save_output(output_file):
    try:
        with open(output_file, "a") as f:
            for line in output_lines:
                f.write(line + "\n")
    except Exception as e:
        print(f"[!] Failed to write to output file: {e}")
