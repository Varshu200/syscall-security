#!/usr/bin/env python3
"""Local-only web interface for the syscall sandbox. Run with sudo python3 app.py."""
from pathlib import Path
import os
import subprocess
from flask import Flask, render_template, request
from safety_analyzer import analyze_text, MAX_SCAN_BYTES

BASE_DIR = Path(__file__).resolve().parent
SANDBOX = BASE_DIR / "sandbox"
ROOTFS = BASE_DIR / "rootfs"
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_SCAN_BYTES + 64 * 1024

# Only fixed programs are available; no shell commands or arbitrary paths.
PROGRAMS = {
    "echo": {"label": "Echo a message", "path": "/bin/echo"},
    "id": {"label": "Show sandbox identity", "path": "/bin/id"},
    "hostname": {"label": "Show isolated hostname", "path": "/bin/hostname"},
    "ls": {"label": "List sandbox /bin", "path": "/bin/ls", "args": ["/bin"]},
    "sleep": {"label": "Sleep (timeout demo)", "path": "/bin/sleep"},
}

def run_demo(program, message, seconds, memory_mb):
    if not SANDBOX.is_file() or not os.access(SANDBOX, os.X_OK):
        return 1, "", "Sandbox binary not found. Run make in the project directory."
    if not ROOTFS.is_dir() or not (ROOTFS / "bin").is_dir():
        return 1, "", "Root filesystem not found. Run setup_rootfs.sh first."
    spec = PROGRAMS.get(program)
    if not spec:
        return 1, "", "Unsupported demo program."
    argv = [spec["path"]]
    if program == "echo":
        argv.append(message[:500])
    elif program == "sleep":
        argv.append("5")
    argv.extend(spec.get("args", []))
    command = [str(SANDBOX), str(seconds), str(memory_mb), str(ROOTFS), *argv]
    try:
        completed = subprocess.run(
            command, cwd=str(BASE_DIR), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            errors="replace", timeout=seconds + 8, check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
        )
        return completed.returncode, completed.stdout[-12000:], None
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return 124, output[-12000:] + "\n[interface] Outer safety timeout reached.", None
    except OSError as exc:
        return 1, "", f"Could not start sandbox: {exc}"

@app.before_request
def local_only():
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return "Local access only", 403

@app.route("/analyze", methods=["GET", "POST"])
def analyze_upload():
    report = None
    error = None
    if request.method == "POST":
        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            error = "Choose a source-code or text file to analyse."
        else:
            # Treat filename as display-only metadata; never use it as a filesystem path.
            filename = uploaded.filename.replace("\\", "/").rsplit("/", 1)[-1][:120]
            try:
                report = analyze_text(filename, uploaded.read(MAX_SCAN_BYTES + 1))
            except ValueError as exc:
                error = str(exc)
    return render_template("analyze.html", report=report, error=error)


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    selected, message, seconds, memory_mb = "echo", "Hello from the sandbox!", 2, 64
    if request.method == "POST":
        selected = request.form.get("program", "echo")
        message = request.form.get("message", "")[:500]
        try:
            seconds = int(request.form.get("seconds", "2"))
            memory_mb = int(request.form.get("memory_mb", "64"))
        except ValueError:
            result = {"status": "Invalid settings", "output": "Time and memory must be numbers.", "ok": False}
        else:
            if not 1 <= seconds <= 10 or memory_mb not in (32, 64, 128, 256):
                result = {"status": "Invalid settings", "output": "Choose 1–10 seconds and 32, 64, 128, or 256 MB.", "ok": False}
            elif selected not in PROGRAMS:
                result = {"status": "Invalid program", "output": "Choose a listed demo program.", "ok": False}
            else:
                code, output, error = run_demo(selected, message, seconds, memory_mb)
                if error:
                    result = {"status": "Setup error", "output": error, "ok": False}
                else:
                    lower = output.lower()
                    if "tle" in lower:
                        status = "Time limit exceeded (TLE)"
                    elif "mle" in lower:
                        status = "Memory limit exceeded (MLE)"
                    elif "killed by seccomp" in lower:
                        status = "Blocked by seccomp"
                    elif "exited with code 0" in lower:
                        status = "Completed successfully"
                    else:
                        status = f"Finished (process exit code {code})"
                    result = {"status": status, "output": output or "(No output)", "ok": code == 0}
    return render_template("index.html", programs=PROGRAMS, selected=selected,
                           message=message, seconds=seconds, memory_mb=memory_mb, result=result)

@app.errorhandler(413)
def too_large(_error):
    return render_template("analyze.html", report=None,
                           error="Upload exceeds the 512 KB analysis limit."), 413


if __name__ == "__main__":
    if os.geteuid() != 0:
        raise SystemExit("Start with sudo: sudo .venv/bin/python app.py")
    # Never expose this privileged development server beyond the local machine.
    app.run(host="127.0.0.1", port=5000, debug=False)
