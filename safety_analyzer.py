"""Heuristic, non-executing source/text risk scan for the local sandbox UI."""
import hashlib
import re
from datetime import datetime, timezone

MAX_SCAN_BYTES = 512 * 1024
ALLOWED_EXTENSIONS = {".c", ".h", ".cpp", ".hpp", ".py", ".sh", ".js", ".php", ".rb", ".pl", ".txt"}

# These are review indicators, not proof of malicious intent.
RULES = [
    ("Command execution", r"\b(system|popen|exec[lvpe]*|subprocess\.(run|Popen|call)|os\.system|child_process\.exec)\b", 3,
     "The file may launch another command or process."),
    ("Dynamic code execution", r"\b(eval|exec)\s*\(", 3,
     "The file may evaluate dynamically constructed code."),
    ("Network access", r"\b(socket|connect|bind|listen|requests\.(get|post)|urllib|curl|wget)\b", 2,
     "The file may communicate over a network or fetch remote content."),
    ("File deletion or modification", r"\b(unlink|remove|rmdir|rename|truncate|fwrite|write\s*\()\b|\b(rm\s+-rf|mkfs|dd\s+if=)", 2,
     "The file may delete or modify files; inspect target paths carefully."),
    ("Privilege or permission changes", r"\b(setuid|seteuid|setgid|chmod|chown|sudo|capset)\b", 3,
     "The file may change permissions or attempt privilege-related operations."),
    ("Process or system inspection", r"\b(ptrace|/proc/|/sys/|fork\s*\(|clone\s*\(|kill\s*\()", 2,
     "The file may inspect or manipulate processes or system state."),
    ("Obfuscation or encoded payload", r"\b(base64\.(b64decode|decodebytes)|b64decode|fromhex|rot13|marshal\.loads|pickle\.loads)\b", 2,
     "The file may decode or load encoded content; review the resulting data."),
    ("Shell/network utility usage", r"\b(curl|wget|nc|netcat|bash\s+-c|sh\s+-c|powershell)\b", 2,
     "The file references utilities often used for command or network activity."),
    ("Sensitive paths or credentials", r"(/etc/shadow|id_rsa|\.ssh/|AWS_SECRET_ACCESS_KEY|api[_-]?key|password\s*=)", 3,
     "The file references a sensitive path or credential-like value."),
]

def analyze_text(filename, raw_bytes):
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError("Unsupported file type. Upload a source-code or text file: " + ", ".join(sorted(ALLOWED_EXTENSIONS)))
    if not raw_bytes:
        raise ValueError("The uploaded file is empty.")
    if len(raw_bytes) > MAX_SCAN_BYTES:
        raise ValueError("File is too large. Maximum size is 512 KB.")
    try:
        source = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError("This upload is not UTF-8 text. Binary executables are not accepted by the static scanner.")

    hits = []
    score = 0
    for title, pattern, weight, explanation in RULES:
        found_lines = []
        for number, line in enumerate(source.splitlines(), 1):
            if re.search(pattern, line, flags=re.IGNORECASE):
                found_lines.append({"line": number, "text": line.strip()[:180]})
                if len(found_lines) == 4:
                    break
        if found_lines:
            score += weight
            hits.append({"title": title, "explanation": explanation, "weight": weight, "lines": found_lines})

    if score >= 8:
        level, label = "high", "HIGH REVIEW PRIORITY"
    elif score >= 4:
        level, label = "medium", "REVIEW RECOMMENDED"
    else:
        level, label = "low", "FEWER KNOWN INDICATORS FOUND"

    if not hits:
        summary = "No patterns from this scanner's limited rule set were detected. This does not establish that the file is safe."
    else:
        summary = f"Detected {len(hits)} category/categories of potentially risky behaviour. Review each finding in context; legitimate programs can use these operations too."

    return {
        "filename": filename,
        "size": len(raw_bytes),
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "line_count": len(source.splitlines()),
        "level": level,
        "label": label,
        "score": score,
        "hits": hits,
        "summary": summary,
        "limitations": [
            "This is a heuristic source/text scan, not antivirus and not a proof of safety.",
            "It does not execute, compile, deobfuscate, or deeply analyse the uploaded file.",
            "It may miss malicious behaviour and may flag harmless code.",
            "Do not run unknown files on your main machine. Use a disposable VM and the sandbox only after reviewing the source and limitations."
        ]
    }
