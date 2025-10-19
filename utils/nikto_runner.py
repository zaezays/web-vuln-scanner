# utils/nikto_runner.py
import subprocess
import shlex
import re
import tempfile
import os
from typing import Dict, Any, List


# 🟩 Categorize Nikto findings based on keywords
def categorize_finding(desc: str) -> str:
    desc_lower = desc.lower()

    if "server:" in desc_lower:
        return "Web Server Type"
    elif "x-powered-by" in desc_lower:
        return "X-Powered-By Header"
    elif "header is not set" in desc_lower or "header not set" in desc_lower or "missing header" in desc_lower:
        return "Security Headers Missing"
    elif "phpmyadmin" in desc_lower or "pgadmin" in desc_lower or "mysql" in desc_lower:
        return "Database Disclosure"
    elif "cookie" in desc_lower and ("secure" in desc_lower or "httponly" in desc_lower):
        return "Cookies Security"
    elif "outdated" in desc_lower or "vulnerable" in desc_lower or "cve-" in desc_lower:
        return "Outdated Software / CVEs"
    else:
        # We ignore “General Finding” and other noise
        return "General Finding"


# 🟩 Parse raw Nikto text output
def parse_nikto_output(text: str) -> Dict[str, Any]:
    """
    Extracts:
      - banner (Server)
      - x-powered-by
      - categorized key findings
    Filters out irrelevant noise.
    """
    lines = text.splitlines()
    findings: List[Dict[str, str]] = []
    banner = None
    x_powered = None

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Detect banner
        m = re.match(r'^\+\s+Server:\s*(.+)$', line, re.I)
        if m:
            banner = m.group(1).strip()
            continue

        # Detect X-Powered-By
        m = re.match(r'^\+\s*(?:/.*)?Retrieved x-powered-by header:\s*(.+)$', line, re.I)
        if m:
            x_powered = m.group(1).strip()
            continue

        # Findings begin with '+ '
        if line.startswith('+ '):
            findings.append({'raw': line[2:].strip()})

    structured: List[Dict[str, str]] = []
    for f in findings:
        raw = f.get('raw', '')
        path = ''
        desc = raw

        # Split path/description
        if raw.startswith('/') or raw.startswith('http'):
            parts = raw.split(' ', 1)
            path = parts[0]
            desc = parts[1] if len(parts) > 1 else raw
        elif ':' in raw:
            parts = raw.split(':', 1)
            left = parts[0].strip()
            right = parts[1].strip()
            if len(left) <= 30 and right:
                path = left
                desc = right

        # Categorize
        category = categorize_finding(desc)
        if category != "General Finding":  # keep only key ones
            structured.append({
                'path': path,
                'description': desc,
                'category': category,
                'raw': raw
            })

    return {
        'banner': banner,
        'x_powered_by': x_powered,
        'findings': structured,
        'findings_filtered_count': len(structured),
        'raw_text': text
    }


# 🟩 Run Nikto scan (fast focused mode)
def run_nikto_scan(target_url: str, timeout: int = 600, mode: str = "full") -> Dict[str, Any]:
    """
    Runs Nikto against target_url using tuned mode (-Tuning 23468c).
    Returns parsed, categorized, and filtered results.
    """
    # Focused DAST categories only; avoids redundant long scans
    cmd = f"nikto -h {shlex.quote(target_url)} -Tuning 23468c -nointeractive"
    print(f"[DEBUG] Running Nikto command: {cmd}")

    # Temp log file
    tmp_log = tempfile.NamedTemporaryFile(delete=False, suffix=".log")
    tmp_path = tmp_log.name
    tmp_log.close()

    try:
        proc = subprocess.Popen(
            shlex.split(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        all_output = []
        for line in iter(proc.stdout.readline, ''):
            if not line:
                break
            line = line.strip()
            print(f"[Nikto] {line}")
            all_output.append(line)
            with open(tmp_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

        proc.stdout.close()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            print(f"[WARN] Nikto scan timed out after {timeout}s, returning partial results.")

        full_text = "\n".join(all_output)
        parsed = parse_nikto_output(full_text)
        parsed.update({
            'exit_code': proc.returncode,
            'log_path': tmp_path,
            'mode': mode,
        })
        return parsed

    except FileNotFoundError:
        return {'error': 'nikto_not_found', 'message': 'Nikto not installed or not in PATH.'}

    except Exception as e:
        print(f"[ERROR] Nikto Exception: {e}")
        partial_text = ''
        if os.path.exists(tmp_path):
            with open(tmp_path, "r", encoding="utf-8") as f:
                partial_text = f.read()
        parsed_partial = parse_nikto_output(partial_text)
        parsed_partial.update({
            'error': 'exception',
            'message': str(e),
            'log_path': tmp_path
        })
        return parsed_partial

