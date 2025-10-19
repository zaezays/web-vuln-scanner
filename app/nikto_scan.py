# nikto_scan.py
import subprocess
import json
import os
import tempfile

def run_nikto_scan(target_url: str):
    """
    Runs Nikto manually with JSON output (standalone use).
    Not used by Flask system.
    """
    print(f"[+] Starting Nikto scan for {target_url}")
    temp_output = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    temp_path = temp_output.name
    temp_output.close()

    command = [
        "perl", "/opt/nikto/program/nikto.pl",
        "-h", target_url,
        "-output", temp_path,
        "-Format", "json"
    ]

    try:
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"[+] Nikto scan completed. Output saved to {temp_path}")

        with open(temp_path, "r") as f:
            data = json.load(f)

        os.remove(temp_path)
        return data

    except subprocess.CalledProcessError as e:
        print(f"[!] Nikto scan failed: {e}")
        return None
    except json.JSONDecodeError:
        print("[!] Could not parse Nikto output (invalid JSON).")
        return None
