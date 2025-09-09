import os
import time
from zapv2 import ZAPv2

# Load config from environment (set in docker-compose.yml)
#ZAP_API_KEY = os.getenv("ZAP_API_KEY", "API KEY")
#ZAP_PROXY = os.getenv("ZAP_PROXY", "http://zap:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "API KEY")
ZAP_PROXY = os.getenv("ZAP_PROXY", "http://zap-daemon:8080")


# Connect to ZAP
zap = ZAPv2(
    apikey=ZAP_API_KEY,
    proxies={
        'http': ZAP_PROXY,
        'https': ZAP_PROXY
    }
)

def run_zap_scan(target_url: str):
    """
    Run an active scan on the target URL using OWASP ZAP.
    Returns a list of alerts (vulnerabilities).
    """
    print(f"[+] Scanning {target_url} using ZAP...")

    # Open target URL in ZAP
    zap.urlopen(target_url)
    time.sleep(2)

    # Start active scan
    scan_id = zap.ascan.scan(target_url, recurse=True)
    print(f"[*] Started scan (ID: {scan_id})")

    # Poll scan progress
    while int(zap.ascan.status(scan_id)) < 100:
        progress = zap.ascan.status(scan_id)
        print(f"    Scan progress: {progress}%")
        time.sleep(2)

    print("[+] Scan complete.")

    # Retrieve alerts
    alerts = zap.core.alerts(baseurl=target_url)
    print(f"[+] Found {len(alerts)} alerts.")
    return alerts

