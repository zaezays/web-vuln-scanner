import os
import time
from zapv2 import ZAPv2

# ------------------------------------------------------
# ✅ Load config from environment (set in docker-compose)
# ------------------------------------------------------
# Load config from environment (set in docker-compose.yml)
#ZAP_API_KEY = os.getenv("ZAP_API_KEY", "824jqse31a5ms0fu24ji2besn4")
#ZAP_PROXY = os.getenv("ZAP_PROXY", "http://zap:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "824jqse31a5ms0fu24ji2besn4")
ZAP_PROXY = os.getenv("ZAP_PROXY", "http://zap-daemon:8080")


# ------------------------------------------------------
# ✅ Connect to ZAP
# ------------------------------------------------------
zap = ZAPv2(
    apikey=ZAP_API_KEY,
    proxies={
        'http': ZAP_PROXY,
        'https': ZAP_PROXY
    }
)

def run_zap_scan(
    target_url: str,
    scan_type: str = "both",
    threshold: str = None,
    strength: str = None,
    use_spider: bool = True,
    use_ajax_spider: bool = False,
    use_auth: bool = False,
    use_api_scan: bool = False,
    use_ws_scan: bool = False
):
    """
    REPLACEMENT: a deterministic 'full scan' flow:
      1) initial request (measure)
      2) set sane scan limits
      3) traditional spider (discover URLs)
      4) passive scan wait
      5) active scan (full)
      6) optional AJAX spider (best-effort)
      7) collect alerts, try to enrich with response times, group alerts
    """

    print(f"[+] Running FULL scan on {target_url} (scan_type param ignored — full scan enforced)")

    # ---- measure initial request response time ----
    try:
        start_time = time.time()
        zap.urlopen(target_url)
        end_time = time.time()
        elapsed_ms = (end_time - start_time) * 1000
        print(f"[INFO] Initial request to {target_url} took {elapsed_ms:.2f} ms")
    except Exception as e:
        print(f"[WARN] Initial request failed: {e}")

    time.sleep(2)

    # ---- set scan limits (safe defaults) ----
    try:
        # full scan total limit (minutes) and per-rule limit
        zap.ascan.set_option_max_scan_duration_in_mins(10)
        zap.ascan.set_option_max_rule_duration_in_mins(2)
        print("[*] Scan time limits set: 10 min full scan, 2 min per rule.")
    except Exception as e:
        print(f"[!] Warning: Could not set scan limits: {e}")

    # ---- 1) Traditional spider to discover URLs ----
    try:
        print("[*] Starting traditional spider...")
        spider_id = zap.spider.scan(target_url)
        # wait until spider completes
        while True:
            try:
                status = int(zap.spider.status(spider_id))
            except Exception:
                status = 100
            print(f"    Spider progress: {status}%")
            if status >= 100:
                break
            time.sleep(2)
        print("[+] Spider complete.")
    except Exception as e:
        print(f"[!] Spider failed/skipped: {e}")

    # small buffer for ZAP to register new messages
    time.sleep(2)

    # ---- 2) Passive scan: wait until done processing all records ----
    try:
        print("[*] Waiting for passive scan to finish (if any records)...")
        # zap.pscan.records_to_scan may be string/number, ensure int-check
        while True:
            try:
                remaining = int(zap.pscan.records_to_scan)
            except Exception:
                remaining = 0
            if remaining <= 0:
                break
            print(f"    Passive scan records remaining: {remaining}")
            time.sleep(2)
        print("[+] Passive scanning complete.")
    except Exception as e:
        print(f"[!] Passive scan wait failed/skipped: {e}")

    # ---- 3) Active scan (full) ----
    try:
        print("[*] Starting active scan (this may take a while)...")
        scan_id = zap.ascan.scan(target_url, recurse=True)
        while True:
            try:
                prog = int(zap.ascan.status(scan_id))
            except Exception:
                prog = 100
            print(f"    Active scan progress: {prog}%")
            if prog >= 100:
                break
            time.sleep(3)
        print("[+] Active scanning complete.")
    except Exception as e:
        print(f"[!] Active scan failed/skipped: {e}")

    # ---- 4) Optional AJAX spider (best-effort) ----
    # keep it non-blocking-critical: attempt, wait a little, but do not fail entire scan if it errors
    if use_ajax_spider:
        try:
            print("[*] Attempting AJAX Spider (optional)...")
            zap.ajaxSpider.scan(target_url)
            # small wait then poll
            time.sleep(5)
            while True:
                try:
                    status = zap.ajaxSpider.status()
                except Exception:
                    status = 'stopped'
                if status != 'running':
                    break
                print("    AJAX Spider still running...")
                time.sleep(3)
            print("[+] AJAX Spider complete.")
        except Exception as e:
            print(f"[!] AJAX spider skipped/failed: {e}")

    # ---- 5) Collect raw alerts ----
    try:
        raw_alerts = zap.core.alerts(baseurl=target_url)
    except Exception as e:
        print(f"[ERROR] Could not fetch alerts from ZAP: {e}")
        raw_alerts = []

    print(f"[+] Found {len(raw_alerts)} raw alerts.")

    # ---- 6) Try to enrich alerts with response time using message history ----
    try:
        history = zap.core.messages(baseurl=target_url)
        print(f"[+] Retrieved {len(history)} HTTP messages for response time mapping.")
        for alert in raw_alerts:
            # ZAP may provide messageId or id — try both
            msg_id = alert.get('messageId') or alert.get('id')
            if msg_id:
                try:
                    msg = zap.core.message(msg_id)
                    # ZAP message shape may differ; check for common fields
                    if isinstance(msg, dict) and 'timeElapsedMillis' in msg:
                        alert['responseTimeInMs'] = int(msg['timeElapsedMillis'])
                except Exception:
                    # ignore per-alert failure
                    continue
    except Exception as e:
        print(f"[WARN] Could not fetch HTTP history for response time: {e}")

    # ---- 7) Group alerts (keep behavior compatible with your DB insertion) ----
    grouped = {}
    for alert in raw_alerts:
        plugin_id = str(alert.get("pluginId") or alert.get("id") or "").strip()
        key = (
            plugin_id,
            alert.get('alert'),
            alert.get('risk'),
            alert.get('description'),
            alert.get('solution')
        )

        if key not in grouped:
            grouped[key] = {
                'pluginId': plugin_id,
                'alert': alert.get('alert'),
                'risk': alert.get('risk'),
                'description': (
                    alert.get('description')
                    or alert.get('desc')
                    or alert.get('otherinfo')
                    or "No description available"
                ),
                'recommendation': (
                    alert.get('solution')
                    or alert.get('recommendation')
                    or "No recommendation provided"
                ),
                'evidence': alert.get('evidence'),
                'instances': [],
                'uri': alert.get('url') or alert.get('uri'),
                'method': alert.get('method'),
                'param': alert.get('param'),
                'attack': alert.get('attack'),
                'response_time': alert.get('responseTimeInMs') or 0,
                'confidence': alert.get('confidence'),
                'cweid': alert.get('cweid'),
                'wascid': alert.get('wascid'),
                'reference': alert.get('reference'),
                'otherinfo': alert.get('otherinfo')
            }

        uri = alert.get('uri') or alert.get('url') or alert.get('reference')
        if uri and uri not in grouped[key]['instances']:
            grouped[key]['instances'].append(uri)

    grouped_alerts = list(grouped.values())
    print(f"[+] Grouped into {len(grouped_alerts)} unique alerts.")

    return grouped_alerts
