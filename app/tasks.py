# app/tasks.py
from celery import Celery, shared_task
from datetime import datetime
from app import db, create_app
from app.models import Scan, Vulnerability, ServerVulnerability
from utils.nikto_runner import run_nikto_scan
from utils.scan_helpers import run_zap_scan, create_notification, log_user_action
from app.custom_alerts import CUSTOM_ALERTS as RAW_CUSTOM_ALERTS
import os, traceback

CUSTOM_ALERTS = RAW_CUSTOM_ALERTS

# Celery initialization
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
celery = Celery(
    "flask_scanner",
    broker=REDIS_URL,
    backend=REDIS_URL
)

celery.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="Asia/Kuala_Lumpur",
    enable_utc=True,
)

# Quick test task
@celery.task
def test_task(name):
    print(f"[CELERY TEST] Task running for {name}")
    return f"Hello, {name}! Task executed successfully."

# Main scanning task
@shared_task(bind=True, name="app.tasks.run_full_scan_task")
def run_full_scan_task(self, scan_id, target_url, scan_type,
                       threshold, strength,
                       use_spider, use_ajax_spider,
                       use_auth, use_api_scan, use_ws_scan):
    app = create_app()
    with app.app_context():
        try:
            print(f"[CELERY] Starting full scan for Scan ID={scan_id}, Target={target_url}")
            scan_rec = Scan.query.get(scan_id)
            if not scan_rec:
                print(f"[CELERY] Scan record {scan_id} not found.")
                return

            # ---------------- ZAP SCAN ----------------
            try:
                alerts = run_zap_scan(target_url=target_url) or []
                print(f"[CELERY] ZAP returned {len(alerts)} alerts.")
            except Exception as e:
                print(f"[ERROR] ZAP scan failed for {target_url}: {e}")
                alerts = []

            # ---------------- NIKTO SCAN ----------------
            try:
                print(f"[CELERY] Starting Nikto scan for {target_url}")
                nikto_result = run_nikto_scan(target_url, timeout=300, mode="tuned")
                print("[CELERY] Nikto scan complete.")

                if nikto_result:
                    banner = nikto_result.get("banner")
                    xpb = nikto_result.get("x_powered_by")
                    findings = nikto_result.get("findings", [])
                    count = len(findings)

                    nikto_summary = f"Nikto: {count} findings"
                    if banner:
                        nikto_summary += f" | Server: {banner}"
                    if xpb:
                        nikto_summary += f" | X-Powered-By: {xpb}"

                    if scan_rec.result_summary:
                        scan_rec.result_summary += f" | {nikto_summary}"
                    else:
                        scan_rec.result_summary = nikto_summary

                    # Save server info
                    if banner:
                        db.session.add(ServerVulnerability(
                            scan_id=scan_rec.id,
                            category="Server Info",
                            title="Server Banner Detected",
                            risk_level="Info",
                            description=f"Server banner: {banner}",
                            recommendation="Ensure server software is up-to-date.",
                            banner=banner
                        ))
                    if xpb:
                        db.session.add(ServerVulnerability(
                            scan_id=scan_rec.id,
                            category="Server Info",
                            title="X-Powered-By Header Detected",
                            risk_level="Info",
                            description=f"Technology disclosed: {xpb}",
                            recommendation="Hide or remove X-Powered-By header to prevent info disclosure.",
                            x_powered_by=xpb
                        ))

                    # Save Nikto findings
                    for f in findings:
                        db.session.add(ServerVulnerability(
                            scan_id=scan_rec.id,
                            category=f.get("category") or "Nikto Finding",
                            title=f.get("path") or "Server Issue",
                            risk_level="Low",
                            description=f.get("description") or f.get("raw"),
                            recommendation="Review server configuration and security headers."
                        ))
                    db.session.commit()

            except Exception as ne:
                print(f"[ERROR] Nikto scan failed: {ne}")

            # ---------------- ZAP FINDINGS ----------------
            for alert in alerts:
                try:
                    plugin_id = str(alert.get('pluginId') or alert.get('id') or "").strip()
                    description = (
                        alert.get('description')
                        or alert.get('desc')
                        or alert.get('otherinfo')
                        or "No description available"
                    )
                    recommendation = (
                        alert.get('solution')
                        or alert.get('recommendation')
                        or "No recommendation provided"
                    )

                    vuln = Vulnerability(
                        scan_id=scan_rec.id,
                        title=alert.get('alert') or alert.get('title'),
                        vuln_type=alert.get('vuln_type') or alert.get('alert_type'),
                        risk_level=alert.get('risk'),
                        description=description,
                        recommendation=recommendation,
                        url=alert.get('url') or alert.get('uri'),
                        method=alert.get('method'),
                        param=alert.get('param'),
                        attack=alert.get('attack'),
                        confidence=alert.get('confidence'),
                        evidence=alert.get('evidence'),
                        otherinfo=alert.get('otherinfo')
                    )
                    db.session.add(vuln)
                except Exception as ex:
                    print(f"[ERROR] Insert vuln failed: {ex}")

            # ---------------- FINALIZE ----------------
            scan_rec.status = "completed"
            scan_rec.completed_at = datetime.utcnow()
            zap_summary = f"{len(alerts)} ZAP issues found"
            if scan_rec.result_summary:
                scan_rec.result_summary = f"{zap_summary} | {scan_rec.result_summary}"
            else:
                scan_rec.result_summary = zap_summary
            db.session.commit()

            create_notification(scan_rec.user_id,
                                 f"Scan completed for {target_url}",
                                 "scan_complete")
            log_user_action(scan_rec.user_id, "Scan",
                            f"Full scan completed on {target_url}")
            print(f"[CELERY] Scan job {scan_id} completed successfully.")

        except Exception as e:
            print(f"[CELERY ERROR] {traceback.format_exc()}")
            if 'scan_rec' in locals():
                scan_rec.status = "failed"
                db.session.commit()
            raise e
