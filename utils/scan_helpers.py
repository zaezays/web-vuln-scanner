# app/utils/scan_helpers.py
from app import db
from app.models import Notification, UserLog
from datetime import datetime

def create_notification(recipient_id, message, notif_type):
    notif = Notification(
        recipient_id=recipient_id,
        message=message,
        type=notif_type,     
        created_at=datetime.utcnow(),
        is_read=False
    )
    db.session.add(notif)
    db.session.commit()


def log_user_action(user_id, action, details):
    from app.models import UserLog
    log = UserLog(user_id=user_id, action=action, details=details, created_at=datetime.utcnow())
    db.session.add(log)
    db.session.commit()


def run_zap_scan(target_url):
    from app.scanner import run_zap_scan as zap_func
    return zap_func(target_url)
