# utils/logging_utils.py

from app import db
from app.models import UserLog
from datetime import datetime

def log_user_action(user_id, action, details=None):
    log = UserLog(
        user_id=user_id,
        action=action,
        details=details,
        created_at=datetime.utcnow()
    )
    db.session.add(log)
    db.session.commit()
