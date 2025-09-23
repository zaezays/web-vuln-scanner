import json
from . import db
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    users = db.relationship('User', backref='company', lazy=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'admin' or 'user'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    otp_secret = db.Column(db.String(64), nullable=True)
    trusted_devices = db.Column(db.Text, nullable=True)  # Store as JSON
    profile_picture = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True)


    # Relationships
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=True)
    scans = db.relationship('Scan', backref='user', lazy=True)
    notifications = db.relationship('Notification', backref='recipient', lazy=True)
    logs = db.relationship('UserLog', backref='user', lazy=True)

    def get_trusted_devices(self):
        if self.trusted_devices:
            return json.loads(self.trusted_devices)
        return []

    def add_trusted_device(self, device_token):
        devices = self.get_trusted_devices()
        if device_token not in devices:
            devices.append(device_token)
            self.trusted_devices = json.dumps(devices)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target_url = db.Column(db.String(255), nullable=False)
    domain = db.Column(db.String(255))
    scan_type = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    result_summary = db.Column(db.Text)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True)
    deep_scan_requests = db.relationship('DeepScanRequest', backref='scan', lazy=True)

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    title = db.Column(db.String(255))
    vuln_type = db.Column(db.String(50))
    risk_level = db.Column(db.String(10))
    description = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class DeepScanRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='open')
    admin_note = db.Column(db.Text)
    result_file = db.Column(db.String(255))
    requested_at = db.Column(db.DateTime, default=datetime.utcnow)
    responded_at = db.Column(db.DateTime)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20))
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)