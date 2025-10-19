import json
from . import db
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from pytz import timezone

shared_notification = db.Table(
    'shared_notification',
    db.Column('notification_id', db.Integer, db.ForeignKey('notification.id'), primary_key=True),
    db.Column('recipient_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

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
    role = db.Column(db.String(10), nullable=False)  
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    otp_secret = db.Column(db.String(64), nullable=True)
    trusted_devices = db.Column(db.Text, nullable=True) 
    profile_picture = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True)


    # Relationships
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=True)
    
    # 🔹 Relationships for scanning, logs, and notification sending
    scans = db.relationship(
        'Scan',
        backref='user',
        lazy=True,
        passive_deletes=True  
    )

    notifications = db.relationship(
        'Notification',
        backref='sender',
        lazy=True,
        foreign_keys='Notification.sender_id',
        cascade="all, delete-orphan"
    )

    logs = db.relationship(
        "UserLog",
        back_populates="user",
        lazy='dynamic',
        passive_deletes=True  
    )
    
    shared_notifications = db.relationship(
        'Notification',
        secondary=shared_notification,
        backref=db.backref('recipients', lazy='dynamic')
    )

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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id', ondelete='SET NULL'), nullable=True)
    target_url = db.Column(db.String(255), nullable=False)
    domain = db.Column(db.String(255))
    scan_type = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    result_summary = db.Column(db.Text)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_shared = db.Column(db.Boolean, default=False)
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True)
    deep_scan_requests = db.relationship('DeepScanRequest', back_populates='scan', lazy=True)

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    title = db.Column(db.String(255))
    vuln_type = db.Column(db.String(50))
    risk_level = db.Column(db.String(10))
    description = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    evidence = db.Column(db.Text, nullable=True)
    url = db.Column(db.String(512), nullable=True)
    method = db.Column(db.String(10), nullable=True)
    param = db.Column(db.String(255), nullable=True)
    attack = db.Column(db.Text, nullable=True)
    otherinfo = db.Column(db.Text, nullable=True)
    confidence = db.Column(db.String(50), nullable=True)
    references = db.Column(db.Text, nullable=True)
    cweid = db.Column(db.String(50), nullable=True)
    wascid = db.Column(db.String(50), nullable=True)
    response_time = db.Column(db.Float)  

class ServerVulnerability(db.Model):
    __tablename__ = 'server_vulnerability'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)

    category = db.Column(db.String(100))      # e.g., "Server Misconfiguration"
    title = db.Column(db.String(255))         # e.g., "Missing X-Frame-Options Header"
    risk_level = db.Column(db.String(20))     # Info, Low, Medium, High
    description = db.Column(db.Text)          # Detailed description of the issue
    recommendation = db.Column(db.Text)       # Suggested mitigation
    url = db.Column(db.String(512), nullable=True)
    method = db.Column(db.String(10), nullable=True)
    banner = db.Column(db.String(255))        # e.g., Apache/2.4.7 (Ubuntu)
    x_powered_by = db.Column(db.String(255))  # e.g., PHP/5.6.40
    reference = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<ServerVulnerability {self.title} ({self.risk_level})>"

class DeepScanRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    status = db.Column(db.String(20), default='Pending')
    admin_note = db.Column(db.Text)
    result_file = db.Column(db.String(255))
    requested_at = db.Column(db.DateTime, default=datetime.utcnow)
    responded_at = db.Column(db.DateTime)
    
      # 🟩 FIXED RELATIONSHIP
    user = db.relationship('User', backref=db.backref('deep_scan_requests', lazy=True))
    scan = db.relationship('Scan', back_populates='deep_scan_requests')

    def __repr__(self):
        return f"<DeepScanRequest id={self.id} scan_id={self.scan_id} user_id={self.user_id} status={self.status}>"

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) 
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20))
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship("User", back_populates="logs")
    
    @property
    def local_time(self):
        tz = timezone("Asia/Kuala_Lumpur")
        return self.created_at.replace(tzinfo=timezone("UTC")).astimezone(tz)
