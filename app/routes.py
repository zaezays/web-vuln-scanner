from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

from . import db
from .models import User, Scan, Vulnerability, Company
from .scanner import run_zap_scan

main = Blueprint('main', __name__)

# -----------------------
# Home Route
# -----------------------
@main.route('/')
def index():
    return "<h1>Welcome to Web Vulnerability Scanner</h1>"

# -----------------------
# Scan Page (Form + Results)
# -----------------------
@main.route('/scan', methods=['GET', 'POST'])
def scan_page():
    if request.method == 'POST':
        target_url = request.form.get('url')
        if not target_url:
            flash('URL is required.', 'danger')
            return redirect(url_for('main.scan_page'))

        alerts = run_zap_scan(target_url)

        scan = Scan(
            user_id=current_user.id if current_user.is_authenticated else 1,
            target_url=target_url,
            domain=target_url.split('/')[2],
            scan_type='basic',
            status='completed',
            result_summary=f"{len(alerts)} issues found",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow()
        )
        db.session.add(scan)
        db.session.commit()

        for alert in alerts:
            vuln = Vulnerability(
                scan_id=scan.id,
                title=alert.get('alert'),
                vuln_type=alert.get('alert'),
                risk_level=alert.get('risk'),
                description=alert.get('description'),
                recommendation=alert.get('solution')
            )
            db.session.add(vuln)

        db.session.commit()

        return render_template('scan.html', scan_result=alerts, target_url=target_url)

    return render_template('scan.html')

# -----------------------
# API Scan Route (JSON-based)
# -----------------------
@main.route('/api/scan', methods=['POST'])
def scan_website_api():
    target_url = request.json.get('url')
    if not target_url:
        return jsonify({'error': 'No URL provided'}), 400

    alerts = run_zap_scan(target_url)

    scan = Scan(
        user_id=1,
        target_url=target_url,
        domain=target_url.split('/')[2],
        scan_type='basic',
        status='completed',
        result_summary=f"{len(alerts)} issues found",
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow()
    )
    db.session.add(scan)
    db.session.commit()

    for alert in alerts:
        vuln = Vulnerability(
            scan_id=scan.id,
            title=alert.get('alert'),
            vuln_type=alert.get('alert'),
            risk_level=alert.get('risk'),
            description=alert.get('description'),
            recommendation=alert.get('solution')
        )
        db.session.add(vuln)

    db.session.commit()

    return jsonify({'message': 'Scan complete', 'scan_id': scan.id, 'vulnerabilities': alerts})


# -----------------------
# Placeholder: Login
# -----------------------
@main.route('/login', methods=['GET', 'POST'])
def login():
    return "<h2>Login route - to be implemented</h2>"

# -----------------------
# Placeholder: Register
# -----------------------
@main.route('/register', methods=['GET', 'POST'])
def register():
    return "<h2>Register route - to be implemented</h2>"
