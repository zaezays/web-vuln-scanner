from flask import (
    Blueprint, render_template, request, jsonify,
    redirect, url_for, flash, session, current_app
)
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime

from utils.auth_utils import generate_otp_secret, generate_otp_code, verify_otp
from utils.auth_roles import admin_required
from utils.logging_utils import log_user_action
from utils.nikto_runner import run_nikto_scan
from flask_mail import Message
from app import mail
from threading import Thread
from app.tasks import run_full_scan_task
from app.custom_alerts import CUSTOM_ALERTS as RAW_CUSTOM_ALERTS
from . import db
from app.models import User, Scan, Vulnerability, Company, Notification, UserLog, ServerVulnerability, DeepScanRequest

from .scanner import run_zap_scan
from .forms import (
    LoginForm, OTPForm, ScanForm, ProfileForm, AddUserForm, AdminEditUserForm, DeepScanReplyForm
)
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from functools import wraps
from sqlalchemy import or_, func
import random
from weasyprint import HTML
from flask import send_file
import io
import pytz
import threading
import re

main = Blueprint('main', __name__)

def csrf_exempt(view_func):
    """Manually exempt a route from CSRF validation."""
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        return view_func(*args, **kwargs)
    wrapped_view._csrf_exempt = True
    return wrapped_view


ALLOWED_PICTURE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Normalize keys/fields so lookups are robust (strip spaces, accept different capitalizations)
NORMALIZED_CUSTOM_ALERTS = {}
for raw_key, raw_val in RAW_CUSTOM_ALERTS.items():
    key = str(raw_key).strip()
    if not key:
        continue

    # accept 'description' or 'Description' etc.
    description = (
        raw_val.get('description')
        or raw_val.get('Description')
        or raw_val.get('desc')
        or raw_val.get('Desc')
        or ""
    )
    recommendation = (
        raw_val.get('recommendation')
        or raw_val.get('Recommendation')
        or raw_val.get('solution')
        or ""
    )

    NORMALIZED_CUSTOM_ALERTS[key] = {
        'description': description,
        'recommendation': recommendation
    }

# Use NORMALIZED_CUSTOM_ALERTS in the rest of the file
CUSTOM_ALERTS = NORMALIZED_CUSTOM_ALERTS


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_PICTURE_EXTENSIONS

# Deep Scan Request Feature

def send_async_email(app, msg):
    """Send email asynchronously to avoid blocking UI."""
    with app.app_context():
        mail = app.extensions.get('mail')
        mail.send(msg)
        
# --- Notification Setting (no SocketIO) ---
def create_notification(recipient_id, message, notif_type="info"):
    notif = Notification(
        recipient_id=recipient_id,
        message=message,
        type=notif_type
    )
    db.session.add(notif)
    db.session.commit()

    # Optional: log in console (for debug visibility)
    print(f"[NOTIFICATION] To: {recipient_id} | {notif_type.upper()} | {message}")

        
        
@main.route('/')
def root():
    return redirect(url_for('main.login'))

@main.route('/admin/forget', methods=['GET', 'POST'])
def admin_forget():
    form = FlaskForm()  # simple empty form for CSRF
    if request.method == 'POST':
        user_email = request.form.get('email')
        if not user_email:
            flash('Please enter your registered email.', 'danger')
            return redirect(url_for('main.admin_forget'))

        msg = Message(
            subject="Password Reset Request - Netwitzscan",
            sender=current_app.config['MAIL_DEFAULT_SENDER'],
            recipients=["netwebzmin25@gmail.com"],
            body=f"A user requested a password reset.\n\nUser Email: {user_email}\n\nPlease reply to this email with the new password."
        )
        mail.send(msg)
        flash('Your request has been sent to the administrator.', 'success')
        return redirect(url_for('main.login'))

    return render_template('admin_forget.html', form=form)


@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip()
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid email or password.', 'danger')
            return render_template('login.html', form=form)

        if not user.is_active:
            flash('Account inactive. Please contact admin.', 'warning')
            return render_template('login.html', form=form)

        if not user.otp_secret:
            user.otp_secret = generate_otp_secret()
            db.session.commit()

        otp = generate_otp_code(user.otp_secret)
        session['otp_user_email'] = email

        msg = Message('Your OTP Code', recipients=[user.email])
        msg.body = f'Your OTP code is: {otp}. It is valid for 5 minutes.'
        try:
            mail.send(msg)
        except Exception as e:
            current_app.logger.error(f"Error sending OTP: {e}")
            flash('Error sending OTP. Please try again.', 'danger')
            return render_template('login.html', form=form)

        flash('OTP sent to your email. Please verify.', 'info')
        return redirect(url_for('main.verify_otp_route'))

    return render_template('login.html', form=form)


@main.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp_route():
    form = OTPForm()
    email = session.get('otp_user_email')

    if not email:
        flash("Session expired. Please login again.", "warning")
        return redirect(url_for('main.login'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('main.login'))

    if not user.is_active:
        flash("Account inactive. Please contact admin.", "warning")
        return redirect(url_for('main.login'))

    if form.validate_on_submit():
        otp_input = form.otp_code.data.strip()
        if verify_otp(user.otp_secret, otp_input):
            login_user(user)
            log_user_action(current_user.id, "Login", "User logged in")
            session.pop('otp_user_email', None)
            flash("Login successful!", "success")
            return redirect(url_for('main.dashboard'))
        else:
            flash("Invalid OTP code.", "danger")

    return render_template('verify_otp.html', form=form, email=email)

@main.route('/resend-otp', methods=['POST'])
@csrf_exempt   
def resend_otp():
    from flask import jsonify
    email = session.get('otp_user_email')
    if not email:
        return jsonify({"status": "error", "message": "Session expired"})

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"status": "error", "message": "User not found"})

    # Generate new OTP
    otp_secret = generate_otp_secret()
    user.otp_secret = otp_secret
    db.session.commit()

    otp_code = generate_otp_code(otp_secret)

    msg = Message(
        "New OTP Code - Witzcore",
        sender=current_app.config['MAIL_DEFAULT_SENDER'],
        recipients=[email]
    )
    msg.body = f"Your new OTP code is: {otp_code}\n\nThis code will expire shortly."
    mail.send(msg)

    return jsonify({"status": "success", "message": "New OTP sent successfully"})


@main.route('/logout')
@login_required
def logout():
    log_user_action(current_user.id, "Logout", f"User {current_user.email} logged out.")
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.login'))


@main.route('/dashboard')
@login_required
def dashboard():
    malaysia_tz = pytz.timezone('Asia/Kuala_Lumpur')


    if current_user.role in ['admin', 'superadmin']:
        total_scans = Scan.query.count()
        completed_scans = Scan.query.filter_by(status='completed').count()
        total_companies = Company.query.count()
        user_count = User.query.count()

        scans = Scan.query.order_by(Scan.started_at.asc()).all()
        vulns = Vulnerability.query.all()
        dashboard_view = "admin"  # identify view mode

    
    else:
        total_scans = (
            Scan.query.join(User, Scan.user_id == User.id)
            .filter(User.company_id == current_user.company_id)
            .count()
        )
        completed_scans = (
            Scan.query.join(User, Scan.user_id == User.id)
            .filter(User.company_id == current_user.company_id, Scan.status == 'completed')
            .count()
        )
        total_companies = 1  # each user belongs to one company
        user_count = (
            User.query.filter_by(company_id=current_user.company_id).count()
            if current_user.company_id else 1
        )

        scans = (
            Scan.query.join(User, Scan.user_id == User.id)
            .filter(User.company_id == current_user.company_id)
            .order_by(Scan.started_at.asc())
            .all()
        )
        vulns = (
            Vulnerability.query.join(Scan, Vulnerability.scan_id == Scan.id)
            .join(User, Scan.user_id == User.id)
            .filter(User.company_id == current_user.company_id)
            .all()
        )
        dashboard_view = "user"  # identify view mode

    # --- Vulnerability Count by Severity ---
    vuln_counts = {
        "Critical": sum(1 for v in vulns if v.risk_level == 'Critical'),
        "High": sum(1 for v in vulns if v.risk_level == 'High'),
        "Medium": sum(1 for v in vulns if v.risk_level == 'Medium'),
        "Low": sum(1 for v in vulns if v.risk_level == 'Low'),
        "Info": sum(1 for v in vulns if v.risk_level == 'Info'),
    }

    # --- Add vulnerability count to each scan for chart data ---
    for s in scans:
        s.vulnerability_count = Vulnerability.query.filter_by(scan_id=s.id).count()

        s.critical_count = Vulnerability.query.filter_by(scan_id=s.id, risk_level='Critical').count()
        s.high_count = Vulnerability.query.filter_by(scan_id=s.id, risk_level='High').count()
        s.medium_count = Vulnerability.query.filter_by(scan_id=s.id, risk_level='Medium').count()
        s.low_count = Vulnerability.query.filter_by(scan_id=s.id, risk_level='Low').count()
        s.info_count = Vulnerability.query.filter_by(scan_id=s.id, risk_level='Info').count()

        if s.started_at:
            dt = s.started_at
            if dt.tzinfo is None:
                dt = pytz.utc.localize(dt)
            s.started_local = dt.astimezone(malaysia_tz)
        else:
            s.started_local = None

    # --- Information Table (5 random info/low vulnerabilities) ---
    try:
        info_vulns = (
            Vulnerability.query
            .order_by(func.random())  # randomize results
            .limit(5)
            .all()
            )
    except Exception as e:
        print(f"[Error fetching random vulnerabilities]: {e}")
        info_vulns = []

    if not info_vulns:
        info_vulns = [
            type('Mock', (), {
                "name": "HTTPS supported",
                "classification": "OWASP A05:2021",
                "confidence": "High",
                "date_scanned": datetime.utcnow()
            })(),
            type('Mock', (), {
                "name": "Valid SSL certificate",
                "classification": "CWE-295",
                "confidence": "High",
                "date_scanned": datetime.utcnow()
            })(),
            type('Mock', (), {
                "name": "Successful HTTPS redirect",
                "classification": "OWASP A05:2021",
                "confidence": "Medium",
                "date_scanned": datetime.utcnow()
            })(),
            type('Mock', (), {
                "name": "No SQL Injection Found",
                "classification": "CWE-89",
                "confidence": "High",
                "date_scanned": datetime.utcnow()
            })(),
            type('Mock', (), {
                "name": "No Cross-Site Scripting Vulnerability Found",
                "classification": "CWE-79",
                "confidence": "Medium",
                "date_scanned": datetime.utcnow()
            })()
        ]

    for v in info_vulns:
        v.name = getattr(v, "name", getattr(v, "title", "No Title"))
        v.classification = getattr(v, "classification", getattr(v, "cweid", "N/A"))
        v.confidence = getattr(v, "confidence", "Medium")
        v.date_scanned = getattr(v, "created_at", datetime.utcnow())

    # --- Recent Scans Table (latest 4) ---
    if current_user.role in ['admin', 'superadmin']:
        recent_scans = Scan.query.order_by(Scan.started_at.desc()).limit(4).all()
    else:
        recent_scans = (
            Scan.query.join(User, Scan.user_id == User.id)
            .filter(User.company_id == current_user.company_id)
            .order_by(Scan.started_at.desc())
            .limit(5)
            .all()
        )

    import random
    for r in recent_scans:
        r.score = random.randint(40, 90)

    # --- Render Template ---
    return render_template(
        'dashboard.html',
        user=current_user,
        dashboard_view=dashboard_view,   
        total_scans=total_scans,
        completed_scans=completed_scans,
        total_companies=total_companies,
        user_count=user_count,
        vuln_counts=vuln_counts,
        scans=scans,
        info_vulns=info_vulns,
        recent_scans=recent_scans
    )


@main.route('/activity-log')
@login_required
def activity_log():
    malaysia_tz = pytz.timezone('Asia/Kuala_Lumpur')
    page = request.args.get('page', 1, type=int)
    per_page = 10

    if current_user.role == 'superadmin':
        pagination = UserLog.query.order_by(UserLog.created_at.desc()).paginate(page=page, per_page=per_page)
    else:
        pagination = (
            UserLog.query
            .join(User, UserLog.user_id == User.id)
            .filter(User.company_id == current_user.company_id)
            .order_by(UserLog.created_at.desc())
            .paginate(page=page, per_page=per_page)
        )

    logs = pagination.items
    return render_template(
        'activity_log.html',
        logs=logs,
        pagination=pagination,
        page_numbers=list(pagination.iter_pages(left_edge=1, right_edge=1, left_current=2, right_current=2)),
        current_page=page,
        prev_page=pagination.prev_num if pagination.has_prev else None,
        next_page=pagination.next_num if pagination.has_next else None
    )

    return render_template('activity_log.html', logs=logs)

@main.route('/scan', methods=['GET', 'POST'])
@login_required
def scan_page():
    form = ScanForm()

    if form.validate_on_submit():
        target_url = form.url.data.strip()

        
        scan_type = "full"

        if not target_url:
            flash("URL is required.", "danger")
            return redirect(url_for('main.scan_page'))

        threshold = request.form.get('threshold')
        strength = request.form.get('intensity')

        
        use_spider = True
        use_ajax_spider = True
        use_auth = False
        use_api_scan = False
        use_ws_scan = False

        # Create a scan record in DB
        scan = Scan(
            user_id=current_user.id,
            target_url=target_url,
            domain=target_url.split('/')[2] if '//' in target_url else target_url,
            scan_type=scan_type, 
            status='in_progress',
            started_at=datetime.utcnow()
        )
        db.session.add(scan)
        db.session.commit()
        
        
        create_notification(
            recipient_id=current_user.id,
            message=f"Scan started for {target_url}",
            notif_type="scan_start"
        )

    
        run_full_scan_task.delay(
            scan.id,
            target_url,
            scan_type,
            threshold,
            strength,
            use_spider,
            use_ajax_spider,
            use_auth,
            use_api_scan,
            use_ws_scan
        )

        flash("Full scan started. It may take a few minutes to complete.", "info")
        return redirect(url_for('main.view_scan_result', scan_id=scan.id))

    return render_template('scan.html', form=form)


@main.route('/scan-result/<int:scan_id>')
@login_required
def view_scan_result(scan_id):
    scan = Scan.query.get_or_404(scan_id)

    if scan.status != 'completed':
        return render_template('scan_loading.html', scan=scan)

    vulns = Vulnerability.query.filter_by(scan_id=scan.id).all()

   
    from app.models import ServerVulnerability
    server_vulns = ServerVulnerability.query.filter_by(scan_id=scan.id).all()

    # Count by severity
    critical_count = sum(1 for v in vulns if v.risk_level == 'Critical')
    high_count = sum(1 for v in vulns if v.risk_level == 'High')
    medium_count = sum(1 for v in vulns if v.risk_level == 'Medium')
    low_count = len(vulns) - critical_count - high_count - medium_count
    
    malaysia_tz = pytz.timezone('Asia/Kuala_Lumpur')
    if scan.started_at:
        if scan.started_at.tzinfo is None:
            scan.started_at = pytz.utc.localize(scan.started_at)
        scan.started_at = scan.started_at.astimezone(malaysia_tz)

    if scan.completed_at:
        if scan.completed_at.tzinfo is None:
            scan.completed_at = pytz.utc.localize(scan.completed_at)
        scan.completed_at = scan.completed_at.astimezone(malaysia_tz)
    
    
    if vulns and hasattr(vulns[0], 'response_time'):
        response_times = [v.response_time for v in vulns if v.response_time]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
    else:
        avg_response_time = 0

  
    return render_template(
        'scan_result.html',
        scan=scan,
        vulnerabilities=vulns,
        server_vulnerabilities=server_vulns,
        target_url=scan.target_url,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        avg_response_time=avg_response_time
    )

@main.route('/api/scan', methods=['POST'])
@login_required
def scan_website_api():
    data = request.get_json()
    target_url = data.get('url') if data else None

    if not target_url:
        return jsonify({'error': 'No URL provided'}), 400

    alerts = run_zap_scan(target_url)

    scan = Scan(
        user_id=current_user.id,
        target_url=target_url,
        domain=target_url.split('/')[2] if '//' in target_url else target_url,
        scan_type='basic',
        status='completed',
        result_summary=f"{len(alerts)} issues found",
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow()
    )
    db.session.add(scan)
    db.session.commit()

 
    normalized_customs = {k.strip(): v for k, v in CUSTOM_ALERTS.items()}

    for alert in alerts:
        plugin_id = str(alert.get('pluginId') or alert.get('id') or "").strip()

        # Default: use ZAP-provided info
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


        if plugin_id in normalized_customs:
            custom = normalized_customs[plugin_id]
            if custom.get('description'):  # lowercase fixed
                description = custom['description']
            if custom.get('recommendation'):  # lowercase fixed
                recommendation = custom['recommendation']
            current_app.logger.info(f"Custom text applied for Plugin ID {plugin_id}: {alert.get('alert')}")
        else:
            current_app.logger.info(f"Using default ZAP text for Plugin ID {plugin_id}: {alert.get('alert')}")

        vuln = Vulnerability(
            scan_id=scan.id,
            title=alert.get('alert'),
            vuln_type=alert.get('vuln_type') or alert.get('alert'),
            risk_level=alert.get('risk'),
            description=description,
            recommendation=recommendation,
            evidence=alert.get('evidence'),
            url=alert.get('url') or alert.get('uri'),
            method=alert.get('method'),
            param=alert.get('param'),
            attack=alert.get('attack'),
            response_time=alert.get('response_time') or 0,
            otherinfo=alert.get('otherinfo'),
            confidence=alert.get('confidence'),
            references=alert.get('reference') or alert.get('references'),
            cweid=str(alert.get('cweid') or ""),
            wascid=str(alert.get('wascid') or "")
        )
        db.session.add(vuln)

    db.session.commit()

    return jsonify({
        'message': 'Scan complete',
        'scan_id': scan.id,
        'vulnerabilities': alerts
    })

@main.route('/scanning-history')
@login_required
def scanning_history():
     
    page = request.args.get('page', 1, type=int)
    per_page = 10

   
    pagination = (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .paginate(page=page, per_page=per_page)
    )
    scans = pagination.items
    
    
    malaysia_tz = pytz.timezone('Asia/Kuala_Lumpur')
    for s in scans:
        # started_at -> started_local (Asia/Kuala_Lumpur)
        if s.started_at:
            dt = s.started_at
            if dt.tzinfo is None:
                dt = pytz.utc.localize(dt)  # mark as UTC if naive
            s.started_local = dt.astimezone(malaysia_tz)
        else:
            s.started_local = None

        
        s.duration_display = (s.completed_at - s.started_at) if (s.completed_at and s.started_at) else None
    
    for s in scans:
        if not s.started_at:
            s.started_at = None
        if not s.completed_at:
            s.completed_at = None

    # Render page (with pagination variables)
    return render_template(
        'scanning_history.html',
        scans=scans,
        pagination=pagination,
        page_numbers=list(pagination.iter_pages(left_edge=1, right_edge=1, left_current=2, right_current=2)),
        current_page=page,
        prev_page=pagination.prev_num if pagination.has_prev else None,
        next_page=pagination.next_num if pagination.has_next else None
    )

@main.route('/delete-scan/<int:scan_id>', methods=['POST'])
@login_required
def delete_scan(scan_id):
    """
    Delete a specific scan and its related vulnerabilities.
    Only the scan owner or a superadmin can perform this action.
    """
    scan = Scan.query.get_or_404(scan_id)

    # 🛡 Permission check
    if scan.user_id != current_user.id and current_user.role != 'superadmin':
        flash("Unauthorized action.", "danger")
        return redirect(url_for('main.scanning_history'))

    # 🧹 Delete vulnerabilities first to maintain integrity
    Vulnerability.query.filter_by(scan_id=scan.id).delete()

    # 🗑 Delete scan record
    db.session.delete(scan)
    db.session.commit()

    # 📝 Log the deletion
    log_user_action(current_user.id, "Delete Scan", f"Deleted scan for {scan.target_url}")

    flash("Scan deleted successfully.", "success")
    return redirect(url_for('main.scanning_history'))

@main.route('/scan-result/<int:scan_id>/export/pdf')
@login_required
def export_scan_pdf(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    vulns = Vulnerability.query.filter_by(scan_id=scan.id).all()

    for v in vulns:
        v.short_description = (
            v.description[:200] + '...' if v.description and len(v.description) > 200 else v.description
        )
        v.short_recommendation = (
            v.recommendation[:200] + '...' if v.recommendation and len(v.recommendation) > 200 else v.recommendation
        )

    rendered = render_template('scan_result_pdf.html', scan=scan, scan_result=vulns)
    pdf = HTML(string=rendered).write_pdf()

    try:
        
        notif = Notification(
            sender_id=current_user.id,
            recipient_id=current_user.id,
            message=f"Report PDF downloaded successfully for {scan.target_url}",
            type="pdf_download"
        )
        db.session.add(notif)
        db.session.commit()
    except Exception as e:
        current_app.logger.warning(f"[Notification] Failed to insert success PDF notif: {e}")

    try:
        return send_file(
            io.BytesIO(pdf),
            download_name=f"scan_result_{scan.id}.pdf",
            as_attachment=True,
            mimetype='application/pdf'
        )
    except Exception as e:
        
        notif_fail = Notification(
            sender_id=current_user.id,
            recipient_id=current_user.id,
            message=f"Failed to download report PDF for {scan.target_url}. Error: {e}",
            type="pdf_download"
        )
        db.session.add(notif_fail)
        db.session.commit()
        current_app.logger.error(f"[PDF ERROR] {e}")
        flash("Error downloading PDF file.", "danger")
        return redirect(url_for('main.view_scan_result', scan_id=scan.id))

    
@main.route('/api/vuln_stats/<int:scan_id>')
@login_required
def vuln_stats(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    vulns = Vulnerability.query.filter_by(scan_id=scan.id).all()

    stats = {
        "Critical": sum(1 for v in vulns if v.risk_level == 'Critical'),
        "High": sum(1 for v in vulns if v.risk_level == 'High'),
        "Medium": sum(1 for v in vulns if v.risk_level == 'Medium'),
        "Low": sum(1 for v in vulns if v.risk_level == 'Low'),
        "Requests": len(vulns),
        "ScanDuration": str(scan.completed_at - scan.started_at) if scan.completed_at else "N/A"
    }

    return jsonify(stats)

@main.route('/deep_scan_request/<int:scan_id>')
@login_required
def deep_scan_request(scan_id):
    scan = Scan.query.get_or_404(scan_id)

  
    rendered = render_template(
        'scan_result_pdf.html',
        scan=scan,
        scan_result=Vulnerability.query.filter_by(scan_id=scan.id).all()
    )
    pdf_data = HTML(string=rendered).write_pdf()

    reports_dir = os.path.join(current_app.root_path, 'static', 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    pdf_path = os.path.join(reports_dir, f'scan_{scan.id}.pdf')
    with open(pdf_path, 'wb') as f:
        f.write(pdf_data)

  
    msg = Message(
        subject=f"Deep Scan Request - {scan.target_url}",
        sender=current_app.config['MAIL_DEFAULT_SENDER'],
        recipients=["netwebzmin25@gmail.com"],
        cc=[current_user.email]
    )

  
    msg.html = f"""
    <div style="font-family: Arial, sans-serif; color: #333;">
      <p>Hello <strong>Admin</strong>,</p>
      <p>A new <strong>Deep Scan Request</strong> has been submitted through the 
      <span style="color:#007bff; font-weight:bold;">WitzCore Web Scanner</span>.</p>

      <table cellpadding="6" cellspacing="0" style="border-collapse: collapse; font-size: 14px;">
        <tr><td style="font-weight:bold;">Requested By:</td><td>{current_user.username} ({current_user.email})</td></tr>
        <tr><td style="font-weight:bold;">Target URL:</td><td><a href="{scan.target_url}" target="_blank">{scan.target_url}</a></td></tr>
        <tr><td style="font-weight:bold;">Request ID:</td><td>{scan.id}</td></tr>
        <tr><td style="font-weight:bold;">Requested At:</td><td>{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC</td></tr>
      </table>

      <p style="margin-top:10px;">This email includes the latest <strong>scan report PDF</strong> attached automatically.</p>
      <p style="color:#666;font-size:13px;">— Automated message from WitzCore Web Scanner system.</p>
    </div>
    """


    with current_app.open_resource(pdf_path) as pdf:
        msg.attach(f"scan_{scan.id}.pdf", "application/pdf", pdf.read())

 
    Thread(target=send_async_email, args=(current_app._get_current_object(), msg)).start()

   
    log_user_action(
        current_user.id,
        "Deep Scan Request",
        f"User requested deep scan for {scan.target_url} (Scan ID: {scan.id})"
    )


    try:
        dsr = DeepScanRequest(
            scan_id=scan.id,
            user_id=current_user.id,
            status='Pending'
            )
        db.session.add(dsr)
        
        user_notif = Notification(
            sender_id=current_user.id,
            recipient_id=current_user.id,
            message=f"Your deep scan request for {scan.target_url} has been submitted successfully. Please wait for admin review.",
            type="deep_scan_request"
            )
        db.session.add(user_notif)
        
    
        admins = User.query.filter(User.role.in_(['admin', 'superadmin'])).all()
        for admin in admins:
            admin_notif = Notification(
                sender_id=current_user.id,
                recipient_id=admin.id,
                message=f"New deep scan request submitted by {current_user.username} for {scan.target_url}.",
                type="deep_scan_request"
                )
            db.session.add(admin_notif)
            
            db.session.commit()
            
    except Exception as e:
        current_app.logger.warning(f"[DeepScanRequest] Failed to create record or notification: {e}")
       


  
    try:
        os.remove(pdf_path)
    except Exception as e:
        current_app.logger.warning(f"Could not delete temp PDF: {e}")

 
    gmail_link = (
        f"mailto:netwebzmin25@gmail.com"
        f"?subject=Deep%20Scan%20Request%20-%20{scan.target_url}"
        f"&body=Hello%20Admin,%0D%0A%0D%0AI've%20requested%20a%20deep%20scan%20for%20{scan.target_url}."
        f"%0D%0ARequest%20ID:%20{scan.id}%0D%0A%0D%0A(This%20request%20has%20been%20automatically%20sent%20with%20the%20PDF%20attached.)"
    )

    flash("Deep Scan Request sent!", "success")
    return redirect(gmail_link)

@main.route('/my-deep-scan-requests')
@login_required
def my_deep_scan_requests():
    """User view: show their own deep scan requests."""
    requests = DeepScanRequest.query.filter_by(user_id=current_user.id).order_by(DeepScanRequest.requested_at.desc()).all()
    return render_template('user_deep_scan_requests.html', requests=requests)


@main.route('/admin/deep-scan-requests')
@login_required
@admin_required
def admin_deep_scan_requests():
    """Admin view: list all deep scan requests."""
    requests = DeepScanRequest.query.order_by(DeepScanRequest.requested_at.desc()).all()
    return render_template('admin_deep_scan_requests.html', requests=requests)


@main.route('/admin/deep-scan-requests/<int:request_id>/reply', methods=['GET', 'POST'])
@login_required
@admin_required
def reply_deep_scan_request(request_id):
    dsr = DeepScanRequest.query.get_or_404(request_id)
    form = DeepScanReplyForm()

    if form.validate_on_submit():
        admin_note = form.admin_note.data
        file = form.result_file.data

        if file:
            filename = secure_filename(file.filename)
            upload_dir = os.path.join(current_app.root_path, 'static', 'deep_results')
            os.makedirs(upload_dir, exist_ok=True)
            save_path = os.path.join(upload_dir, filename)
            file.save(save_path)
            dsr.result_file = filename

        dsr.admin_note = admin_note
        dsr.status = 'Completed'
        dsr.responded_at = datetime.utcnow()
        db.session.commit()
        
       
        try:
            if dsr.user_id:
                user_notif = Notification(
                    sender_id=current_user.id,
                    recipient_id=dsr.user_id,
                    message=f"Your deep scan request for {dsr.scan.target_url} has been completed. You may now view the report.",
                    type="deep_scan_result"
                    )
                db.session.add(user_notif)
                
                admin_notif = Notification(
                    sender_id=current_user.id,
                    recipient_id=current_user.id,
                    message=f"You have successfully completed and sent the deep scan result for {dsr.scan.target_url}.",
                    type="deep_scan_result"
                    )
                db.session.add(admin_notif)
                db.session.commit()
                
        except Exception as e:
            current_app.logger.warning(f"[DeepScanReply] Failed to send notifications: {e}")


        flash("Deep scan result sent successfully!", "success")
        return redirect(url_for('main.admin_deep_scan_requests'))

@main.route('/admin/deep-scan-requests/<int:request_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_deep_scan_request(request_id):
    """Delete a deep scan request (admin only)."""
    dsr = DeepScanRequest.query.get_or_404(request_id)

    try:
        # Remove associated uploaded result file (if exists)
        if dsr.result_file:
            file_path = os.path.join(current_app.root_path, 'static', 'deep_results', dsr.result_file)
            if os.path.exists(file_path):
                os.remove(file_path)

        db.session.delete(dsr)
        db.session.commit()

    
        log_user_action(
            current_user.id,
            "Delete Deep Scan Request",
            f"Admin deleted deep scan request ID {request_id} for {dsr.scan.target_url if dsr.scan else 'Unknown URL'}"
        )

      
        if dsr.user_id:
            notif = Notification(
                sender_id=current_user.id,
                recipient_id=dsr.user_id,
                message=f"Your deep scan request (ID {request_id}) has been deleted by admin.",
                type="deep_scan_deleted"
            )
            db.session.add(notif)
            db.session.commit()

        flash("Deep scan request deleted successfully.", "success")

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"[DeleteDeepScan] Error deleting request: {e}")
        flash("An error occurred while deleting the request.", "danger")

    return redirect(url_for('main.admin_deep_scan_requests'))

@main.route('/admin/users')
@login_required
@admin_required
def user_management():
    q = request.args.get('q', '', type=str)
    company_id = request.args.get('company_id', type=int)
    page = request.args.get('page', 1, type=int)
    per_page = 10

    query = User.query

    if q:
        query = query.filter(or_(
            User.username.ilike(f"%{q}%"),
            User.email.ilike(f"%{q}%")
        ))

    if company_id:
        query = query.filter_by(company_id=company_id)

    pagination = query.order_by(User.created_at.desc()).paginate(page=page, per_page=per_page)
    users = pagination.items
    companies = Company.query.all()

    return render_template(
        'admin_users.html',
        users=users,
        companies=companies,
        selected_company_id=company_id,
        total_users=pagination.total,
        users_start=(pagination.page - 1) * per_page + 1,
        users_end=(pagination.page - 1) * per_page + len(users),
        current_page=page,
        prev_page=pagination.prev_num if pagination.has_prev else None,
        next_page=pagination.next_num if pagination.has_next else None,
        page_numbers=list(pagination.iter_pages(left_edge=1, right_edge=1, left_current=2, right_current=2)),
        q=q
    )


@main.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    form = AddUserForm()
    if form.validate_on_submit():
        existing = User.query.filter_by(email=form.email.data.strip()).first()
        if existing:
            flash("Email already in use.", "danger")
            return render_template('admin_user_add.html', form=form)

        company = None
        comp_name = form.company_name.data.strip() if form.company_name.data else None
        if comp_name:
            company = Company.query.filter_by(name=comp_name).first()
            if not company:
                company = Company(name=comp_name)
                db.session.add(company)
                db.session.flush()

        new_user = User(
            username=form.username.data.strip(),
            email=form.email.data.strip(),
            password_hash=generate_password_hash(form.password.data),
            role=form.role.data,
            company_id=company.id if company else None,
            is_active=bool(form.is_active.data)
        )

        db.session.add(new_user)
        db.session.commit()
        
        create_notification(
            recipient_id=current_user.id,
            message=f"User {new_user.email} added successfully.",
            notif_type="user_action"
        )
        
        log_user_action(current_user.id, "Add User", f"Added user {new_user.email} to company {company.name if company else 'None'}")

        flash("User created successfully.", "success")
        return redirect(url_for('main.user_management'))

    elif request.method == 'POST':
        current_app.logger.info(f"AddUserForm errors: {form.errors}")

    return render_template('admin_user_add.html', form=form)


@main.route('/admin/users/<int:user_id>')
@login_required
@admin_required
def view_user(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('admin_user_show.html', user=user)


@main.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = AdminEditUserForm()

    if form.validate_on_submit():
        user.username = form.username.data.strip()
        user.email = form.email.data.strip()

        if form.password.data:
            if form.password.data == form.confirm_password.data:
                user.password_hash = generate_password_hash(form.password.data)
            else:
                flash("Passwords do not match.", "danger")
                return render_template('admin_user_edit.html', form=form, user=user)

        comp_name = form.company_name.data.strip() if form.company_name.data else None
        if comp_name:
            company = Company.query.filter_by(name=comp_name).first()
            if not company:
                company = Company(name=comp_name)
                db.session.add(company)
                db.session.flush()
            user.company_id = company.id
        else:
            user.company_id = None

        user.is_active = form.is_active.data

        db.session.commit()
        
        create_notification(
            recipient_id=current_user.id,
            message=f"User {user.email} profile edited successfully.",
            notif_type="user_action"
        )
        
        log_user_action(current_user.id, "Edit User", f"Edited user {user.email}")
        flash("User updated successfully.", "success")
        return redirect(url_for('main.user_management'))

    elif request.method == 'GET':
        form.username.data = user.username
        form.email.data = user.email
        form.company_name.data = user.company.name if user.company else ''
        form.is_active.data = user.is_active

    return render_template('admin_user_edit.html', form=form, user=user)


@main.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user == current_user:
        flash("You cannot delete yourself.", "warning")
        return redirect(url_for('main.user_management'))

    if user.profile_picture:
        path = os.path.join(current_app.root_path, 'static', 'uploads', user.profile_picture)
        if os.path.exists(path):
            try:
                os.remove(path)
            except Exception as e:
                current_app.logger.error(f"Error deleting picture: {e}")

    db.session.delete(user)
    db.session.commit()
    
    create_notification(
        recipient_id=current_user.id,
        message=f"Deleted user {user.email} successfully.",
        notif_type="user_action"
    )
    
    log_user_action(current_user.id, "Delete User", f"Deleted user {user.email}")
    
    flash("User deleted successfully.", "success")
    return redirect(url_for('main.user_management'))


@main.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()
    if form.validate_on_submit():
        current_user.username = form.username.data.strip()

        if form.picture.data and allowed_file(form.picture.data.filename):
            filename = secure_filename(form.picture.data.filename)
            _, ext = os.path.splitext(filename)
            pic_filename = f"user_{current_user.id}{ext}"
            upload_dir = os.path.join(current_app.root_path, 'static', 'uploads')
            os.makedirs(upload_dir, exist_ok=True)
            full_path = os.path.join(upload_dir, pic_filename)
            try:
                form.picture.data.save(full_path)
                current_user.profile_picture = pic_filename
            except Exception as e:
                current_app.logger.error(f"Error saving picture: {e}")
                flash("Failed to upload picture.", "danger")
                return redirect(url_for('main.profile'))

        db.session.commit()
        flash("Profile updated successfully.", "success")
        return redirect(url_for('main.profile'))

    elif request.method == 'GET':
        form.username.data = current_user.username

    return render_template('profile.html', form=form, user=current_user)

@main.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = ProfileForm()
    if form.validate_on_submit():
        current_user.username = form.username.data.strip()

        if form.picture.data and allowed_file(form.picture.data.filename):
            filename = secure_filename(form.picture.data.filename)
            _, ext = os.path.splitext(filename)
            pic_filename = f"user_{current_user.id}{ext}"
            upload_dir = os.path.join(current_app.root_path, 'static', 'uploads')
            os.makedirs(upload_dir, exist_ok=True)
            full_path = os.path.join(upload_dir, pic_filename)
            form.picture.data.save(full_path)
            current_user.profile_picture = pic_filename

        db.session.commit()
        flash("Profile updated successfully.", "success")
        return redirect(url_for('main.profile'))

    elif request.method == 'GET':
        form.username.data = current_user.username

    return render_template('profile_edit.html', form=form)


@main.route('/notifications', defaults={'filter_type': 'all'})
@main.route('/notifications/<string:filter_type>')
@login_required
def notifications(filter_type):
    """
    Display notifications belonging only to the current user.
    Supports filter: all, new, unread
    """
    base_query = Notification.query.filter_by(
        recipient_id=current_user.id
    ).order_by(Notification.created_at.desc())

    if filter_type == 'new':
        notifications = base_query.filter_by(is_read=False).all()
    elif filter_type == 'unread':
        notifications = base_query.filter_by(is_read=False).all()
    else:
        notifications = base_query.all()

    return render_template('notifications.html', notifications=notifications, filter=filter_type)


@main.app_context_processor
def inject_notifications():
    """Inject unread count + recent notifications into all templates."""
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(
            recipient_id=current_user.id, is_read=False
        ).count()

        latest_notifs = (
            Notification.query.filter_by(recipient_id=current_user.id)
            .order_by(Notification.created_at.desc())
            .limit(5)
            .all()
        )
        return dict(unread_count=unread_count, latest_notifs=latest_notifs)

    return dict(unread_count=0, latest_notifs=[])


@main.route("/notifications/mark_all_read", methods=["POST"])
@login_required
def mark_all_notifications_read():
    """Mark all user's notifications as read."""
    notifications = Notification.query.filter_by(
        recipient_id=current_user.id, is_read=False
    ).all()

    for n in notifications:
        n.is_read = True

    db.session.commit()
    flash("All notifications marked as read.", "success")
    return redirect(url_for("main.notifications"))


@main.route("/notifications/delete/<int:notif_id>", methods=["POST"])
@login_required
def delete_notification(notif_id):
    """Delete a specific notification (only if it belongs to the current user)."""
    notif = Notification.query.filter_by(id=notif_id, recipient_id=current_user.id).first()

    if notif:
        db.session.delete(notif)
        db.session.commit()
        flash("Notification deleted successfully.", "success")
    else:
        flash("Notification not found or access denied.", "danger")

    return redirect(url_for("main.notifications"))


@main.route("/notifications/read/<int:notif_id>", methods=["GET"])
@login_required
def mark_notification_read(notif_id):
    """Mark a single notification as read and redirect to notification page."""
    notif = Notification.query.filter_by(id=notif_id, recipient_id=current_user.id).first()

    if notif and not notif.is_read:
        notif.is_read = True
        db.session.commit()

    return redirect(url_for("main.notifications"))


@main.route('/settings')
@login_required
def settings():
    return render_template('settings.html', user=current_user)
