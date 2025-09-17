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
from flask_mail import Message
from app import mail
from . import db
from .models import User, Scan, Vulnerability, Company
from .scanner import run_zap_scan
from app.forms import LoginForm, OTPForm, ScanForm, ProfileForm
from sqlalchemy import or_

# Allowed extensions for image upload
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

main = Blueprint('main', __name__)


# -----------------------
# Home Route
# -----------------------
@main.route('/')
def root():
    return redirect(url_for('main.login'))


# -----------------------
# Login & Authentication
# -----------------------
@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('main.login'))

        if not getattr(user, 'otp_secret', None):
            user.otp_secret = generate_otp_secret()
            db.session.commit()

        otp_code = generate_otp_code(user.otp_secret)
        session['otp_user_email'] = email

        msg = Message('Your OTP Code', recipients=[user.email])
        msg.body = f'Your OTP code is: {otp_code}. It is valid for 5 minutes.'
        mail.send(msg)

        flash('OTP sent to your email. Please verify.', 'info')
        return redirect(url_for('main.verify_otp_route'))

    return render_template('login.html', form=form)


@main.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp_route():
    form = OTPForm()
    email = session.get('otp_user_email')

    if not email:
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for('main.login'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('main.login'))

    if form.validate_on_submit():
        otp_input = form.otp_code.data
        if verify_otp(user.otp_secret, otp_input):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('main.dashboard'))
        else:
            flash("Invalid OTP.", "danger")

    return render_template('verify_otp.html', form=form)


# -----------------------
# Dashboard
# -----------------------
@main.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)


# -----------------------
# Logout
# -----------------------
@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.login'))


# -----------------------
# Scan Pages
# -----------------------
@main.route('/scan', methods=['GET', 'POST'])
@login_required
def scan_page():
    form = ScanForm()

    if request.method == 'POST':
        target_url = request.form.get('url')
        if not target_url:
            flash('URL is required.', 'danger')
            return redirect(url_for('main.scan_page'))

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
        return render_template('scan.html', form=form, scan_result=alerts, target_url=target_url)

    return render_template('scan.html', form=form)


@main.route('/api/scan', methods=['POST'])
@login_required
def scan_website_api():
    target_url = request.json.get('url')
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
# Registration (Placeholder)
# -----------------------
@main.route('/register', methods=['GET', 'POST'])
def register():
    return "<h2>Register route - to be implemented</h2>"


# -----------------------
# Admin: User Management
# -----------------------
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
        users_start=(pagination.page - 1) * pagination.per_page + 1,
        users_end=(pagination.page - 1) * pagination.per_page + len(users),
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
    return "<h2>Add User Page (To be implemented)</h2>"


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
    form = ProfileForm()

    if form.validate_on_submit():
        user.username = form.username.data

        pic = form.picture.data
        if pic and allowed_file(pic.filename):
            filename = secure_filename(pic.filename)
            _, ext = os.path.splitext(filename)
            pic_filename = f"user_{user.id}{ext}"
            upload_path = os.path.join(current_app.root_path, 'static', 'uploads', pic_filename)
            pic.save(upload_path)
            user.profile_picture = pic_filename

        db.session.commit()
        flash('User updated successfully.', 'success')
        return redirect(url_for('main.user_management'))

    elif request.method == 'GET':
        form.username.data = user.username

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
        try:
            path = os.path.join(current_app.root_path, 'static', 'uploads', user.profile_picture)
            if os.path.exists(path):
                os.remove(path)
        except Exception as e:
            current_app.logger.error(f"Error removing user picture: {e}")

    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    return redirect(url_for('main.user_management'))


# -----------------------
# Profile Settings
# -----------------------
@main.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()
    if form.validate_on_submit():
        new_username = form.username.data
        pic = form.picture.data

        if pic and allowed_file(pic.filename):
            filename = secure_filename(pic.filename)
            _, ext = os.path.splitext(filename)
            pic_filename = f"user_{current_user.id}{ext}"
            upload_path = os.path.join(current_app.root_path, 'static', 'uploads', pic_filename)
            pic.save(upload_path)
            current_user.profile_picture = pic_filename

        current_user.username = new_username
        db.session.commit()
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('main.profile'))

    elif request.method == 'GET':
        form.username.data = current_user.username

    return render_template('profile.html', form=form, user=current_user)


# -----------------------
# Helpers
# -----------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
