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
from .models import User, Scan, Vulnerability, Company, Notification
from .scanner import run_zap_scan
from app.forms import LoginForm, OTPForm, ScanForm, ProfileForm, AddUserForm, AdminEditUserForm
from sqlalchemy import or_

main = Blueprint('main', __name__)

ALLOWED_PICTURE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_PICTURE_EXTENSIONS


@main.route('/')
def root():
    return redirect(url_for('main.login'))


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
            session.pop('otp_user_email', None)
            flash("Login successful!", "success")
            return redirect(url_for('main.dashboard'))
        else:
            flash("Invalid OTP code.", "danger")

    return render_template('verify_otp.html', form=form, email=email)


@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.login'))


@main.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)


@main.route('/scan', methods=['GET', 'POST'])
@login_required
def scan_page():
    form = ScanForm()
    if form.validate_on_submit():
        target_url = form.url.data.strip()
        if not target_url:
            flash("URL is required.", "danger")
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

    return jsonify({
        'message': 'Scan complete',
        'scan_id': scan.id,
        'vulnerabilities': alerts
    })


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


@main.route('/notifications')
@login_required
def notifications():
    notifs = Notification.query.filter_by(recipient_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return render_template('notifications.html', notifications=notifs)


@main.route('/settings')
@login_required
def settings():
    return render_template('settings.html', user=current_user)

