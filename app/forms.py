# app/forms.py

from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, SubmitField, SelectField,
    BooleanField, FileField
)
from flask_wtf.file import FileAllowed
from wtforms import TextAreaField, FileField, SubmitField
from wtforms.validators import DataRequired, Email, Length, URL, EqualTo, Optional

ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif']

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Login')

class OTPForm(FlaskForm):
    otp_code = StringField('OTP Code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify OTP')

class ScanForm(FlaskForm):
    url = StringField('URL', validators=[DataRequired(), URL()])

class ProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    picture = FileField('Profile Picture', validators=[
        FileAllowed(ALLOWED_EXTENSIONS, 'Images only!')
    ])
    submit = SubmitField('Update Profile')

class AddUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('admin','Admin'),('user','User')], validators=[DataRequired()])
    company_name = StringField('Company Name', validators=[Optional(), Length(max=255)])
    is_active = BooleanField('Active')  # <-- This
    profile_picture = FileField('Profile Picture', validators=[
        FileAllowed(ALLOWED_EXTENSIONS, 'Images only!')
    ])
    submit = SubmitField('Create User')
    

class AdminEditUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('New Password', validators=[Optional(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[Optional()])
    company_name = StringField('Company Name', validators=[Optional(), Length(max=255)])
    is_active = BooleanField('Active')
    submit = SubmitField('Save Changes')

class ScanForm(FlaskForm):
    url = StringField('Target URL', validators=[DataRequired(), URL()])

    
   
    intensity = SelectField(
        'Attack Strength',
        choices=[
            ('LOW', 'Low'),
            ('MEDIUM', 'Medium'),
            ('HIGH', 'High'),
            ('INSANE', 'Insane')
        ],
        default='MEDIUM'
    )

  
    threshold = SelectField(
        'Alert Threshold',
        choices=[
            ('OFF', 'Off'),
            ('LOW', 'Low'),
            ('MEDIUM', 'Medium'),
            ('HIGH', 'High')
        ],
        default='MEDIUM'
    )

    submit = SubmitField('Start Scan')
    

class DeepScanReplyForm(FlaskForm):
    admin_note = TextAreaField("Admin Note", validators=[DataRequired()])
    result_file = FileField("Result File", validators=[DataRequired(), FileAllowed(['pdf'], 'PDFs only!')])
    submit = SubmitField("Send Result")
