# app/forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from flask_wtf.file import FileField, FileAllowed
from wtforms.validators import DataRequired, Email, Length, URL
from config import ALLOWED_EXTENSIONS

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
    picture = FileField('Profile Picture', validators=[FileAllowed(ALLOWED_EXTENSIONS, 'Images only!')])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=150)])
    submit = SubmitField('Save')