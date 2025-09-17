import pyotp
import secrets

def generate_otp_secret():
    return pyotp.random_base32()

def generate_otp_code(secret):
    totp = pyotp.TOTP(secret, interval=300)  # code valid for 5 minutes
    return totp.now()

def verify_otp(secret, code):
    totp = pyotp.TOTP(secret, interval=300)
    return totp.verify(code)