from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import random
import os
import json
import struct
import hashlib
import base64
import subprocess
import time
from typing import Optional
from PIL import Image
import wave
from array import array
import threading
from concurrent.futures import ThreadPoolExecutor

# ===================== OPTIONAL DEPENDENCIES =====================
try:
    import cv2
    import numpy as np
    OPENCV = True
    NUMPY = True
except ImportError:
    OPENCV = False
    NUMPY = False
    print("⚠️  NumPy/OpenCV not available - falling back to standard mode")

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives import padding, hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("⚠️  Cryptography library not available - using basic encryption only")

# ===================== FLASK APP INITIALIZATION =====================
app = Flask(__name__)
CORS(app)

# ===================== CONFIGURATION =====================
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())

# Database Configuration
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'users.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Email Configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your_email@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your_app_password')
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']

# Steganography Folders
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'stego_temp')
DEFAULT_OUTPUT_FOLDER = os.path.join(os.getcwd(), 'stego_output')

for folder in [UPLOAD_FOLDER, DEFAULT_OUTPUT_FOLDER]:
    os.makedirs(folder, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DEFAULT_OUTPUT_FOLDER'] = DEFAULT_OUTPUT_FOLDER

# Initialize Extensions
db = SQLAlchemy(app)
mail = Mail(app)

# ===================== DATABASE MODELS =====================
class User(db.Model):
    """User authentication model"""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f'<User {self.username}>'

class OTPStore(db.Model):
    """OTP verification storage model"""
    __tablename__ = 'otp_store'
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(100), nullable=False, index=True)
    otp = db.Column(db.String(6), nullable=False)
    purpose = db.Column(db.String(20), nullable=False)
    temp_data = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, default=0)
    email = db.Column(db.String(120), nullable=True)

    def is_expired(self):
        return datetime.utcnow() > self.expires_at

    def increment_attempts(self):
        self.attempts += 1
        db.session.commit()

    def is_locked(self):
        return self.attempts >= 5

# ===================== DATABASE INITIALIZATION =====================
def init_database():
    """Initialize database with migrations"""
    import sqlite3
    db_exists = os.path.exists(DB_PATH)
    
    if db_exists:
        print("\n" + "="*70)
        print("⚠️  EXISTING DATABASE DETECTED - Running migrations...")
        print("="*70)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            # Check and add missing columns to users table
            cursor.execute("PRAGMA table_info(users)")
            columns = [col[1] for col in cursor.fetchall()]
            if 'is_active' not in columns:
                print("📝 Adding 'is_active' column to users table...")
                cursor.execute("ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT 1")
                conn.commit()
                print("✅ Column added!")
            
            # Check and add missing columns to otp_store table
            cursor.execute("PRAGMA table_info(otp_store)")
            columns = [col[1] for col in cursor.fetchall()]
            if 'attempts' not in columns:
                print("📝 Adding 'attempts' column to otp_store table...")
                cursor.execute("ALTER TABLE otp_store ADD COLUMN attempts INTEGER DEFAULT 0")
                conn.commit()
                print("✅ Column added!")
            if 'email' not in columns:
                print("📝 Adding 'email' column to otp_store table...")
                cursor.execute("ALTER TABLE otp_store ADD COLUMN email TEXT")
                conn.commit()
                print("✅ Column added!")
            
            print("="*70 + "\n")
        except Exception as e:
            print(f"❌ Migration error: {e}")
            conn.rollback()
        finally:
            conn.close()
    
    with app.app_context():
        db.create_all()
        if not db_exists:
            print(f"\n✅ DATABASE CREATED: {DB_PATH}\n")
        else:
            print("✅ Database ready!\n")

init_database()

# ===================== ENCRYPTION CLASSES =====================
class EncryptionMethod:
    """Base encryption method interface"""
    def encrypt(self, plaintext: str, key: str) -> bytes:
        raise NotImplementedError
    
    def decrypt(self, ciphertext: bytes, key: str) -> str:
        raise NotImplementedError

class UltraFastXOREncryption(EncryptionMethod):
    """Ultra-fast XOR encryption with NumPy optimization"""
    
    def _generate_key_stream_numpy(self, key: str, length: int) -> bytes:
        """Generate key stream for XOR operation"""
        if NUMPY:
            key_bytes = key.encode('utf-8', errors='replace') or b'default'
            key_array = np.frombuffer(key_bytes, dtype=np.uint8)
            repeats = (length + len(key_array) - 1) // len(key_array)
            key_stream = np.tile(key_array, repeats)[:length]
            return key_stream.tobytes()
        else:
            key_bytes = key.encode('utf-8', errors='replace') or b'default'
            key_stream = bytearray(length)
            key_len = len(key_bytes)
            for i in range(length):
                key_stream[i] = key_bytes[i % key_len]
            return bytes(key_stream)
    
    def encrypt(self, plaintext: str, key: str) -> bytes:
        """Encrypt plaintext using XOR cipher"""
        try:
            pt_bytes = plaintext.encode('utf-8', errors='replace')
            if NUMPY:
                pt_array = np.frombuffer(pt_bytes, dtype=np.uint8)
                ks_bytes = self._generate_key_stream_numpy(key, len(pt_bytes))
                ks_array = np.frombuffer(ks_bytes, dtype=np.uint8)
                result_array = pt_array ^ ks_array
                return result_array.tobytes()
            else:
                ks = self._generate_key_stream_numpy(key, len(pt_bytes))
                return bytes([pt_bytes[i] ^ ks[i] for i in range(len(pt_bytes))])
        except Exception as e:
            raise ValueError(f"XOR encryption failed: {e}")
    
    def decrypt(self, ciphertext: bytes, key: str) -> str:
        """Decrypt ciphertext using XOR cipher"""
        try:
            if NUMPY:
                ct_array = np.frombuffer(ciphertext, dtype=np.uint8)
                ks_bytes = self._generate_key_stream_numpy(key, len(ciphertext))
                ks_array = np.frombuffer(ks_bytes, dtype=np.uint8)
                result_array = ct_array ^ ks_array
                return result_array.tobytes().decode('utf-8', errors='replace')
            else:
                ks = self._generate_key_stream_numpy(key, len(ciphertext))
                pt_bytes = bytes([ciphertext[i] ^ ks[i] for i in range(len(ciphertext))])
                return pt_bytes.decode('utf-8', errors='replace')
        except Exception as e:
            raise ValueError(f"XOR decryption failed: {e}")

class UltraFastCaesarEncryption(EncryptionMethod):
    """Lightning-fast Caesar cipher using translation tables"""
    
    def _get_shift(self, key: str) -> int:
        """Calculate shift value from key"""
        return sum(ord(c) for c in key) % 26 if key else 13
    
    def encrypt(self, plaintext: str, key: str) -> bytes:
        """Encrypt plaintext using Caesar cipher"""
        try:
            shift = self._get_shift(key)
            upper_trans = bytes.maketrans(
                b'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
                bytes([(ord(c) - 65 + shift) % 26 + 65 for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'])
            )
            lower_trans = bytes.maketrans(
                b'abcdefghijklmnopqrstuvwxyz',
                bytes([(ord(c) - 97 + shift) % 26 + 97 for c in 'abcdefghijklmnopqrstuvwxyz'])
            )
            
            text_bytes = plaintext.encode('utf-8', errors='replace')
            result = text_bytes.translate(upper_trans).translate(lower_trans)
            return result
        except Exception as e:
            raise ValueError(f"Caesar encryption failed: {e}")
    
    def decrypt(self, ciphertext: bytes, key: str) -> str:
        """Decrypt ciphertext using Caesar cipher"""
        try:
            shift = self._get_shift(key)
            upper_trans = bytes.maketrans(
                b'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
                bytes([(ord(c) - 65 - shift) % 26 + 65 for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'])
            )
            lower_trans = bytes.maketrans(
                b'abcdefghijklmnopqrstuvwxyz',
                bytes([(ord(c) - 97 - shift) % 26 + 97 for c in 'abcdefghijklmnopqrstuvwxyz'])
            )
            
            result = ciphertext.translate(upper_trans).translate(lower_trans)
            return result.decode('utf-8', errors='replace')
        except Exception as e:
            raise ValueError(f"Caesar decryption failed: {e}")

class UltraFastBase64Encryption(EncryptionMethod):
    """Base64 encoding with XOR encryption"""
    
    def encrypt(self, plaintext: str, key: str) -> bytes:
        """Encrypt and encode to base64"""
        try:
            xor_bytes = UltraFastXOREncryption().encrypt(plaintext, key)
            return base64.b64encode(xor_bytes)
        except Exception as e:
            raise ValueError(f"Base64 encryption failed: {e}")
    
    def decrypt(self, ciphertext: bytes, key: str) -> str:
        """Decode from base64 and decrypt"""
        try:
            decoded = base64.b64decode(ciphertext)
            return UltraFastXOREncryption().decrypt(decoded, key)
        except Exception as e:
            raise ValueError(f"Base64 decryption failed: {e}")

# Advanced encryption classes (if cryptography library available)
if CRYPTO_AVAILABLE:
    class LightningAESEncryption(EncryptionMethod):
        """Lightning-fast AES-256 encryption with no KDF overhead"""
        
        def _normalize_key(self, key: str) -> bytes:
            """Normalize key to 256 bits using SHA-256"""
            return hashlib.sha256(key.encode('utf-8', errors='replace')).digest()
        
        def encrypt(self, plaintext: str, key: str) -> bytes:
            """Encrypt using AES-256-CBC"""
            try:
                key_bytes = self._normalize_key(key)
                iv = os.urandom(16)
                cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                padder = padding.PKCS7(128).padder()
                padded = padder.update(plaintext.encode('utf-8', errors='replace')) + padder.finalize()
                ct = encryptor.update(padded) + encryptor.finalize()
                return iv + ct
            except Exception as e:
                raise ValueError(f"AES encryption failed: {e}")
        
        def decrypt(self, ciphertext: bytes, key: str) -> str:
            """Decrypt using AES-256-CBC"""
            try:
                iv = ciphertext[:16]
                ct = ciphertext[16:]
                key_bytes = self._normalize_key(key)
                cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                padded_plain = decryptor.update(ct) + decryptor.finalize()
                unpadder = padding.PKCS7(128).unpadder()
                return (unpadder.update(padded_plain) + unpadder.finalize()).decode('utf-8', errors='replace')
            except Exception as e:
                raise ValueError(f"AES decryption failed: {e}")

    class LightningFernetEncryption(EncryptionMethod):
        """Ultra-fast Fernet encryption with reduced iterations"""
        
        def _derive_key(self, password: str) -> bytes:
            """Derive Fernet key with only 1000 iterations"""
            salt = hashlib.sha256(password.encode('utf-8', errors='replace')).digest()[:16]
            kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 1000, backend=default_backend())
            return base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8', errors='replace')))
        
        def encrypt(self, plaintext: str, key: str) -> bytes:
            """Encrypt using Fernet"""
            try:
                k = self._derive_key(key)
                return Fernet(k).encrypt(plaintext.encode('utf-8', errors='replace'))
            except Exception as e:
                raise ValueError(f"Fernet encryption failed: {e}")
        
        def decrypt(self, ciphertext: bytes, key: str) -> str:
            """Decrypt using Fernet"""
            try:
                k = self._derive_key(key)
                return Fernet(k).decrypt(ciphertext).decode('utf-8', errors='replace')
            except Exception as e:
                raise ValueError(f"Fernet decryption failed: {e}")

    class LightningChaCha20Encryption(EncryptionMethod):
        """Lightning ChaCha20 stream cipher"""
        
        def _normalize_key(self, key: str) -> bytes:
            """Normalize key to 256 bits"""
            return hashlib.sha256(key.encode('utf-8', errors='replace')).digest()
        
        def encrypt(self, plaintext: str, key: str) -> bytes:
            """Encrypt using ChaCha20"""
            try:
                key_bytes = self._normalize_key(key)
                nonce = os.urandom(16)
                cipher = Cipher(algorithms.ChaCha20(key_bytes, nonce), mode=None, backend=default_backend())
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(plaintext.encode('utf-8', errors='replace')) + encryptor.finalize()
                return nonce + ciphertext
            except Exception as e:
                raise ValueError(f"ChaCha20 encryption failed: {e}")
        
        def decrypt(self, ciphertext: bytes, key: str) -> str:
            """Decrypt using ChaCha20"""
            try:
                key_bytes = self._normalize_key(key)
                nonce = ciphertext[:16]
                ct = ciphertext[16:]
                cipher = Cipher(algorithms.ChaCha20(key_bytes, nonce), mode=None, backend=default_backend())
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(ct) + decryptor.finalize()
                return plaintext.decode('utf-8', errors='replace')
            except Exception as e:
                raise ValueError(f"ChaCha20 decryption failed: {e}")

    class LightningAESGCMEncryption(EncryptionMethod):
        """Ultra-fast AES-GCM with 5K iterations"""
        
        def _derive_key(self, password: str, salt: bytes) -> bytes:
            """Derive key with only 5000 iterations"""
            kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 5000, backend=default_backend())
            return kdf.derive(password.encode('utf-8', errors='replace'))
        
        def encrypt(self, plaintext: str, key: str) -> bytes:
            """Encrypt using AES-GCM"""
            try:
                salt = os.urandom(16)
                k = self._derive_key(key, salt)
                aesgcm = AESGCM(k)
                nonce = os.urandom(12)
                ct = aesgcm.encrypt(nonce, plaintext.encode('utf-8', errors='replace'), b'')
                return b"SG" + salt + nonce + ct
            except Exception as e:
                raise ValueError(f"AES-GCM encryption failed: {e}")
        
        def decrypt(self, ciphertext: bytes, key: str) -> str:
            """Decrypt using AES-GCM"""
            try:
                if not ciphertext.startswith(b"SG"):
                    raise ValueError("Invalid AESGCM payload")
                salt = ciphertext[2:18]
                nonce = ciphertext[18:30]
                ct = ciphertext[30:]
                k = self._derive_key(key, salt)
                aesgcm = AESGCM(k)
                pt = aesgcm.decrypt(nonce, ct, b'')
                return pt.decode('utf-8', errors='replace')
            except Exception as e:
                raise ValueError(f"AES-GCM decryption failed: {e}")

    class LightningChaCha20Poly1305Encryption(EncryptionMethod):
        """Lightning ChaCha20-Poly1305 AEAD cipher"""
        
        def _derive_key(self, password: str, salt: bytes) -> bytes:
            """Derive key with only 5000 iterations"""
            kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 5000, backend=default_backend())
            return kdf.derive(password.encode('utf-8', errors='replace'))
        
        def encrypt(self, plaintext: str, key: str) -> bytes:
            """Encrypt using ChaCha20-Poly1305"""
            try:
                salt = os.urandom(16)
                k = self._derive_key(key, salt)
                aead = ChaCha20Poly1305(k)
                nonce = os.urandom(12)
                ct = aead.encrypt(nonce, plaintext.encode('utf-8', errors='replace'), b'')
                return b"CP" + salt + nonce + ct
            except Exception as e:
                raise ValueError(f"ChaCha20-Poly1305 encryption failed: {e}")
        
        def decrypt(self, ciphertext: bytes, key: str) -> str:
            """Decrypt using ChaCha20-Poly1305"""
            try:
                if not ciphertext.startswith(b"CP"):
                    raise ValueError("Invalid ChaCha20-Poly1305 payload")
                salt = ciphertext[2:18]
                nonce = ciphertext[18:30]
                ct = ciphertext[30:]
                k = self._derive_key(key, salt)
                aead = ChaCha20Poly1305(k)
                pt = aead.decrypt(nonce, ct, b'')
                return pt.decode('utf-8', errors='replace')
            except Exception as e:
                raise ValueError(f"ChaCha20-Poly1305 decryption failed: {e}")

# ===================== ENCRYPTION REGISTRY =====================
ENCRYPTION_METHODS = {
    'xor': UltraFastXOREncryption(),
    'caesar': UltraFastCaesarEncryption(),
    'base64': UltraFastBase64Encryption(),
}

if CRYPTO_AVAILABLE:
    ENCRYPTION_METHODS.update({
        'aes': LightningAESEncryption(),
        'fernet': LightningFernetEncryption(),
        'chacha20': LightningChaCha20Encryption(),
        'aesgcm': LightningAESGCMEncryption(),
        'chacha20poly1305': LightningChaCha20Poly1305Encryption(),
    })

# ===================== AUTHENTICATION HELPER FUNCTIONS =====================
def generate_otp():
    """Generate 6-digit OTP"""
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp, username=None, purpose='verification'):
    """Send OTP via email with fallback to console"""
    try:
        mail_username = app.config.get('MAIL_USERNAME')
        mail_password = app.config.get('MAIL_PASSWORD')
        
        print(f"\n🔍 Email Config Check: {mail_username}")
        
        # Development mode - print to console
        if not mail_username or not mail_password or mail_username == 'your_email@gmail.com':
            print("\n" + "="*70)
            print("⚠️  DEVELOPMENT MODE - OTP DISPLAYED IN CONSOLE")
            print("="*70)
            print(f"   To: {email}")
            print(f"   OTP: {otp}")
            print(f"   User: {username or 'N/A'}")
            print(f"   Purpose: {purpose}")
            print("="*70 + "\n")
            return True
        
        # Production mode - send actual email
        title = "Welcome! Verify Your Email" if purpose == 'registration' else "Login Verification"
        message = "Complete your registration with this OTP:" if purpose == 'registration' else "Your OTP to login:"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; color: #333; background: #f5f5f5; }}
                .container {{ max-width: 600px; margin: 40px auto; background: white; 
                             border-radius: 15px; overflow: hidden; box-shadow: 0 5px 20px rgba(0,0,0,0.1); }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                           color: white; padding: 40px; text-align: center; }}
                .header h1 {{ margin: 0; font-size: 28px; }}
                .content {{ padding: 40px; }}
                .content p {{ line-height: 1.8; color: #555; }}
                .otp-box {{ background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); 
                           border: 3px dashed #667eea; padding: 30px; text-align: center; 
                           margin: 30px 0; border-radius: 12px; }}
                .otp-code {{ font-size: 36px; font-weight: bold; color: #667eea; 
                            letter-spacing: 8px; text-shadow: 2px 2px 4px rgba(0,0,0,0.1); }}
                .info {{ background: #e3f2fd; padding: 15px; border-radius: 8px; 
                         margin: 20px 0; border-left: 4px solid #2196f3; }}
                .warning {{ color: #e74c3c; margin-top: 20px; font-weight: bold; 
                           padding: 15px; background: #fee; border-radius: 8px; }}
                .footer {{ background: #f9f9f9; padding: 20px; text-align: center; 
                          color: #999; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 {title}</h1>
                </div>
                <div class="content">
                    <p><strong>Hello{' ' + username if username else ''},</strong></p>
                    <p>{message}</p>
                    <div class="otp-box">
                        <div class="otp-code">{otp}</div>
                    </div>
                    <div class="info">
                        <p><strong>⏰ This OTP expires in 5 minutes</strong></p>
                        <p>Please enter this code to complete your verification.</p>
                    </div>
                    <div class="warning">
                        <p>⚠️ SECURITY NOTICE</p>
                        <p>Never share this code with anyone. Our team will never ask for your OTP.</p>
                    </div>
                </div>
                <div class="footer">
                    <p>This is an automated message. Please do not reply.</p>
                    <p>© 2025 Secure Authentication System</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        msg = Message(
            subject=f"Your OTP Code - {purpose.title()}",
            recipients=[email],
            html=html_body
        )
        
        print(f"📧 Attempting to send email to {email}...")
        mail.send(msg)
        print(f"✅ EMAIL SENT SUCCESSFULLY to {email} - OTP: {otp}\n")
        return True
        
    except Exception as e:
        print(f"\n❌ EMAIL SENDING FAILED: {type(e).__name__} - {str(e)}")
        if 'authentication' in str(e).lower():
            print("💡 TIP: Generate a new App Password at: https://myaccount.google.com/apppasswords")
        print(f"\n🔐 FALLBACK MODE - OTP: {otp} for {email}\n")
        return True  # Return True to allow process to continue

def validate_phone(phone):
    """Validate phone number format"""
    if not phone:
        return False
    digits = ''.join(filter(str.isdigit, phone))
    return len(digits) >= 10

def validate_email(email):
    """Validate email format"""
    if not email or '@' not in email:
        return False
    parts = email.split('@')
    return len(parts) == 2 and '.' in parts[1]

def get_session_id():
    """Get or create session ID for OTP tracking"""
    if 'temp_session_id' not in session:
        session['temp_session_id'] = os.urandom(16).hex()
    return session['temp_session_id']

def cleanup_expired_otps():
    """Remove expired OTP records from database"""
    try:
        expired = OTPStore.query.filter(OTPStore.expires_at < datetime.utcnow()).all()
        if expired:
            for otp in expired:
                db.session.delete(otp)
            db.session.commit()
            print(f"🧹 Cleaned {len(expired)} expired OTP record(s)")
    except Exception as e:
        print(f"⚠️  Error cleaning OTPs: {e}")
        db.session.rollback()

# ===================== STEGANOGRAPHY HELPER FUNCTIONS =====================

# File extension definitions
IMG_EXT = {"png", "jpg", "jpeg", "bmp", "tif", "tiff", "webp"}
AUD_EXT = {"wav", "mp3", "flac", "aac", "m4a", "ogg", "opus"}
VID_EXT = {"mp4", "mkv", "avi", "mov", "webm", "m4v"}

# Steganography constants
MAGIC = b"STEG"
HEADER_LEN = 9

def list_encryption_methods():
    """List available encryption methods with descriptions"""
    descriptions = {
        'xor': 'Ultra-Fast XOR cipher with NumPy vectorization',
        'caesar': 'Lightning Caesar cipher with translation tables',
        'base64': 'Base64 encoding with ultra-fast XOR',
    }
    if CRYPTO_AVAILABLE:
        descriptions.update({
            'aes': 'Lightning AES-256 with no KDF overhead',
            'fernet': 'Ultra-Fast Fernet (1K iterations only)',
            'chacha20': 'Lightning ChaCha20 stream cipher',
            'aesgcm': 'Ultra-Fast AES-GCM (5K iterations only)',
            'chacha20poly1305': 'Lightning ChaCha20-Poly1305 (5K iterations only)',
        })
    return descriptions

def choose_random_encryption():
    """Choose random encryption method"""
    if CRYPTO_AVAILABLE:
        fast_methods = ['xor', 'caesar', 'aes', 'chacha20']
        strong_fast = ['aes', 'chacha20']
        if random.random() < 0.7:
            return random.choice(fast_methods)
        else:
            return random.choice(strong_fast)
    else:
        return random.choice(['xor', 'caesar', 'base64'])

def detect_mode(path):
    """Detect file type from extension"""
    try:
        ext = os.path.splitext(path)[1].lower().lstrip('.')
        if ext in IMG_EXT:
            return "image"
        elif ext in AUD_EXT:
            return "audio"
        elif ext in VID_EXT:
            return "video"
        else:
            raise ValueError("Unsupported file extension")
    except Exception as e:
        raise ValueError(f"Error detecting file type: {e}")

def safe_filename(filename):
    """Sanitize filename for safe storage"""
    import re
    try:
        if not filename:
            return f"stego_{int(time.time())}"
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
        filename = filename.strip(' .')
        if not filename:
            filename = f"stego_{int(time.time())}"
        return filename
    except Exception:
        return f"stego_{int(time.time())}"

def ensure_directory_exists(path):
    """Create directory if it doesn't exist"""
    try:
        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True)
        return True
    except Exception as e:
        print(f"Warning: Could not create directory {path}: {e}")
        return False

def parse_simple_path(user_input, original_filename="image"):
    """Parse user input path for custom save location"""
    try:
        if not user_input or user_input.strip() == "":
            return None, None
        
        user_input = user_input.strip()
        user_input = os.path.expandvars(user_input)
        user_input = os.path.expanduser(user_input)
        
        if os.path.sep in user_input or ('\\' in user_input and os.name == 'nt'):
            directory = os.path.dirname(user_input)
            filename = os.path.basename(user_input)
            
            if not filename:
                base_name = os.path.splitext(original_filename)[0]
                filename = f"{safe_filename(base_name)}_stego"
            elif not os.path.splitext(filename)[1]:
                filename = f"{safe_filename(filename)}_stego"
        else:
            directory = os.getcwd()
            if not os.path.splitext(user_input)[1]:
                filename = f"{safe_filename(user_input)}_stego"
            else:
                filename = safe_filename(user_input)
        
        return directory, filename
    except Exception:
        return None, None

def check_ffmpeg():
    """Check if FFmpeg is installed and accessible"""
    try:
        result = subprocess.run(
            ["ffmpeg", "-version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False

def _temp_path(name: str) -> str:
    """Generate temporary file path"""
    return os.path.join(os.getcwd(), f"__stego_tmp_{name}")

def to_lossless(in_path: str, mode: str) -> str:
    """Convert media file to lossless format using FFmpeg"""
    if not check_ffmpeg():
        if mode == "image" and in_path.lower().endswith('.png'):
            return in_path
        raise RuntimeError("FFmpeg not found. Install it and add to PATH.")
    
    try:
        if mode == "image":
            out = _temp_path("carrier.png")
            cmd = ["ffmpeg", "-y", "-i", in_path, "-frames:v", "1", out]
        elif mode == "audio":
            out = _temp_path("carrier.wav")
            cmd = ["ffmpeg", "-y", "-i", in_path, "-ar", "44100", "-ac", "2", "-c:a", "pcm_s16le", out]
        elif mode == "video":
            out = _temp_path("carrier.avi")
            cmd = ["ffmpeg", "-y", "-i", in_path, "-c:v", "ffv1", "-an", out]
        else:
            raise ValueError("Unknown mode")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise RuntimeError(f"FFmpeg failed: {result.stderr}")
        
        return out
    except subprocess.TimeoutExpired:
        raise RuntimeError("FFmpeg conversion timed out")
    except Exception as e:
        raise RuntimeError(f"FFmpeg conversion error: {e}")

def cleanup_temp_files():
    """Clean up temporary steganography files"""
    try:
        for file in os.listdir('.'):
            if file.startswith('__stego_tmp_'):
                try:
                    os.remove(file)
                except OSError:
                    pass
    except Exception:
        pass

def build_payload(data: bytes, method_name: str) -> bytes:
    """Build steganography payload with header"""
    try:
        method_idx = list(ENCRYPTION_METHODS.keys()).index(method_name)
        return MAGIC + struct.pack(">I", len(data)) + method_idx.to_bytes(1, 'big') + data
    except Exception as e:
        raise ValueError(f"Failed to build payload: {e}")

def lightning_bytes_to_bits_numpy(data):
    """Convert bytes to bits using NumPy or fallback"""
    try:
        if NUMPY:
            data_array = np.frombuffer(data, dtype=np.uint8)
            bits_array = np.unpackbits(data_array)
            return bits_array.tolist()
        else:
            bits = []
            for byte in data:
                bits.extend([
                    (byte >> 7) & 1,
                    (byte >> 6) & 1,
                    (byte >> 5) & 1,
                    (byte >> 4) & 1,
                    (byte >> 3) & 1,
                    (byte >> 2) & 1,
                    (byte >> 1) & 1,
                    byte & 1
                ])
            return bits
    except Exception as e:
        raise ValueError(f"Error converting bytes to bits: {e}")

def lightning_bits_to_bytes_numpy(bits):
    """Convert bits to bytes using NumPy or fallback"""
    try:
        if NUMPY:
            bits_array = np.array(bits, dtype=np.uint8)
            remainder = len(bits_array) % 8
            if remainder:
                bits_array = np.append(bits_array, np.zeros(8 - remainder, dtype=np.uint8))
            bits_reshaped = bits_array.reshape(-1, 8)
            bytes_array = np.packbits(bits_reshaped, axis=1).flatten()
            return bytes_array.tobytes()
        else:
            out = bytearray()
            for i in range(0, len(bits), 8):
                byte = 0
                chunk = bits[i:i+8]
                for j, bit in enumerate(chunk):
                    byte |= (bit << (7 - j))
                out.append(byte)
            return bytes(out)
    except Exception as e:
        raise ValueError(f"Error converting bits to bytes: {e}")

def lightning_parse_payload_from_bits(bits):
    """Parse steganography payload from bit stream"""
    try:
        if len(bits) < HEADER_LEN * 8:
            raise ValueError("Insufficient data for header")
        
        header_bits = bits[:HEADER_LEN*8]
        header_bytes = lightning_bits_to_bytes_numpy(header_bits)
        
        if header_bytes[:4] != MAGIC:
            raise ValueError("Invalid or missing MAGIC header")
        
        data_len = struct.unpack(">I", header_bytes[4:8])[0]
        method_idx = header_bytes[8]
        
        if method_idx >= len(ENCRYPTION_METHODS):
            raise ValueError("Invalid encryption method index")
        
        method_name = list(ENCRYPTION_METHODS.keys())[method_idx]
        
        if len(bits) < HEADER_LEN*8 + data_len*8:
            raise ValueError("Insufficient data for payload")
        
        data_bits = bits[HEADER_LEN*8:HEADER_LEN*8 + data_len*8]
        data_bytes = lightning_bits_to_bytes_numpy(data_bits)
        
        return data_bytes, method_name
    except Exception as e:
        raise ValueError(f"Failed to parse payload: {e}")

# ===================== IMAGE STEGANOGRAPHY =====================
def lightning_hide_in_image_numpy(cover_path, payload, out_path):
    """Hide payload in image using LSB technique"""
    try:
        img = Image.open(cover_path)
        if img.mode != "RGB":
            img = img.convert("RGB")
        
        w, h = img.size
        max_bits = w * h * 3
        bits = lightning_bytes_to_bits_numpy(payload)
        
        if len(bits) > max_bits:
            raise ValueError(f"Image too small: need {len(bits)} bits, max {max_bits}")
        
        if NUMPY:
            img_array = np.array(img, dtype=np.uint8)
            flat_img = img_array.flatten()
            
            bits_array = np.array(bits + [0] * (len(flat_img) - len(bits)), dtype=np.uint8)
            flat_img = (flat_img & 0xFE) | bits_array[:len(flat_img)]
            
            modified_img = flat_img.reshape(img_array.shape)
            result_img = Image.fromarray(modified_img, 'RGB')
            result_img.save(out_path, "PNG", optimize=True)
        else:
            pixels = list(img.getdata())
            modified_pixels = []
            
            bit_idx = 0
            for pixel in pixels:
                if bit_idx >= len(bits):
                    modified_pixels.append(pixel)
                    continue
                
                r, g, b = pixel
                
                if bit_idx < len(bits):
                    r = (r & 0xFE) | bits[bit_idx]
                    bit_idx += 1
                if bit_idx < len(bits):
                    g = (g & 0xFE) | bits[bit_idx]
                    bit_idx += 1
                if bit_idx < len(bits):
                    b = (b & 0xFE) | bits[bit_idx]
                    bit_idx += 1
                
                modified_pixels.append((r, g, b))
            
            new_img = Image.new("RGB", img.size)
            new_img.putdata(modified_pixels)
            new_img.save(out_path, "PNG", optimize=True)
        
    except Exception as e:
        raise RuntimeError(f"Failed to hide data in image: {e}")

def lightning_extract_from_image_numpy(stego_path):
    """Extract payload from image using LSB technique"""
    try:
        img = Image.open(stego_path)
        if img.mode != "RGB":
            img = img.convert("RGB")
        
        if NUMPY:
            img_array = np.array(img, dtype=np.uint8)
            flat_img = img_array.flatten()
            bits_array = flat_img & 1
            bits = bits_array.tolist()
        else:
            pixels = list(img.getdata())
            bits = []
            for pixel in pixels:
                r, g, b = pixel
                bits.extend([r & 1, g & 1, b & 1])
        
        return lightning_parse_payload_from_bits(bits)
    except Exception as e:
        raise RuntimeError(f"Failed to extract data from image: {e}")

# ===================== AUDIO STEGANOGRAPHY =====================
def lightning_hide_in_wav_numpy(cover_wav_path: str, payload: bytes, out_wav_path: str):
    """Hide payload in WAV audio using LSB technique"""
    try:
        with wave.open(cover_wav_path, 'rb') as wf:
            params = wf.getparams()
            if params.sampwidth != 2:
                raise ValueError("Only 16-bit PCM WAV supported")
            raw_data = wf.readframes(params.nframes)
        
        bits = lightning_bytes_to_bits_numpy(payload)
        
        if NUMPY:
            samples_array = np.frombuffer(raw_data, dtype=np.int16)
            
            if len(bits) > len(samples_array):
                raise ValueError(f"Audio too small. Need {len(bits)} bits, have {len(samples_array)} samples")
            
            bits_array = np.array(bits + [0] * (len(samples_array) - len(bits)), dtype=np.uint16)
            samples_array = (samples_array & 0xFFFE) | bits_array[:len(samples_array)]
            modified_data = samples_array.astype(np.int16).tobytes()
        else:
            samples = array('h')
            samples.frombytes(raw_data)
            
            if len(bits) > len(samples):
                raise ValueError(f"Audio too small. Need {len(bits)} bits, have {len(samples)} samples")
            
            for i in range(len(bits)):
                samples[i] = (samples[i] & 0xFFFE) | bits[i]
            
            modified_data = samples.tobytes()
        
        with wave.open(out_wav_path, 'wb') as out_wf:
            out_wf.setparams(params)
            out_wf.writeframes(modified_data)
    except Exception as e:
        raise RuntimeError(f"Failed to hide data in audio: {e}")

def lightning_extract_from_wav_numpy(stego_wav_path: str):
    """Extract payload from WAV audio using LSB technique"""
    try:
        with wave.open(stego_wav_path, 'rb') as wf:
            params = wf.getparams()
            if params.sampwidth != 2:
                raise ValueError("Only 16-bit PCM WAV supported")
            raw_data = wf.readframes(params.nframes)
        
        if NUMPY:
            samples_array = np.frombuffer(raw_data, dtype=np.int16)
            bits_array = samples_array & 1
            bits = bits_array.tolist()
        else:
            samples = array('h')
            samples.frombytes(raw_data)
            bits = [sample & 1 for sample in samples]
        
        return lightning_parse_payload_from_bits(bits)
    except Exception as e:
        raise RuntimeError(f"Failed to extract data from audio: {e}")

# ===================== VIDEO STEGANOGRAPHY =====================
def lightning_hide_in_video_numpy(cover_avi_path: str, payload: bytes, out_avi_path: str):
    """Hide payload in video using LSB technique"""
    if not OPENCV:
        raise ImportError("Install OpenCV (pip install opencv-python) for video support")
    
    try:
        cap = cv2.VideoCapture(cover_avi_path)
        if not cap.isOpened():
            raise ValueError("Cannot open video file")
        
        fps = int(cap.get(cv2.CAP_PROP_FPS) or 25)
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        
        bits = lightning_bytes_to_bits_numpy(payload)
        max_bits = frame_count * width * height * 3
        
        if len(bits) > max_bits:
            raise ValueError(f"Video too small. Need {len(bits)} bits, have {max_bits}")
        
        fourcc = cv2.VideoWriter_fourcc(*"FFV1")
        out = cv2.VideoWriter(out_avi_path, fourcc, fps, (width, height))
        
        if not out.isOpened():
            fourcc = cv2.VideoWriter_fourcc(*"MJPG")
            out = cv2.VideoWriter(out_avi_path, fourcc, fps, (width, height))
        
        bit_idx = 0
        bits_array = np.array(bits + [0] * max_bits, dtype=np.uint8)
        
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            
            if bit_idx < len(bits) and NUMPY:
                flat_frame = frame.flatten()
                frame_size = len(flat_frame)
                
                frame_bits = bits_array[bit_idx:bit_idx + frame_size]
                flat_frame = (flat_frame & 0xFE) | frame_bits[:len(flat_frame)]
                
                frame = flat_frame.reshape(frame.shape)
                bit_idx += frame_size
            elif bit_idx < len(bits):
                flat_frame = frame.flatten()
                for i in range(min(len(flat_frame), len(bits) - bit_idx)):
                    flat_frame[i] = (flat_frame[i] & 0xFE) | bits[bit_idx + i]
                frame = flat_frame.reshape(frame.shape)
                bit_idx += len(flat_frame)
            
            out.write(frame)
        
        cap.release()
        out.release()
        
    except Exception as e:
        raise RuntimeError(f"Failed to hide data in video: {e}")

def lightning_extract_from_video_numpy(stego_avi_path: str):
    """Extract payload from video using LSB technique"""
    if not OPENCV:
        raise ImportError("Install OpenCV (pip install opencv-python) for video support")
    
    try:
        cap = cv2.VideoCapture(stego_avi_path)
        if not cap.isOpened():
            raise ValueError("Cannot open video file")
        
        bits = []
        
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            
            if NUMPY:
                flat_frame = frame.flatten()
                frame_bits = (flat_frame & 1).tolist()
                bits.extend(frame_bits)
            else:
                flat_frame = frame.flatten()
                frame_bits = [pixel & 1 for pixel in flat_frame]
                bits.extend(frame_bits)
        
        cap.release()
        return lightning_parse_payload_from_bits(bits)
        
    except Exception as e:
        raise RuntimeError(f"Failed to extract data from video: {e}")

# ===================== MAIN STEGANOGRAPHY FUNCTIONS =====================
def lightning_encrypt_and_hide(carrier_path, secret_key, message, encryption_method='xor', out_path=None):
    """Main function to encrypt message and hide in carrier file"""
    try:
        if encryption_method not in ENCRYPTION_METHODS:
            encryption_method = 'xor'
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            encrypt_future = executor.submit(
                ENCRYPTION_METHODS[encryption_method].encrypt, message, secret_key
            )
            
            mode_future = executor.submit(detect_mode, carrier_path)
            
            mode = mode_future.result()
            encrypted_data = encrypt_future.result()
            payload = build_payload(encrypted_data, encryption_method)
            
            lossless_path = carrier_path
            temp_file = None
            
            try:
                if mode == "image" and not carrier_path.lower().endswith('.png'):
                    lossless_path = to_lossless(carrier_path, mode)
                    temp_file = lossless_path
                elif mode in ["audio", "video"]:
                    lossless_path = to_lossless(carrier_path, mode)
                    temp_file = lossless_path
                
                if out_path is None:
                    base, ext = os.path.splitext(carrier_path)
                    if mode == "image":
                        out_path = base + "_stego.png"
                    elif mode == "audio":
                        out_path = base + "_stego.wav"
                    elif mode == "video":
                        out_path = base + "_stego.avi"
                
                if mode == "image":
                    lightning_hide_in_image_numpy(lossless_path, payload, out_path)
                elif mode == "audio":
                    lightning_hide_in_wav_numpy(lossless_path, payload, out_path)
                elif mode == "video":
                    lightning_hide_in_video_numpy(lossless_path, payload, out_path)
                else:
                    raise ValueError("Unsupported file type")
                
            finally:
                if temp_file and os.path.exists(temp_file):
                    try:
                        os.remove(temp_file)
                    except OSError:
                        pass
        
        return out_path
        
    except Exception as e:
        raise RuntimeError(f"Lightning encryption and hiding failed: {e}")

def lightning_extract_and_decrypt(stego_path, secret_key):
    """Main function to extract and decrypt hidden message"""
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            mode_future = executor.submit(detect_mode, stego_path)
            mode = mode_future.result()
            
            if mode == "image":
                extract_future = executor.submit(lightning_extract_from_image_numpy, stego_path)
            elif mode == "audio":
                extract_future = executor.submit(lightning_extract_from_wav_numpy, stego_path)
            elif mode == "video":
                extract_future = executor.submit(lightning_extract_from_video_numpy, stego_path)
            else:
                raise ValueError("Unsupported file type")
            
            encrypted_data, method_name = extract_future.result()
            
            if method_name not in ENCRYPTION_METHODS:
                raise ValueError(f"Unknown encryption method used: {method_name}")
            
            decrypt_future = executor.submit(
                ENCRYPTION_METHODS[method_name].decrypt, encrypted_data, secret_key
            )
            message = decrypt_future.result()
        
        return message, method_name
        
    except Exception as e:
        raise RuntimeError(f"Lightning extraction and decryption failed: {e}")

# ===================== WEB ROUTES - AUTHENTICATION =====================
@app.route('/')
def home():
    """Home page route"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/register')
def register_page():
    """Registration page route"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/login')
def login_page():
    """Login page route"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    """User dashboard route"""
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login_page'))
    return render_template('dashboard.html', user=user)

@app.route('/stego')
def stego_page():
    """Steganography tool page route"""
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('stego.html')

@app.route('/logout')
def logout():
    """Logout route"""
    session.clear()
    return redirect(url_for('home'))

# ===================== API ROUTES - REGISTRATION =====================
@app.route('/api/send-registration-otp', methods=['POST'])
def send_registration_otp():
    """Send OTP for registration"""
    try:
        cleanup_expired_otps()
        data = request.json or request.form.to_dict()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400

        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        phone = data.get('phone', '').strip()
        password = data.get('password', '')
        dob = data.get('dob', '')

        # Validation
        if not all([username, email, phone, password, dob]):
            return jsonify({'success': False, 'message': 'All fields required'}), 400
        if len(username) < 3 or len(username) > 50:
            return jsonify({'success': False, 'message': 'Username must be 3-50 characters'}), 400
        if not validate_email(email):
            return jsonify({'success': False, 'message': 'Invalid email format'}), 400
        if not validate_phone(phone):
            return jsonify({'success': False, 'message': 'Invalid phone number'}), 400
        if len(password) < 6 or len(password) > 100:
            return jsonify({'success': False, 'message': 'Password must be 6-100 characters'}), 400

        try:
            dob_date = datetime.strptime(dob, '%Y-%m-%d').date()
            age = (datetime.now().date() - dob_date).days // 365
            if age < 13 or age > 120:
                return jsonify({'success': False, 'message': 'Invalid age'}), 400
        except ValueError:
            return jsonify({'success': False, 'message': 'Invalid date format'}), 400

        # Check for existing users
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already taken'}), 400
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already registered'}), 400
        if User.query.filter_by(phone=phone).first():
            return jsonify({'success': False, 'message': 'Phone already registered'}), 400

        # Generate and store OTP
        otp = generate_otp()
        session_id = get_session_id()
        
        temp_data = json.dumps({
            'username': username,
            'email': email,
            'phone': phone,
            'password': password,
            'dob': dob
        })

        old_otp = OTPStore.query.filter_by(session_id=session_id, purpose='registration').first()
        if old_otp:
            db.session.delete(old_otp)

        otp_record = OTPStore(
            session_id=session_id,
            otp=otp,
            purpose='registration',
            temp_data=temp_data,
            email=email,
            expires_at=datetime.utcnow() + timedelta(minutes=5),
            attempts=0
        )
        db.session.add(otp_record)
        db.session.commit()

        send_otp_email(email, otp, username, 'registration')
        print(f"📤 Registration OTP: {otp} → {email}")
        
        return jsonify({
            'success': True,
            'message': f'OTP sent to {email}. Check your inbox or console!'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Failed to send OTP'}), 500

@app.route('/api/verify-registration-otp', methods=['POST'])
def verify_registration_otp():
    """Verify OTP and complete registration"""
    try:
        data = request.json or request.form.to_dict()
        otp = data.get('otp', '').strip()
        session_id = get_session_id()

        if not otp or len(otp) != 6 or not otp.isdigit():
            return jsonify({'success': False, 'message': 'Invalid OTP format'}), 400

        otp_record = OTPStore.query.filter_by(session_id=session_id, purpose='registration').first()
        if not otp_record:
            return jsonify({'success': False, 'message': 'OTP not found'}), 400
        if otp_record.is_expired():
            db.session.delete(otp_record)
            db.session.commit()
            return jsonify({'success': False, 'message': 'OTP expired'}), 400
        if otp_record.is_locked():
            db.session.delete(otp_record)
            db.session.commit()
            return jsonify({'success': False, 'message': 'Too many attempts'}), 400

        if otp_record.otp != otp:
            otp_record.increment_attempts()
            remaining = 5 - otp_record.attempts
            if remaining <= 0:
                db.session.delete(otp_record)
                db.session.commit()
                return jsonify({'success': False, 'message': 'Too many attempts'}), 400
            return jsonify({'success': False, 'message': f'Invalid OTP. {remaining} attempts left'}), 400

        # Create user account
        user_data = json.loads(otp_record.temp_data)
        password_hash = generate_password_hash(user_data['password'], method='pbkdf2:sha256')
        dob_date = datetime.strptime(user_data['dob'], '%Y-%m-%d').date()

        new_user = User(
            username=user_data['username'],
            email=user_data['email'],
            phone=user_data['phone'],
            password_hash=password_hash,
            dob=dob_date,
            is_active=True
        )
        
        db.session.add(new_user)
        db.session.delete(otp_record)
        db.session.commit()

        session['user_id'] = new_user.id
        session['username'] = new_user.username
        session.permanent = True
        session.pop('temp_session_id', None)

        print(f"✅ User registered: {new_user.username}")
        return jsonify({
            'success': True,
            'message': f'Welcome {new_user.username}!',
            'redirectUrl': '/dashboard'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error: {e}")
        return jsonify({'success': False, 'message': 'Verification failed'}), 500

# ===================== API ROUTES - LOGIN =====================
@app.route('/api/send-login-otp', methods=['POST'])
def send_login_otp():
    """Send OTP for login"""
    try:
        cleanup_expired_otps()
        data = request.json or request.form.to_dict()
        
        username = data.get('username', '').strip()
        password = data.get('password', '')

        if not username or not password:
            return jsonify({'success': False, 'message': 'Username and password required'}), 400
        if len(username) < 3:
            return jsonify({'success': False, 'message': 'Invalid username'}), 400

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        if not user.is_active:
            return jsonify({'success': False, 'message': 'Account deactivated'}), 403

        otp = generate_otp()
        session_id = get_session_id()
        session['pending_user_id'] = user.id

        old_otp = OTPStore.query.filter_by(session_id=session_id, purpose='login').first()
        if old_otp:
            db.session.delete(old_otp)

        otp_record = OTPStore(
            session_id=session_id,
            otp=otp,
            purpose='login',
            temp_data=str(user.id),
            email=user.email,
            expires_at=datetime.utcnow() + timedelta(minutes=5),
            attempts=0
        )
        db.session.add(otp_record)
        db.session.commit()

        send_otp_email(user.email, otp, user.username, 'login')
        
        email_parts = user.email.split('@')
        masked = f"{email_parts[0][:2]}***@{email_parts[1]}"
        print(f"📤 Login OTP: {otp} → {user.email}")
        
        return jsonify({
            'success': True,
            'message': f'OTP sent to {masked}'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error: {e}")
        return jsonify({'success': False, 'message': 'Failed to send OTP'}), 500

@app.route('/api/verify-login-otp', methods=['POST'])
def verify_login_otp():
    """Verify OTP and complete login"""
    try:
        data = request.json or request.form.to_dict()
        otp = data.get('otp', '').strip()
        session_id = get_session_id()

        if not otp or len(otp) != 6 or not otp.isdigit():
            return jsonify({'success': False, 'message': 'Invalid OTP format'}), 400

        otp_record = OTPStore.query.filter_by(session_id=session_id, purpose='login').first()
        if not otp_record:
            return jsonify({'success': False, 'message': 'OTP not found'}), 400
        if otp_record.is_expired():
            db.session.delete(otp_record)
            db.session.commit()
            return jsonify({'success': False, 'message': 'OTP expired'}), 400
        if otp_record.is_locked():
            db.session.delete(otp_record)
            db.session.commit()
            return jsonify({'success': False, 'message': 'Too many attempts'}), 400

        if otp_record.otp != otp:
            otp_record.increment_attempts()
            remaining = 5 - otp_record.attempts
            if remaining <= 0:
                db.session.delete(otp_record)
                db.session.commit()
                return jsonify({'success': False, 'message': 'Too many attempts'}), 400
            return jsonify({'success': False, 'message': f'Invalid OTP. {remaining} attempts left'}), 400

        user_id = int(otp_record.temp_data)
        user = User.query.get(user_id)
        if not user or not user.is_active:
            db.session.delete(otp_record)
            db.session.commit()
            return jsonify({'success': False, 'message': 'User not found'}), 404

        session['user_id'] = user.id
        session['username'] = user.username
        session.permanent = True
        session.pop('temp_session_id', None)
        session.pop('pending_user_id', None)

        db.session.delete(otp_record)
        db.session.commit()

        print(f"✅ Login: {user.username}")
        return jsonify({
            'success': True,
            'message': f'Welcome back {user.username}!',
            'redirectUrl': '/dashboard'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error: {e}")
        return jsonify({'success': False, 'message': 'Verification failed'}), 500

# ===================== API ROUTES - OTP RESEND =====================
@app.route('/api/resend-otp', methods=['POST'])
def resend_otp():
    """Resend OTP for registration or login"""
    try:
        data = request.json or request.form.to_dict()
        purpose = data.get('purpose', 'login')
        session_id = get_session_id()

        if purpose not in ['registration', 'login']:
            return jsonify({'success': False, 'message': 'Invalid purpose'}), 400

        otp_record = OTPStore.query.filter_by(session_id=session_id, purpose=purpose).first()
        if not otp_record:
            return jsonify({'success': False, 'message': 'No pending verification'}), 400

        time_since = (datetime.utcnow() - otp_record.created_at).total_seconds()
        if time_since < 30:
            wait = int(30 - time_since)
            return jsonify({'success': False, 'message': f'Wait {wait} seconds'}), 429

        new_otp = generate_otp()
        otp_record.otp = new_otp
        otp_record.expires_at = datetime.utcnow() + timedelta(minutes=5)
        otp_record.attempts = 0
        otp_record.created_at = datetime.utcnow()
        db.session.commit()

        email = username = None
        if purpose == 'registration':
            user_data = json.loads(otp_record.temp_data)
            email = user_data.get('email')
            username = user_data.get('username')
        else:
            user = User.query.get(int(otp_record.temp_data))
            if user:
                email = user.email
                username = user.username

        if not email:
            return jsonify({'success': False, 'message': 'Email not found'}), 400

        send_otp_email(email, new_otp, username, purpose)
        print(f"🔄 Resent OTP: {new_otp} → {email}")
        
        return jsonify({'success': True, 'message': 'New OTP sent'}), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error: {e}")
        return jsonify({'success': False, 'message': 'Failed to resend OTP'}), 500

# ===================== API ROUTES - STEGANOGRAPHY =====================
@app.route('/api/stego/process', methods=['POST'])
def process_stego():
    """Process steganography hide/extract operations"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
        action = request.form.get('action')
        start_time = time.time()
        
        if action == 'hide':
            carrier = request.files.get('carrier_file')
            secret_key = request.form.get('secret_key')
            message = request.form.get('message')
            enc_method = request.form.get('encryption_method', 'xor')
            save_mode = request.form.get('save_mode', 'auto')
            file_path = request.form.get('file_path', '').strip()

            if not carrier or not secret_key or not message:
                return jsonify({'success': False, 'error': 'All fields required'}), 400

            timestamp = str(int(time.time()))
            filename = carrier.filename
            safe_temp_filename = f"{timestamp}_{filename}"
            temp_save_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_temp_filename)
            carrier.save(temp_save_path)

            try:
                media_type = detect_mode(temp_save_path)
                
                if not enc_method:
                    enc_method = choose_random_encryption()

                if enc_method not in list_encryption_methods():
                    return jsonify({'success': False, 'error': f'Invalid encryption method: {enc_method}'}), 400

                # Determine output path
                if save_mode == 'auto':
                    base, ext = os.path.splitext(filename)
                    if media_type == "image":
                        out_filename = f"{timestamp}_{safe_filename(base)}_stego.png"
                    elif media_type == "audio":
                        out_filename = f"{timestamp}_{safe_filename(base)}_stego.wav"
                    elif media_type == "video":
                        out_filename = f"{timestamp}_{safe_filename(base)}_stego.avi"
                    out_directory = app.config['DEFAULT_OUTPUT_FOLDER']
                    out_path = os.path.join(out_directory, out_filename)
                    is_custom = False
                    
                elif save_mode == 'custom' and file_path:
                    parsed_directory, parsed_filename = parse_simple_path(file_path, filename)
                    
                    if parsed_directory and parsed_filename:
                        out_directory = parsed_directory
                        base_name = os.path.splitext(parsed_filename)[0]
                        if media_type == "image":
                            out_filename = f"{base_name}.png"
                        elif media_type == "audio":
                            out_filename = f"{base_name}.wav"
                        elif media_type == "video":
                            out_filename = f"{base_name}.avi"
                        out_path = os.path.join(out_directory, out_filename)
                        is_custom = True
                    else:
                        base, ext = os.path.splitext(filename)
                        if media_type == "image":
                            out_filename = f"{timestamp}_{safe_filename(base)}_stego.png"
                        elif media_type == "audio":
                            out_filename = f"{timestamp}_{safe_filename(base)}_stego.wav"
                        elif media_type == "video":
                            out_filename = f"{timestamp}_{safe_filename(base)}_stego.avi"
                        out_directory = app.config['DEFAULT_OUTPUT_FOLDER']
                        out_path = os.path.join(out_directory, out_filename)
                        is_custom = False
                else:
                    base, ext = os.path.splitext(filename)
                    if media_type == "image":
                        out_filename = f"{timestamp}_{safe_filename(base)}_stego.png"
                    elif media_type == "audio":
                        out_filename = f"{timestamp}_{safe_filename(base)}_stego.wav"
                    elif media_type == "video":
                        out_filename = f"{timestamp}_{safe_filename(base)}_stego.avi"
                    out_directory = app.config['DEFAULT_OUTPUT_FOLDER']
                    out_path = os.path.join(out_directory, out_filename)
                    is_custom = False

                ensure_directory_exists(out_directory)

                # Check FFmpeg requirement
                ffmpeg_used = False
                if media_type in ["audio", "video"] or (media_type == "image" and not temp_save_path.lower().endswith('.png')):
                    if not check_ffmpeg():
                        return jsonify({'success': False, 'error': 'FFmpeg required but not installed'}), 500
                    ffmpeg_used = True

                # Perform steganography
                try:
                    lightning_encrypt_and_hide(temp_save_path, secret_key, message, enc_method, out_path)
                except Exception as stego_error:
                    return jsonify({'success': False, 'error': f'Steganography failed: {str(stego_error)}'}), 500
                
                file_size = os.path.getsize(out_path)
                processing_time = f"{time.time() - start_time:.3f}s"
                
                return jsonify({
                    'success': True,
                    'method': enc_method,
                    'media_type': media_type,
                    'filename': out_filename,
                    'directory': out_directory,
                    'full_path': out_path,
                    'file_size': file_size,
                    'processing_time': processing_time,
                    'save_mode': save_mode.replace('_', ' ').title(),
                    'is_custom': is_custom,
                    'ffmpeg_used': ffmpeg_used,
                    'lightning': True
                }), 200

            except Exception as e:
                return jsonify({'success': False, 'error': str(e)}), 500
            finally:
                if os.path.exists(temp_save_path):
                    try:
                        os.remove(temp_save_path)
                    except OSError:
                        pass
                cleanup_temp_files()

        elif action == 'extract':
            stego = request.files.get('stego_file')
            secret_key = request.form.get('secret_key')

            if not stego or not secret_key:
                return jsonify({'success': False, 'error': 'All fields required'}), 400

            timestamp = str(int(time.time()))
            filename = stego.filename
            safe_temp_filename = f"{timestamp}_{filename}"
            temp_stego_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_temp_filename)
            stego.save(temp_stego_path)

            try:
                media_type = detect_mode(temp_stego_path)
                
                if media_type in ["audio", "video"] and not check_ffmpeg():
                    return jsonify({'success': False, 'error': 'FFmpeg required but not installed'}), 500
                
                message, method_used = lightning_extract_and_decrypt(temp_stego_path, secret_key)
                processing_time = f"{time.time() - start_time:.3f}s"
                
                return jsonify({
                    'success': True,
                    'message': message,
                    'method': method_used,
                    'media_type': media_type,
                    'processing_time': processing_time,
                    'lightning': True
                }), 200

            except Exception as e:
                return jsonify({'success': False, 'error': str(e)}), 500
            finally:
                if os.path.exists(temp_stego_path):
                    try:
                        os.remove(temp_stego_path)
                    except OSError:
                        pass
                cleanup_temp_files()

        else:
            return jsonify({'success': False, 'error': 'Invalid action'}), 400

    except Exception as e:
        cleanup_temp_files()
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'}), 500

@app.route('/api/stego/methods')
def get_stego_methods():
    """Get available steganography encryption methods"""
    return jsonify({
        'methods': list_encryption_methods(),
        'crypto_available': CRYPTO_AVAILABLE,
        'numpy_available': NUMPY,
        'opencv_available': OPENCV,
        'ffmpeg_available': check_ffmpeg(),
        'upload_folder': app.config['UPLOAD_FOLDER'],
        'default_output_folder': app.config['DEFAULT_OUTPUT_FOLDER'],
        'supported_formats': {
            'image': list(IMG_EXT),
            'audio': list(AUD_EXT),
            'video': list(VID_EXT)
        },
        'lightning_optimizations': [
            'NumPy vectorized operations',
            'Ultra-reduced PBKDF2 iterations (1K-5K vs 100K-200K)',
            'Multi-core processing with ThreadPoolExecutor',
            'Vectorized LSB operations',
            'Translation table Caesar cipher',
            'No-KDF AES encryption'
        ]
    })

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': 'combined-lightning-optimized',
        'authentication': 'enabled',
        'steganography': 'enabled',
        'encryption_methods': len(ENCRYPTION_METHODS),
        'crypto_support': CRYPTO_AVAILABLE,
        'numpy_support': NUMPY,
        'opencv_support': OPENCV,
        'ffmpeg_support': check_ffmpeg(),
        'database': os.path.exists(DB_PATH),
        'upload_folder_exists': os.path.exists(app.config['UPLOAD_FOLDER']),
        'output_folder_exists': os.path.exists(app.config['DEFAULT_OUTPUT_FOLDER']),
        'supported_formats': {
            'images': len(IMG_EXT),
            'audio': len(AUD_EXT),
            'video': len(VID_EXT)
        }
    })

# ===================== ERROR HANDLERS =====================
@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    return redirect(url_for('home'))

@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors"""
    db.session.rollback()
    return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.errorhandler(413)
def request_entity_too_large(e):
    """Handle file too large errors"""
    return jsonify({'success': False, 'error': 'File too large'}), 413

# ===================== APPLICATION ENTRY POINT =====================
if __name__ == '__main__':
    print("\n" + "="*80)
    print("🚀 COMBINED FLASK APPLICATION - Authentication + Steganography")
    print("="*80)
    print("\n📍 Available Routes:")
    print("   http://127.0.0.1:5000/              - Home Page")
    print("   http://127.0.0.1:5000/register      - User Registration")
    print("   http://127.0.0.1:5000/login         - User Login")
    print("   http://127.0.0.1:5000/dashboard     - User Dashboard (requires auth)")
    print("   http://127.0.0.1:5000/stego         - Steganography Tool (requires auth)")
    print("   http://127.0.0.1:5000/logout        - Logout")
    print("\n📡 API Endpoints:")
    print("   POST /api/send-registration-otp     - Send registration OTP")
    print("   POST /api/verify-registration-otp   - Verify registration")
    print("   POST /api/send-login-otp            - Send login OTP")
    print("   POST /api/verify-login-otp          - Verify login")
    print("   POST /api/resend-otp                - Resend OTP")
    print("   POST /api/stego/process             - Process steganography")
    print("   GET  /api/stego/methods             - Get encryption methods")
    print("   GET  /api/health                    - Health check")
    print("\n" + "="*80)
    print("📊 System Status:")
    print(f"   📁 Database: {DB_PATH}")
    print(f"   📧 Email: {app.config.get('MAIL_USERNAME')}")
    print(f"   🔐 Encryption Methods: {list(ENCRYPTION_METHODS.keys())}")
    print(f"   ⚡ NumPy Acceleration: {'✅ Enabled' if NUMPY else '❌ Disabled'}")
    print(f"   🎬 OpenCV Support: {'✅ Enabled' if OPENCV else '❌ Disabled'}")
    print(f"   🎥 FFmpeg Support: {'✅ Enabled' if check_ffmpeg() else '❌ Disabled'}")
    print(f"   🔒 Cryptography Lib: {'✅ Enabled' if CRYPTO_AVAILABLE else '❌ Disabled'}")
    print(f"   📂 Upload Folder: {app.config['UPLOAD_FOLDER']}")
    print(f"   📂 Output Folder: {app.config['DEFAULT_OUTPUT_FOLDER']}")
    print("="*80)
    print("\n💡 Features:")
    print("   ✓ OTP-based authentication (registration + login)")
    print("   ✓ Multi-media steganography (image, audio, video)")
    print("   ✓ Multiple encryption algorithms")
    print("   ✓ Lightning-fast processing with NumPy")
    print("   ✓ Session management")
    print("   ✓ Secure password hashing")
    print("   ✓ Email OTP delivery with console fallback")
    print("\n⚠️  Important Notes:")
    print("   • OTPs are displayed in console (development mode)")
    print("   • Configure MAIL_USERNAME and MAIL_PASSWORD for production")
    print("   • Install FFmpeg for audio/video steganography")
    print("   • Install NumPy for optimal performance")
    print("="*80)
    print("\n🎯 Getting Started:")
    print("   1. Register a new account at /register")
    print("   2. Enter OTP from console")
    print("   3. Login at /login")
    print("   4. Access steganography tool at /stego")
    print("="*80 + "\n")
    
    # Check for warnings
    warnings = []
    if not NUMPY:
        warnings.append("NumPy not installed - performance will be reduced")
    if not OPENCV:
        warnings.append("OpenCV not installed - video steganography unavailable")
    if not check_ffmpeg():
        warnings.append("FFmpeg not installed - audio/video processing unavailable")
    if app.config.get('MAIL_USERNAME') == 'your_email@gmail.com':
        warnings.append("Email not configured - using console OTP mode")
    
    if warnings:
        print("⚠️  WARNINGS:")
        for warning in warnings:
            print(f"   • {warning}")
        print()
    
    print("🚀 Starting server...\n")
    
    # Run the application
    app.run(debug=True, host='127.0.0.1', port=5000)