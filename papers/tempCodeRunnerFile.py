from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_cors import CORS
import os
import struct
import random
import hashlib
import base64
import subprocess
import time
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
import datetime
from typing import Optional
from PIL import Image
import wave
from array import array
import threading
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import multiprocessing

# Optional video support with NumPy optimization
try:
    import cv2
    import numpy as np
    OPENCV = True
    NUMPY = True
except ImportError:
    OPENCV = False
    NUMPY = False

# Cryptography support
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
    print("Warning: cryptography library not installed. Only basic XOR encryption available.")

# ===================== EMAIL CONFIGURATION =====================

# Email configuration (Update these with your SMTP settings)
EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': 'kulasekharvelamala@gmail.com',
    'sender_password': 'pjnekjvvorzkophv',
    'use_tls': True
}

# ===================== EMAIL-BASED KEY DERIVATION =====================

def derive_master_key_from_email(receiver_email: str) -> bytes:
    """Derives a master key from receiver's email (first 4 chars) + current year"""
    try:
        email_prefix = receiver_email.strip()[:4].lower()
        current_year = str(datetime.datetime.now().year)
        key_material = f"{email_prefix}{current_year}"
        
        if CRYPTO_AVAILABLE:
            salt = hashlib.sha256(key_material.encode('utf-8')).digest()[:16]
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=10000,
                backend=default_backend()
            )
            master_key = kdf.derive(key_material.encode('utf-8'))
            return master_key
        else:
            return hashlib.sha256(key_material.encode('utf-8')).digest()
    except Exception as e:
        raise ValueError(f"Failed to derive master key from email: {e}")

def generate_encryption_key_from_email(receiver_email: str) -> str:
    """Generate auto encryption key from email (first 4 chars + year)"""
    try:
        email_prefix = receiver_email.strip()[:4].lower()
        current_year = str(datetime.datetime.now().year)
        return f"{email_prefix}{current_year}"
    except Exception as e:
        raise ValueError(f"Failed to generate encryption key: {e}")

def encrypt_secret_key(secret_key: str, master_key: bytes) -> str:
    """Encrypts the secret key using the master key derived from receiver's email"""
    try:
        if CRYPTO_AVAILABLE:
            aesgcm = AESGCM(master_key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, secret_key.encode('utf-8'), b'')
            return base64.b64encode(nonce + ciphertext).decode('utf-8')
        else:
            key_bytes = master_key
            secret_bytes = secret_key.encode('utf-8')
            encrypted = bytes([secret_bytes[i % len(secret_bytes)] ^ key_bytes[i % len(key_bytes)] 
                             for i in range(len(secret_bytes))])
            return base64.b64encode(encrypted).decode('utf-8')
    except Exception as e:
        raise ValueError(f"Failed to encrypt secret key: {e}")

def decrypt_secret_key(encrypted_key: str, master_key: bytes) -> str:
    """Decrypts the secret key using the master key derived from receiver's email"""
    try:
        encrypted_data = base64.b64decode(encrypted_key.encode('utf-8'))
        
        if CRYPTO_AVAILABLE:
            aesgcm = AESGCM(master_key)
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            plaintext = aesgcm.decrypt(nonce, ciphertext, b'')
            return plaintext.decode('utf-8')
        else:
            key_bytes = master_key
            decrypted = bytes([encrypted_data[i] ^ key_bytes[i % len(key_bytes)] 
                             for i in range(len(encrypted_data))])
            return decrypted.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Failed to decrypt secret key: {e}")

def send_stego_file_with_key(receiver_email: str, stego_file_path: str, encrypted_key: str, 
                             sender_name: str = "Anonymous", file_info: dict = None) -> dict:
    """Send steganography file and encrypted key to receiver via email"""
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_CONFIG['sender_email']
        msg['To'] = receiver_email
        msg['Subject'] = '🔐 Secure Encrypted Message - Steganography File Attached'
        
        current_year = str(datetime.datetime.now().year)
        email_prefix = receiver_email[:4].lower()
        
        body = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔐 SECURE MESSAGE DELIVERY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Hello,

{sender_name} has sent you a secure steganography file containing an encrypted message.

📧 YOUR ENCRYPTED KEY:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{encrypted_key}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📎 ATTACHED FILE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
The steganography file is attached to this email.

"""
        
        if file_info:
            body += f"""
📁 FILE INFORMATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Filename: {file_info.get('filename', 'N/A')}
• File Type: {file_info.get('media_type', 'N/A').upper()}
• Encryption: {file_info.get('method', 'N/A').upper()}
• File Size: {file_info.get('file_size_kb', 'N/A')} KB
• Created: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

"""
        
        body += f"""
🔓 TO DECRYPT THE MESSAGE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Download the attached steganography file

2. Go to the Steganography platform

3. Enter the following in the decryption form:
   • Your Email: {receiver_email}
   • Encrypted Key: Copy the key above

4. Upload the steganography file you downloaded

5. Click "Extract & Decrypt Message"

🔑 KEY DERIVATION INFO:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Your key is derived from: {email_prefix} (first 4 chars) + {current_year} (current year)
• This ensures only you can decrypt the message
• The key changes automatically each year for security

⚠️ SECURITY NOTICE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Keep this email and encrypted key confidential
• The attached file contains your secure message
• Only you can decrypt the message with your email-derived key
• Delete this email after successfully decrypting the message
• Never share your encrypted key with anyone else

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Best regards,
Steganography Pro Security Team

This is an automated secure message delivery.
Please do not reply to this email.
"""
        
        msg.attach(MIMEText(body, 'plain'))
        
        if os.path.exists(stego_file_path):
            with open(stego_file_path, 'rb') as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
            
            encoders.encode_base64(part)
            filename = os.path.basename(stego_file_path)
            part.add_header('Content-Disposition', f'attachment; filename= {filename}')
            msg.attach(part)
        else:
            raise FileNotFoundError(f"Steganography file not found: {stego_file_path}")
        
        if EMAIL_CONFIG['use_tls']:
            server = smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port'])
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port'])
        
        server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
        server.send_message(msg)
        server.quit()
        
        return {
            'success': True,
            'receiver': receiver_email,
            'sent_at': datetime.datetime.now().isoformat(),
            'attachment': filename
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

# ===================== ULTRA-FAST ENCRYPTION CLASSES =====================

class EncryptionMethod:
    def encrypt(self, plaintext: str, key: str) -> bytes:
        raise NotImplementedError
    def decrypt(self, ciphertext: bytes, key: str) -> str:
        raise NotImplementedError

class UltraFastXOREncryption(EncryptionMethod):
    def _generate_key_stream_numpy(self, key: str, length: int) -> bytes:
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
    def _get_shift(self, key: str) -> int:
        return sum(ord(c) for c in key) % 26 if key else 13
    
    def encrypt(self, plaintext: str, key: str) -> bytes:
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
    def encrypt(self, plaintext: str, key: str) -> bytes:
        try:
            xor_bytes = UltraFastXOREncryption().encrypt(plaintext, key)
            return base64.b64encode(xor_bytes)
        except Exception as e:
            raise ValueError(f"Base64 encryption failed: {e}")
    
    def decrypt(self, ciphertext: bytes, key: str) -> str:
        try:
            decoded = base64.b64decode(ciphertext)
            return UltraFastXOREncryption().decrypt(decoded, key)
        except Exception as e:
            raise ValueError(f"Base64 decryption failed: {e}")

if CRYPTO_AVAILABLE:
    class LightningAESEncryption(EncryptionMethod):
        def _normalize_key(self, key: str) -> bytes:
            return hashlib.sha256(key.encode('utf-8', errors='replace')).digest()
        
        def encrypt(self, plaintext: str, key: str) -> bytes:
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
        def _derive_key(self, password: str) -> bytes:
            salt = hashlib.sha256(password.encode('utf-8', errors='replace')).digest()[:16]
            kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 1000, backend=default_backend())
            return base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8', errors='replace')))
        
        def encrypt(self, plaintext: str, key: str) -> bytes:
            try:
                k = self._derive_key(key)
                return Fernet(k).encrypt(plaintext.encode('utf-8', errors='replace'))
            except Exception as e:
                raise ValueError(f"Fernet encryption failed: {e}")
        
        def decrypt(self, ciphertext: bytes, key: str) -> str:
            try:
                k = self._derive_key(key)
                return Fernet(k).decrypt(ciphertext).decode('utf-8', errors='replace')
            except Exception as e:
                raise ValueError(f"Fernet decryption failed: {e}")

    class LightningChaCha20Encryption(EncryptionMethod):
        def _normalize_key(self, key: str) -> bytes:
            return hashlib.sha256(key.encode('utf-8', errors='replace')).digest()
        
        def encrypt(self, plaintext: str, key: str) -> bytes:
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
        def _derive_key(self, password: str, salt: bytes) -> bytes:
            kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 5000, backend=default_backend())
            return kdf.derive(password.encode('utf-8', errors='replace'))
        
        def encrypt(self, plaintext: str, key: str) -> bytes:
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
        def _derive_key(self, password: str, salt: bytes) -> bytes:
            kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 5000, backend=default_backend())
            return kdf.derive(password.encode('utf-8', errors='replace'))
        
        def encrypt(self, plaintext: str, key: str) -> bytes:
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

# Ultra-fast encryption methods registry
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

# ===================== HELPER FUNCTIONS =====================

def list_encryption_methods():
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
    if CRYPTO_AVAILABLE:
        fast_methods = ['xor', 'caesar', 'aes', 'chacha20']
        strong_fast = ['aes', 'chacha20']
        if random.random() < 0.7:
            return random.choice(fast_methods)
        else:
            return random.choice(strong_fast)
    else:
        return random.choice(['xor', 'caesar', 'base64'])

IMG_EXT = {"png", "jpg", "jpeg", "bmp", "tif", "tiff", "webp"}
AUD_EXT = {"wav", "mp3", "flac", "aac", "m4a", "ogg", "opus"}
VID_EXT = {"mp4", "mkv", "avi", "mov", "webm", "m4v"}

def detect_mode(path):
    try:
        ext = os.path.splitext(path)[1].lower().lstrip('.')
        if ext in IMG_EXT:
            return "image"
        elif ext in AUD_EXT:
            return "audio"
        elif ext in VID_EXT:
            return "video"
        else:
            raise ValueError("Unsupported file extension.")
    except Exception as e:
        raise ValueError(f"Error detecting file type: {e}")

def safe_filename(filename):
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
    try:
        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True)
        return True
    except Exception as e:
        print(f"Warning: Could not create directory {path}: {e}")
        return False

def parse_simple_path(user_input, original_filename="image"):
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
    try:
        result = subprocess.run(["ffmpeg", "-version"],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                             timeout=10)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False

def _temp_path(name: str) -> str:
    return os.path.join(os.getcwd(), f"__stego_tmp_{name}")

def to_lossless(in_path: str, mode: str) -> str:
    if not check_ffmpeg():
        if mode == "image" and in_path.lower().endswith('.png'):
            return in_path
        raise RuntimeError("ffmpeg not found. Install it and ensure it's in PATH.")
    
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
            raise ValueError("Unknown mode.")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise RuntimeError(f"FFMPEG failed: {result.stderr}")
        
        return out
    except subprocess.TimeoutExpired:
        raise RuntimeError("FFMPEG conversion timed out.")
    except Exception as e:
        raise RuntimeError(f"FFMPEG conversion error: {e}")

def cleanup_temp_files():
    try:
        for file in os.listdir('.'):
            if file.startswith('__stego_tmp_'):
                try:
                    os.remove(file)
                except OSError:
                    pass
    except Exception:
        pass

# ===================== ULTRA-FAST PAYLOAD BUILD/READ =====================
MAGIC = b"STEG"
HEADER_LEN = 9

def build_payload(data: bytes, method_name: str) -> bytes:
    try:
        method_idx = list(ENCRYPTION_METHODS.keys()).index(method_name)
        return MAGIC + struct.pack(">I", len(data)) + method_idx.to_bytes(1, 'big') + data
    except Exception as e:
        raise ValueError(f"Failed to build payload: {e}")

def lightning_bytes_to_bits_numpy(data):
    try:
        if NUMPY:
            data_array = np.frombuffer(data, dtype=np.uint8)
            bits_array = np.unpackbits(data_array)
            return bits_array.tolist()
        else:
            bits = []
            for byte in data:
                bits.extend([
                    (byte >> 7) & 1, (byte >> 6) & 1, (byte >> 5) & 1, (byte >> 4) & 1,
                    (byte >> 3) & 1, (byte >> 2) & 1, (byte >> 1) & 1, byte & 1
                ])
            return bits
    except Exception as e:
        raise ValueError(f"Error converting bytes to bits: {e}")

def lightning_bits_to_bytes_numpy(bits):
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

# ===================== LIGHTNING-FAST STEGANOGRAPHY FUNCTIONS =====================

def lightning_hide_in_image_numpy(cover_path, payload, out_path):
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

def lightning_hide_in_wav_numpy(cover_wav_path: str, payload: bytes, out_wav_path: str):
    try:
        with wave.open(cover_wav_path, 'rb') as wf:
            params = wf.getparams()
            if params.sampwidth != 2:
                raise ValueError("Only 16-bit PCM WAV supported.")
            raw_data = wf.readframes(params.nframes)
        
        bits = lightning_bytes_to_bits_numpy(payload)
        
        if NUMPY:
            samples_array = np.frombuffer(raw_data, dtype=np.int16)
            if len(bits) > len(samples_array):
                raise ValueError(f"Audio too small. Need {len(bits)} bits, have {len(samples_array)} samples.")
            bits_array = np.array(bits + [0] * (len(samples_array) - len(bits)), dtype=np.uint16)
            samples_array = (samples_array & 0xFFFE) | bits_array[:len(samples_array)]
            modified_data = samples_array.astype(np.int16).tobytes()
        else:
            samples = array('h')
            samples.frombytes(raw_data)
            if len(bits) > len(samples):
                raise ValueError(f"Audio too small. Need {len(bits)} bits, have {len(samples)} samples.")
            for i in range(len(bits)):
                samples[i] = (samples[i] & 0xFFFE) | bits[i]
            modified_data = samples.tobytes()
        
        with wave.open(out_wav_path, 'wb') as out_wf:
            out_wf.setparams(params)
            out_wf.writeframes(modified_data)
    except Exception as e:
        raise RuntimeError(f"Failed to hide data in audio: {e}")

def lightning_extract_from_wav_numpy(stego_wav_path: str):
    try:
        with wave.open(stego_wav_path, 'rb') as wf:
            params = wf.getparams()
            if params.sampwidth != 2:
                raise ValueError("Only 16-bit PCM WAV supported.")
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

def lightning_hide_in_video_numpy(cover_avi_path: str, payload: bytes, out_avi_path: str):
    if not OPENCV:
        raise ImportError("Install OpenCV (pip install opencv-python) for video support")
    
    try:
        cap = cv2.VideoCapture(cover_avi_path)
        if not cap.isOpened():
            raise ValueError("Cannot open video file.")
        
        fps = int(cap.get(cv2.CAP_PROP_FPS) or 25)
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        
        bits = lightning_bytes_to_bits_numpy(payload)
        max_bits = frame_count * width * height * 3
        
        if len(bits) > max_bits:
            raise ValueError(f"Video too small. Need {len(bits)} bits, have {max_bits}.")
        
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
    if not OPENCV:
        raise ImportError("Install OpenCV (pip install opencv-python) for video support")
    
    try:
        cap = cv2.VideoCapture(stego_avi_path)
        if not cap.isOpened():
            raise ValueError("Cannot open video file.")
        
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

def lightning_encrypt_and_hide(carrier_path, secret_key, message, encryption_method='xor', out_path=None):
    try:
        if encryption_method not in ENCRYPTION_METHODS:
            encryption_method = 'xor'
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            encrypt_future = executor.submit(ENCRYPTION_METHODS[encryption_method].encrypt, message, secret_key)
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
            
            decrypt_future = executor.submit(ENCRYPTION_METHODS[method_name].decrypt, encrypted_data, secret_key)
            message = decrypt_future.result()
        return message, method_name
    except Exception as e:
        raise RuntimeError(f"Lightning extraction and decryption failed: {e}")

# ===================== Flask Web Application =====================

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)
app.secret_key = os.urandom(32)

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'stego_temp')
DEFAULT_OUTPUT_FOLDER = os.path.join(os.getcwd(), 'stego_output')

for folder in [UPLOAD_FOLDER, DEFAULT_OUTPUT_FOLDER]:
    ensure_directory_exists(folder)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DEFAULT_OUTPUT_FOLDER'] = DEFAULT_OUTPUT_FOLDER

@app.route('/')
@app.route('/dashboard')
def index():
    return render_template('dashboard.html')

@app.route('/api/generate-key', methods=['POST'])
def generate_key():
    """Generate encryption key from receiver email"""
    try:
        data = request.get_json()
        receiver_email = data.get('receiver_email', '').strip()
        
        if not receiver_email:
            return jsonify({'success': False, 'error': 'Email is required'})
        
        encryption_key = generate_encryption_key_from_email(receiver_email)
        
        return jsonify({
            'success': True,
            'encryption_key': encryption_key,
            'email_prefix': receiver_email[:4].lower(),
            'year': str(datetime.datetime.now().year)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/process', methods=['POST'])
def process():
    try:
        action = request.form.get('action')
        start_time = time.time()
        
        if action == 'hide':
            carrier = request.files.get('carrier_file')
            secret_key = request.form.get('secret_key')
            message = request.form.get('message')
            enc_method = request.form.get('encryption_method')
            save_mode = request.form.get('save_mode', 'auto')
            file_path = request.form.get('file_path', '').strip()
            send_email = request.form.get('send_email', 'false').lower() == 'true'
            receiver_email = request.form.get('receiver_email', '').strip()

            if not carrier or not secret_key or not message:
                return jsonify({'success': False, 'error': 'All fields are required for hiding'})
            
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
                    return jsonify({'success': False, 'error': f'Invalid encryption method: {enc_method}'})

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

                ffmpeg_used = False
                if media_type in ["audio", "video"] or (media_type == "image" and not temp_save_path.lower().endswith('.png')):
                    if not check_ffmpeg():
                        return jsonify({'success': False, 'error': 'FFmpeg is required but not installed'})
                    ffmpeg_used = True

                try:
                    lightning_encrypt_and_hide(temp_save_path, secret_key, message, enc_method, out_path)
                except Exception as stego_error:
                    return jsonify({'success': False, 'error': f'Steganography failed: {str(stego_error)}'})
                
                file_size = os.path.getsize(out_path)
                processing_time = f"{time.time() - start_time:.3f}s"
                
                response_data = {
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
                }
                
                # Email handling
                if send_email and receiver_email and EMAIL_CONFIG['sender_email'] != 'your_email@gmail.com':
                    try:
                        # Use the actual secret_key that was used for encryption
                        master_key = derive_master_key_from_email(receiver_email)
                        encrypted_secret_key = encrypt_secret_key(secret_key, master_key)
                        
                        file_info = {
                            'filename': out_filename,
                            'media_type': media_type,
                            'method': enc_method,
                            'file_size_kb': round(file_size / 1024, 2)
                        }
                        
                        email_result = send_stego_file_with_key(
                            receiver_email,
                            out_path,
                            encrypted_secret_key,
                            sender_name="Sender",
                            file_info=file_info
                        )
                        
                        response_data['email_sent'] = email_result.get('success', False)
                        response_data['receiver_email'] = receiver_email
                        response_data['encrypted_key'] = encrypted_secret_key
                        response_data['encryption_key_used'] = secret_key
                        response_data['email_sent_at'] = email_result.get('sent_at')
                        response_data['key_info'] = f"Use your secret key '{secret_key}' to decrypt, or use email-based decryption with the encrypted key sent via email"
                        
                        if not email_result.get('success'):
                            response_data['email_error'] = email_result.get('error')
                    except Exception as e:
                        response_data['email_sent'] = False
                        response_data['email_error'] = str(e)
                
                return jsonify(response_data)

            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
            finally:
                if os.path.exists(temp_save_path):
                    try:
                        os.remove(temp_save_path)
                    except OSError:
                        pass
                cleanup_temp_files()

        elif action == 'extract':
            stego = request.files.get('stego_file')
            secret_key = request.form.get('secret_key', '').strip()
            encrypted_key = request.form.get('encrypted_key', '').strip()
            receiver_email = request.form.get('receiver_email', '').strip()

            if not stego:
                return jsonify({'success': False, 'error': 'Steganography file is required'})
            
            # Support BOTH methods: direct secret_key OR encrypted_key + receiver_email
            actual_secret_key = None
            
            if encrypted_key and receiver_email:
                # Email-based decryption
                try:
                    master_key = derive_master_key_from_email(receiver_email)
                    actual_secret_key = decrypt_secret_key(encrypted_key, master_key)
                except Exception as e:
                    return jsonify({'success': False, 'error': f'Failed to decrypt key from email: {str(e)}'})
            elif secret_key:
                # Direct secret key method
                actual_secret_key = secret_key
            else:
                return jsonify({'success': False, 'error': 'Either secret_key OR (encrypted_key + receiver_email) is required'})

            timestamp = str(int(time.time()))
            filename = stego.filename
            safe_temp_filename = f"{timestamp}_{filename}"
            temp_stego_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_temp_filename)
            stego.save(temp_stego_path)

            try:
                media_type = detect_mode(temp_stego_path)
                
                if media_type in ["audio", "video"] and not check_ffmpeg():
                    return jsonify({'success': False, 'error': 'FFmpeg is required but not installed'})
                
                message, method_used = lightning_extract_and_decrypt(temp_stego_path, actual_secret_key)
                processing_time = f"{time.time() - start_time:.3f}s"
                
                return jsonify({
                    'success': True,
                    'message': message,
                    'method': method_used,
                    'media_type': media_type,
                    'processing_time': processing_time,
                    'lightning': True,
                    'decryption_method': 'email-based' if encrypted_key and receiver_email else 'direct-key'
                })

            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
            finally:
                if os.path.exists(temp_stego_path):
                    try:
                        os.remove(temp_stego_path)
                    except OSError:
                        pass
                cleanup_temp_files()

        else:
            return jsonify({'success': False, 'error': 'Invalid action'})

    except Exception as e:
        cleanup_temp_files()
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'})

@app.route('/api/methods')
def get_methods():
    return jsonify({
        'methods': list_encryption_methods(),
        'crypto_available': CRYPTO_AVAILABLE,
        'numpy_available': NUMPY,
        'opencv_available': OPENCV,
        'ffmpeg_available': check_ffmpeg(),
        'email_configured': EMAIL_CONFIG['sender_email'] != 'your_email@gmail.com',
        'supported_formats': {
            'image': list(IMG_EXT),
            'audio': list(AUD_EXT),
            'video': list(VID_EXT)
        }
    })

@app.route('/health')
def health_check():
    return jsonify({
        'status': 'lightning',
        'version': 'dual-key-support-v1.0',
        'encryption_methods': len(ENCRYPTION_METHODS),
        'crypto_support': CRYPTO_AVAILABLE,
        'numpy_support': NUMPY,
        'opencv_support': OPENCV,
        'ffmpeg_support': check_ffmpeg(),
        'email_configured': EMAIL_CONFIG['sender_email'] != 'your_email@gmail.com',
        'decryption_modes': ['direct-secret-key', 'email-based-encrypted-key']
    })

if __name__ == '__main__':
    print("=" * 80)
    print("Starting LIGHTNING-FAST Steganography with Dual Key Support")
    print("=" * 80)
    print("\n🚀 Server: http://localhost:5000")
    print("\n🔑 DUAL KEY DECRYPTION SUPPORT:")
    print("  ✅ Method 1: Direct Secret Key (traditional)")
    print("  ✅ Method 2: Email-Based Encrypted Key (secure)")
    print("\n📧 EMAIL FILE DELIVERY:")
    print("  ✉️  Automatic steganography file delivery via email")
    print("  🔑 Email-based key derivation (first 4 chars + year)")
    print("  🔐 Encrypted key included in email body")
    print("  📎 Stego file attached to email")
    print(f"  📮 Status: {'✅ CONFIGURED' if EMAIL_CONFIG['sender_email'] != 'your_email@gmail.com' else '⚠️  NOT CONFIGURED'}")
    
    if EMAIL_CONFIG['sender_email'] == 'your_email@gmail.com':
        print("\n⚠️  EMAIL NOT CONFIGURED!")
        print("  Update EMAIL_CONFIG with your SMTP settings")
    
    print("\n⚡ LIGHTNING OPTIMIZATIONS:")
    print("  ⚡ NumPy vectorized operations")
    print("  ⚡ Ultra-reduced PBKDF2 (1K-5K iterations)")
    print("  ⚡ Multi-core processing")
    print("  ⚡ Vectorized LSB operations")
    
    print(f"\n📚 Encryption Methods: {list(ENCRYPTION_METHODS.keys())}")
    print(f"🔧 NumPy: {'✅ Available' if NUMPY else '⚠️  Not installed'}")
    print(f"🎥 OpenCV: {'✅ Available' if OPENCV else '⚠️  Not installed'}")
    print(f"🎬 FFmpeg: {'✅ Available' if check_ffmpeg() else '⚠️  Not installed'}")
    print(f"🔐 Cryptography: {'✅ Available' if CRYPTO_AVAILABLE else '⚠️  Not installed'}")
    
    print("\n" + "=" * 80)
    print("🚀 System Ready! Dual key decryption enabled.")
    print("=" * 80 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)