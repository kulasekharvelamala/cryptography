import os
import sys
import struct
import subprocess
import hashlib
import base64
import random
from typing import Iterable, Optional
from PIL import Image
import wave
from array import array

# Optional (only needed for video support)
try:
    import cv2
    import numpy as np
    OPENCV = True
except ImportError:
    OPENCV = False

# Cryptography
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

# ===================== ENCRYPTION ALGORITHMS =====================

class EncryptionMethod:
    """Base class for encryption methods"""
    def encrypt(self, plaintext: str, key: str) -> bytes:
        raise NotImplementedError
    
    def decrypt(self, ciphertext: bytes, key: str) -> str:
        raise NotImplementedError

class XOREncryption(EncryptionMethod):
    """Simple XOR encryption (always available)"""
    
    def _generate_key_stream(self, key: str, length: int) -> bytes:
        key_bytes = key.encode('utf-8')
        if len(key_bytes) == 0:
            key_bytes = b'default'
        
        key_stream = bytearray()
        for i in range(length):
            key_stream.append(key_bytes[i % len(key_bytes)])
        return bytes(key_stream)
    
    def encrypt(self, plaintext: str, key: str) -> bytes:
        plaintext_bytes = plaintext.encode('utf-8')
        key_stream = self._generate_key_stream(key, len(plaintext_bytes))
        
        ciphertext = bytearray()
        for i in range(len(plaintext_bytes)):
            ciphertext.append(plaintext_bytes[i] ^ key_stream[i])
        
        return bytes(ciphertext)
    
    def decrypt(self, ciphertext: bytes, key: str) -> str:
        key_stream = self._generate_key_stream(key, len(ciphertext))
        
        plaintext = bytearray()
        for i in range(len(ciphertext)):
            plaintext.append(ciphertext[i] ^ key_stream[i])
        
        return plaintext.decode('utf-8')

class CaesarEncryption(EncryptionMethod):
    """Caesar cipher with dynamic shift based on key"""
    
    def _get_shift(self, key: str) -> int:
        return sum(ord(c) for c in key) % 26
    
    def encrypt(self, plaintext: str, key: str) -> bytes:
        shift = self._get_shift(key)
        result = ""
        
        for char in plaintext:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += char
        
        return result.encode('utf-8')
    
    def decrypt(self, ciphertext: bytes, key: str) -> str:
        shift = self._get_shift(key)
        plaintext = ciphertext.decode('utf-8')
        result = ""
        
        for char in plaintext:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
            else:
                result += char
        
        return result

class Base64Encryption(EncryptionMethod):
    """Base64 encoding with XOR (not true encryption, but obfuscation)"""
    
    def encrypt(self, plaintext: str, key: str) -> bytes:
        # First XOR, then base64
        xor_cipher = XOREncryption()
        xor_result = xor_cipher.encrypt(plaintext, key)
        return base64.b64encode(xor_result)
    
    def decrypt(self, ciphertext: bytes, key: str) -> str:
        # First decode base64, then XOR
        decoded = base64.b64decode(ciphertext)
        xor_cipher = XOREncryption()
        return xor_cipher.decrypt(decoded, key)

if CRYPTO_AVAILABLE:
    class AESEncryption(EncryptionMethod):
        """AES encryption with CBC mode and PKCS7 padding"""
        
        def _normalize_key(self, key: str) -> bytes:
            key_bytes = key.encode('utf-8')
            if len(key_bytes) < 32:
                key_bytes += b' ' * (32 - len(key_bytes))
            else:
                key_bytes = key_bytes[:32]
            return key_bytes
        
        def encrypt(self, plaintext: str, key: str) -> bytes:
            key_bytes = self._normalize_key(key)
            iv = os.urandom(16)
            
            cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Pad the plaintext
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
            
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            return iv + ciphertext  # Prepend IV
        
        def decrypt(self, ciphertext: bytes, key: str) -> str:
            key_bytes = self._normalize_key(key)
            iv = ciphertext[:16]
            ct = ciphertext[16:]
            
            cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            padded_plaintext = decryptor.update(ct) + decryptor.finalize()
            
            # Unpad the plaintext
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext.decode('utf-8')

    class FernetEncryption(EncryptionMethod):
        """Fernet encryption (AES 128 in CBC mode with HMAC)"""
        
        def _derive_key(self, password: str) -> bytes:
            password_bytes = password.encode('utf-8')
            salt = hashlib.sha256(password_bytes).digest()[:16]  # Deterministic salt for compatibility
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            return base64.urlsafe_b64encode(kdf.derive(password_bytes))
        
        def encrypt(self, plaintext: str, key: str) -> bytes:
            derived_key = self._derive_key(key)
            f = Fernet(derived_key)
            return f.encrypt(plaintext.encode('utf-8'))
        
        def decrypt(self, ciphertext: bytes, key: str) -> str:
            derived_key = self._derive_key(key)
            f = Fernet(derived_key)
            return f.decrypt(ciphertext).decode('utf-8')

    class ChaCha20Encryption(EncryptionMethod):
        """ChaCha20 encryption (stream cipher, NOT authenticated)"""
        
        def _normalize_key(self, key: str) -> bytes:
            key_bytes = key.encode('utf-8')
            if len(key_bytes) < 32:
                key_bytes += b' ' * (32 - len(key_bytes))
            else:
                key_bytes = key_bytes[:32]
            return key_bytes
        
        def encrypt(self, plaintext: str, key: str) -> bytes:
            key_bytes = self._normalize_key(key)
            nonce = os.urandom(16)  # ChaCha20 uses 16-byte nonce
            
            cipher = Cipher(algorithms.ChaCha20(key_bytes, nonce), mode=None, backend=default_backend())
            encryptor = cipher.encryptor()
            
            ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
            
            return nonce + ciphertext  # Prepend nonce
        
        def decrypt(self, ciphertext: bytes, key: str) -> str:
            key_bytes = self._normalize_key(key)
            nonce = ciphertext[:16]
            ct = ciphertext[16:]
            
            cipher = Cipher(algorithms.ChaCha20(key_bytes, nonce), mode=None, backend=default_backend())
            decryptor = cipher.decryptor()
            
            plaintext = decryptor.update(ct) + decryptor.finalize()
            
            return plaintext.decode('utf-8')

    # -------- Added Modern AEAD Schemes --------
    class AESGCMEncryption(EncryptionMethod):
        """AES-256 GCM (authenticated encryption)"""
        def _derive_key(self, password: str, salt: bytes) -> bytes:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=200_000,
                backend=default_backend()
            )
            return kdf.derive(password.encode('utf-8'))

        def encrypt(self, plaintext: str, key: str) -> bytes:
            salt = os.urandom(16)
            k = self._derive_key(key, salt)
            aesgcm = AESGCM(k)
            nonce = os.urandom(12)
            ct = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), b'')
            # store: salt || nonce || ct
            return b"SG" + salt + nonce + ct

        def decrypt(self, ciphertext: bytes, key: str) -> str:
            if not ciphertext.startswith(b"SG"):
                raise ValueError("Invalid AESGCM payload")
            salt = ciphertext[2:18]
            nonce = ciphertext[18:30]
            ct = ciphertext[30:]
            k = self._derive_key(key, salt)
            aesgcm = AESGCM(k)
            pt = aesgcm.decrypt(nonce, ct, b'')
            return pt.decode('utf-8')

    class ChaCha20Poly1305Encryption(EncryptionMethod):
        """ChaCha20-Poly1305 (authenticated encryption)"""
        def _derive_key(self, password: str, salt: bytes) -> bytes:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=200_000,
                backend=default_backend()
            )
            return kdf.derive(password.encode('utf-8'))

        def encrypt(self, plaintext: str, key: str) -> bytes:
            salt = os.urandom(16)
            k = self._derive_key(key, salt)
            aead = ChaCha20Poly1305(k)
            nonce = os.urandom(12)
            ct = aead.encrypt(nonce, plaintext.encode('utf-8'), b'')
            return b"CP" + salt + nonce + ct

        def decrypt(self, ciphertext: bytes, key: str) -> str:
            if not ciphertext.startswith(b"CP"):
                raise ValueError("Invalid ChaCha20-Poly1305 payload")
            salt = ciphertext[2:18]
            nonce = ciphertext[18:30]
            ct = ciphertext[30:]
            k = self._derive_key(key, salt)
            aead = ChaCha20Poly1305(k)
            pt = aead.decrypt(nonce, ct, b'')
            return pt.decode('utf-8')

    # -------- Added Legacy Block Ciphers (CBC with PKCS7) --------
    class BlowfishEncryption(EncryptionMethod):
        """Blowfish CBC with PKCS7 padding (64-bit block)"""
        def _derive_key(self, password: str) -> bytes:
            # Blowfish key length: 4..56 bytes
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # we will truncate
                salt=b"BF_FIXED_SALT",
                iterations=150_000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode('utf-8'))
            return key[:32]  # cryptography accepts up to 56; 32 is fine

        def encrypt(self, plaintext: str, key: str) -> bytes:
            k = self._derive_key(key)
            iv = os.urandom(8)  # 64-bit block size
            cipher = Cipher(algorithms.Blowfish(k), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(64).padder()
            padded = padder.update(plaintext.encode('utf-8')) + padder.finalize()
            ct = encryptor.update(padded) + encryptor.finalize()
            return iv + ct

        def decrypt(self, ciphertext: bytes, key: str) -> str:
            iv = ciphertext[:8]
            ct = ciphertext[8:]
            k = self._derive_key(key)
            cipher = Cipher(algorithms.Blowfish(k), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded = decryptor.update(ct) + decryptor.finalize()
            unpadder = padding.PKCS7(64).unpadder()
            pt = unpadder.update(padded) + unpadder.finalize()
            return pt.decode('utf-8')

    class TripleDESEncryption(EncryptionMethod):
        """TripleDES (3DES) CBC with PKCS7 padding (legacy)"""
        def _derive_key(self, password: str) -> bytes:
            # 24-byte (192-bit) key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=24,
                salt=b"TDES_FIXED_SALT",
                iterations=150_000,
                backend=default_backend()
            )
            return kdf.derive(password.encode('utf-8'))

        def encrypt(self, plaintext: str, key: str) -> bytes:
            k = self._derive_key(key)
            iv = os.urandom(8)  # 64-bit block size
            cipher = Cipher(algorithms.TripleDES(k), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(64).padder()
            padded = padder.update(plaintext.encode('utf-8')) + padder.finalize()
            ct = encryptor.update(padded) + encryptor.finalize()
            return iv + ct

        def decrypt(self, ciphertext: bytes, key: str) -> str:
            iv = ciphertext[:8]
            ct = ciphertext[8:]
            k = self._derive_key(key)
            cipher = Cipher(algorithms.TripleDES(k), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded = decryptor.update(ct) + decryptor.finalize()
            unpadder = padding.PKCS7(64).unpadder()
            pt = unpadder.update(padded) + unpadder.finalize()
            return pt.decode('utf-8')

# Encryption method registry
ENCRYPTION_METHODS = {
    'xor': XOREncryption(),
    'caesar': CaesarEncryption(),
    'base64': Base64Encryption(),
}

if CRYPTO_AVAILABLE:
    ENCRYPTION_METHODS.update({
        'aes': AESEncryption(),
        'fernet': FernetEncryption(),
        'chacha20': ChaCha20Encryption(),
        'aesgcm': AESGCMEncryption(),
        'chacha20poly1305': ChaCha20Poly1305Encryption(),
        'blowfish': BlowfishEncryption(),
        '3des': TripleDESEncryption(),
    })

# ===================== HELPER FUNCTIONS =====================

def list_encryption_methods() -> dict:
    """List available encryption methods with descriptions."""
    descriptions = {
        'xor': 'Simple XOR cipher (fast, basic security)',
        'caesar': 'Caesar cipher with dynamic shift (educational purposes)',
        'base64': 'Base64 encoding with XOR (obfuscation only)',
    }
    
    if CRYPTO_AVAILABLE:
        descriptions.update({
            'aes': 'AES-256 in CBC mode (strong, not authenticated)',
            'fernet': 'Fernet encryption with PBKDF2 (AES-CBC + HMAC, secure)',
            'chacha20': 'ChaCha20 stream cipher (modern, not authenticated)',
            'aesgcm': 'AES-256 in GCM mode (AEAD, recommended)',
            'chacha20poly1305': 'ChaCha20-Poly1305 (AEAD, recommended)',
            'blowfish': 'Blowfish CBC with PKCS7 (legacy)',
            '3des': 'TripleDES CBC with PKCS7 (legacy)',
        })
    
    return descriptions

def choose_random_encryption() -> str:
    """Choose a random encryption method, preferring stronger methods."""
    if CRYPTO_AVAILABLE:
        strong_methods = ['aesgcm', 'chacha20poly1305', 'fernet', 'aes']
        basic_methods = ['xor', 'caesar', 'base64', 'chacha20', 'blowfish', '3des']
        
        if random.random() < 0.75:
            return random.choice(strong_methods)
        else:
            return random.choice(basic_methods)
    else:
        basic_methods = ['xor', 'caesar', 'base64']
        return random.choice(basic_methods)

# ===================== PAYLOAD HANDLING =====================
MAGIC = b"STEG"
HEADER_LEN = 9  # 4B magic + 4B length + 1B encryption method

def build_payload(data: bytes, encryption_method: str) -> bytes:
    method_byte = list(ENCRYPTION_METHODS.keys()).index(encryption_method).to_bytes(1, 'big')
    return MAGIC + struct.pack(">I", len(data)) + method_byte + data

def parse_payload_from_bits(bit_iter: Iterable[int]) -> tuple[bytes, str]:
    try:
        header_bits = [next(bit_iter) for _ in range(HEADER_LEN * 8)]
        header = bits_to_bytes(header_bits)
        
        if header[:4] != MAGIC:
            raise ValueError("Invalid/absent MAGIC header.")
        
        data_len = struct.unpack(">I", header[4:8])[0]
        method_index = header[8]
        
        method_names = list(ENCRYPTION_METHODS.keys())
        if method_index >= len(method_names):
            raise ValueError("Unknown encryption method index.")
        
        encryption_method = method_names[method_index]
        
        data_bits = [next(bit_iter) for _ in range(data_len * 8)]
        return bits_to_bytes(data_bits), encryption_method
    except StopIteration:
        raise ValueError("Insufficient data in carrier file.")

def bytes_to_bits(data: bytes) -> Iterable[int]:
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1

def bits_to_bytes(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for bit in bits[i:i+8]:
            b = (b << 1) | (bit & 1)
        out.append(b)
    return bytes(out)

# ===================== FILE TYPE DETECTION =====================
IMG_EXT = {"png", "jpg", "jpeg", "bmp", "tif", "tiff", "webp"}
AUD_EXT = {"wav", "mp3", "flac", "aac", "m4a", "ogg", "opus"}
VID_EXT = {"mp4", "mkv", "avi", "mov", "webm", "m4v"}

def detect_mode(path: str) -> str:
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")
    
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    if ext in IMG_EXT: return "image"
    if ext in AUD_EXT: return "audio"
    if ext in VID_EXT: return "video"
    raise ValueError(f"Unsupported file extension: .{ext}")

# ===================== FFMPEG HELPERS =====================
def check_ffmpeg():
    try:
        result = subprocess.run(["ffmpeg", "-version"],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                             timeout=10)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False

def _temp_path(name: str) -> str:
    return os.path.join(os.getcwd(), f"__stego_tmp_{name}")

def to_lossless(in_path: str, mode: str) -> str:
    if not check_ffmpeg():
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
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            raise RuntimeError(f"FFMPEG failed: {result.stderr}")
        
        return out
    except subprocess.TimeoutExpired:
        raise RuntimeError("FFMPEG conversion timed out.")

def cleanup_temp_files():
    """Clean up temporary files"""
    for file in os.listdir('.'):
        if file.startswith('__stego_tmp_'):
            try:
                os.remove(file)
            except OSError:
                pass

# ===================== IMAGE STEGANOGRAPHY =====================
def hide_in_image(cover_png_path: str, payload: bytes, out_png_path: str):
    try:
        img = Image.open(cover_png_path).convert("RGB")
        w, h = img.size
        max_bits = w * h * 3
        bits = list(bytes_to_bits(payload))
        
        if len(bits) > max_bits:
            raise ValueError(f"Image too small. Need {len(bits)} bits, have {max_bits} bits.")
        
        pixels = img.load()
        idx = 0
        
        for y in range(h):
            for x in range(w):
                if idx >= len(bits):
                    break
                r, g, b = pixels[x, y]
                if idx < len(bits):
                    r = (r & 0xFE) | bits[idx]
                    idx += 1
                if idx < len(bits):
                    g = (g & 0xFE) | bits[idx]
                    idx += 1
                if idx < len(bits):
                    b = (b & 0xFE) | bits[idx]
                    idx += 1
                pixels[x, y] = (r, g, b)
            if idx >= len(bits):
                break
        
        img.save(out_png_path)
    except Exception as e:
        raise RuntimeError(f"Failed to hide data in image: {str(e)}")

def extract_from_image(stego_png_path: str) -> tuple[bytes, str]:
    try:
        img = Image.open(stego_png_path).convert("RGB")
        w, h = img.size
        pixels = img.load()
        
        def gen():
            for y in range(h):
                for x in range(w):
                    r, g, b = pixels[x, y]
                    yield r & 1
                    yield g & 1
                    yield b & 1
        
        return parse_payload_from_bits(gen())
    except Exception as e:
        raise RuntimeError(f"Failed to extract data from image: {str(e)}")

# ===================== AUDIO STEGANOGRAPHY =====================
def hide_in_wav(cover_wav_path: str, payload: bytes, out_wav_path: str):
    try:
        with wave.open(cover_wav_path, 'rb') as wf:
            nchannels = wf.getnchannels()
            sampwidth = wf.getsampwidth()
            framerate = wf.getframerate()
            nframes = wf.getnframes()
            
            if sampwidth != 2:
                raise ValueError("Only 16-bit PCM WAV supported.")
            
            raw_data = wf.readframes(nframes)
        
        samples = array('h')
        samples.frombytes(raw_data)
        bits = list(bytes_to_bits(payload))
        
        if len(bits) > len(samples):
            raise ValueError(f"Audio too small. Need {len(bits)} bits, have {len(samples)} bits.")
        
        for i, bit in enumerate(bits):
            samples[i] = (samples[i] & 0xFFFE) | bit
        
        with wave.open(out_wav_path, 'wb') as out_wf:
            out_wf.setnchannels(nchannels)
            out_wf.setsampwidth(sampwidth)
            out_wf.setframerate(framerate)
            out_wf.writeframes(samples.tobytes())
    except Exception as e:
        raise RuntimeError(f"Failed to hide data in audio: {str(e)}")

def extract_from_wav(stego_wav_path: str) -> tuple[bytes, str]:
    try:
        with wave.open(stego_wav_path, 'rb') as wf:
            sampwidth = wf.getsampwidth()
            nframes = wf.getnframes()
            
            if sampwidth != 2:
                raise ValueError("Only 16-bit PCM WAV supported.")
            
            raw_data = wf.readframes(nframes)
        
        samples = array('h')
        samples.frombytes(raw_data)
        
        def gen():
            for sample in samples:
                yield sample & 1
        
        return parse_payload_from_bits(gen())
    except Exception as e:
        raise RuntimeError(f"Failed to extract data from audio: {str(e)}")

# ===================== VIDEO STEGANOGRAPHY =====================
def hide_in_video(cover_avi_path: str, payload: bytes, out_avi_path: str):
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
        
        bits = list(bytes_to_bits(payload))
        max_bits = frame_count * width * height * 3
        
        if len(bits) > max_bits:
            raise ValueError(f"Video too small. Need {len(bits)} bits, have {max_bits}.")
        
        fourcc = cv2.VideoWriter_fourcc(*"FFV1")
        out = cv2.VideoWriter(out_avi_path, fourcc, fps, (width, height))
        
        idx = 0
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            
            for y in range(height):
                for x in range(width):
                    if idx >= len(bits):
                        break
                    for c in range(3):  # BGR channels
                        if idx < len(bits):
                            frame[y, x, c] = (frame[y, x, c] & 0xFE) | bits[idx]
                            idx += 1
            
            out.write(frame)
        
        cap.release()
        out.release()
    except Exception as e:
        raise RuntimeError(f"Failed to hide data in video: {str(e)}")

def extract_from_video(stego_avi_path: str) -> tuple[bytes, str]:
    if not OPENCV:
        raise ImportError("Install OpenCV (pip install opencv-python) for video support")
    
    try:
        cap = cv2.VideoCapture(stego_avi_path)
        if not cap.isOpened():
            raise ValueError("Cannot open video file.")
        
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        
        def gen():
            while True:
                ret, frame = cap.read()
                if not ret:
                    break
                for y in range(height):
                    for x in range(width):
                        for c in range(3):  # BGR channels
                            yield frame[y, x, c] & 1
        
        data = parse_payload_from_bits(gen())
        cap.release()
        return data
    except Exception as e:
        raise RuntimeError(f"Failed to extract data from video: {str(e)}")

# ===================== HIGH-LEVEL API =====================
def encrypt_and_hide(carrier_path: str, secret_key: str, message: str,
                    encryption_method: str = 'aes', out_path: Optional[str] = None) -> str:
    """
    Encrypt a message and hide it in a carrier file.
    
    Args:
        carrier_path: Path to the carrier file (image, audio, or video)
        secret_key: Encryption key
        message: Message to hide
        encryption_method: Encryption method to use
        out_path: Output path (optional)
    
    Returns:
        Path to the output file
    """
    try:
        # Validate encryption method
        if encryption_method not in ENCRYPTION_METHODS:
            available = ', '.join(ENCRYPTION_METHODS.keys())
            raise ValueError(f"Unknown encryption method '{encryption_method}'. Available: {available}")
        
        # Encrypt the message
        encryptor = ENCRYPTION_METHODS[encryption_method]
        encrypted_data = encryptor.encrypt(message, secret_key)
        
        # Build payload
        payload = build_payload(encrypted_data, encryption_method)
        
        # Detect file type and convert to lossless
        mode = detect_mode(carrier_path)
        lossless_path = to_lossless(carrier_path, mode)
        
        # Generate output path if not provided
        if out_path is None:
            base, ext = os.path.splitext(carrier_path)
            if mode == "image":
                out_path = f"{base}_stego.png"
            elif mode == "audio":
                out_path = f"{base}_stego.wav"
            elif mode == "video":
                out_path = f"{base}_stego.avi"
        
        # Hide data based on file type
        try:
            if mode == "image":
                hide_in_image(lossless_path, payload, out_path)
            elif mode == "audio":
                hide_in_wav(lossless_path, payload, out_path)
            elif mode == "video":
                hide_in_video(lossless_path, payload, out_path)
        finally:
            # Cleanup temporary lossless file
            try:
                os.remove(lossless_path)
            except OSError:
                pass
        
        print(f"Success! Message hidden using {encryption_method.upper()} encryption.")
        print(f"Output saved to: {out_path}")
        return out_path
        
    except Exception as e:
        cleanup_temp_files()
        raise RuntimeError(f"Failed to encrypt and hide message: {str(e)}")

def extract_and_decrypt(stego_path: str, secret_key: str) -> tuple[str, str]:
    """
    Extract and decrypt a hidden message from a stego file.
    
    Args:
        stego_path: Path to the stego file
        secret_key: Decryption key
    
    Returns:
        Tuple of (decrypted_message, encryption_method_used)
    """
    try:
        mode = detect_mode(stego_path)
        
        # Extract data based on file type
        if mode == "image":
            encrypted_data, encryption_method = extract_from_image(stego_path)
        elif mode == "audio":
            encrypted_data, encryption_method = extract_from_wav(stego_path)
        elif mode == "video":
            encrypted_data, encryption_method = extract_from_video(stego_path)
        else:
            raise ValueError("Unsupported file type.")
        
        # Decrypt the data
        if encryption_method not in ENCRYPTION_METHODS:
            raise ValueError(f"Unknown encryption method: {encryption_method}")
        
        decryptor = ENCRYPTION_METHODS[encryption_method]
        message = decryptor.decrypt(encrypted_data, secret_key)
        
        return message, encryption_method
        
    except Exception as e:
        raise RuntimeError(f"Failed to extract and decrypt message: {str(e)}")

# ===================== CLI INTERFACE =====================
def main():
    """Command-line interface for the steganography tool."""
    print("=== Advanced Steganography Tool ===")
    print()
    
    # Show available encryption methods
    methods = list_encryption_methods()
    print("Available encryption methods:")
    for method, description in methods.items():
        print(f"  {method}: {description}")
    print()
    
    try:
        action = input("Choose (E)ncrypt or (D)ecrypt: ").lower().strip()
        
        if action in ['e', 'encrypt']:
            # Encryption mode
            file_path = input("Enter carrier file path: ").strip()
            if not os.path.exists(file_path):
                print(f"Error: File '{file_path}' not found.")
                return
            
            key = input("Enter secret key: ").strip()
            if not key:
                print("Error: Secret key cannot be empty.")
                return
            
            message = input("Enter message to hide: ").strip()
            if not message:
                print("Error: Message cannot be empty.")
                return
            
            # Choose encryption method
            print("Encryption method options:")
            print("  [Enter] - Auto-select random method (recommended)")
            print("  manual  - Choose method manually")
            for method, description in methods.items():
                print(f"  {method}   - {description}")
            print()
            
            choice = input(f"Choose option [auto]: ").strip().lower()
            
            if not choice or choice == 'auto':
                method = choose_random_encryption()
                print(f"🎲 Randomly selected encryption method: {method.upper()}")
            elif choice == 'manual':
                method = input(f"Choose encryption method ({'/'.join(methods.keys())}): ").strip().lower()
                if method not in methods:
                    print(f"Error: Invalid encryption method '{method}'.")
                    return
            elif choice in methods:
                method = choice
                print(f"✓ Using encryption method: {method.upper()}")
            else:
                print(f"Error: Invalid option '{choice}'.")
                return
            
            out_path = input("Output path (press Enter for auto): ").strip()
            if not out_path or out_path.lower() == 'auto':
                out_path = None
            
            try:
                result_path = encrypt_and_hide(file_path, key, message, method, out_path)
                print(f"✓ Success! File saved as: {result_path}")
            except Exception as e:
                print(f"✗ Error: {e}")
        
        elif action in ['d', 'decrypt']:
            # Decryption mode
            file_path = input("Enter stego file path: ").strip()
            if not os.path.exists(file_path):
                print(f"Error: File '{file_path}' not found.")
                return
            
            key = input("Enter secret key: ").strip()
            if not key:
                print("Error: Secret key cannot be empty.")
                return
            
            print("🔍 Analyzing file and detecting encryption method...")
            try:
                message, method_used = extract_and_decrypt(file_path, key)
                print(f"✓ Success! Auto-detected encryption method: {method_used.upper()}")
                print(f"📝 Hidden message: {message}")
            except Exception as e:
                print(f"✗ Error: {e}")
        
        else:
            print("Error: Please choose 'E' for encrypt or 'D' for decrypt.")
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        cleanup_temp_files()

if __name__ == "__main__":
    main()
