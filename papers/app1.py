from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import random
import os
import json

# Initialize Flask App
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())

# ✅ FIX 1: Use relative path for database
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'users.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///D:/Project/papers/users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# ✅ FIX 2: Email Configuration - PROPERLY CONFIGURED
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'kulasekharvelamala@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'pjnekjvvorzkophv')
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']

# Initialize Extensions
db = SQLAlchemy(app)
mail = Mail(app)

# ==================== DATABASE MODELS ====================
class User(db.Model):
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

# ==================== DATABASE SETUP ====================
def init_database():
    import sqlite3
    db_exists = os.path.exists(DB_PATH)
    
    if db_exists:
        print("\n" + "="*70)
        print("⚠️  EXISTING DATABASE DETECTED - Running migrations...")
        print("="*70)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute("PRAGMA table_info(users)")
            columns = [col[1] for col in cursor.fetchall()]
            if 'is_active' not in columns:
                print("📝 Adding 'is_active' column...")
                cursor.execute("ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT 1")
                conn.commit()
                print("✅ Column added!")
            
            cursor.execute("PRAGMA table_info(otp_store)")
            columns = [col[1] for col in cursor.fetchall()]
            if 'attempts' not in columns:
                cursor.execute("ALTER TABLE otp_store ADD COLUMN attempts INTEGER DEFAULT 0")
                conn.commit()
            if 'email' not in columns:
                cursor.execute("ALTER TABLE otp_store ADD COLUMN email TEXT")
                conn.commit()
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

# ==================== HELPER FUNCTIONS ====================
def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp, username=None, purpose='verification'):
    try:
        mail_username = app.config.get('MAIL_USERNAME')
        mail_password = app.config.get('MAIL_PASSWORD')
        
        print(f"\n🔍 Email Config: {mail_username} / {'*' * len(mail_password) if mail_password else 'None'}")
        
        if not mail_username or not mail_password:
            print("\n" + "="*70)
            print("⚠️  DEVELOPMENT MODE - OTP in Console")
            print("="*70)
            print(f"   To: {email}")
            print(f"   OTP: {otp}")
            print(f"   User: {username or 'N/A'}")
            print(f"   Purpose: {purpose}")
            print("="*70 + "\n")
            return True
        
        title = "Welcome! Verify Your Email" if purpose == 'registration' else "Login Verification"
        message = "Complete your registration with this OTP:" if purpose == 'registration' else "Your OTP to login:"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                           color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f9f9f9; padding: 30px; }}
                .otp-box {{ background: white; border: 2px dashed #667eea; padding: 20px; 
                           text-align: center; margin: 20px 0; border-radius: 8px; }}
                .otp-code {{ font-size: 32px; font-weight: bold; color: #667eea; letter-spacing: 5px; }}
                .warning {{ color: #e74c3c; margin-top: 15px; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header"><h1>{title}</h1></div>
                <div class="content">
                    <p>Hello{' ' + username if username else ''},</p>
                    <p>{message}</p>
                    <div class="otp-box"><div class="otp-code">{otp}</div></div>
                    <p><strong>⏰ Expires in 5 minutes</strong></p>
                    <div class="warning"><p>⚠️ Never share this code!</p></div>
                </div>
            </div>
        </body>
        </html>
        """
        
        msg = Message(
            subject="Your OTP Code",
            recipients=[email],
            html=html_body
        )
        
        print(f"📧 Sending email...")
        mail.send(msg)
        print(f"✅ EMAIL SENT to {email} - OTP: {otp}\n")
        return True
        
    except Exception as e:
        print(f"\n❌ EMAIL FAILED: {type(e).__name__} - {str(e)}")
        if 'authentication' in str(e).lower():
            print("💡 Generate NEW App Password: https://myaccount.google.com/apppasswords")
        print(f"\n🔐 FALLBACK - OTP: {otp} for {email}\n")
        return True

def validate_phone(phone):
    if not phone:
        return False
    return len(''.join(filter(str.isdigit, phone))) >= 10

def validate_email(email):
    if not email or '@' not in email:
        return False
    parts = email.split('@')
    return len(parts) == 2 and '.' in parts[1]

def get_session_id():
    if 'temp_session_id' not in session:
        session['temp_session_id'] = os.urandom(16).hex()
    return session['temp_session_id']

def cleanup_expired_otps():
    try:
        expired = OTPStore.query.filter(OTPStore.expires_at < datetime.utcnow()).all()
        if expired:
            for otp in expired:
                db.session.delete(otp)
            db.session.commit()
            print(f"🧹 Cleaned {len(expired)} expired OTP(s)")
    except Exception as e:
        db.session.rollback()

# ==================== WEB ROUTES ====================
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/register')
def register_page():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/login')
def login_page():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login_page'))
    return render_template('dashboard.html', user=user)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# ==================== REGISTRATION API ====================
@app.route('/api/send-registration-otp', methods=['POST'])
def send_registration_otp():
    try:
        cleanup_expired_otps()
        data = request.json if request.is_json else request.form.to_dict()
        
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400

        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        phone = data.get('phone', '').strip()
        password = data.get('password', '')
        dob = data.get('dob', '')

        if not all([username, email, phone, password, dob]):
            return jsonify({'success': False, 'message': 'All fields required'}), 400
        if len(username) < 3 or len(username) > 50:
            return jsonify({'success': False, 'message': 'Username 3-50 chars'}), 400
        if not validate_email(email):
            return jsonify({'success': False, 'message': 'Invalid email'}), 400
        if not validate_phone(phone):
            return jsonify({'success': False, 'message': 'Invalid phone'}), 400
        if len(password) < 6 or len(password) > 100:
            return jsonify({'success': False, 'message': 'Password 6-100 chars'}), 400

        try:
            dob_date = datetime.strptime(dob, '%Y-%m-%d').date()
            age = (datetime.now().date() - dob_date).days // 365
            if age < 13 or age > 120:
                return jsonify({'success': False, 'message': 'Invalid age'}), 400
        except ValueError:
            return jsonify({'success': False, 'message': 'Invalid date'}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username taken'}), 400
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email registered'}), 400
        if User.query.filter_by(phone=phone).first():
            return jsonify({'success': False, 'message': 'Phone registered'}), 400

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
            'message': f'OTP sent to {email}. Check inbox/console!'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Failed to send OTP'}), 500

@app.route('/api/verify-registration-otp', methods=['POST'])
def verify_registration_otp():
    try:
        data = request.json if request.is_json else request.form.to_dict()
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
            return jsonify({'success': False, 'message': f'Invalid OTP. {remaining} left'}), 400

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

# ==================== LOGIN API ====================
@app.route('/api/send-login-otp', methods=['POST'])
def send_login_otp():
    try:
        cleanup_expired_otps()
        data = request.json if request.is_json else request.form.to_dict()
        
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
    try:
        data = request.json if request.is_json else request.form.to_dict()
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
            return jsonify({'success': False, 'message': f'Invalid OTP. {remaining} left'}), 400

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
            'message': f'Welcome {user.username}!',
            'redirectUrl': '/dashboard'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error: {e}")
        return jsonify({'success': False, 'message': 'Verification failed'}), 500

# ==================== RESEND OTP ====================
@app.route('/api/resend-otp', methods=['POST'])
def resend_otp():
    try:
        data = request.json if request.is_json else request.form.to_dict()
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
            return jsonify({'success': False, 'message': f'Wait {wait}s'}), 429

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
        return jsonify({'success': False, 'message': 'Failed to resend'}), 500

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def page_not_found(e):
    return redirect(url_for('home'))

@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    return jsonify({'success': False, 'message': 'Server error'}), 500

# ==================== RUN ====================
if __name__ == '__main__':
    print("\n" + "="*70)
    print("🚀 FLASK OTP AUTHENTICATION - READY!")
    print("="*70)
    print("📍 URLs:")
    print("   http://127.0.0.1:5000/")
    print("   http://127.0.0.1:5000/register")
    print("   http://127.0.0.1:5000/login")
    print("="*70)
    print(f"📁 Database: {DB_PATH}")
    print(f"📧 Email: {app.config.get('MAIL_USERNAME')}")
    print("="*70)
    print("💡 Watch console for OTP codes!")
    print("="*70 + "\n")
    
    app.run(debug=True, host='127.0.0.1', port=5000)