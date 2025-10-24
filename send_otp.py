from flask import Flask, request, jsonify, send_from_directory
import random
import time
import yagmail
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ==== Email Credentials (use App Password) ====
EMAIL_USER = 'your_email@gmail.com'  # ✅ Replace with your Gmail
EMAIL_PASS = 'your_app_password'     # ✅ Replace with your 16-digit app password (no spaces)

yag = yagmail.SMTP(EMAIL_USER, EMAIL_PASS)

# ==== Store OTPs in memory ====
otp_store = {}  # Format: {email: (otp, expiry_time)}

# ==== Serve index.html ====
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

# ==== Send Email OTP ====
@app.route('/send-email-otp', methods=['POST'])
def send_email_otp():
    data = request.json
    email = data['email']

    otp = str(random.randint(100000, 999999))
    expiry_time = time.time() + 300  # OTP valid for 5 minutes
    otp_store[email] = (otp, expiry_time)

    try:
        yag.send(
            to=email,
            subject="Your OTP for Registration",
            contents=f"🔐 Your OTP is: {otp}\n\nIt is valid for 5 minutes."
        )
        return jsonify({'message': '✅ OTP sent to your email successfully'})
    except Exception as e:
        return jsonify({'message': f'❌ Failed to send OTP: {str(e)}'})

# ==== Verify Email OTP ====
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    email = data['id']
    entered_otp = data['otp']

    if email not in otp_store:
        return jsonify({'verified': False, 'message': '❌ OTP not found. Please request again.'})

    actual_otp, expiry_time = otp_store[email]
    if time.time() > expiry_time:
        del otp_store[email]
        return jsonify({'verified': False, 'message': '❌ OTP expired. Please request a new one.'})

    if entered_otp == actual_otp:
        del otp_store[email]
        return jsonify({'verified': True, 'message': '✅ OTP verified successfully!'})
    else:
        return jsonify({'verified': False, 'message': '❌ Incorrect OTP'})

# ==== Run the server ====
if __name__ == '__main__':
    app.run(debug=True)
