from flask import Flask, render_template, request, jsonify, Response, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import pickle
import pandas as pd
import numpy as np
import os
import io
import random
import csv
from datetime import datetime
import pyotp
import qrcode
import base64

# ReportLab for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

app = Flask(__name__)
app.secret_key = 'super_secret_cybersecurity_key_change_in_production'

# --- Database Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- User Database Model ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    totp_secret = db.Column(db.String(32), nullable=False)
    is_2fa_setup = db.Column(db.Boolean, default=False)

# --- Load ML Model and Scaler ---
MODEL_PATH = 'model/model.pkl'
SCALER_PATH = 'model/scaler.pkl'

if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    with open(SCALER_PATH, 'rb') as f:
        scaler = pickle.load(f)
else:
    print("Warning: Model or Scaler not found. Run train_model.py first.")

# --- ISOLATED USER DATA DICTIONARY ---
# This replaces the single global dictionary so users don't share data.
user_predictions = {}

def get_user_data(username):
    # If the user doesn't have a data bucket yet, create one for them.
    if username not in user_predictions:
        user_predictions[username] = {
            'total': 0, 'normal': 0, 'attack': 0, 
            'recent': [], 'history': [],
            'trend_labels': [], 'trend_data': []
        }
    return user_predictions[username]

# --- Authentication Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'): return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- XAI, Severity, and Confidence Logic ---
def get_explanation(features, prediction_result):
    if prediction_result == "Normal": return "None", "Traffic within expected parameters."
    reasons = []
    if features['duration'] > 10: reasons.append("Abnormal duration")
    if features['src_bytes'] > 2000: reasons.append("High source bytes")
    if features['count'] > 50: reasons.append("Unusual connection count")
    if features['dst_bytes'] < 50 and features['src_bytes'] > 1000: reasons.append("Suspicious payload ratio")
    reason_str = ", ".join(reasons) if reasons else "Anomalous multivariate pattern detected"
    
    if features['count'] > 100: attack_type = "DoS"
    elif features['count'] > 20 and features['duration'] > 5: attack_type = "Probe"
    elif features['src_bytes'] > 5000 and features['dst_bytes'] < 100: attack_type = "R2L"
    else: attack_type = "U2R"
    return attack_type, reason_str

def get_severity(features, prediction):
    if prediction == "Normal": return "Low"
    if features['count'] > 100 or features['duration'] > 30 or features['src_bytes'] > 8000:
        return "High"
    elif features['count'] > 50 or features['src_bytes'] > 4000:
        return "Medium"
    return "Low"

def get_confidence(score):
    conf = min(50 + (abs(score) * 100), 99.9)
    return round(conf, 2)

def predict_packet(features_dict, username):
    """Core function to process a single packet, scale it, and predict."""
    clean_features = {
        'duration': float(features_dict.get('duration', 0)), 
        'src_bytes': float(features_dict.get('src_bytes', 0)), 
        'dst_bytes': float(features_dict.get('dst_bytes', 0)), 
        'count': float(features_dict.get('count', 0)), 
        'srv_count': float(features_dict.get('srv_count', 0))
    }
    
    features_list = list(clean_features.values())
    scaled_features = scaler.transform([features_list])
    
    prediction_val = model.predict(scaled_features)[0]
    score = model.decision_function(scaled_features)[0]
    
    result = "Normal" if prediction_val == 1 else "Attack"
    attack_type, reason = get_explanation(clean_features, result)
    severity = get_severity(clean_features, result)
    confidence = get_confidence(score)
    timestamp = datetime.now().strftime('%H:%M:%S')
    
    # Grab the specific user's bucket
    db_predictions = get_user_data(username)
    
    db_predictions['total'] += 1
    if result == "Attack": db_predictions['attack'] += 1
    else: db_predictions['normal'] += 1
    
    record = {
        "timestamp": timestamp, "features": clean_features, "result": result, 
        "attack_type": attack_type, "reason": reason, "severity": severity, "confidence": confidence
    }
    
    db_predictions['history'].append(record)
    db_predictions['recent'].insert(0, record)
    if len(db_predictions['recent']) > 15: db_predictions['recent'].pop()
    
    db_predictions['trend_labels'].append(timestamp)
    db_predictions['trend_data'].append(db_predictions['attack'])
    if len(db_predictions['trend_labels']) > 20: 
        db_predictions['trend_labels'].pop(0)
        db_predictions['trend_data'].pop(0)
        
    return record

# --- Authentication Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # 1. Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error="Username already exists. Please choose another.")

        # 2. Securely hash password and generate 2FA secret
        hashed_pw = generate_password_hash(password)
        totp_secret = pyotp.random_base32()

        # 3. Save new user to SQLite Database
        new_user = User(username=username, password_hash=hashed_pw, totp_secret=totp_secret)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login', message="Registration successful! Please log in."))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = request.args.get('message') # Catch success messages from registration
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Query database for user
        user = User.query.filter_by(username=username).first()
        
        # Validate User and Verify Password Hash
        if user and check_password_hash(user.password_hash, password):
            session['username'] = user.username
            session['pre_2fa'] = True
            return redirect(url_for('verify_2fa' if user.is_2fa_setup else 'setup_2fa'))
            
        return render_template('login.html', error="Invalid username or password.")
        
    return render_template('login.html', message=message)

@app.route('/setup_2fa', methods=['GET', 'POST'])
def setup_2fa():
    if not session.get('pre_2fa'): return redirect(url_for('login'))
    
    user = User.query.filter_by(username=session['username']).first()
    
    if request.method == 'POST':
        if pyotp.TOTP(user.totp_secret).verify(request.form.get('otp')):
            # Mark 2FA as complete in database
            user.is_2fa_setup = True
            db.session.commit()
            
            session['logged_in'] = True
            session.pop('pre_2fa', None)
            return redirect(url_for('index'))
        return render_template('setup_2fa.html', error="Invalid code.", secret=user.totp_secret)
        
    img = qrcode.make(pyotp.totp.TOTP(user.totp_secret).provisioning_uri(name=f"{user.username}@core-ids", issuer_name="Core-IDS"))
    buf = io.BytesIO()
    img.save(buf)
    return render_template('setup_2fa.html', qr_code=base64.b64encode(buf.getvalue()).decode('utf-8'), secret=user.totp_secret)

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if not session.get('pre_2fa'): return redirect(url_for('login'))
    
    user = User.query.filter_by(username=session['username']).first()
    
    if request.method == 'POST':
        if pyotp.TOTP(user.totp_secret).verify(request.form.get('otp')):
            session['logged_in'] = True
            session.pop('pre_2fa', None)
            return redirect(url_for('index'))
        return render_template('verify_2fa.html', error="Invalid code.")
    return render_template('verify_2fa.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- IDS Application Routes ---
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Pass the isolated data bucket for the logged-in user
    user_stats = get_user_data(session['username'])
    return render_template('dashboard.html', stats=user_stats)

@app.route('/predict_manual', methods=['POST'])
@login_required
def predict_manual():
    try:
        # Pass the username into the predictor
        return jsonify({'status': 'success', 'data': predict_packet(request.json, session['username'])})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/predict_file', methods=['POST'])
@login_required
def predict_file():
    try:
        file = request.files.get('file')
        if not file or file.filename == '': 
            return jsonify({'status': 'error', 'message': 'No selected file'})
            
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        df = pd.read_csv(stream)
        
        required_cols = ['duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count']
        if not all(col in df.columns for col in required_cols):
            return jsonify({'status': 'error', 'message': f'CSV must contain columns: {", ".join(required_cols)}'})
            
        attack_count, normal_count = 0, 0
        for _, row in df.iterrows():
            # Pass the username into the predictor
            record = predict_packet(row.to_dict(), session['username'])
            if record['result'] == 'Attack': attack_count += 1
            else: normal_count += 1
                
        return jsonify({'status': 'success', 'message': f'Batch Processed. Attacks: {attack_count} | Normal: {normal_count}'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/simulate', methods=['GET'])
@login_required
def simulate_traffic():
    is_attack = random.choice([True, False, False, False])
    data = {'duration': round(random.uniform(10, 60), 2), 'src_bytes': round(random.uniform(5000, 15000), 2), 'dst_bytes': round(random.uniform(0, 50), 2), 'count': random.randint(50, 200), 'srv_count': random.randint(50, 200)} if is_attack else {'duration': round(random.uniform(0.1, 2.0), 2), 'src_bytes': round(random.uniform(100, 300), 2), 'dst_bytes': round(random.uniform(1000, 4000), 2), 'count': random.randint(1, 10), 'srv_count': random.randint(1, 10)}
    
    # Process the packet for this specific user
    record = predict_packet(data, session['username'])
    user_stats = get_user_data(session['username'])
    
    return jsonify({'status': 'success', 'record': record, 'stats': user_stats})

@app.route('/download_pdf')
@login_required
def download_pdf():
    # Grab the isolated data for the PDF
    db_predictions = get_user_data(session['username'])
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    elements = []
    styles = getSampleStyleSheet()
    
    elements.append(Paragraph("<b>Core-IDS: Threat Detection Report</b>", styles['Title']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"<b>Total Packets:</b> {db_predictions['total']} | <b>Normal:</b> {db_predictions['normal']} | <b>Attacks:</b> {db_predictions['attack']}", styles['Normal']))
    elements.append(Spacer(1, 12))
    
    data = [["Time", "Type", "Status", "Conf.", "Severity", "XAI Reason"]]
    wrap_style = styles['Normal']
    wrap_style.fontSize = 9
    wrap_style.leading = 11 
    
    for r in db_predictions['history'][-50:]: 
        wrapped_reason = Paragraph(r['reason'], wrap_style)
        data.append([r['timestamp'], r['attack_type'], r['result'], f"{r['confidence']}%", r['severity'], wrapped_reason])
        
    table = Table(data, colWidths=[50, 50, 50, 50, 60, 280])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'), 
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    elements.append(table)
    doc.build(elements)
    buffer.seek(0)
    return Response(buffer, mimetype='application/pdf', headers={'Content-Disposition': 'attachment;filename=ids_report.pdf'})

# Initialize the Database before running the app
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, port=5000)