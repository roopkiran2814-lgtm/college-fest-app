import os
import sqlite3
import pandas as pd
import qrcode
import io
import base64
from datetime import datetime
import secrets
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session, g, jsonify
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# --- Configuration ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app.config['DATABASE'] = 'college_fest.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- Credentials & API Keys from Environment ---
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'password')
SCANNER_USERNAME = os.environ.get('SCANNER_USERNAME', 'guard')
SCANNER_PASSWORD = os.environ.get('SCANNER_PASSWORD', 'password')
QR_CODE_BASE_URL = os.environ.get('QR_CODE_BASE_URL', 'http://127.0.0.1:5000')

# --- Database Functions ---

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        # This assumes schema.sql is in the same directory.
        # Ensure you have created schema.sql on the server.
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# --- Decorators for Authentication ---

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def scanner_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('scanner_logged_in'):
            flash('Please log in as a scanner to access this page.', 'warning')
            return redirect(url_for('scanner_login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Authentication Routes ---

@app.route('/')
def index():
    return redirect(url_for('admin_login'))

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'error')
    return render_template('admin_login.html')

@app.route('/admin_logout')
def admin_logout():
    session.pop('logged_in', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('admin_login'))

@app.route('/scanner_login', methods=['GET', 'POST'])
def scanner_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == SCANNER_USERNAME and password == SCANNER_PASSWORD:
            session['scanner_logged_in'] = True
            return redirect(url_for('scanner_page'))
        else:
            flash('Invalid scanner credentials.', 'error')
    return render_template('scanner_login.html')

@app.route('/scanner_logout')
def scanner_logout():
    session.pop('scanner_logged_in', None)
    flash('Scanner logged out.', 'info')
    return redirect(url_for('scanner_login'))

# --- Core Application Routes ---

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    attendees = db.execute('SELECT * FROM attendees ORDER BY name').fetchall()
    return render_template('dashboard.html', attendees=attendees)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('dashboard'))
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('dashboard'))
    if file and file.filename.endswith('.xlsx'):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        try:
            df = pd.read_excel(filepath, dtype={'roll_number': str})
            db = get_db()
            cursor = db.cursor()
            for index, row in df.iterrows():
                cursor.execute(
                    'INSERT OR REPLACE INTO attendees (name, batch, roll_number, designation, email) VALUES (?, ?, ?, ?, ?)',
                    (row['name'], row['batch'], row['roll_number'], row['designation'], row['email'])
                )
            db.commit()
            flash('Attendee data uploaded and saved successfully!', 'success')
        except Exception as e:
            flash(f'Error processing Excel file: {e}', 'error')
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid file type. Please upload a .xlsx file.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/generate_qrs', methods=['POST'])
@login_required
def generate_qrs():
    data = request.get_json()
    event_type = data.get('event_type')
    event_datetime_str = data.get('event_datetime')

    if not event_type or not event_datetime_str:
        return jsonify({'status': 'error', 'message': 'Missing event type or datetime'}), 400

    try:
        event_datetime = datetime.strptime(event_datetime_str, '%Y-%m-%d %H:%M')
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Invalid datetime format. Use YYYY-MM-DD HH:MM'}), 400

    db = get_db()
    attendees = db.execute('SELECT id, designation FROM attendees').fetchall()
    
    count = 0
    for attendee in attendees:
        unique_qr_string = secrets.token_urlsafe(16)
        is_multi_entry = 1 if str(attendee['designation']).lower() in ['organizer', 'staff', 'security'] else 0
        db.execute(
            'INSERT INTO qr_codes (attendee_id, event_type, unique_qr_string, is_multi_entry, event_datetime) VALUES (?, ?, ?, ?, ?)',
            (attendee['id'], event_type, unique_qr_string, is_multi_entry, event_datetime)
        )
        count += 1
    
    db.commit()
    return jsonify({'status': 'success', 'message': f'Successfully generated {count} QR codes for {event_type}.'})

@app.route('/scanner')
@scanner_login_required
def scanner_page():
    return render_template('scanner.html')

@app.route('/validate_qr/<unique_qr_string>')
def validate_qr(unique_qr_string):
    db = get_db()
    qr_code = db.execute(
        'SELECT * FROM qr_codes WHERE unique_qr_string = ?', (unique_qr_string,)
    ).fetchone()

    if not qr_code:
        return jsonify({'valid': False, 'message': 'QR code not found', 'status': 'error'}), 404

    attendee = db.execute(
        'SELECT * FROM attendees WHERE id = ?', (qr_code['attendee_id'],)
    ).fetchone()
    
    attendee_info = dict(attendee) if attendee else {}

    now = datetime.now()
    event_time = datetime.strptime(qr_code['event_datetime'], '%Y-%m-%d %H:%M:%S')
    expiry_time = event_time.replace(hour=22, minute=0, second=0)

    if now < event_time:
        return jsonify({'valid': False, 'message': 'QR Code is not yet active', 'status': 'invalid', 'attendee_info': attendee_info}), 403
    
    if now > expiry_time:
        return jsonify({'valid': False, 'message': 'QR Code has expired', 'status': 'invalid', 'attendee_info': attendee_info}), 403

    if qr_code['scanned_at'] and not qr_code['is_multi_entry']:
        return jsonify({'valid': False, 'message': 'QR code already scanned', 'status': 'invalid', 'attendee_info': attendee_info}), 409

    if not qr_code['is_multi_entry']:
        db.execute(
            'UPDATE qr_codes SET scanned_at = ? WHERE id = ?', (datetime.now(), qr_code['id'])
        )
        db.commit()

    return jsonify({'valid': True, 'message': 'Entry Granted!', 'status': 'valid', 'attendee_info': attendee_info})
