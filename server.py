from flask import Flask, request, jsonify, session, render_template, send_from_directory
from flask_cors import CORS
import json
import hashlib
import secrets
import random
import string
from datetime import datetime, timedelta
from functools import wraps
import os

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = secrets.token_hex(32)
CORS(app)

LICENSES_FILE = "licenses.json"
USERS_FILE = "users.json"

# Load data
def load_licenses():
    if os.path.exists(LICENSES_FILE):
        with open(LICENSES_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_licenses(data):
    with open(LICENSES_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    # Default admin account
    return {"admin": {"password": hashlib.sha256("admin123".encode()).hexdigest()}}

def save_users(data):
    with open(USERS_FILE, 'w') as f:
        json.dump(data, f, indent=2)

# Admin login decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('admin.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    users = load_users()
    if username in users:
        hashed = hashlib.sha256(password.encode()).hexdigest()
        if users[username]['password'] == hashed:
            session['logged_in'] = True
            session['username'] = username
            return jsonify({"success": True, "message": "Login successful"})
    
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"success": True})

@app.route('/api/check_auth', methods=['GET'])
def check_auth():
    if session.get('logged_in'):
        return jsonify({"authenticated": True, "username": session.get('username')})
    return jsonify({"authenticated": False})

@app.route('/api/generate_key', methods=['POST'])
@admin_required
def generate_key():
    data = request.json
    plan = data.get('plan', 'Basic')
    days_valid = data.get('days_valid', 30)
    
    # Generate unique key
    key = "EVAL-"
    for _ in range(3):
        key += ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
        if _ < 2:
            key += "-"
    
    licenses = load_licenses()
    licenses[key] = {
        "plan": plan,
        "created": datetime.now().isoformat(),
        "expires": (datetime.now() + timedelta(days=days_valid)).isoformat(),
        "hwid": None,
        "activated": False,
        "activated_date": None,
        "days_valid": days_valid
    }
    save_licenses(licenses)
    
    return jsonify({
        "success": True,
        "key": key,
        "plan": plan,
        "days_valid": days_valid,
        "expires": licenses[key]["expires"]
    })

@app.route('/api/validate', methods=['POST'])
def validate_key():
    data = request.json
    key = data.get('key', '').strip().upper()
    hwid = data.get('hwid', '')
    
    licenses = load_licenses()
    
    if key not in licenses:
        return jsonify({"valid": False, "error": "Invalid license key"})
    
    license_data = licenses[key]
    
    # Check expiry
    expires = datetime.fromisoformat(license_data["expires"])
    if datetime.now() > expires:
        return jsonify({"valid": False, "error": f"License expired on {expires.strftime('%Y-%m-%d')}"})
    
    # Check if activated
    if license_data.get("activated", False):
        if license_data.get("hwid") == hwid:
            remaining = (expires - datetime.now()).days
            return jsonify({
                "valid": True,
                "activated": True,
                "plan": license_data["plan"],
                "expires": license_data["expires"],
                "days_remaining": remaining,
                "message": f"Valid - {remaining} days remaining"
            })
        else:
            return jsonify({"valid": False, "error": "License already activated on another PC. Contact support."})
    
    return jsonify({
        "valid": True,
        "activated": False,
        "plan": license_data["plan"],
        "expires": license_data["expires"],
        "message": "License valid, ready to activate"
    })

@app.route('/api/activate', methods=['POST'])
def activate_key():
    data = request.json
    key = data.get('key', '').strip().upper()
    hwid = data.get('hwid', '')
    
    licenses = load_licenses()
    
    if key not in licenses:
        return jsonify({"success": False, "error": "Invalid license key"})
    
    license_data = licenses[key]
    
    # Check expiry
    expires = datetime.fromisoformat(license_data["expires"])
    if datetime.now() > expires:
        return jsonify({"success": False, "error": f"License expired on {expires.strftime('%Y-%m-%d')}"})
    
    # Check if already activated
    if license_data.get("activated", False):
        if license_data.get("hwid") == hwid:
            remaining = (expires - datetime.now()).days
            return jsonify({
                "success": True,
                "activated": True,
                "plan": license_data["plan"],
                "days_remaining": remaining,
                "message": "Already activated on this PC"
            })
        else:
            return jsonify({"success": False, "error": "License already activated on another PC. Contact support."})
    
    # Activate
    license_data["activated"] = True
    license_data["hwid"] = hwid
    license_data["activated_date"] = datetime.now().isoformat()
    save_licenses(licenses)
    
    remaining = (expires - datetime.now()).days
    return jsonify({
        "success": True,
        "activated": True,
        "plan": license_data["plan"],
        "days_remaining": remaining,
        "message": "License activated successfully"
    })

@app.route('/api/list_licenses', methods=['GET'])
@admin_required
def list_licenses():
    licenses = load_licenses()
    return jsonify(licenses)

@app.route('/api/delete_key', methods=['POST'])
@admin_required
def delete_key():
    data = request.json
    key = data.get('key')
    licenses = load_licenses()
    if key in licenses:
        del licenses[key]
        save_licenses(licenses)
        return jsonify({"success": True})
    return jsonify({"error": "Key not found"}), 404

@app.route('/api/reset_key', methods=['POST'])
@admin_required
def reset_key():
    data = request.json
    key = data.get('key')
    licenses = load_licenses()
    if key in licenses:
        licenses[key]["activated"] = False
        licenses[key]["hwid"] = None
        licenses[key]["activated_date"] = None
        save_licenses(licenses)
        return jsonify({"success": True})
    return jsonify({"error": "Key not found"}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
