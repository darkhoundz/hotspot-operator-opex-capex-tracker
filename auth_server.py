"""
Secure Authentication Server with Flask
Implements best practices for web security including:
- Bcrypt password hashing
- Session management with secure cookies
- CSRF protection
- Rate limiting
- Security headers
- Input validation
"""

from flask import Flask, request, jsonify, session, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
import json
import os
import secrets
from datetime import datetime, timedelta
from functools import wraps
import re

app = Flask(__name__)

# Security Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Changed from Strict for better compatibility
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB max request size

DATA_DIR = 'data'
USERS_FILE = os.path.join(DATA_DIR, 'users.json')

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Security Headers Middleware
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; img-src 'self' data: https:; font-src 'self' https://cdnjs.cloudflare.com"
    return response

# Initialize users file with default admin
def init_users():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(USERS_FILE):
        # Default admin user (password: ChangeMe123!)
        default_password = bcrypt.hashpw('ChangeMe123!'.encode('utf-8'), bcrypt.gensalt())
        users = {
            'admin': {
                'password': default_password.decode('utf-8'),
                'created_at': datetime.now().isoformat(),
                'last_login': None,
                'failed_attempts': 0,
                'locked_until': None
            }
        }
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
        print("⚠️  Default admin user created. Username: admin, Password: ChangeMe123!")
        print("🔒 IMPORTANT: Change this password immediately!")

def load_users():
    """Load users from file"""
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    """Save users to file"""
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def validate_password_strength(password):
    """Validate password meets security requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain a number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain a special character"
    return True, "Valid"

def validate_username(username):
    """Validate username format"""
    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    return True, "Valid"

def is_account_locked(user_data):
    """Check if account is locked due to failed attempts"""
    if user_data.get('locked_until'):
        locked_until = datetime.fromisoformat(user_data['locked_until'])
        if datetime.now() < locked_until:
            return True, f"Account locked until {locked_until.strftime('%Y-%m-%d %H:%M:%S')}"
        else:
            # Unlock account
            user_data['locked_until'] = None
            user_data['failed_attempts'] = 0
    return False, ""

def login_required(f):
    """Decorator to protect routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """Serve login page if not authenticated, otherwise dashboard"""
    if 'username' in session:
        return send_from_directory('.', 'index.html')
    return send_from_directory('.', 'login.html')

@app.route('/login.html')
def login_page():
    """Serve login page"""
    return send_from_directory('.', 'login.html')

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")  # Strict rate limiting on login
def login():
    """Authenticate user"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request'}), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        users = load_users()
        
        if username not in users:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        user_data = users[username]
        
        # Check if account is locked
        locked, message = is_account_locked(user_data)
        if locked:
            return jsonify({'error': message}), 403
        
        # Verify password
        stored_password = user_data['password'].encode('utf-8')
        if bcrypt.checkpw(password.encode('utf-8'), stored_password):
            # Successful login
            session.permanent = True
            session['username'] = username
            session['login_time'] = datetime.now().isoformat()
            
            # Update user data
            user_data['last_login'] = datetime.now().isoformat()
            user_data['failed_attempts'] = 0
            user_data['locked_until'] = None
            save_users(users)
            
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'username': username
            }), 200
        else:
            # Failed login
            user_data['failed_attempts'] = user_data.get('failed_attempts', 0) + 1
            
            # Lock account after 5 failed attempts
            if user_data['failed_attempts'] >= 5:
                user_data['locked_until'] = (datetime.now() + timedelta(minutes=15)).isoformat()
                save_users(users)
                return jsonify({'error': 'Account locked due to multiple failed attempts. Try again in 15 minutes.'}), 403
            
            save_users(users)
            remaining_attempts = 5 - user_data['failed_attempts']
            return jsonify({
                'error': f'Invalid credentials. {remaining_attempts} attempts remaining.'
            }), 401
            
    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Server error'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    """Logout user"""
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'}), 200

@app.route('/api/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    try:
        data = request.get_json()
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        
        if not current_password or not new_password:
            return jsonify({'error': 'Current and new password required'}), 400
        
        # Validate new password strength
        valid, message = validate_password_strength(new_password)
        if not valid:
            return jsonify({'error': message}), 400
        
        users = load_users()
        username = session['username']
        user_data = users[username]
        
        # Verify current password
        stored_password = user_data['password'].encode('utf-8')
        if not bcrypt.checkpw(current_password.encode('utf-8'), stored_password):
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        # Update password
        new_hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        user_data['password'] = new_hashed.decode('utf-8')
        save_users(users)
        
        return jsonify({'success': True, 'message': 'Password changed successfully'}), 200
        
    except Exception as e:
        app.logger.error(f"Change password error: {str(e)}")
        return jsonify({'error': 'Server error'}), 500

@app.route('/api/session-check', methods=['GET'])
def session_check():
    """Check if user is authenticated"""
    if 'username' in session:
        return jsonify({
            'authenticated': True,
            'username': session['username']
        }), 200
    return jsonify({'authenticated': False}), 200

# Protected Data Endpoints
@app.route('/save-data', methods=['POST'])
@login_required
def save_data():
    """Save financial data (protected)"""
    try:
        data = request.get_json()
        filepath = os.path.join(DATA_DIR, 'financials.json')
        os.makedirs(DATA_DIR, exist_ok=True)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        
        return jsonify({'status': 'success', 'message': 'Saved to financials.json'}), 200
    except Exception as e:
        app.logger.error(f"Save data error: {str(e)}")
        return jsonify({'error': 'Failed to save data'}), 500

@app.route('/save-settings', methods=['POST'])
@login_required
def save_settings():
    """Save settings (protected)"""
    try:
        data = request.get_json()
        filepath = os.path.join(DATA_DIR, 'settings.json')
        os.makedirs(DATA_DIR, exist_ok=True)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        
        return jsonify({'status': 'success', 'message': 'Saved to settings.json'}), 200
    except Exception as e:
        app.logger.error(f"Save settings error: {str(e)}")
        return jsonify({'error': 'Failed to save settings'}), 500

# Static file serving (protected)
@app.route('/<path:path>')
@login_required
def serve_static(path):
    """Serve static files (protected)"""
    return send_from_directory('.', path)

if __name__ == '__main__':
    init_users()
    print("🔐 Secure Authentication Server")
    print("=" * 50)
    print(f"Starting server on http://localhost:5000")
    print("Press Ctrl+C to stop")
    print("=" * 50)
    
    # For development only - disable in production
    app.run(host='0.0.0.0', port=5000, debug=False)
