import os
import sqlite3
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SelectField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import uuid
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
import requests
import json
import time
import psutil
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SESSION_SECRET')
if not app.config['SECRET_KEY']:
    raise ValueError('SESSION_SECRET environment variable must be set')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png'}
# Session security settings (conditional for development)
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)  # 2-hour session timeout

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Create uploads directory
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = None
login_manager.session_protection = "strong"

# Database setup
DATABASE = 'disciplinary_system.db'
EXONERATED_DATABASE = 'exonerated_cases.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    # Enable foreign key constraints
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

def get_exonerated_db_connection():
    conn = sqlite3.connect(EXONERATED_DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

def migrate_db():
    """Migrate existing database to new schema"""
    conn = get_db_connection()

    # Check if migration is needed
    cursor = conn.execute("PRAGMA table_info(cases)")
    columns = [row[1] for row in cursor.fetchall()]

    # If we still have the old case_type column, we need to recreate the table
    if 'case_type' in columns:
        print("Migrating database schema...")

        # First ensure case_types table exists and has data
        case_types_exist = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='case_types'").fetchone()
        if not case_types_exist:
            # Create case_types table first
            conn.execute('''
                CREATE TABLE case_types (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT,
                    severity_level INTEGER DEFAULT 1
                )
            ''')

            # Insert default case types
            case_types = [
                ('Academic Misconduct', 'Cheating, plagiarism, or other academic violations', 3),
                ('Bullying', 'Physical or verbal harassment of other students', 3),
                ('Disruptive Behavior', 'Behavior that disrupts the learning environment', 2),
                ('Violation of Code of Conduct', 'General violations of institutional policies', 2),
                ('Substance Abuse', 'Use or possession of illegal substances on campus', 3),
                ('Vandalism', 'Damage to institutional property', 2),
                ('Theft', 'Stealing institutional or personal property', 3),
                ('Absenteeism', 'Excessive unexcused absences', 1)
            ]

            for case_type in case_types:
                conn.execute('''
                    INSERT OR IGNORE INTO case_types (name, description, severity_level)
                    VALUES (?, ?, ?)
                ''', case_type)

        # Get default case type
        default_case_type = conn.execute('SELECT id FROM case_types LIMIT 1').fetchone()
        default_case_type_id = default_case_type['id'] if default_case_type else 1

        # Create new cases table with correct schema
        conn.execute('''
            CREATE TABLE cases_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_number TEXT UNIQUE NOT NULL,
                student_reg_number TEXT NOT NULL,
                reported_by INTEGER NOT NULL,
                case_type_id INTEGER NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                case_file TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (student_reg_number) REFERENCES students (reg_number) ON DELETE CASCADE,
                FOREIGN KEY (reported_by) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (case_type_id) REFERENCES case_types (id) ON DELETE RESTRICT
            )
        ''')

        # Copy existing data, using default case type for all records
        try:
            conn.execute('''
                INSERT INTO cases_new (id, case_number, student_reg_number, reported_by, case_type_id, description, status, case_file, created_at, updated_at)
                SELECT id, case_number, student_reg_number, reported_by, ?, description, status, case_file, created_at, updated_at
                FROM cases
            ''', (default_case_type_id,))
        except:
            # If there's any issue with existing data, just create the new table
            print("No existing cases to migrate")

        # Drop old table and rename new one
        conn.execute('DROP TABLE IF EXISTS cases')
        conn.execute('ALTER TABLE cases_new RENAME TO cases')

        # Recreate indexes
        conn.execute('CREATE INDEX IF NOT EXISTS idx_cases_student ON cases(student_reg_number)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_cases_created ON cases(created_at)')

        conn.commit()
        print("Database migration completed.")

    conn.close()

def init_exonerated_db():
    """Initialize the exonerated cases database"""
    conn = get_exonerated_db_connection()

    # Exonerated cases table - stores complete case information
    conn.execute('''
        CREATE TABLE IF NOT EXISTS exonerated_cases (
            id INTEGER PRIMARY KEY,
            case_number TEXT UNIQUE NOT NULL,
            student_reg_number TEXT NOT NULL,
            student_first_name TEXT,
            student_last_name TEXT,
            student_email TEXT,
            reported_by_username TEXT,
            case_type_name TEXT,
            description TEXT NOT NULL,
            case_file TEXT,
            original_created_at TIMESTAMP,
            exonerated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            exonerated_by INTEGER,
            exoneration_reason TEXT
        )
    ''')

    # Create index for fast lookup
    conn.execute('CREATE INDEX IF NOT EXISTS idx_exonerated_reg_number ON exonerated_cases(student_reg_number)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_exonerated_case_number ON exonerated_cases(case_number)')

    conn.commit()
    conn.close()

def init_db():
    conn = get_db_connection()

    # Users table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student',
            department TEXT,
            can_give_verdict BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')

    # Add columns if they don't exist (for existing databases)
    try:
        conn.execute('ALTER TABLE users ADD COLUMN can_give_verdict BOOLEAN DEFAULT 0')
    except sqlite3.OperationalError:
        pass  # Column already exists

    try:
        conn.execute('ALTER TABLE users ADD COLUMN department TEXT')
    except sqlite3.OperationalError:
        pass  # Column already exists

    try:
        conn.execute('ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass  # Column already exists

    try:
        conn.execute('ALTER TABLE users ADD COLUMN locked_until TIMESTAMP NULL')
    except sqlite3.OperationalError:
        pass  # Column already exists

    try:
        conn.execute('ALTER TABLE users ADD COLUMN temp_password_hash TEXT NULL')
    except sqlite3.OperationalError:
        pass  # Column already exists

    try:
        conn.execute('ALTER TABLE users ADD COLUMN temp_password_expiry TIMESTAMP NULL')
    except sqlite3.OperationalError:
        pass  # Column already exists

    # Students table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS students (
            reg_number TEXT PRIMARY KEY,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            department TEXT,
            year_of_study INTEGER,
            phone TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')

    # Case types table (create this BEFORE cases table due to foreign key constraint)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS case_types (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            severity_level INTEGER DEFAULT 1
        )
    ''')

    # Cases table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_number TEXT UNIQUE NOT NULL,
            student_reg_number TEXT NOT NULL,
            reported_by INTEGER NOT NULL,
            case_type_id INTEGER NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            case_file TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_reg_number) REFERENCES students (reg_number) ON DELETE CASCADE,
            FOREIGN KEY (reported_by) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (case_type_id) REFERENCES case_types (id) ON DELETE RESTRICT
        )
    ''')

    # Insert default case types
    case_types = [
        ('Academic Misconduct', 'Cheating, plagiarism, or other academic violations', 3),
        ('Bullying', 'Physical or verbal harassment of other students', 3),
        ('Disruptive Behavior', 'Behavior that disrupts the learning environment', 2),
        ('Violation of Code of Conduct', 'General violations of institutional policies', 2),
        ('Substance Abuse', 'Use or possession of illegal substances on campus', 3),
        ('Vandalism', 'Damage to institutional property', 2),
        ('Theft', 'Stealing institutional or personal property', 3),
        ('Absenteeism', 'Excessive unexcused absences', 1)
    ]

    for case_type in case_types:
        conn.execute('''
            INSERT OR IGNORE INTO case_types (name, description, severity_level)
            VALUES (?, ?, ?)
        ''', case_type)

    # Create default admin user
    admin_password = generate_password_hash('admin123')
    conn.execute('''
        INSERT OR IGNORE INTO users (username, email, password_hash, role)
        VALUES (?, ?, ?, ?)
    ''', ('admin', 'admin@system.edu', admin_password, 'admin'))

    # Email settings table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS email_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            smtp_server TEXT NOT NULL DEFAULT 'smtp.gmail.com',
            smtp_port INTEGER NOT NULL DEFAULT 587,
            email_address TEXT NOT NULL,
            email_password TEXT NOT NULL,
            sender_name TEXT DEFAULT 'Disciplinary Management System',
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Email tracking/log table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS email_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_email TEXT NOT NULL,
            recipient_type TEXT NOT NULL,
            subject TEXT NOT NULL,
            message TEXT NOT NULL,
            sent_status TEXT DEFAULT 'pending',
            error_message TEXT,
            case_number TEXT,
            sent_by INTEGER,
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sent_by) REFERENCES users (id)
        )
    ''')

    # Audit logs table for advanced tracking
    conn.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id TEXT,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # Calendar events table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS calendar_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            event_type TEXT NOT NULL DEFAULT 'hearing',
            case_id INTEGER,
            start_datetime DATETIME NOT NULL,
            end_datetime DATETIME NOT NULL,
            location TEXT,
            attendees TEXT,
            created_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (case_id) REFERENCES cases (id),
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
    ''')

    # Performance monitoring table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS performance_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint TEXT NOT NULL,
            method TEXT NOT NULL,
            response_time REAL NOT NULL,
            status_code INTEGER NOT NULL,
            user_id INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # API requests log table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS api_requests_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint TEXT NOT NULL,
            method TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            request_data TEXT,
            response_status INTEGER,
            reg_number_checked TEXT,
            requesting_domain TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # System settings table for admin recovery email and other system configurations
    conn.execute('''
        CREATE TABLE IF NOT EXISTS system_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            setting_key TEXT UNIQUE NOT NULL,
            setting_value TEXT,
            description TEXT,
            updated_by INTEGER,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (updated_by) REFERENCES users (id)
        )
    ''')

    # Create indexes for better performance
    conn.execute('CREATE INDEX IF NOT EXISTS idx_cases_student ON cases(student_reg_number)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_cases_created ON cases(created_at)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_students_reg ON students(reg_number)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_calendar_case ON calendar_events(case_id)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_performance_endpoint ON performance_logs(endpoint)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_api_requests_timestamp ON api_requests_log(timestamp)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_api_requests_ip ON api_requests_log(ip_address)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_api_requests_domain ON api_requests_log(requesting_domain)')

    conn.commit()
    conn.close()

# Audit logging functions
def log_audit_action(action, resource_type=None, resource_id=None, details=None):
    """Log user actions for audit trail"""
    try:
        user_id = getattr(current_user, 'id', None) if current_user.is_authenticated else None
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))
        user_agent = request.headers.get('User-Agent', '')[:500]  # Limit length
        
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO audit_logs (user_id, action, resource_type, resource_id, details, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, action, resource_type, resource_id, details, ip_address, user_agent))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Failed to log audit action: {str(e)}")

def log_api_request(endpoint, method, ip_address, user_agent, request_data, response_status, reg_number=None, domain=None):
    """Log API requests for monitoring"""
    try:
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO api_requests_log (endpoint, method, ip_address, user_agent, request_data, response_status, reg_number_checked, requesting_domain)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (endpoint, method, ip_address, user_agent[:1000], str(request_data)[:2000], response_status, reg_number, domain))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Failed to log API request: {str(e)}")

# Performance monitoring decorator
def monitor_performance(f):
    """Decorator to monitor endpoint performance"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = time.time()
        try:
            result = f(*args, **kwargs)
            status_code = getattr(result, 'status_code', 200)
        except Exception as e:
            status_code = 500
            raise e
        finally:
            end_time = time.time()
            response_time = (end_time - start_time) * 1000  # Convert to milliseconds
            
            # Log performance data
            try:
                user_id = getattr(current_user, 'id', None) if current_user.is_authenticated else None
                conn = get_db_connection()
                conn.execute('''
                    INSERT INTO performance_logs (endpoint, method, response_time, status_code, user_id)
                    VALUES (?, ?, ?, ?, ?)
                ''', (request.endpoint, request.method, response_time, status_code, user_id))
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"Failed to log performance data: {str(e)}")
        
        return result
    return decorated_function

# Email functions
def get_email_settings():
    """Get active email settings"""
    conn = get_db_connection()
    settings = conn.execute(
        'SELECT * FROM email_settings WHERE is_active = 1 ORDER BY updated_at DESC LIMIT 1'
    ).fetchone()
    conn.close()
    return settings

def create_email_log(recipient_email, recipient_type, subject, message, sent_status, error_message=None, case_number=None, sent_by=None):
    """Create email log entry and return the log ID"""
    try:
        conn = get_db_connection()
        cursor = conn.execute('''
            INSERT INTO email_logs (recipient_email, recipient_type, subject, message, sent_status, error_message, case_number, sent_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (recipient_email, recipient_type, subject, message, sent_status, error_message, case_number, sent_by))
        log_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return log_id
    except Exception as e:
        print(f"Failed to create email log: {str(e)}")
        return None

def update_email_log(log_id, sent_status, error_message=None):
    """Update existing email log with status and error details"""
    try:
        if log_id:
            conn = get_db_connection()
            conn.execute('''
                UPDATE email_logs 
                SET sent_status = ?, error_message = ?, sent_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (sent_status, error_message, log_id))
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"Failed to update email log: {str(e)}")

def log_email(recipient_email, recipient_type, subject, message, sent_status, error_message=None, case_number=None, sent_by=None):
    """Legacy function - create email log entry (for backward compatibility)"""
    return create_email_log(recipient_email, recipient_type, subject, message, sent_status, error_message, case_number, sent_by)

def send_email_async(to_email, subject, body, recipient_type='general', case_number=None):
    """Send email using SMTP with tracking"""
    # Get user context before threading to avoid "working outside request context" error
    sent_by = getattr(current_user, 'id', None) if current_user.is_authenticated else None

    def send_email():
        log_id = None
        try:
            # Enhanced email body with comprehensive privacy and no-reply notices
            enhanced_body = f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background-color: #d32f2f; color: white; padding: 10px; text-align: center; font-weight: bold;">
                    🚫 DO NOT REPLY - CONFIDENTIAL COMMUNICATION 🚫
                </div>

                <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 10px 0;">
                    <h4 style="color: #856404; margin: 0 0 10px 0;">⚠️ CONFIDENTIALITY NOTICE</h4>
                    <p style="color: #856404; font-size: 13px; margin: 0;">
                        This email contains confidential and privileged information intended solely for the addressee. 
                        If you have received this email in error, please immediately delete it and notify the sender. 
                        Any unauthorized copying, sharing, distribution, or use of this information is strictly prohibited 
                        and may be subject to legal action.
                    </p>
                </div>

                <div style="padding: 20px; background-color: #f8f9fa;">
                    {body}
                </div>

                <div style="background-color: #e9ecef; padding: 15px; margin-top: 20px; border-top: 2px solid #dee2e6;">
                    <h5 style="color: #dc3545; margin: 0 0 10px 0;">📵 DO NOT REPLY TO THIS EMAIL</h5>
                    <p style="font-size: 12px; color: #666; margin: 0 0 10px 0;">
                        This is an automated notification from the Disciplinary Management System. 
                        This email address is not monitored for replies.
                    </p>
                    <p style="font-size: 12px; color: #666; margin: 0;">
                        <strong>For inquiries or assistance:</strong><br>
                        • Contact your administrator directly<br>
                        • Visit the disciplinary office during business hours<br>
                        • Use official institutional communication channels only
                    </p>
                </div>

                <div style="background-color: #fff3cd; padding: 10px; margin-top: 10px; border: 1px solid #ffeaa7;">
                    <p style="font-size: 11px; color: #856404; margin: 0; text-align: center;">
                        <strong>PRIVACY PROTECTION:</strong> This communication is protected by institutional privacy policies. 
                        Recipients must maintain confidentiality and are prohibited from sharing, copying, or distributing 
                        this information without proper authorization.
                    </p>
                </div>
            </div>
            """

            # Update subject to include no-reply indicator
            enhanced_subject = f"[DO NOT REPLY] {subject}"

            # Create initial log entry
            log_id = create_email_log(to_email, recipient_type, enhanced_subject, enhanced_body, 'sending', case_number=case_number, sent_by=sent_by)

            # Send using SMTP (primary method)
            success, error_msg = send_smtp_email_with_details(to_email, enhanced_subject, enhanced_body)

            # Update log with result
            status = 'sent' if success else 'failed'
            update_email_log(log_id, status, error_msg)

            return success
        except Exception as e:
            error_msg = str(e)
            print(f"Failed to send email to {to_email}: {error_msg}")
            if log_id:
                update_email_log(log_id, 'failed', error_msg)
            else:
                create_email_log(to_email, recipient_type, subject, body, 'failed', error_message=error_msg, case_number=case_number, sent_by=sent_by)
            return False

    # Run in background thread
    thread = threading.Thread(target=send_email)
    thread.daemon = True
    thread.start()

def send_replit_email(to_email, subject, body):
    """Send email using Replit Mail service"""
    try:
        print(f"[EMAIL DEBUG] Attempting to send email via Replit Mail to {to_email}")

        # Get authentication token from environment
        repl_identity = os.environ.get('REPL_IDENTITY')
        web_repl_renewal = os.environ.get('WEB_REPL_RENEWAL')

        if repl_identity:
            auth_token = f"repl {repl_identity}"
        elif web_repl_renewal:
            auth_token = f"depl {web_repl_renewal}"
        else:
            error_msg = "No Replit authentication token found. Please ensure you're running in Replit environment."
            print(f"[EMAIL ERROR] {error_msg}")
            return False, error_msg

        # Prepare the email payload
        payload = {
            "to": to_email,
            "subject": subject,
            "html": body,
            "text": body  # Also include text version
        }

        # Make request to Replit Mail API
        headers = {
            "Content-Type": "application/json",
            "X_REPLIT_TOKEN": auth_token
        }

        print(f"[EMAIL DEBUG] Sending request to Replit Mail API...")
        response = requests.post(
            "https://connectors.replit.com/api/v2/mailer/send",
            headers=headers,
            data=json.dumps(payload),
            timeout=30
        )

        if response.status_code == 200:
            result = response.json()
            print(f"[EMAIL DEBUG] Email sent successfully via Replit Mail to {to_email}")
            print(f"[EMAIL DEBUG] Message ID: {result.get('messageId', 'N/A')}")
            return True, None
        else:
            error_msg = f"Replit Mail API error: {response.status_code} - {response.text}"
            print(f"[EMAIL ERROR] {error_msg}")
            return False, error_msg

    except requests.exceptions.RequestException as e:
        error_msg = f"Network error sending email via Replit Mail: {str(e)}"
        print(f"[EMAIL ERROR] {error_msg}")
        return False, error_msg
    except Exception as e:
        error_msg = f"Unexpected error sending email via Replit Mail: {str(e)}"
        print(f"[EMAIL ERROR] {error_msg}")
        return False, error_msg

def send_smtp_email_with_details(to_email, subject, body):
    """Send email using SMTP with detailed error reporting"""
    try:
        # Get email settings from database
        settings = get_email_settings()
        if not settings:
            error_msg = "No email settings configured"
            print(f"[EMAIL DEBUG] {error_msg}")
            return False, error_msg

        print(f"[EMAIL DEBUG] Attempting to send email to {to_email}")
        print(f"[EMAIL DEBUG] Using SMTP server: {settings['smtp_server']}:{settings['smtp_port']}")
        print(f"[EMAIL DEBUG] From email: {settings['email_address']}")

        # Create message
        msg = MIMEMultipart('alternative')
        msg['From'] = f"{settings['sender_name']} <{settings['email_address']}>"
        msg['To'] = to_email
        msg['Subject'] = subject

        # Attach HTML body
        html_part = MIMEText(body, 'html')
        msg.attach(html_part)

        # Connect to SMTP server
        print(f"[EMAIL DEBUG] Connecting to SMTP server...")
        with smtplib.SMTP(settings['smtp_server'], settings['smtp_port']) as server:
            print(f"[EMAIL DEBUG] Starting TLS...")
            server.starttls()  # Enable TLS encryption

            print(f"[EMAIL DEBUG] Logging in...")
            server.login(settings['email_address'], settings['email_password'])

            print(f"[EMAIL DEBUG] Sending email...")
            # Send email
            text = msg.as_string()
            server.sendmail(settings['email_address'], to_email, text)

        print(f"[EMAIL DEBUG] Email sent successfully to {to_email}")
        return True, None

    except smtplib.SMTPAuthenticationError as e:
        error_msg = f"SMTP Authentication failed - check email credentials. Error: {str(e)}"
        print(f"[EMAIL ERROR] {error_msg}")
        return False, error_msg
    except smtplib.SMTPConnectError as e:
        error_msg = f"Failed to connect to SMTP server. Error: {str(e)}"
        print(f"[EMAIL ERROR] {error_msg}")
        return False, error_msg
    except smtplib.SMTPException as e:
        error_msg = f"SMTP error occurred: {str(e)}"
        print(f"[EMAIL ERROR] {error_msg}")
        return False, error_msg
    except Exception as e:
        error_msg = f"Unexpected error sending email: {str(e)}"
        print(f"[EMAIL ERROR] {error_msg}")
        return False, error_msg

def send_smtp_email(to_email, subject, body):
    """Legacy SMTP function for backward compatibility"""
    success, error_msg = send_smtp_email_with_details(to_email, subject, body)
    return success

def send_case_notification(case_data, student_data, case_type_name):
    """Send email notification for new case"""
    if not student_data or not student_data.get('email'):
        print("No student email available for notification")
        return

    subject = f"New Disciplinary Case - {case_data['case_number']}"

    body = f"""
    <html>
    <body>
        <h2>New Disciplinary Case Notification</h2>
        <p>Dear {student_data.get('first_name', 'Student')},</p>

        <p>A new disciplinary case has been filed regarding your conduct. Please find the details below:</p>

        <table border="1" cellpadding="10" cellspacing="0" style="border-collapse: collapse;">
            <tr>
                <td><strong>Case Number:</strong></td>
                <td>{case_data['case_number']}</td>
            </tr>
            <tr>
                <td><strong>Registration Number:</strong></td>
                <td>{case_data['student_reg_number']}</td>
            </tr>
            <tr>
                <td><strong>Case Type:</strong></td>
                <td>{case_type_name}</td>
            </tr>
            <tr>
                <td><strong>Description:</strong></td>
                <td>{case_data['description']}</td>
            </tr>
            <tr>
                <td><strong>Date Filed:</strong></td>
                <td>{datetime.now().strftime('%Y-%m-%d %H:%M')}</td>
            </tr>
            <tr>
                <td><strong>Status:</strong></td>
                <td>Pending</td>
            </tr>
        </table>

        <p><strong>Important:</strong> Please contact the disciplinary office at your earliest convenience to discuss this matter.</p>

        <p>Best regards,<br>
        Disciplinary Management Office</p>
    </body>
    </html>
    """

    send_email_async(student_data['email'], subject, body, 'student', case_data['case_number'])

def send_staff_notification(case_data, student_data, case_type_name, staff_email):
    """Send email notification to staff for new case"""
    if not staff_email:
        return

    subject = f"New Case Created - {case_data['case_number']}"

    body = f"""
    <html>
    <body>
        <h2>New Disciplinary Case Created</h2>
        <p>Dear Staff Member,</p>

        <p>A new disciplinary case has been created in the system. Please find the details below:</p>

        <table border="1" cellpadding="10" cellspacing="0" style="border-collapse: collapse;">
            <tr>
                <td><strong>Case Number:</strong></td>
                <td>{case_data['case_number']}</td>
            </tr>
            <tr>
                <td><strong>Student:</strong></td>
                <td>{student_data.get('first_name', 'Unknown')} {student_data.get('last_name', 'Student')} ({case_data['student_reg_number']})</td>
            </tr>
            <tr>
                <td><strong>Case Type:</strong></td>
                <td>{case_type_name}</td>
            </tr>
            <tr>
                <td><strong>Description:</strong></td>
                <td>{case_data['description']}</td>
            </tr>
            <tr>
                <td><strong>Date Created:</strong></td>
                <td>{datetime.now().strftime('%Y-%m-%d %H:%M')}</td>
            </tr>
            <tr>
                <td><strong>Status:</strong></td>
                <td>Pending</td>
            </tr>
        </table>

        <p><strong>Action Required:</strong> Please review this case and take appropriate action through the DMS system.</p>

        <p>Best regards,<br>
        Disciplinary Management System</p>
    </body>
    </html>
    """

    send_email_async(staff_email, subject, body, 'staff', case_data['case_number'])

def send_status_update_notification(case_data, student_data, old_status, new_status):
    """Send email notification for case status update"""
    if not student_data or not student_data.get('email'):
        return

    subject = f"Case Status Update - {case_data['case_number']}"

    status_messages = {
        'pending': 'Your case is now under review.',
        'waiting_hearing': 'Your case is scheduled for a hearing. You will be contacted with the date and time.',
        'blacklisted': 'Your case has resulted in disciplinary action. Please contact the disciplinary office immediately.',
        'exonerated': 'Your case has been resolved in your favor. No further action is required.',
        'resolved': 'Your case has been closed and resolved.'
    }

    body = f"""
    <html>
    <body>
        <h2>Case Status Update</h2>
        <p>Dear {student_data.get('first_name', 'Student')},</p>

        <p>The status of your disciplinary case has been updated:</p>

        <table border="1" cellpadding="10" cellspacing="0" style="border-collapse: collapse;">
            <tr>
                <td><strong>Case Number:</strong></td>
                <td>{case_data['case_number']}</td>
            </tr>
            <tr>
                <td><strong>Previous Status:</strong></td>
                <td>{old_status.replace('_', ' ').title()}</td>
            </tr>
            <tr>
                <td><strong>New Status:</strong></td>
                <td>{new_status.replace('_', ' ').title()}</td>
            </tr>
            <tr>
                <td><strong>Updated:</strong></td>
                <td>{datetime.now().strftime('%Y-%m-%d %H:%M')}</td>
            </tr>
        </table>

        <p>{status_messages.get(new_status, 'Please contact the disciplinary office for more information.')}</p>

        <p>Best regards,<br>
        Disciplinary Management Office</p>
    </body>
    </html>
    """

    send_email_async(student_data['email'], subject, body, 'student', case_data['case_number'])

# Authorized domains management
def add_authorized_domain(domain_url, description=None):
    """Add an authorized domain to the system"""
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO system_settings (setting_key, setting_value, description, updated_by)
            VALUES (?, ?, ?, ?)
        ''', (f'authorized_domain_{domain_url}', domain_url, description or f'Authorized domain: {domain_url}', current_user.id))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def get_authorized_domains():
    """Get all authorized domains"""
    conn = get_db_connection()
    domains = conn.execute('''
        SELECT setting_value, description, updated_at 
        FROM system_settings 
        WHERE setting_key LIKE 'authorized_domain_%'
        ORDER BY updated_at DESC
    ''').fetchall()
    conn.close()
    return domains

def remove_authorized_domain(domain_url):
    """Remove an authorized domain"""
    conn = get_db_connection()
    conn.execute('DELETE FROM system_settings WHERE setting_key = ?', (f'authorized_domain_{domain_url}',))
    conn.commit()
    conn.close()

def is_domain_authorized(domain_url):
    """Check if a domain is authorized"""
    conn = get_db_connection()
    domain = conn.execute(
        'SELECT setting_value FROM system_settings WHERE setting_key = ?', 
        (f'authorized_domain_{domain_url}',)
    ).fetchone()
    conn.close()
    return domain is not None

# System settings functions
def get_system_setting(setting_key, default_value=None):
    """Get a system setting value by key"""
    conn = get_db_connection()
    setting = conn.execute(
        'SELECT setting_value FROM system_settings WHERE setting_key = ?', 
        (setting_key,)
    ).fetchone()
    conn.close()
    return setting['setting_value'] if setting else default_value

def set_system_setting(setting_key, setting_value, description=None, updated_by=None):
    """Set a system setting value"""
    conn = get_db_connection()
    
    # Check if setting exists
    existing = conn.execute(
        'SELECT id FROM system_settings WHERE setting_key = ?', 
        (setting_key,)
    ).fetchone()
    
    if existing:
        # Update existing setting
        conn.execute('''
            UPDATE system_settings 
            SET setting_value = ?, description = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP
            WHERE setting_key = ?
        ''', (setting_value, description, updated_by, setting_key))
    else:
        # Insert new setting
        conn.execute('''
            INSERT INTO system_settings (setting_key, setting_value, description, updated_by)
            VALUES (?, ?, ?, ?)
        ''', (setting_key, setting_value, description, updated_by))
    
    conn.commit()
    conn.close()

def get_admin_recovery_email():
    """Get admin recovery email from system settings"""
    return get_system_setting('admin_recovery_email')

def generate_temporary_password(length=6):
    """Generate a secure 6-digit temporary password"""
    import secrets
    import string
    
    # Use only digits for a 6-digit password
    digits = string.digits
    temp_password = ''.join(secrets.choice(digits) for _ in range(length))
    return temp_password

def send_temporary_password_email(user_id, username, user_email):
    """Send temporary password email for locked admin accounts"""
    try:
        # Get admin recovery email
        recovery_email = get_admin_recovery_email()
        if not recovery_email:
            print(f"[SECURITY] No admin recovery email configured - cannot send temporary password")
            return False
        
        # Generate temporary password
        temp_password = generate_temporary_password()
        temp_password_hash = generate_password_hash(temp_password)
        
        # Set expiry time (30 minutes from now)
        from datetime import datetime, timedelta
        expiry_time = datetime.now() + timedelta(minutes=30)
        
        # Update user with temporary password
        conn = get_db_connection()
        conn.execute('''
            UPDATE users 
            SET temp_password_hash = ?, temp_password_expiry = ? 
            WHERE id = ?
        ''', (temp_password_hash, expiry_time.isoformat(), user_id))
        conn.commit()
        conn.close()
        
        # Send email to recovery address
        subject = "🔐 Admin Account Locked - Temporary Password"
        body = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background-color: #dc3545; color: white; padding: 15px; text-align: center;">
                <h2>🔐 SECURITY ALERT - Admin Account Locked</h2>
            </div>
            
            <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 10px 0;">
                <h4 style="color: #856404; margin: 0 0 10px 0;">⚠️ ACCOUNT SECURITY NOTICE</h4>
                <p style="color: #856404; margin: 0;">
                    An admin account has been automatically locked due to multiple failed login attempts.
                </p>
            </div>
            
            <div style="padding: 20px; background-color: #f8f9fa;">
                <p><strong>Account Details:</strong></p>
                <ul>
                    <li><strong>Username:</strong> {username}</li>
                    <li><strong>User Email:</strong> {user_email}</li>
                    <li><strong>Locked Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</li>
                    <li><strong>Reason:</strong> 5 failed login attempts</li>
                </ul>
                
                <div style="background-color: #d1ecf1; padding: 15px; border-radius: 5px; margin: 15px 0;">
                    <h4 style="color: #0c5460; margin: 0 0 10px 0;">🔑 TEMPORARY PASSWORD</h4>
                    <p style="color: #0c5460; margin: 0 0 10px 0;">
                        Use this temporary password to regain access:
                    </p>
                    <div style="background-color: #bee5eb; padding: 10px; border-radius: 3px; font-family: monospace; font-size: 16px; font-weight: bold; text-align: center; color: #0c5460;">
                        {temp_password}
                    </div>
                    <p style="color: #0c5460; margin: 10px 0 0 0; font-size: 12px;">
                        <strong>⏰ Expires in 30 minutes</strong> - You must login and change your password immediately.
                    </p>
                </div>
                
                <div style="background-color: #f8d7da; padding: 15px; border-radius: 5px; margin: 15px 0;">
                    <h5 style="color: #721c24; margin: 0 0 10px 0;">🚨 IMMEDIATE ACTION REQUIRED</h5>
                    <ol style="color: #721c24; margin: 0;">
                        <li>Login using the temporary password above</li>
                        <li>Change your password immediately</li>
                        <li>Review account security</li>
                        <li>Check for any unauthorized access attempts</li>
                    </ol>
                </div>
            </div>
            
            <div style="background-color: #e9ecef; padding: 15px; margin-top: 20px;">
                <p style="margin: 0; font-size: 12px; color: #666;">
                    <strong>Security Notice:</strong> This is an automated security notification. If you did not attempt to login, 
                    please take immediate action to secure your account and review system logs.
                </p>
            </div>
        </div>
        """
        
        # Send email to recovery address
        send_email_async(recovery_email, subject, body, 'admin_security', None)
        print(f"[SECURITY] Temporary password email sent to recovery address for user: {username}")
        return True
        
    except Exception as e:
        print(f"[SECURITY ERROR] Failed to send temporary password email: {str(e)}")
        return False

# Security decorators
def require_role(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if not current_user.has_permission(required_role):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

class User(UserMixin):
    def __init__(self, id, username, email, role, can_give_verdict=False):
        self.id = id
        self.username = username
        self.email = email
        self.role = role
        self.can_give_verdict = can_give_verdict

    def has_permission(self, required_role):
        role_hierarchy = {'staff': 1, 'admin': 2}
        return role_hierarchy.get(self.role, 0) >= role_hierarchy.get(required_role, 0)

    def can_update_case_status(self):
        # Admin always has verdict permission, or staff with verdict permission can update case status
        return self.role == 'admin' or (self.role == 'staff' and self.can_give_verdict)

    def can_create_cases(self):
        # Staff and admin can create cases
        return self.role in ['staff', 'admin']

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ? AND is_active = 1', (user_id,)).fetchone()
    conn.close()

    if user:
        can_give_verdict = user['can_give_verdict'] if 'can_give_verdict' in user.keys() else False
        return User(user['id'], user['username'], user['email'], user['role'], can_give_verdict)
    return None

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ? AND is_active = 1', 
            (username,)
        ).fetchone()

        if user:
            # Check if account is locked
            failed_attempts = user['failed_login_attempts'] if 'failed_login_attempts' in user.keys() else 0
            locked_until = user['locked_until'] if 'locked_until' in user.keys() else None

            if failed_attempts >= 5:
                if locked_until:
                    from datetime import datetime, timedelta
                    lock_time = datetime.fromisoformat(locked_until)
                    if datetime.now() < lock_time:
                        conn.close()
                        flash('Account locked due to multiple failed attempts. Try again later.', 'error')
                        return render_template('login.html')
                    else:
                        # Reset attempts after lock period expires
                        conn.execute('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?', (user['id'],))
                        conn.commit()
                else:
                    # Lock account for 30 minutes and send temporary password email for admin accounts
                    from datetime import datetime, timedelta
                    lock_until = datetime.now() + timedelta(minutes=30)
                    conn.execute('UPDATE users SET locked_until = ? WHERE id = ?', (lock_until.isoformat(), user['id']))
                    conn.commit()
                    
                    # Send temporary password email if user is admin and admin recovery email is set
                    if user['role'] == 'admin':
                        send_temporary_password_email(user['id'], user['username'], user['email'])
                    
                    conn.close()
                    flash('Account locked due to multiple failed attempts. Try again in 30 minutes.', 'error')
                    return render_template('login.html')

            # Check for temporary password first (if account is locked and temp password exists)
            temp_password_hash = user['temp_password_hash'] if 'temp_password_hash' in user.keys() else None
            temp_password_expiry = user['temp_password_expiry'] if 'temp_password_expiry' in user.keys() else None
            is_temp_password_valid = False
            
            if temp_password_hash and temp_password_expiry:
                from datetime import datetime
                try:
                    expiry_time = datetime.fromisoformat(temp_password_expiry)
                    if datetime.now() < expiry_time and check_password_hash(temp_password_hash, password):
                        is_temp_password_valid = True
                        # Clear temporary password after successful use
                        conn.execute('''
                            UPDATE users 
                            SET temp_password_hash = NULL, temp_password_expiry = NULL,
                                failed_login_attempts = 0, locked_until = NULL 
                            WHERE id = ?
                        ''', (user['id'],))
                        conn.commit()
                        flash('Logged in with temporary password. Please change your password immediately.', 'warning')
                except ValueError:
                    # Invalid datetime format
                    pass
            
            # Check regular password or temporary password
            if check_password_hash(user['password_hash'], password) or is_temp_password_valid:
                # Reset failed attempts on successful login (if not already done for temp password)
                if not is_temp_password_valid:
                    conn.execute('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?', (user['id'],))
                    conn.commit()
                
                conn.close()

                can_give_verdict = user['can_give_verdict'] if 'can_give_verdict' in user.keys() else False
                user_obj = User(user['id'], user['username'], user['email'], user['role'], can_give_verdict)
                login_user(user_obj)
                
                # Redirect to system settings if logged in with temporary password
                if is_temp_password_valid:
                    return redirect(url_for('system_settings'))
                else:
                    return redirect(url_for('dashboard'))
            else:
                # Increment failed attempts
                new_attempts = failed_attempts + 1
                conn.execute('UPDATE users SET failed_login_attempts = ? WHERE id = ?', (new_attempts, user['id']))
                conn.commit()
                conn.close()
                flash(f'Invalid password. {5 - new_attempts} attempts remaining.', 'error')
        else:
            conn.close()
            flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()

    # Get statistics
    stats = {}

    if current_user.role == 'admin':
        stats['total_students'] = conn.execute('SELECT COUNT(*) FROM students WHERE is_active = 1').fetchone()[0]
        stats['total_cases'] = conn.execute('SELECT COUNT(*) FROM cases').fetchone()[0]
        stats['pending_cases'] = conn.execute('SELECT COUNT(*) FROM cases WHERE status = "pending"').fetchone()[0]
        stats['blacklisted_students'] = conn.execute('SELECT COUNT(*) FROM cases WHERE status = "blacklisted"').fetchone()[0]

        # Recent cases
        recent_cases = conn.execute('''
            SELECT c.*, s.first_name, s.last_name, ct.name as case_type_name
            FROM cases c 
            JOIN students s ON c.student_reg_number = s.reg_number 
            LEFT JOIN case_types ct ON c.case_type_id = ct.id
            ORDER BY c.created_at DESC LIMIT 5
        ''').fetchall()

    else:  # staff
        stats['my_cases'] = conn.execute('SELECT COUNT(*) FROM cases WHERE reported_by = ?', (current_user.id,)).fetchone()[0]
        stats['pending_cases'] = conn.execute('SELECT COUNT(*) FROM cases WHERE status = "pending"').fetchone()[0]

        # All recent cases (not just mine)
        recent_cases = conn.execute('''
            SELECT c.*, s.first_name, s.last_name, ct.name as case_type_name, u.username as reported_by_name
            FROM cases c 
            LEFT JOIN students s ON c.student_reg_number = s.reg_number 
            LEFT JOIN case_types ct ON c.case_type_id = ct.id
            LEFT JOIN users u ON c.reported_by = u.id
            ORDER BY c.created_at DESC LIMIT 5
        ''').fetchall()

    conn.close()

    return render_template('dashboard.html', stats=stats, recent_cases=recent_cases)

# Students route removed - registration numbers will be entered directly in case form

@app.route('/cases')
@login_required
def cases():
    conn = get_db_connection()

    cases = conn.execute('''
        SELECT c.*, s.first_name, s.last_name, u.username as reported_by_name, ct.name as case_type_name
        FROM cases c 
        LEFT JOIN students s ON c.student_reg_number = s.reg_number 
        JOIN users u ON c.reported_by = u.id
        LEFT JOIN case_types ct ON c.case_type_id = ct.id
        ORDER BY c.created_at DESC
    ''').fetchall()

    conn.close()
    return render_template('cases.html', cases=cases)

@app.route('/cases/add', methods=['GET', 'POST'])
@login_required
def add_case():
    if not current_user.can_create_cases():
        flash('You do not have permission to create cases', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        student_reg_number = request.form['student_reg_number'].upper()
        student_first_name = request.form['student_first_name']
        student_last_name = request.form['student_last_name']
        student_email = request.form.get('student_email', '').strip()
        case_type_id = request.form['case_type_id']
        description = request.form['description']

        # Generate unique case number
        case_number = f"CASE-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"

        # Handle file upload with validation
        case_file = None
        if 'case_file' in request.files:
            file = request.files['case_file']
            if file and file.filename:
                if allowed_file(file.filename):
                    filename = secure_filename(f"{case_number}_{file.filename}")
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    case_file = filename
                else:
                    flash('Invalid file type. Only PDF, DOC, DOCX, JPG, PNG files are allowed.', 'error')
                    conn = get_db_connection()
                    case_types = conn.execute('SELECT id, name FROM case_types ORDER BY name').fetchall()
                    students = conn.execute('SELECT reg_number, first_name, last_name FROM students WHERE is_active = 1 ORDER BY last_name, first_name').fetchall()
                    conn.close()
                    return render_template('add_case.html', case_types=case_types, students=students)

        # Validate registration number format
        import re
        if not re.match(r'^R\d{6}[A-Z]$', student_reg_number):
            flash('Invalid registration number format. Use format: R123456A', 'error')
            conn = get_db_connection()
            case_types = conn.execute('SELECT id, name FROM case_types ORDER BY name').fetchall()
            departments = ['Accommodation', 'Asset Protection', 'Admin']
            conn.close()
            return render_template('add_case.html', case_types=case_types, departments=departments)

        conn = get_db_connection()
        try:
            # Auto-create or update student record
            existing_student = conn.execute('SELECT reg_number FROM students WHERE reg_number = ?', (student_reg_number,)).fetchone()
            if not existing_student:
                # Create student record with provided information
                if not student_email:
                    student_email = f'{student_reg_number.lower()}@student.edu'
                conn.execute('''
                    INSERT INTO students (reg_number, first_name, last_name, email, is_active)
                    VALUES (?, ?, ?, ?, ?)
                ''', (student_reg_number, student_first_name, student_last_name, student_email, 1))
            else:
                # Update existing student record if it has "Unknown" data
                existing_student_data = conn.execute('SELECT first_name, last_name FROM students WHERE reg_number = ?', (student_reg_number,)).fetchone()
                if existing_student_data and (existing_student_data['first_name'] == 'Unknown' or existing_student_data['last_name'] == 'Student'):
                    update_email = student_email if student_email else f'{student_reg_number.lower()}@student.edu'
                    conn.execute('''
                        UPDATE students SET first_name = ?, last_name = ?, email = ?
                        WHERE reg_number = ?
                    ''', (student_first_name, student_last_name, update_email, student_reg_number))

            conn.execute('''
                INSERT INTO cases (case_number, student_reg_number, reported_by, case_type_id, description, case_file)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (case_number, student_reg_number, current_user.id, case_type_id, description, case_file))
            conn.commit()

            # Get case type name for email
            case_type_name = conn.execute('SELECT name FROM case_types WHERE id = ?', (case_type_id,)).fetchone()['name']

            # Get student data for email
            student_data = conn.execute('SELECT * FROM students WHERE reg_number = ?', (student_reg_number,)).fetchone()

            # Send email notifications
            case_data = {
                'case_number': case_number,
                'student_reg_number': student_reg_number,
                'description': description
            }

            # Send notification to student
            if student_data:
                send_case_notification(case_data, dict(student_data), case_type_name)

            # Send notification to all staff members
            staff_users = conn.execute(
                'SELECT username, email FROM users WHERE role IN ("admin", "staff") AND is_active = 1 AND email IS NOT NULL AND email != ""'
            ).fetchall()

            for staff in staff_users:
                if staff['email']:  # Double check email exists
                    send_staff_notification(case_data, dict(student_data), case_type_name, staff['email'])

            flash('Case created successfully', 'success')
            return redirect(url_for('cases'))
        except sqlite3.IntegrityError as e:
            flash('Error creating case: ' + str(e), 'error')
        finally:
            conn.close()

    # Get case types for the form
    conn = get_db_connection()
    case_types = conn.execute('SELECT id, name FROM case_types ORDER BY name').fetchall()
    departments = ['Accommodation', 'Asset Protection', 'Admin']
    conn.close()

    return render_template('add_case.html', case_types=case_types, departments=departments)

@app.route('/api/student/<reg_number>')
@login_required
def get_student_data(reg_number):
    """API endpoint to get student data by registration number"""
    if not current_user.can_create_cases():
        return jsonify({'error': 'Unauthorized'}), 403

    conn = get_db_connection()
    student = conn.execute(
        'SELECT reg_number, first_name, last_name, email FROM students WHERE reg_number = ? AND is_active = 1',
        (reg_number.upper(),)
    ).fetchone()
    conn.close()

    if student:
        return jsonify({
            'exists': True,
            'reg_number': student['reg_number'],
            'first_name': student['first_name'],
            'last_name': student['last_name'],
            'email': student['email']
        })
    else:
        return jsonify({
            'exists': False,
            'email': f'{reg_number.lower()}@student.edu'
        })

@app.route('/cases/update', methods=['POST'])
@login_required
def update_case_status():
    if not current_user.can_update_case_status():
        flash('You do not have permission to update case status', 'error')
        return redirect(url_for('cases'))

    case_id = request.form['case_id']
    new_status = request.form['status']
    exoneration_reason = request.form.get('exoneration_reason', '')

    conn = get_db_connection()

    # Get current case data for email notification
    current_case = conn.execute('''
        SELECT c.*, s.first_name, s.last_name, s.email
        FROM cases c 
        LEFT JOIN students s ON c.student_reg_number = s.reg_number 
        WHERE c.id = ?
    ''', (case_id,)).fetchone()

    old_status = current_case['status'] if current_case else 'unknown'

    # If status is being changed to exonerated, move case to exonerated database
    if new_status == 'exonerated':
        # Get complete case information
        case_data = conn.execute('''
            SELECT c.*, s.first_name, s.last_name, s.email as student_email,
                   u.username as reported_by_username, ct.name as case_type_name
            FROM cases c 
            LEFT JOIN students s ON c.student_reg_number = s.reg_number 
            LEFT JOIN users u ON c.reported_by = u.id
            LEFT JOIN case_types ct ON c.case_type_id = ct.id
            WHERE c.id = ?
        ''', (case_id,)).fetchone()

        if case_data:
            # Move to exonerated database
            exon_conn = get_exonerated_db_connection()
            exon_conn.execute('''
                INSERT INTO exonerated_cases (
                    id, case_number, student_reg_number, student_first_name, student_last_name,
                    student_email, reported_by_username, case_type_name, description, case_file,
                    original_created_at, exonerated_by, exoneration_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                case_data['id'], case_data['case_number'], case_data['student_reg_number'],
                case_data['first_name'], case_data['last_name'], case_data['student_email'],
                case_data['reported_by_username'], case_data['case_type_name'],
                case_data['description'], case_data['case_file'], case_data['created_at'],
                current_user.id, exoneration_reason
            ))
            exon_conn.commit()
            exon_conn.close()

            # Remove from main database
            conn.execute('DELETE FROM cases WHERE id = ?', (case_id,))
            conn.commit()
            flash('Case exonerated and moved to exonerated database', 'success')
        else:
            flash('Case not found', 'error')
    else:
        # Normal status update
        conn.execute('''
            UPDATE cases SET status = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (new_status, case_id))
        conn.commit()

        # Send email notification for status update
        if current_case:
            case_data = {
                'case_number': current_case['case_number'],
                'student_reg_number': current_case['student_reg_number']
            }
            student_data = {
                'first_name': current_case['first_name'],
                'last_name': current_case['last_name'],
                'email': current_case['email']
            }
            send_status_update_notification(case_data, student_data, old_status, new_status)

        flash('Case status updated successfully', 'success')

    conn.close()
    return redirect(url_for('cases'))

@app.route('/cases/delete/<int:case_id>', methods=['POST'])
@login_required
@require_role('admin')
def delete_case(case_id):
    """Delete a case - admin only"""
    conn = get_db_connection()

    # Get case information before deletion
    case = conn.execute('''
        SELECT case_number, case_file FROM cases WHERE id = ?
    ''', (case_id,)).fetchone()

    if not case:
        flash('Case not found', 'error')
        conn.close()
        return redirect(url_for('cases'))

    try:
        # Delete associated file if it exists
        if case['case_file']:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], case['case_file'])
            if os.path.exists(file_path):
                os.remove(file_path)

        # Delete the case from database
        conn.execute('DELETE FROM cases WHERE id = ?', (case_id,))
        conn.commit()
        flash(f'Case {case["case_number"]} deleted successfully', 'success')
    except sqlite3.Error as e:
        flash(f'Error deleting case: {str(e)}', 'error')
    finally:
        conn.close()

    return redirect(url_for('cases'))

# Database backup functions
def create_database_backup():
    """Create a backup of the database and return the filename"""
    import shutil
    from datetime import datetime

    backup_filename = f"dms_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    backup_path = os.path.join(app.config['UPLOAD_FOLDER'], backup_filename)

    try:
        # Copy the main database
        shutil.copy2(DATABASE, backup_path)
        return backup_filename, backup_path
    except Exception as e:
        print(f"Error creating database backup: {str(e)}")
        return None, None

def check_new_cases_today():
    """Check if any new cases were created today"""
    from datetime import date

    conn = get_db_connection()
    today = date.today().isoformat()

    count = conn.execute('''
        SELECT COUNT(*) as count FROM cases 
        WHERE DATE(created_at) = ?
    ''', (today,)).fetchone()

    conn.close()
    return count['count'] > 0

def send_database_backup_email():
    """Send daily database backup if new cases were created"""
    try:
        # Check if there were new cases today
        if not check_new_cases_today():
            print("[BACKUP] No new cases today - skipping backup")
            return False

        print("[BACKUP] New cases found - creating backup")

        # Create database backup
        backup_filename, backup_path = create_database_backup()
        if not backup_filename:
            print("[BACKUP] Failed to create backup file")
            return False

        # Get admin email for backup destination
        conn = get_db_connection()
        admin_settings = conn.execute('''
            SELECT email FROM users WHERE role = 'admin' AND is_active = 1 
            ORDER BY id LIMIT 1
        ''').fetchone()
        conn.close()

        if not admin_settings or not admin_settings['email']:
            print("[BACKUP] No admin email configured for backup")
            return False

        admin_email = admin_settings['email']

        # Prepare backup email
        subject = f"Daily Database Backup - {datetime.now().strftime('%Y-%m-%d')}"

        body = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background-color: #1e3a8a; color: white; padding: 15px; text-align: center;">
                <h2>🗄️ Daily Database Backup</h2>
            </div>

            <div style="padding: 20px; background-color: #f8f9fa;">
                <h3>Automated Backup Report</h3>

                <div style="background-color: #d4edda; border: 1px solid #c3e6cb; border-radius: 5px; padding: 15px; margin: 15px 0;">
                    <h4 style="color: #155724; margin: 0 0 10px 0;">✅ Backup Details</h4>
                    <ul style="color: #155724; margin: 0;">
                        <li><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</li>
                        <li><strong>Backup File:</strong> {backup_filename}</li>
                        <li><strong>Reason:</strong> New disciplinary cases were created today</li>
                        <li><strong>Status:</strong> Backup completed successfully</li>
                    </ul>
                </div>

                <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 5px; padding: 15px; margin: 15px 0;">
                    <h4 style="color: #856404; margin: 0 0 10px 0;">📋 Backup Information</h4>
                    <p style="color: #856404; margin: 0;">
                        This automated backup is created daily at midnight when new disciplinary cases 
                        are recorded in the system. The backup includes all case data, student records, 
                        and system configuration for disaster recovery purposes.
                    </p>
                </div>

                <div style="background-color: #f8d7da; border: 1px solid #f5c6cb; border-radius: 5px; padding: 15px; margin: 15px 0;">
                    <h4 style="color: #721c24; margin: 0 0 10px 0;">🔒 Security Notice</h4>
                    <p style="color: #721c24; margin: 0; font-size: 13px;">
                        <strong>CONFIDENTIAL:</strong> This backup contains sensitive student disciplinary data. 
                        Store securely and ensure compliance with institutional data protection policies. 
                        Do not forward or share this backup file.
                    </p>
                </div>
            </div>

            <div style="background-color: #e9ecef; padding: 15px; text-align: center; border-top: 2px solid #dee2e6;">
                <p style="margin: 0; font-size: 12px; color: #666;">
                    <strong>Disciplinary Management System</strong><br>
                    Automated Backup Service
                </p>
            </div>
        </div>
        """

        # Note: For file attachments, we'll include the backup path information in the email
        # since basic email functionality doesn't include attachments
        enhanced_body = body + f"""
        <div style="margin: 20px 0; padding: 15px; background-color: #e3f2fd; border: 1px solid #2196f3; border-radius: 5px;">
            <p style="color: #0d47a1; margin: 0;">
                <strong>📎 Backup File Location:</strong><br>
                Server Path: {backup_path}<br>
                <em>Contact system administrator to retrieve backup file</em>
            </p>
        </div>
        """

        # Send backup notification email
        success = send_email_async(admin_email, subject, enhanced_body, 'backup')

        if success:
            print(f"[BACKUP] Backup notification sent to {admin_email}")
            return True
        else:
            print(f"[BACKUP] Failed to send backup notification to {admin_email}")
            return False

    except Exception as e:
        print(f"[BACKUP] Error in backup process: {str(e)}")
        return False

@app.route('/admin/manual-backup', methods=['POST'])
@login_required
@require_role('admin')
def manual_backup():
    """Manually trigger database backup"""
    success = send_database_backup_email()

    if success:
        flash('Database backup created and notification sent successfully', 'success')
    else:
        flash('Failed to create database backup or send notification', 'error')

    return redirect(url_for('admin_panel'))

@app.route('/api/daily-backup-check')
def api_daily_backup_check():
    """API endpoint for scheduled backup check (can be called by cron/scheduler)"""
    try:
        success = send_database_backup_email()
        return jsonify({
            "status": "success" if success else "skipped",
            "message": "Backup completed" if success else "No new cases today or backup failed",
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500


@app.route('/admin')
@login_required
@require_role('admin')
def admin_panel():

    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users ORDER BY username').fetchall()
    email_settings = conn.execute('SELECT * FROM email_settings WHERE is_active = 1 ORDER BY updated_at DESC LIMIT 1').fetchone()
    conn.close()

    return render_template('admin.html', users=users, email_settings=email_settings)

@app.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
@require_role('admin')
def add_user():

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        department = request.form['department']
        can_give_verdict = 'can_give_verdict' in request.form

        password_hash = generate_password_hash(password)

        conn = get_db_connection()
        try:
            conn.execute('''
                INSERT INTO users (username, email, password_hash, role, department, can_give_verdict)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, email, password_hash, role, department, can_give_verdict))
            conn.commit()
            flash('User created successfully', 'success')
            return redirect(url_for('admin_panel'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'error')
        finally:
            conn.close()

    departments = ['Accommodation', 'Asset Protection', 'Admin', 'Academic Affairs', 'Student Affairs', 'IT Services', 'Finance', 'Human Resources']
    return render_template('add_user.html', departments=departments)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@require_role('admin')
def edit_user(user_id):
    conn = get_db_connection()

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        role = request.form['role']
        department = request.form['department']
        can_give_verdict = 'can_give_verdict' in request.form
        is_active = 'is_active' in request.form

        # Update password if provided
        if request.form.get('password'):
            password_hash = generate_password_hash(request.form['password'])
            conn.execute('''
                UPDATE users SET username = ?, email = ?, password_hash = ?, role = ?, 
                department = ?, can_give_verdict = ?, is_active = ?
                WHERE id = ?
            ''', (username, email, password_hash, role, department, can_give_verdict, is_active, user_id))
        else:
            conn.execute('''
                UPDATE users SET username = ?, email = ?, role = ?, 
                department = ?, can_give_verdict = ?, is_active = ?
                WHERE id = ?
            ''', (username, email, role, department, can_give_verdict, is_active, user_id))

        conn.commit()
        conn.close()
        flash('User updated successfully', 'success')
        return redirect(url_for('admin_panel'))

    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()

    if not user:
        flash('User not found', 'error')
        return redirect(url_for('admin_panel'))

    departments = ['Accommodation', 'Asset Protection', 'Admin', 'Academic Affairs', 'Student Affairs', 'IT Services', 'Finance', 'Human Resources']
    return render_template('edit_user.html', user=user, departments=departments)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@require_role('admin')
def delete_user(user_id):
    # Don't allow deletion of the current user
    if user_id == current_user.id:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('admin_panel'))

    conn = get_db_connection()

    # Check if user exists
    user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('admin_panel'))

    try:
        # Delete the user
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        flash(f'User "{user["username"]}" deleted successfully', 'success')
    except sqlite3.IntegrityError:
        flash('Cannot delete user - they have associated records', 'error')
    finally:
        conn.close()

    return redirect(url_for('admin_panel'))

@app.route('/admin/users/reset-password/<int:user_id>', methods=['POST'])
@login_required
@require_role('admin')
def reset_user_password(user_id):
    new_password = request.form.get('new_password')
    if not new_password:
        flash('Password cannot be empty', 'error')
        return redirect(url_for('edit_user', user_id=user_id))

    conn = get_db_connection()

    # Check if user exists
    user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('admin_panel'))

    # Update password and reset login attempts
    password_hash = generate_password_hash(new_password)
    conn.execute('''
        UPDATE users SET password_hash = ?, failed_login_attempts = 0, locked_until = NULL
        WHERE id = ?
    ''', (password_hash, user_id))
    conn.commit()
    conn.close()

    flash(f'Password reset successfully for "{user["username"]}"', 'success')
    return redirect(url_for('edit_user', user_id=user_id))

@app.route('/admin/users/unlock/<int:user_id>', methods=['POST'])
@login_required
@require_role('admin')
def unlock_user(user_id):
    conn = get_db_connection()

    user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('admin_panel'))

    # Unlock the account
    conn.execute('''
        UPDATE users SET failed_login_attempts = 0, locked_until = NULL
        WHERE id = ?
    ''', (user_id,))
    conn.commit()
    conn.close()

    flash(f'Account unlocked for "{user["username"]}"', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/email-settings', methods=['GET', 'POST'])
@login_required
@require_role('admin')
def email_settings():
    conn = get_db_connection()

    if request.method == 'POST':
        email_address = request.form['email_address']
        email_password = request.form['email_password']
        sender_name = request.form['sender_name']
        smtp_server = request.form.get('smtp_server', 'smtp.gmail.com')
        smtp_port = int(request.form.get('smtp_port', 587))

        # Deactivate old settings
        conn.execute('UPDATE email_settings SET is_active = 0')

        # Add new settings
        conn.execute('''
            INSERT INTO email_settings (smtp_server, smtp_port, email_address, email_password, sender_name, is_active)
            VALUES (?, ?, ?, ?, ?, 1)
        ''', (smtp_server, smtp_port, email_address, email_password, sender_name))

        conn.commit()
        flash('Email settings updated successfully', 'success')
        return redirect(url_for('admin_panel'))

    # Get current settings for form
    current_settings = conn.execute('SELECT * FROM email_settings WHERE is_active = 1 ORDER BY updated_at DESC LIMIT 1').fetchone()
    conn.close()

    return render_template('email_settings.html', settings=current_settings)

@app.route('/admin/system-settings', methods=['GET', 'POST'])
@login_required
@require_role('admin')
def system_settings():
    conn = get_db_connection()
    
    if request.method == 'POST':
        admin_recovery_email = request.form.get('admin_recovery_email', '').strip()
        admin_password = request.form.get('admin_password', '').strip()
        new_domain = request.form.get('new_domain', '').strip()
        remove_domain = request.form.get('remove_domain', '').strip()
        
        # Update admin recovery email
        if admin_recovery_email:
            set_system_setting('admin_recovery_email', admin_recovery_email, 
                             'Email address for admin account recovery and security notifications', 
                             current_user.id)
            flash('Admin recovery email updated successfully', 'success')
        
        # Update admin password if provided
        if admin_password:
            password_hash = generate_password_hash(admin_password)
            conn.execute('''
                UPDATE users SET password_hash = ? WHERE role = 'admin' AND id = ?
            ''', (password_hash, current_user.id))
            conn.commit()
            flash('Admin password updated successfully', 'success')
        
        # Add new authorized domain
        if new_domain:
            if add_authorized_domain(new_domain):
                flash(f'Domain {new_domain} added successfully', 'success')
            else:
                flash(f'Domain {new_domain} already exists', 'error')
        
        # Remove domain
        if remove_domain:
            remove_authorized_domain(remove_domain)
            flash(f'Domain {remove_domain} removed successfully', 'success')
        
        return redirect(url_for('system_settings'))
    
    # Get current system settings
    admin_recovery_email = get_system_setting('admin_recovery_email', '')
    authorized_domains = get_authorized_domains()
    
    conn.close()
    return render_template('system_settings.html', 
                         admin_recovery_email=admin_recovery_email,
                         authorized_domains=authorized_domains)

@app.route('/admin/test-email', methods=['POST'])
@login_required
@require_role('admin')
def test_email():
    test_email_address = request.form['test_email']

    if not test_email_address:
        flash('Please provide a test email address', 'error')
        return redirect(url_for('email_settings'))

    # Send test email synchronously for immediate feedback
    subject = "Test Email from Disciplinary Management System"
    body = f"""
    <div style="padding: 20px;">
        <h2>📧 Email Configuration Test</h2>
        <p>This is a test email to verify that your email settings are working correctly.</p>
        <div style="background-color: #d4edda; padding: 15px; border: 1px solid #c3e6cb; border-radius: 5px;">
            <p><strong>✅ Test Details:</strong></p>
            <ul>
                <li>Test sent at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</li>
                <li>SMTP Configuration: Active</li>
                <li>Email Delivery: Successful</li>
            </ul>
        </div>
        <p>If you received this email, your email integration is working correctly and ready for production use.</p>
        <p><em>This test email includes the same privacy and no-reply protections as production emails.</em></p>
        <p>Best regards,<br><strong>Disciplinary Management System</strong></p>
    </div>
    """

    print(f"[EMAIL TEST] Sending test email to {test_email_address}")

    # Send email directly (not async) for immediate feedback using SMTP
    success, error_msg = send_smtp_email_with_details(test_email_address, subject, body)

    if success:
        flash(f'✅ Test email sent successfully to {test_email_address}', 'success')
        # Also log it
        log_email(test_email_address, 'test', subject, body, 'sent', case_number=None, sent_by=current_user.id)
    else:
        flash(f'❌ Failed to send test email: {error_msg}', 'error')
        # Log the failure
        log_email(test_email_address, 'test', subject, body, 'failed', error_message=error_msg, case_number=None, sent_by=current_user.id)

    return redirect(url_for('email_settings'))

@app.route('/admin/email-diagnostics')
@login_required
@require_role('admin')
def email_diagnostics():
    """Diagnose email configuration issues"""
    conn = get_db_connection()
    settings = get_email_settings()

    diagnostics = {
        'settings_configured': settings is not None,
        'smtp_server': settings['smtp_server'] if settings else 'Not configured',
        'smtp_port': settings['smtp_port'] if settings else 'Not configured',
        'email_address': settings['email_address'] if settings else 'Not configured',
        'sender_name': settings['sender_name'] if settings else 'Not configured',
        'password_set': bool(settings and settings['email_password']) if settings else False
    }

    # Check recent email logs
    recent_failures = conn.execute('''
        SELECT recipient_email, error_message, sent_at 
        FROM email_logs 
        WHERE sent_status = 'failed' 
        ORDER BY sent_at DESC 
        LIMIT 10
    ''').fetchall()

    conn.close()

    return render_template('email_diagnostics.html', 
                         diagnostics=diagnostics, 
                         settings=settings,
                         recent_failures=recent_failures)

@app.route('/admin/email-logs')
@login_required
@require_role('admin')
def email_logs():
    """View all email logs for tracking"""
    conn = get_db_connection()

    # Get page number for pagination
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page

    # Get email logs with user information
    logs = conn.execute('''
        SELECT el.*, u.username as sent_by_username
        FROM email_logs el
        LEFT JOIN users u ON el.sent_by = u.id
        ORDER BY el.sent_at DESC
        LIMIT ? OFFSET ?
    ''', (per_page, offset)).fetchall()

    # Get total count for pagination
    total_count = conn.execute('SELECT COUNT(*) as count FROM email_logs').fetchone()['count']

    # Get statistics
    stats = conn.execute('''
        SELECT 
            COUNT(*) as total_emails,
            SUM(CASE WHEN sent_status = 'sent' THEN 1 ELSE 0 END) as sent_count,
            SUM(CASE WHEN sent_status = 'failed' THEN 1 ELSE 0 END) as failed_count,
            SUM(CASE WHEN sent_status = 'pending' THEN 1 ELSE 0 END) as pending_count
        FROM email_logs
    ''').fetchone()

    conn.close()

    # Calculate pagination info
    total_pages = (total_count + per_page - 1) // per_page

    return render_template('email_logs.html', 
                         logs=logs, 
                         stats=stats,
                         page=page,
                         total_pages=total_pages,
                         total_count=total_count)

@app.route('/admin/requests-log')
@login_required
@require_role('admin')
def requests_log():
    """View all API requests log for monitoring"""
    conn = get_db_connection()

    # Get page number for pagination
    page = request.args.get('page', 1, type=int)
    per_page = 50
    offset = (page - 1) * per_page

    # Get API requests
    requests_data = conn.execute('''
        SELECT * FROM api_requests_log
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    ''', (per_page, offset)).fetchall()

    # Get total count for pagination
    total_count = conn.execute('SELECT COUNT(*) as count FROM api_requests_log').fetchone()['count']

    # Get statistics
    stats = conn.execute('''
        SELECT 
            COUNT(*) as total_requests,
            COUNT(DISTINCT ip_address) as unique_ips,
            COUNT(DISTINCT requesting_domain) as unique_domains,
            SUM(CASE WHEN response_status = 200 THEN 1 ELSE 0 END) as successful_requests,
            SUM(CASE WHEN response_status >= 400 THEN 1 ELSE 0 END) as failed_requests
        FROM api_requests_log
    ''').fetchone()

    # Get recent domains
    recent_domains = conn.execute('''
        SELECT requesting_domain, COUNT(*) as request_count, MAX(timestamp) as last_request
        FROM api_requests_log
        WHERE requesting_domain IS NOT NULL AND requesting_domain != 'direct'
        GROUP BY requesting_domain
        ORDER BY last_request DESC
        LIMIT 10
    ''').fetchall()

    # Get most checked registration numbers
    top_reg_numbers = conn.execute('''
        SELECT reg_number_checked, COUNT(*) as check_count, MAX(timestamp) as last_check
        FROM api_requests_log
        WHERE reg_number_checked IS NOT NULL 
        AND reg_number_checked NOT LIKE '%numbers%'
        GROUP BY reg_number_checked
        ORDER BY check_count DESC
        LIMIT 10
    ''').fetchall()

    conn.close()

    # Calculate pagination info
    total_pages = (total_count + per_page - 1) // per_page

    return render_template('requests_log.html', 
                         requests=requests_data, 
                         stats=stats,
                         recent_domains=recent_domains,
                         top_reg_numbers=top_reg_numbers,
                         page=page,
                         total_pages=total_pages,
                         total_count=total_count)

@app.route('/cases/<int:case_id>')
@login_required
def case_detail(case_id):
    conn = get_db_connection()

    case = conn.execute('''
        SELECT c.*, s.first_name, s.last_name, s.email as student_email, s.department as student_department,
               u.username as reported_by_name, ct.name as case_type_name, ct.description as case_type_description
        FROM cases c 
        LEFT JOIN students s ON c.student_reg_number = s.reg_number 
        JOIN users u ON c.reported_by = u.id
        LEFT JOIN case_types ct ON c.case_type_id = ct.id
        WHERE c.id = ?
    ''', (case_id,)).fetchone()

    conn.close()

    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('cases'))

    return render_template('case_detail.html', case=case)

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# External Integration API Endpoints
@app.route('/api/external/check-student', methods=['POST'])
def api_external_check_student():
    """
    External API endpoint for other systems to check if a student exists
    Expects JSON: {"reg_number": "R123456A", "domain": "example.edu"}
    Returns: {"exists": true/false, "status": "active/blacklisted/exonerated"}
    """
    try:
        # Verify request has JSON data
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
        
        reg_number = data.get('reg_number', '').strip().upper()
        requesting_domain = data.get('domain', '').strip()
        
        if not reg_number or not requesting_domain:
            return jsonify({"error": "reg_number and domain are required"}), 400
        
        # Check if domain is authorized
        if not is_domain_authorized(requesting_domain):
            return jsonify({"error": "Unauthorized domain"}), 403
        
        # Validate registration number format
        import re
        if not re.match(r'^R\d{6}[A-Z]$', reg_number):
            return jsonify({"error": "Invalid registration number format"}), 400
        
        # Log the external request for audit
        log_audit_action('external_student_check', 'api_request', reg_number, 
                        f'Domain: {requesting_domain}, IP: {request.environ.get("REMOTE_ADDR")}')
        
        # Log API request
        log_api_request('/api/external/check-student', 'POST', 
                       request.environ.get('REMOTE_ADDR'), 
                       request.headers.get('User-Agent', ''),
                       data, 200, reg_number, requesting_domain)
        
        # Check if student exists in main database
        conn = get_db_connection()
        student = conn.execute('''
            SELECT s.reg_number, s.first_name, s.last_name, s.is_active,
                   COUNT(c.id) as total_cases,
                   SUM(CASE WHEN c.status = 'blacklisted' THEN 1 ELSE 0 END) as blacklisted_cases
            FROM students s
            LEFT JOIN cases c ON s.reg_number = c.student_reg_number
            WHERE UPPER(s.reg_number) = ?
            GROUP BY s.reg_number, s.first_name, s.last_name, s.is_active
        ''', (reg_number,)).fetchone()
        conn.close()
        
        if student:
            # Determine status
            if student['blacklisted_cases'] > 0:
                status = 'blacklisted'
            elif student['is_active']:
                status = 'active'
            else:
                status = 'inactive'
            
            response = {
                "exists": True,
                "status": status,
                "reg_number": student['reg_number'],
                "total_cases": student['total_cases'],
                "requesting_domain": requesting_domain,
                "timestamp": datetime.now().isoformat()
            }
        else:
            # Check exonerated database
            exon_conn = get_exonerated_db_connection()
            exonerated = exon_conn.execute(
                'SELECT COUNT(*) as count FROM exonerated_cases WHERE UPPER(student_reg_number) = ?',
                (reg_number,)
            ).fetchone()
            exon_conn.close()
            
            if exonerated['count'] > 0:
                response = {
                    "exists": True,
                    "status": "exonerated",
                    "reg_number": reg_number,
                    "total_cases": 0,
                    "requesting_domain": requesting_domain,
                    "timestamp": datetime.now().isoformat()
                }
            else:
                response = {
                    "exists": False,
                    "status": "not_found",
                    "reg_number": reg_number,
                    "requesting_domain": requesting_domain,
                    "timestamp": datetime.now().isoformat()
                }
        
        return jsonify(response), 200
        
    except Exception as e:
        print(f"[API ERROR] External check student error: {str(e)}")
        return jsonify({"error": "Internal server error", "timestamp": datetime.now().isoformat()}), 500

@app.route('/api/external/verify-domain', methods=['POST'])
def api_external_verify_domain():
    """
    Verify if a domain is authorized to access the system
    This can be extended to include domain whitelist functionality
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400
        
        data = request.get_json()
        domain = data.get('domain', '').strip().lower()
        
        if not domain:
            return jsonify({"error": "domain is required"}), 400
        
        # For now, we'll allow all .edu domains and specific authorized domains
        authorized_domains = [
            '.edu', '.ac.', 'university.', 'college.', 'school.',
            'education.gov', 'moe.gov'  # Add specific authorized domains
        ]
        
        is_authorized = any(auth_domain in domain for auth_domain in authorized_domains)
        
        response = {
            "domain": domain,
            "authorized": is_authorized,
            "message": "Domain verification complete",
            "timestamp": datetime.now().isoformat()
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        print(f"[API ERROR] Domain verification error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/external/batch-check', methods=['POST'])
def api_external_batch_check():
    """
    Check multiple registration numbers at once
    Expects JSON: {"reg_numbers": ["R123456A", "R789012B"], "domain": "example.edu"}
    Returns: {"results": [{"reg_number": "R123456A", "exists": true, "status": "active"}, ...]}
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400
        
        data = request.get_json()
        reg_numbers = data.get('reg_numbers', [])
        requesting_domain = data.get('domain', '').strip().lower()
        
        if not reg_numbers or not requesting_domain:
            return jsonify({"error": "reg_numbers array and domain are required"}), 400
        
        if len(reg_numbers) > 100:  # Limit batch size
            return jsonify({"error": "Maximum 100 registration numbers per batch"}), 400
        
        results = []
        
        for reg_number in reg_numbers:
            reg_number = str(reg_number).strip().upper()
            
            # Validate format
            import re
            if not re.match(r'^R\d{6}[A-Z]$', reg_number):
                results.append({
                    "reg_number": reg_number,
                    "exists": False,
                    "status": "invalid_format",
                    "error": "Invalid registration number format"
                })
                continue
            
            # Check student
            conn = get_db_connection()
            student = conn.execute('''
                SELECT s.reg_number, s.is_active,
                       COUNT(c.id) as total_cases,
                       SUM(CASE WHEN c.status = 'blacklisted' THEN 1 ELSE 0 END) as blacklisted_cases
                FROM students s
                LEFT JOIN cases c ON s.reg_number = c.student_reg_number
                WHERE UPPER(s.reg_number) = ?
                GROUP BY s.reg_number, s.is_active
            ''', (reg_number,)).fetchone()
            conn.close()
            
            if student:
                if student['blacklisted_cases'] > 0:
                    status = 'blacklisted'
                elif student['is_active']:
                    status = 'active'
                else:
                    status = 'inactive'
                
                results.append({
                    "reg_number": reg_number,
                    "exists": True,
                    "status": status,
                    "total_cases": student['total_cases']
                })
            else:
                # Check exonerated
                exon_conn = get_exonerated_db_connection()
                exonerated = exon_conn.execute(
                    'SELECT COUNT(*) as count FROM exonerated_cases WHERE UPPER(student_reg_number) = ?',
                    (reg_number,)
                ).fetchone()
                exon_conn.close()
                
                if exonerated['count'] > 0:
                    results.append({
                        "reg_number": reg_number,
                        "exists": True,
                        "status": "exonerated",
                        "total_cases": 0
                    })
                else:
                    results.append({
                        "reg_number": reg_number,
                        "exists": False,
                        "status": "not_found"
                    })
        
        # Log batch request
        log_audit_action('external_batch_check', 'api_request', None, 
                        f'Domain: {requesting_domain}, Count: {len(reg_numbers)}, IP: {request.environ.get("REMOTE_ADDR")}')
        
        # Log API request
        log_api_request('/api/external/batch-check', 'POST', 
                       request.environ.get('REMOTE_ADDR'), 
                       request.headers.get('User-Agent', ''),
                       data, 200, f'{len(reg_numbers)} numbers', requesting_domain)
        
        response = {
            "results": results,
            "total_checked": len(results),
            "requesting_domain": requesting_domain,
            "timestamp": datetime.now().isoformat()
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        print(f"[API ERROR] Batch check error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# Internal API Endpoints
@app.route('/api/check-registration/<reg_number>')
def api_check_registration(reg_number):
    """
    API endpoint to check if a registration number exists in the main database
    Case-insensitive comparison (R228905p == r228905p == R228905P)
    Returns: {"exists": true/false, "reg_number": "normalized_format"}
    """
    # Normalize the registration number to uppercase
    normalized_reg = reg_number.upper().strip()

    conn = get_db_connection()

    # Check in students table first
    student = conn.execute(
        'SELECT reg_number FROM students WHERE UPPER(reg_number) = ? AND is_active = 1',
        (normalized_reg,)
    ).fetchone()

    # If not found in students, check in cases table
    if not student:
        case = conn.execute(
            'SELECT student_reg_number FROM cases WHERE UPPER(student_reg_number) = ?',
            (normalized_reg,)
        ).fetchone()
        if case:
            student = {'reg_number': case['student_reg_number']}

    conn.close()

    if student:
        return jsonify({
            "exists": True,
            "reg_number": student['reg_number'],
            "status": "active"
        })
    else:
        return jsonify({
            "exists": False,
            "reg_number": normalized_reg,
            "status": "not_found"
        })

@app.route('/api/check-registration-detailed/<reg_number>')
def api_check_registration_detailed(reg_number):
    """
    API endpoint to get detailed information about a registration number
    Checks both main database and exonerated database
    Returns: {"exists": true/false, "details": {...}, "exonerated": true/false}
    """
    normalized_reg = reg_number.upper().strip()

    # Check main database
    conn = get_db_connection()
    student_info = conn.execute('''
        SELECT s.*, COUNT(c.id) as active_cases
        FROM students s
        LEFT JOIN cases c ON s.reg_number = c.student_reg_number
        WHERE UPPER(s.reg_number) = ? AND s.is_active = 1
        GROUP BY s.reg_number, s.first_name, s.last_name, s.email, s.department, s.year_of_study, s.phone, s.created_at, s.is_active
    ''', (normalized_reg,)).fetchone()
    conn.close()

    # Check exonerated database
    exon_conn = get_exonerated_db_connection()
    exonerated_cases = exon_conn.execute(
        'SELECT COUNT(*) as count FROM exonerated_cases WHERE UPPER(student_reg_number) = ?',
        (normalized_reg,)
    ).fetchone()
    exon_conn.close()

    if student_info:
        return jsonify({
            "exists": True,
            "reg_number": student_info['reg_number'],
            "details": {
                "first_name": student_info['first_name'],
                "last_name": student_info['last_name'],
                "email": student_info['email'],
                "department": student_info['department'],
                "year_of_study": student_info['year_of_study'],
                "active_cases": student_info['active_cases']
            },
            "exonerated_cases": exonerated_cases['count'],
            "status": "active"
        })
    else:
        # Check if only exists in exonerated database
        exon_conn = get_exonerated_db_connection()
        exonerated_student = exon_conn.execute(
            'SELECT student_first_name, student_last_name, student_email FROM exonerated_cases WHERE UPPER(student_reg_number) = ? LIMIT 1',
            (normalized_reg,)
        ).fetchone()
        exon_conn.close()

        if exonerated_student:
            return jsonify({
                "exists": True,
                "reg_number": normalized_reg,
                "details": {
                    "first_name": exonerated_student['student_first_name'],
                    "last_name": exonerated_student['student_last_name'],
                    "email": exonerated_student['student_email'],
                    "active_cases": 0
                },
                "exonerated_cases": exonerated_cases['count'],
                "status": "exonerated_only"
            })
        else:
            return jsonify({
                "exists": False,
                "reg_number": normalized_reg,
                "status": "not_found"
            })

@app.route('/api/external/check-exists/<reg_number>')
def api_check_exists(reg_number):
    """
    Simple API endpoint to check if a registration number exists
    Returns: {"exists": "yes"/"no", "reg_number": "R123456A"}
    """
    try:
        # Normalize the registration number
        normalized_reg = reg_number.upper().strip()
        
        # Validate format
        import re
        if not re.match(r'^R\d{6}[A-Z]$', normalized_reg):
            return jsonify({
                "exists": "no",
                "reg_number": normalized_reg,
                "error": "Invalid format"
            }), 400
        
        # Check main database
        conn = get_db_connection()
        student = conn.execute(
            'SELECT reg_number FROM students WHERE UPPER(reg_number) = ? AND is_active = 1',
            (normalized_reg,)
        ).fetchone()
        
        # If not in students, check cases
        if not student:
            case = conn.execute(
                'SELECT student_reg_number FROM cases WHERE UPPER(student_reg_number) = ?',
                (normalized_reg,)
            ).fetchone()
            if case:
                student = {'reg_number': case['student_reg_number']}
        
        conn.close()
        
        # Check exonerated database if not found
        if not student:
            exon_conn = get_exonerated_db_connection()
            exonerated = exon_conn.execute(
                'SELECT student_reg_number FROM exonerated_cases WHERE UPPER(student_reg_number) = ?',
                (normalized_reg,)
            ).fetchone()
            exon_conn.close()
            
            if exonerated:
                student = {'reg_number': exonerated['student_reg_number']}
        
        # Log the request
        log_audit_action('external_simple_check', 'api_request', normalized_reg, 
                        f'IP: {request.environ.get("REMOTE_ADDR")}')
        
        # Log API request
        log_api_request('/api/external/check-exists', 'GET', 
                       request.environ.get('REMOTE_ADDR'), 
                       request.headers.get('User-Agent', ''),
                       {'reg_number': normalized_reg}, 200, normalized_reg, 'direct')
        
        return jsonify({
            "exists": "yes" if student else "no",
            "reg_number": normalized_reg,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"[API ERROR] Simple check error: {str(e)}")
        return jsonify({
            "exists": "no",
            "reg_number": reg_number,
            "error": "Server error"
        }), 500

@app.route('/api/health')
def api_health():
    """Health check endpoint for the API"""
    return jsonify({
        "status": "healthy",
        "service": "Disciplinary Management System API",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/search-cases')
@login_required
def api_search_cases():
    """Search cases by registration number"""
    query = request.args.get('q', '').strip()
    if len(query) < 2:
        return jsonify([])
    
    conn = get_db_connection()
    cases = conn.execute('''
        SELECT c.id, c.case_number, s.first_name, s.last_name, s.reg_number, c.status
        FROM cases c
        JOIN students s ON c.student_reg_number = s.reg_number
        WHERE s.reg_number LIKE ? OR s.first_name LIKE ? OR s.last_name LIKE ?
        ORDER BY c.created_at DESC LIMIT 10
    ''', (f'%{query}%', f'%{query}%', f'%{query}%')).fetchall()
    
    conn.close()
    
    results = []
    for case in cases:
        results.append({
            'id': case['id'],
            'case_number': case['case_number'],
            'student_name': f"{case['first_name']} {case['last_name']}",
            'reg_number': case['reg_number'],
            'status': case['status']
        })
    
    return jsonify(results)

@app.route('/api-docs')
def api_documentation():
    """Public API documentation page"""
    return render_template('api_documentation.html')

@app.route('/health-dashboard')
@login_required
@require_role('admin')
@monitor_performance
def health_dashboard():
    """System health monitoring dashboard"""
    log_audit_action('view_health_dashboard', 'system', None, 'Accessed health dashboard')
    
    conn = get_db_connection()
    
    # System statistics
    try:
        # Database metrics
        total_cases = conn.execute('SELECT COUNT(*) as count FROM cases').fetchone()['count']
        total_students = conn.execute('SELECT COUNT(*) as count FROM students').fetchone()['count']
        total_users = conn.execute('SELECT COUNT(*) as count FROM users WHERE is_active = 1').fetchone()['count']
        
        # Recent performance metrics
        avg_response_time = conn.execute('''
            SELECT AVG(response_time) as avg_time FROM performance_logs 
            WHERE timestamp > datetime('now', '-1 hour')
        ''').fetchone()['avg_time'] or 0
        
        # Error rate
        total_requests = conn.execute('''
            SELECT COUNT(*) as count FROM performance_logs 
            WHERE timestamp > datetime('now', '-1 hour')
        ''').fetchone()['count']
        
        error_requests = conn.execute('''
            SELECT COUNT(*) as count FROM performance_logs 
            WHERE timestamp > datetime('now', '-1 hour') AND status_code >= 400
        ''').fetchone()['count']
        
        error_rate = (error_requests / total_requests * 100) if total_requests > 0 else 0
        
        # System resources
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Email system status
        email_failed_count = conn.execute('''
            SELECT COUNT(*) as count FROM email_logs 
            WHERE sent_status = 'failed' AND sent_at > datetime('now', '-24 hours')
        ''').fetchone()['count']
        
        system_health = {
            'database': {
                'status': 'healthy',
                'total_cases': total_cases,
                'total_students': total_students,
                'total_users': total_users
            },
            'performance': {
                'avg_response_time': round(avg_response_time, 2),
                'error_rate': round(error_rate, 2),
                'total_requests_hour': total_requests
            },
            'system': {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'disk_percent': (disk.used / disk.total) * 100
            },
            'email': {
                'status': 'healthy' if email_failed_count < 10 else 'warning',
                'failed_count_24h': email_failed_count
            }
        }
        
    except Exception as e:
        print(f"Health check error: {str(e)}")
        system_health = {'error': 'Unable to retrieve system metrics'}
    
    conn.close()
    
    return render_template('health_dashboard.html', health=system_health)

def reset_database():
    """Reset the database completely - use only if migration fails"""
    if os.path.exists(DATABASE):
        os.remove(DATABASE)
    init_db()

if __name__ == '__main__':
    try:
        migrate_db()  # Try migration first
        init_db()     # Ensure all tables exist
        init_exonerated_db()  # Initialize exonerated cases database
    except Exception as e:
        print(f"Migration failed: {e}")
        print("Resetting database...")
        reset_database()
        init_exonerated_db()  # Initialize exonerated cases database

    # Disable debug mode for security - only enable for development
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)