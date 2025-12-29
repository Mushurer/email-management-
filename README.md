# Disciplinary Management System (DMS)

A comprehensive Flask-based web application for managing student disciplinary cases within educational institutions.

## 🚀 Features

- **Role-Based Access Control**: Secure authentication system with Admin, Staff, and Student roles
- **Case Management**: Complete lifecycle management of disciplinary cases
- **Student Records**: Comprehensive student registration and profile management  
- **File Upload System**: Secure document attachment for case evidence
- **Email Notifications**: Automated email system using Replit Mail service
- **Dashboard Analytics**: Real-time reporting and case statistics
- **Audit Trail**: Complete logging of all email communications and case activities

## 🛠️ Technology Stack

- **Backend**: Flask 3.1.2 (Python web framework)
- **Database**: SQLite with foreign key constraints
- **Authentication**: Flask-Login 0.6.3 with session management
- **Security**: CSRF protection, password hashing, secure file uploads
- **Email**: Replit Mail API integration (no SMTP required)
- **Frontend**: Jinja2 3.1.6 templates with responsive design
- **Forms**: WTForms 3.2.1 with Flask-WTF 1.2.2 validation

## 📋 Requirements

- Python 3.8+
- All dependencies listed in `requirements.txt`
- SESSION_SECRET environment variable
- REPL_IDENTITY environment variable (automatically provided in Replit)

## 🚀 Installation & Setup

### 1. Clone and Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Set required environment variable
export SESSION_SECRET="your-secure-secret-key-here"
```

### 2. Database Initialization
The application automatically creates and migrates the database on first run.

### 3. Run the Application
```bash
python app.py
```

The application will be available at:
- **Local development**: `http://localhost:5000`
- **Replit environment**: Accessible via the Replit preview pane on port 5000

## 🔐 Default Admin Account

On first run, the system creates a default admin account:
- **Username**: admin
- **Password**: admin123

**⚠️ Important**: Change the default password immediately after first login!

## 👥 User Roles

### Admin
- Full system access
- User management and role assignment
- System configuration and email settings
- Complete case oversight and reporting

### Staff
- Create and manage disciplinary cases
- Student registration and profile management
- Case documentation and file uploads
- Limited reporting capabilities

### Student
- View personal disciplinary cases only
- Read-only access to case details
- No administrative functions

## 📁 Project Structure

```
disciplinary_system/
├── app.py                 # Main application file
├── requirements.txt       # Python dependencies
├── replit.md             # Detailed technical documentation
├── disciplinary_system.db # SQLite database (auto-created)
├── uploads/              # File upload directory
├── templates/            # Jinja2 HTML templates
│   ├── base.html
│   ├── dashboard.html
│   ├── cases/
│   ├── students/
│   └── admin/
└── static/              # CSS, JS, and static assets
    └── style.css
```

## 🔧 Configuration

### Environment Variables
- `SESSION_SECRET`: Required for session encryption (must be set)
- `REPL_IDENTITY`: Automatically provided by Replit for email functionality

### File Upload Settings
- Maximum file size: 16MB
- Allowed formats: PDF, DOC, DOCX, JPG, JPEG, PNG
- Secure filename handling prevents directory traversal attacks

### Email Configuration
The application uses Replit's integrated mail service for notifications:
- **No external SMTP setup required** - bypasses traditional authentication issues
- **Automatic authentication** via REPL_IDENTITY environment variable
- **Built-in delivery tracking and logging** with comprehensive audit trail
- **Secure API integration** using Replit's connectors service
- **No email credentials needed** - works out of the box in Replit environment

## 🔒 Security Features

- **CSRF Protection**: All forms protected against cross-site request forgery
- **Secure Sessions**: HTTP-only, secure cookies with proper SameSite settings
- **Password Security**: Bcrypt hashing with salt
- **File Upload Security**: Type validation and secure filename handling
- **SQL Injection Prevention**: Parameterized queries throughout
- **Role-Based Access**: Strict permission enforcement on all routes

## 📧 Email System

The application includes a comprehensive email notification system:
- Welcome emails for new users
- Case status update notifications
- Administrative alerts and summaries
- Email delivery tracking and audit logs
- Integration with Replit Mail service (no external SMTP required)

## 🗄️ Automated Database Backup System

The system includes an intelligent daily backup feature:
- **Automated Daily Backups**: Creates database backups at midnight when new cases are created
- **Smart Backup Logic**: Only creates backups on days when new disciplinary cases are recorded
- **Admin Notifications**: Sends backup confirmation emails to the admin with backup details
- **Manual Backup Option**: Administrators can trigger manual backups from the admin panel
- **Secure Storage**: Backup files are stored in the uploads directory with timestamped filenames
- **API Endpoint**: `/api/daily-backup-check` for integration with external scheduling systems

### Backup Schedule Configuration
For automatic daily backups, you can set up a scheduled task using Replit's Scheduled Deployments:
1. Go to the **Deployments** section in your Repl
2. Create a **Scheduled Deployment** 
3. Set schedule to run daily at midnight: `0 0 * * *`
4. Use the run command: `curl -X GET http://localhost:5000/api/daily-backup-check`
5. This will check for new cases and create backups automatically

## 🗄️ Database Schema

### Core Tables
- **users**: Authentication and role management
- **students**: Student records and registration details
- **cases**: Disciplinary case tracking
- **case_types**: Predefined disciplinary categories
- **email_logs**: Complete email communication audit trail

## 🚀 Deployment

### Replit Deployment (Recommended)
This application is optimized for Replit deployment:

1. **Automatic Configuration**: Flask workflow runs on port 5000
2. **Environment Management**: SESSION_SECRET via Replit secrets, REPL_IDENTITY auto-provided
3. **Persistent Storage**: SQLite database and file uploads are preserved
4. **Integrated Email**: Replit Mail service works immediately without setup
5. **Zero Configuration**: Run button starts the application instantly

### Manual Deployment
For deployment outside Replit:
1. Install dependencies: `pip install -r requirements.txt`
2. Set SESSION_SECRET environment variable
3. Configure external email service (replace Replit Mail integration)
4. Ensure file upload directory permissions
5. Run with production WSGI server (e.g., Gunicorn)

## 📚 Additional Documentation

For detailed technical documentation, architecture decisions, and development notes, see `replit.md`.

## 🤝 Support

For issues or questions about the Disciplinary Management System, contact your system administrator.

## 📄 License

This project is proprietary software developed for educational institution use.