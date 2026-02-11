#!/bin/bash

# Installation and Setup Script for Financial Dashboard
# This script helps set up the secure authentication system

echo "=========================================="
echo "Financial Dashboard - Setup Script"
echo "=========================================="
echo ""

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3 first."
    exit 1
fi

echo "✓ Python 3 found"

# Create virtual environment
echo ""
echo "Creating Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

# Activate virtual environment
echo ""
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo ""
echo "Installing Python dependencies..."
pip install --upgrade pip > /dev/null 2>&1
pip install flask flask-limiter bcrypt colorama requests

echo "✓ Dependencies installed"

# Create data directory
echo ""
echo "Setting up data directory..."
mkdir -p data
chmod 700 data
echo "✓ Data directory created"

# Generate secure secret key
echo ""
echo "Generating secure secret key..."
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "SECRET_KEY=$SECRET_KEY" > .env
    chmod 600 .env
    echo "✓ Secret key generated and saved to .env"
else
    echo "ℹ .env file already exists, keeping existing configuration"
fi

# Make startup script executable
if [ -f "start_server.sh" ]; then
    chmod +x start_server.sh
fi

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "📝 Next Steps:"
echo ""
echo "1. Start the authentication server:"
echo "   python3 auth_server.py"
echo ""
echo "2. Default credentials (CHANGE IMMEDIATELY):"
echo "   Username: admin"
echo "   Password: ChangeMe123!"
echo ""
echo "3. Run security tests (in a separate terminal):"
echo "   python3 security_tests.py"
echo ""
echo "4. For production deployment:"
echo "   - Generate SSL certificates (Let's Encrypt recommended)"
echo "   - Copy nginx.conf to /etc/nginx/sites-available/"
echo "   - Update domain name in nginx.conf"
echo "   - Set SECRET_KEY environment variable"
echo "   - Use a production WSGI server (gunicorn/uwsgi)"
echo ""
echo "🔒 Security Reminders:"
echo "   - Change default password immediately"
echo "   - Keep SECRET_KEY confidential"
echo "   - Enable HTTPS in production"
echo "   - Regularly update dependencies"
echo "   - Monitor logs for suspicious activity"
echo ""
