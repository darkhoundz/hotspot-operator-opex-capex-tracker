# 💼 Financial Dashboard - Secure OPEX/CAPEX Tracker

A modern, secure web-based financial dashboard for tracking operational expenses (OPEX), capital expenditures (CAPEX), revenue, and WiFi vendo income. Built with enterprise-grade security features and ready for production deployment.

![Security Grade](https://img.shields.io/badge/Security-A--Excellent-brightgreen)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 🌟 Features

### 📊 Financial Tracking
- **Revenue Management** - Track all income sources
- **OPEX Tracking** - Monitor operational expenses
- **CAPEX Tracking** - Capital expenditure management
- **WiFi Vendo Module** - Dedicated vending machine income tracking
- **Real-time Dashboard** - Live profit/loss calculations
- **Multiple Frequencies** - Daily, monthly, quarterly, annually
- **Data Export/Import** - JSON backup and restore

### 🔒 Security Features
- **Bcrypt Password Hashing** - Military-grade encryption
- **Session Management** - Secure, auto-expiring sessions
- **Rate Limiting** - Brute force protection
- **Account Lockout** - 5 failed attempts → 15 min lockout
- **Password Strength Validation** - Enforced strong passwords
- **XSS Protection** - Input sanitization
- **CSRF Protection** - SameSite cookies
- **Security Headers** - HSTS, CSP, X-Frame-Options
- **Path Traversal Prevention** - Restricted file access

### 🎨 User Experience
- **Modern Dark Theme** - Easy on the eyes
- **Responsive Design** - Works on all devices
- **Interactive Charts** - Chart.js visualizations
- **Real-time Updates** - Instant calculations
- **User-friendly Forms** - Intuitive data entry

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Modern web browser

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/financial-dashboard.git
cd financial-dashboard
```

2. **Run the setup script**
```bash
chmod +x setup.sh
./setup.sh
```

Or install manually:
```bash
pip3 install -r requirements.txt
```

3. **Start the server**
```bash
python3 auth_server.py
```

4. **Access the dashboard**
- Open your browser: http://localhost:5000
- Default credentials:
  - Username: `admin`
  - Password: `ChangeMe123!`
- **⚠️ CHANGE PASSWORD IMMEDIATELY!**

## 📖 Documentation

- **[Quick Start Guide](QUICKSTART.md)** - Get started in 5 minutes
- **[Security Documentation](SECURITY.md)** - Security features and best practices
- **[Deployment Guide](DEPLOYMENT.md)** - Production deployment instructions
- **[Security Test Results](SECURITY_TEST_RESULTS.md)** - Vulnerability test analysis
- **[Password Change Feature](PASSWORD_CHANGE_FEATURE.md)** - Password management docs

## 🛡️ Security

This application has been tested against common vulnerabilities:

| Vulnerability | Status |
|--------------|--------|
| SQL Injection | ✅ Protected |
| XSS | ✅ Protected |
| CSRF | ✅ Protected |
| Brute Force | ✅ Protected |
| Session Hijacking | ✅ Protected |
| Path Traversal | ✅ Protected |
| Command Injection | ✅ Protected |

**Security Grade:** A- (Excellent)

See [SECURITY_TEST_RESULTS.md](SECURITY_TEST_RESULTS.md) for detailed test results.

## 🏗️ Architecture

```
financial-dashboard/
├── auth_server.py          # Flask authentication server
├── login.html              # Login page
├── index.html              # Main dashboard
├── js/
│   └── script.js          # Frontend logic
├── css/                   # Stylesheets
├── data/
│   ├── financials.json    # Financial data
│   ├── settings.json      # Application settings
│   └── users.json         # User credentials (auto-created)
├── security_tests.py      # Security testing suite
└── nginx.conf             # Production Nginx config
```

## 🔧 Configuration

### Environment Variables
```bash
# Set a secure secret key for production
export SECRET_KEY="your-secure-secret-key-here"
```

### Settings
Configure via Settings page in the dashboard:
- Company Name
- Currency Symbol
- Report Title
- Logo URL
- WiFi Vendo Machines

## 🧪 Testing

Run the security test suite:
```bash
# Make sure server is running first
python3 security_tests.py
```

Test password change functionality:
```bash
python3 test_password_change.py
```

## 🌐 Production Deployment

### Option 1: DIY Home Server with Nginx

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed instructions.

**Quick Overview:**
1. Install SSL certificate (Let's Encrypt)
2. Configure Nginx with provided config
3. Set environment variables
4. Use Gunicorn as WSGI server
5. Create systemd service
6. Configure firewall

### Option 2: Cloud Deployment

Compatible with:
- **DigitalOcean** - App Platform or Droplet
- **AWS** - EC2 or Elastic Beanstalk
- **Heroku** - Web dyno
- **Google Cloud** - App Engine or Compute Engine
- **Azure** - App Service

## 📊 Usage

### Adding Transactions
1. Navigate to **Entries** tab
2. Select transaction type (Revenue/OPEX/CAPEX)
3. Enter name, amount, and frequency
4. Click **Add Transaction**

### WiFi Vendo Management
1. Go to **WiFi Vendo** tab
2. Add machines in Settings
3. Track income and expenses per machine
4. Filter by date range

### Changing Password
1. Go to **Settings** → **Change Password**
2. Enter current and new password
3. Must meet strength requirements
4. Auto-logout after change

### Data Backup
- **Export:** Click "Save Data" in sidebar
- **Import:** Click "Load Data" and select JSON file

## 🔐 Security Best Practices

### For Development
- ✅ Keep dependencies updated
- ✅ Never commit `.env` or `users.json`
- ✅ Use development server only on localhost

### For Production
- ✅ Change default admin password
- ✅ Set strong SECRET_KEY
- ✅ Enable HTTPS/SSL
- ✅ Configure firewall (ports 22, 80, 443)
- ✅ Use production WSGI server (Gunicorn)
- ✅ Enable all security headers
- ✅ Regular backups
- ✅ Monitor logs
- ✅ Keep software updated

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Common Issues

**Can't login**
- Check caps lock
- Verify password
- Wait 15 minutes if account is locked

**Server won't start**
- Check if port 5000 is in use: `lsof -i :5000`
- Kill existing process: `kill -9 <PID>`
- Check logs: `tail -f server.log`

**Rate limited**
- Wait 1 minute for login endpoint
- Normal behavior for rapid requests

### Getting Help
- Check [QUICKSTART.md](QUICKSTART.md) for setup help
- Review [SECURITY.md](SECURITY.md) for security questions
- See [DEPLOYMENT.md](DEPLOYMENT.md) for production issues

## 🗺️ Roadmap

### Planned Features
- [ ] Two-Factor Authentication (2FA)
- [ ] Email notifications
- [ ] Multi-user support with roles
- [ ] API endpoints for integrations
- [ ] Mobile app (React Native)
- [ ] Advanced reporting (PDF exports)
- [ ] Budget forecasting
- [ ] Receipt/document upload
- [ ] Multi-currency support
- [ ] Audit trail logging

## 📈 Changelog

### v1.0.0 (February 2026)
- ✅ Initial release
- ✅ Secure authentication system
- ✅ Financial tracking (Revenue, OPEX, CAPEX)
- ✅ WiFi Vendo module
- ✅ Password change feature
- ✅ Security testing suite
- ✅ Production-ready Nginx config
- ✅ Comprehensive documentation

## 👥 Authors

- **Your Name** - *Initial work* - [YourGitHub](https://github.com/yourusername)

## 🙏 Acknowledgments

- [Flask](https://flask.palletsprojects.com/) - Web framework
- [Chart.js](https://www.chartjs.org/) - Charts and graphs
- [Tailwind CSS](https://tailwindcss.com/) - Styling
- [Font Awesome](https://fontawesome.com/) - Icons
- [OWASP](https://owasp.org/) - Security guidelines

## 📞 Contact

- Email: your.email@example.com
- Project Link: https://github.com/yourusername/financial-dashboard

---

**⭐ Star this repository if you find it helpful!**

Made with ❤️ for financial transparency and security
