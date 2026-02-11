# 🚀 Deployment Guide - Financial Dashboard

Complete step-by-step guide for deploying your Financial Dashboard to production.

---

## 📋 Table of Contents

1. [Pre-Deployment Checklist](#pre-deployment-checklist)
2. [Option 1: DIY Home Server with Nginx](#option-1-diy-home-server-with-nginx)
3. [Option 2: DigitalOcean Droplet](#option-2-digitalocean-droplet)
4. [Option 3: AWS EC2](#option-3-aws-ec2)
5. [Option 4: Heroku](#option-4-heroku)
6. [Post-Deployment](#post-deployment)
7. [Troubleshooting](#troubleshooting)

---

## Pre-Deployment Checklist

Before deploying to production, ensure:

- [ ] **Changed default password** from `ChangeMe123!`
- [ ] **Generated strong SECRET_KEY** (not using default)
- [ ] **Tested locally** - all features work
- [ ] **Backed up data** - exported JSON files
- [ ] **Reviewed security settings** in SECURITY.md
- [ ] **Domain name ready** (if applicable)
- [ ] **SSL certificate plan** (Let's Encrypt recommended)

---

## Option 1: DIY Home Server with Nginx

Perfect for hosting on your own hardware with full control.

### Prerequisites
- Ubuntu 20.04+ or Debian 11+
- Static IP or Dynamic DNS
- Router port forwarding
- Domain name (optional but recommended)

### Step 1: System Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y python3 python3-pip nginx certbot python3-certbot-nginx git

# Install Python dependencies
pip3 install --break-system-packages flask flask-limiter bcrypt gunicorn
```

### Step 2: Clone and Setup

```bash
# Create application directory
sudo mkdir -p /var/www/financial-dashboard
cd /var/www/financial-dashboard

# Clone repository (or upload files)
git clone https://github.com/yourusername/financial-dashboard.git .

# Set permissions
sudo chown -R $USER:$USER /var/www/financial-dashboard
chmod 700 data/

# Generate secret key
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
echo "export SECRET_KEY='$SECRET_KEY'" >> ~/.bashrc
```

### Step 3: Configure Nginx

```bash
# Copy nginx configuration
sudo cp nginx.conf /etc/nginx/sites-available/financial-dashboard

# Edit configuration with your domain
sudo nano /etc/nginx/sites-available/financial-dashboard
# Replace: your-domain.com → yourdomain.com

# Create symbolic link
sudo ln -s /etc/nginx/sites-available/financial-dashboard /etc/nginx/sites-enabled/

# Remove default site
sudo rm /etc/nginx/sites-enabled/default

# Test configuration
sudo nginx -t

# If test passes, reload
sudo systemctl reload nginx
```

### Step 4: SSL Certificate (Let's Encrypt)

```bash
# Install certificate
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com

# Follow prompts:
# - Enter email for renewal notifications
# - Agree to Terms of Service
# - Choose to redirect HTTP to HTTPS (recommended)

# Test auto-renewal
sudo certbot renew --dry-run
```

### Step 5: Create Systemd Service

```bash
# Create service file
sudo nano /etc/systemd/system/financial-dashboard.service
```

Paste this content:

```ini
[Unit]
Description=Financial Dashboard
After=network.target

[Service]
Type=notify
User=www-data
Group=www-data
WorkingDirectory=/var/www/financial-dashboard
Environment="SECRET_KEY=your-secret-key-here"
ExecStart=/usr/local/bin/gunicorn -w 4 -b 127.0.0.1:5000 --timeout 120 auth_server:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Replace `your-secret-key-here` with your actual secret key.

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service
sudo systemctl enable financial-dashboard

# Start service
sudo systemctl start financial-dashboard

# Check status
sudo systemctl status financial-dashboard
```

### Step 6: Configure Firewall

```bash
# Allow SSH, HTTP, HTTPS
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status
```

### Step 7: Router Configuration

Forward these ports from your router to your server:
- Port 80 (HTTP) → Server IP
- Port 443 (HTTPS) → Server IP

### Step 8: Dynamic DNS (if no static IP)

Use services like:
- No-IP
- DuckDNS
- Cloudflare (with Dynamic DNS)

---

## Option 2: DigitalOcean Droplet

### Step 1: Create Droplet

1. Go to [DigitalOcean](https://www.digitalocean.com/)
2. Create → Droplets
3. Choose:
   - **Image:** Ubuntu 22.04 LTS
   - **Plan:** Basic ($6/month recommended)
   - **Region:** Closest to you
   - **Authentication:** SSH key (recommended)
4. Click **Create Droplet**

### Step 2: Initial Setup

```bash
# SSH into droplet
ssh root@your-droplet-ip

# Update system
apt update && apt upgrade -y

# Create non-root user
adduser dashboard
usermod -aG sudo dashboard

# Switch to new user
su - dashboard
```

### Step 3: Follow Steps from Option 1

Continue with Steps 1-6 from the DIY Home Server guide above.

### Step 4: Point Domain to Droplet

1. Get your droplet's IP address
2. In your domain registrar:
   - Add A record: `@` → `droplet-ip`
   - Add A record: `www` → `droplet-ip`
3. Wait for DNS propagation (up to 24 hours)

---

## Option 3: AWS EC2

### Step 1: Launch EC2 Instance

1. Go to [AWS Console](https://console.aws.amazon.com/)
2. Navigate to EC2 → Launch Instance
3. Choose:
   - **AMI:** Ubuntu Server 22.04 LTS
   - **Instance Type:** t2.micro (free tier) or t2.small
   - **Security Group:** 
     - SSH (22) from your IP
     - HTTP (80) from anywhere
     - HTTPS (443) from anywhere
4. Create/select key pair
5. Launch instance

### Step 2: Connect to Instance

```bash
# Download your .pem key
chmod 400 your-key.pem

# Connect
ssh -i your-key.pem ubuntu@your-ec2-public-ip
```

### Step 3: Follow Option 1 Setup

Follow Steps 1-6 from DIY Home Server guide.

### Step 4: Elastic IP (Optional)

1. Allocate Elastic IP in AWS Console
2. Associate with your instance
3. Update DNS records with Elastic IP

---

## Option 4: Heroku

### Step 1: Prepare Application

```bash
# Create Procfile
echo "web: gunicorn auth_server:app" > Procfile

# Create runtime.txt
echo "python-3.11.0" > runtime.txt

# Update requirements.txt to include gunicorn
echo "gunicorn==21.2.0" >> requirements.txt
```

### Step 2: Heroku Setup

```bash
# Install Heroku CLI
# Visit: https://devcenter.heroku.com/articles/heroku-cli

# Login
heroku login

# Create app
heroku create your-app-name

# Set environment variables
heroku config:set SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Deploy
git push heroku main

# Open app
heroku open
```

### Step 3: Add SSL

Heroku provides automatic SSL certificates for apps.

---

## Post-Deployment

### 1. Verify Deployment

```bash
# Test HTTPS
curl -I https://yourdomain.com

# Check SSL grade
# Visit: https://www.ssllabs.com/ssltest/
```

### 2. Change Default Password

1. Access your dashboard
2. Login with default credentials
3. Go to Settings → Change Password
4. Set a strong password

### 3. Configure Monitoring

```bash
# Check logs
sudo journalctl -u financial-dashboard -f

# Monitor Nginx
sudo tail -f /var/log/nginx/financial-dashboard-*.log

# Set up log rotation
sudo nano /etc/logrotate.d/financial-dashboard
```

### 4. Setup Backups

```bash
# Create backup script
sudo nano /usr/local/bin/backup-dashboard.sh
```

Paste:
```bash
#!/bin/bash
BACKUP_DIR="/var/backups/financial-dashboard"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR
tar -czf $BACKUP_DIR/backup_$DATE.tar.gz /var/www/financial-dashboard/data/

# Keep only last 30 days
find $BACKUP_DIR -name "backup_*.tar.gz" -mtime +30 -delete
```

```bash
# Make executable
sudo chmod +x /usr/local/bin/backup-dashboard.sh

# Add to crontab (daily at 2 AM)
sudo crontab -e
# Add: 0 2 * * * /usr/local/bin/backup-dashboard.sh
```

### 5. Security Hardening

```bash
# Fail2ban for SSH protection
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Automatic security updates
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure -plow unattended-upgrades
```

### 6. Performance Optimization

```bash
# Enable Nginx gzip compression
sudo nano /etc/nginx/nginx.conf
# Uncomment gzip lines

# Reload Nginx
sudo systemctl reload nginx
```

---

## Monitoring & Maintenance

### Daily Tasks
- Check application logs
- Monitor failed login attempts
- Verify backups completed

### Weekly Tasks
- Review security logs
- Check disk space: `df -h`
- Monitor CPU/memory: `htop`

### Monthly Tasks
- Update system packages
- Update Python dependencies
- Review and rotate logs
- Test backup restoration
- Run security tests

### Useful Commands

```bash
# View application logs
sudo journalctl -u financial-dashboard -f

# Restart application
sudo systemctl restart financial-dashboard

# Check Nginx status
sudo systemctl status nginx

# Test Nginx config
sudo nginx -t

# View disk usage
du -sh /var/www/financial-dashboard/*

# Check open ports
sudo netstat -tulpn | grep LISTEN

# Monitor real-time traffic
sudo tcpdump -i any port 443
```

---

## Troubleshooting

### Application Won't Start

```bash
# Check logs
sudo journalctl -u financial-dashboard -e

# Check Python errors
python3 auth_server.py

# Verify dependencies
pip3 list | grep -E "flask|bcrypt|gunicorn"
```

### 502 Bad Gateway

```bash
# Check if application is running
sudo systemctl status financial-dashboard

# Check Nginx error logs
sudo tail -f /var/log/nginx/error.log

# Verify port 5000 is listening
sudo netstat -tulpn | grep 5000
```

### SSL Certificate Issues

```bash
# Renew certificate manually
sudo certbot renew

# Check certificate expiration
sudo certbot certificates

# Test renewal
sudo certbot renew --dry-run
```

### Database/Data Issues

```bash
# Backup current data
cp -r data/ data_backup_$(date +%Y%m%d)/

# Reset users (if locked out)
rm data/users.json
sudo systemctl restart financial-dashboard
# Login with default credentials
```

### Performance Issues

```bash
# Check resource usage
htop

# Increase Gunicorn workers (if needed)
# Edit /etc/systemd/system/financial-dashboard.service
# Change: -w 4 to -w 8

# Reload
sudo systemctl daemon-reload
sudo systemctl restart financial-dashboard
```

---

## Security Checklist Post-Deployment

- [ ] **Changed default password**
- [ ] **SSL/HTTPS enabled and working**
- [ ] **Firewall configured correctly**
- [ ] **Rate limiting active**
- [ ] **Security headers verified**
- [ ] **Automatic backups configured**
- [ ] **Log monitoring setup**
- [ ] **Fail2ban installed (if applicable)**
- [ ] **System updates automated**
- [ ] **Regular security scans scheduled**

---

## Updating the Application

```bash
# Pull latest changes
cd /var/www/financial-dashboard
git pull origin main

# Install new dependencies (if any)
pip3 install -r requirements.txt --upgrade

# Restart application
sudo systemctl restart financial-dashboard

# Clear browser cache and test
```

---

## Rollback Procedure

```bash
# Stop application
sudo systemctl stop financial-dashboard

# Restore from backup
sudo tar -xzf /var/backups/financial-dashboard/backup_YYYYMMDD_HHMMSS.tar.gz -C /

# Restart application
sudo systemctl start financial-dashboard
```

---

## Support Resources

- **Documentation:** Check all .md files in repository
- **Security Tests:** Run `python3 security_tests.py`
- **Community:** GitHub Issues or Discussions
- **Professional Help:** Consider hiring a DevOps consultant for production deployments

---

**Deployment Status Checklist:**

```
□ System prepared
□ Application installed
□ Nginx configured
□ SSL certificate installed
□ Systemd service created
□ Firewall configured
□ DNS configured
□ Monitoring setup
□ Backups configured
□ Security hardened
□ Default password changed
□ Tested all features
```

---

**🎉 Congratulations!** Your Financial Dashboard is now deployed and secured for production use!

For ongoing support, refer to [SECURITY.md](SECURITY.md) and [QUICKSTART.md](QUICKSTART.md).
