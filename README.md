# SDM SSL Certificate Client

Generate SSL Certificate for private IP address

A Python client for requesting SSL certificates from the Sanusi Digital Media SSL Generator API (https://sslgen.sanusi.id). This client automatically downloads and stores certificates in `/etc/ssl/sdmcert` for easy integration with web servers.

## � Features

- 🔐 **Secure API Integration** - Bearer token authentication
- 📁 **Organized Storage** - Certificates stored in `/etc/ssl/sdmcert/{ip_address}/`
- 🔧 **Multiple Formats** - Generates cert.pem, chain.pem, fullchain.pem, and privkey.pem
- 🤖 **Automation Ready** - Systemd service for automatic renewal
- 🌐 **Web Server Integration** - Auto-installation scripts for Nginx and Apache
- 📊 **Comprehensive Logging** - Detailed logs for monitoring and debugging
- 🎯 **Interactive Mode** - User-friendly command-line interface

## 🚀 Quick Start

### 1. Installation
```bash
# Download and run the installation script
sudo ./install.sh
```

### 2. Get API Token
Visit https://sslgen.sanusi.id/register to get your API token.

### 3. Configure
Edit the configuration file:
```bash
sudo nano /etc/sdm-ssl/config.json
```

Add your API token:
```json
{
  "token": "sdm_your_actual_token_here",
  "ip_address": "192.168.1.100",
  "base_url": "https://sslgen.sanusi.id"
}
```

### 4. Generate Certificate
```bash
# Using configuration file
ssl_client.py --config /etc/sdm-ssl/config.json

# Using command line arguments
ssl_client.py --ip 192.168.1.100 --token sdm_your_token_here

# Interactive mode (recommended)
ssl_client.py --interactive
```

### 5. Install for Web Server
```bash
# Automatically configure Nginx or Apache
sudo install_certs.sh 192.168.1.100
```

## 📋 Usage Examples

### Basic Certificate Generation
```bash
ssl_client.py --ip 192.168.1.100 --token sdm_abc123xyz789
```

### Interactive Mode
```bash
ssl_client.py --interactive
```

### Using Configuration File
```bash
ssl_client.py --config /path/to/config.json
```

### List Stored Certificates
```bash
ssl_client.py --list
```

### Custom Certificate Directory
```bash
ssl_client.py --ip 192.168.1.100 --token sdm_token --cert-dir /custom/path
```

## ⚙️ Configuration File Format

```json
{
  "token": "sdm_your_api_token_here",
  "ip_address": "192.168.1.100",
  "base_url": "https://sslgen.sanusi.id",
  "cert_dir": "/etc/ssl/sdmcert",
  "certificates": [
    {
      "ip_address": "192.168.1.100",
      "description": "Web server"
    },
    {
      "ip_address": "192.168.1.200", 
      "description": "API server"
    }
  ]
}
```

## �️ Certificate Storage

Certificates are stored in `/etc/ssl/sdmcert/{ip_address}/`:
```
/etc/ssl/sdmcert/192.168.1.100/
├── cert.pem          # Server certificate
├── chain.pem         # Intermediate certificate  
├── fullchain.pem     # cert.pem + chain.pem
├── privkey.pem       # Private key (600 permissions)
└── metadata.json     # Generation metadata
```

## 🌐 Web Server Integration

### Nginx Configuration
```nginx
server {
    listen 443 ssl;
    server_name 192.168.1.100;
    
    ssl_certificate /etc/ssl/sdmcert/192.168.1.100/fullchain.pem;
    ssl_certificate_key /etc/ssl/sdmcert/192.168.1.100/privkey.pem;
    
    # Your other configuration...
}
```

### Apache Configuration
```apache
<VirtualHost 192.168.1.100:443>
    ServerName 192.168.1.100
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/sdmcert/192.168.1.100/cert.pem
    SSLCertificateKeyFile /etc/ssl/sdmcert/192.168.1.100/privkey.pem
    SSLCertificateChainFile /etc/ssl/sdmcert/192.168.1.100/chain.pem
    
    # Your other configuration...
</VirtualHost>
```

### Web Server Setup
```bash
# Auto-configure Nginx or Apache
sudo install_certs.sh 192.168.1.100
```

## 🔄 Automatic Renewal

### Enable Systemd Timer
```bash
sudo systemctl enable sdm-ssl-renewal.timer
sudo systemctl start sdm-ssl-renewal.timer

# Check status
sudo systemctl status sdm-ssl-renewal.timer
```

### Manual Renewal
```bash
# Test renewal service
sudo systemctl start sdm-ssl-renewal.service

# Check logs
sudo journalctl -u sdm-ssl-renewal.service
```

## 🛠️ Command Line Options

```
usage: ssl_client.py [-h] [--ip IP] [--token TOKEN] [--config CONFIG]
                     [--interactive] [--list] [--base-url BASE_URL]
                     [--cert-dir CERT_DIR] [--verbose]

SSL Certificate Client for Sanusi Digital Media

optional arguments:
  -h, --help            show this help message and exit
  --ip IP               Private IP address for certificate
  --token TOKEN         API token from sslgen.sanusi.id
  --config CONFIG       JSON configuration file path
  --interactive, -i     Interactive mode
  --list, -l            List stored certificates
  --base-url BASE_URL   Base URL for the API
  --cert-dir CERT_DIR   Certificate storage directory
  --verbose, -v         Verbose logging
```

## 🔒 Security Considerations

1. **Token Security** - Keep your API token secure, store in protected config files
2. **File Permissions** - Private keys are automatically set to 600 (owner read-only)
3. **Directory Permissions** - Certificate directories are created with appropriate permissions
4. **Network Security** - All API communication uses HTTPS
5. **Log Security** - Logs don't contain sensitive information

## 🚨 Troubleshooting

### Permission Errors
Make sure you're running as root or with sudo:
```bash
sudo ssl_client.py --interactive
```

### API Token Issues
- Verify your token at https://sslgen.sanusi.id/register
- Check for rate limits (10 requests/hour per token)
- Ensure token starts with `sdm_`

### Network Issues
- Verify connectivity to sslgen.sanusi.id
- Check firewall settings
- Ensure DNS resolution works

### Certificate Issues
- Only private IP addresses are supported (RFC 1918)
- Certificates are valid for 1 year
- Install the CA certificate on client devices

### Log Analysis
```bash
# View recent logs
sudo tail -f /var/log/sdm-ssl-client.log

# View systemd service logs
sudo journalctl -u sdm-ssl-renewal.service -f
```

## ⚡ Rate Limits

- **API Limit** - 10 requests per hour per token
- **Private IPs Only** - Only RFC 1918 private IP addresses are supported
- **Certificate Validity** - 1 year from generation date

## 📦 What's Included

- **`ssl_client.py`** - Main client application
- **`install.sh`** - System installation script  
- **`install_certs.sh`** - Web server configuration script
- **`config.json.example`** - Configuration template
- **`sdm-ssl-renewal.service`** - Systemd service file
- **`sdm-ssl-renewal.timer`** - Systemd timer file

## 🛠️ Requirements

- Python 3.6+
- `requests` library
- Root/sudo access for installation
- Valid API token from sslgen.sanusi.id

## 📞 Support

- **API Documentation** - Available at sslgen.sanusi.id
- **Issues** - Contact alice@sanusi.id
- **Web Interface** - https://sslgen.sanusi.id
- **Registration** - https://sslgen.sanusi.id/register

## 📄 License

This client is provided as-is for use with the Sanusi Digital Media SSL Certificate service.
