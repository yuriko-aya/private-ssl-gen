#!/bin/bash
# Installation script for SDM SSL Certificate Client

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/sdm-ssl"
VENV_DIR="$INSTALL_DIR/venv"
CONFIG_DIR="/etc/sdm-ssl"
LOG_DIR="/var/log"

echo "=== SDM SSL Certificate Client Installation ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root (use sudo)"
    exit 1
fi

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "✅ Found Python $PYTHON_VERSION"

# Create installation directory
echo "� Creating installation directory..."
mkdir -p "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR"
echo "✅ Created: $INSTALL_DIR"

# Create virtual environment
echo "🐍 Creating Python virtual environment..."
python3 -m venv "$VENV_DIR"
echo "✅ Created virtual environment: $VENV_DIR"

# Install Python dependencies in virtual environment
echo "📦 Installing Python dependencies in virtual environment..."
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install requests

# Install main script
echo "📋 Installing SSL client script..."
cp "$SCRIPT_DIR/ssl_client.py" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/ssl_client.py"

# Update shebang to use virtual environment Python
sed -i "1s|.*|#!$VENV_DIR/bin/python3|" "$INSTALL_DIR/ssl_client.py"
echo "✅ Installed: $INSTALL_DIR/ssl_client.py"

# Create wrapper script in /usr/local/bin
echo "🔗 Creating wrapper script..."
cat > "/usr/local/bin/ssl_client.py" << EOF
#!/bin/bash
exec $VENV_DIR/bin/python3 $INSTALL_DIR/ssl_client.py "\$@"
EOF
chmod +x "/usr/local/bin/ssl_client.py"
echo "✅ Created wrapper: /usr/local/bin/ssl_client.py"

# Install helper script
echo "📋 Installing certificate installation script..."
cp "$SCRIPT_DIR/install_certs.sh" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/install_certs.sh"

# Create wrapper script for install_certs.sh
cat > "/usr/local/bin/install_certs.sh" << EOF
#!/bin/bash
exec $INSTALL_DIR/install_certs.sh "\$@"
EOF
chmod +x "/usr/local/bin/install_certs.sh"
echo "✅ Installed: $INSTALL_DIR/install_certs.sh"
echo "✅ Created wrapper: /usr/local/bin/install_certs.sh"

# Create configuration directory
echo "📁 Creating configuration directory..."
mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

# Install example configuration
if [ ! -f "$CONFIG_DIR/config.json" ]; then
    if [ -f "$SCRIPT_DIR/config.json.example" ]; then
        cp "$SCRIPT_DIR/config.json.example" "$CONFIG_DIR/config.json"
        chmod 600 "$CONFIG_DIR/config.json"
        echo "✅ Installed example config: $CONFIG_DIR/config.json"
        echo "⚠️  Please edit $CONFIG_DIR/config.json with your API token and settings"
    else
        echo "⚠️  Example config not found, creating basic config..."
        cat > "$CONFIG_DIR/config.json" << EOF
{
  "token": "your_api_token_here",
  "ip_address": "192.168.1.100",
  "base_url": "https://sslgen.sanusi.id"
}
EOF
        chmod 600 "$CONFIG_DIR/config.json"
        echo "✅ Created basic config: $CONFIG_DIR/config.json"
    fi
else
    echo "ℹ️  Configuration file already exists: $CONFIG_DIR/config.json"
fi

# Install systemd service files (if systemd is available)
if command -v systemctl &> /dev/null; then
    echo "🔧 Installing systemd service files..."
    
    if [ -f "$SCRIPT_DIR/sdm-ssl-renewal.service" ]; then
        cp "$SCRIPT_DIR/sdm-ssl-renewal.service" "/etc/systemd/system/"
        echo "✅ Installed: /etc/systemd/system/sdm-ssl-renewal.service"
    fi
    
    if [ -f "$SCRIPT_DIR/sdm-ssl-renewal.timer" ]; then
        cp "$SCRIPT_DIR/sdm-ssl-renewal.timer" "/etc/systemd/system/"
        echo "✅ Installed: /etc/systemd/system/sdm-ssl-renewal.timer"
    fi
    
    # Reload systemd
    systemctl daemon-reload
    echo "✅ Systemd configuration reloaded"
    
    echo ""
    echo "To enable automatic certificate renewal:"
    echo "  systemctl enable sdm-ssl-renewal.timer"
    echo "  systemctl start sdm-ssl-renewal.timer"
else
    echo "ℹ️  Systemd not available, skipping service installation"
fi

# Create certificate directory
echo "📁 Creating certificate storage directory..."
mkdir -p "/etc/ssl/sdmcert"
chmod 755 "/etc/ssl/sdmcert"
echo "✅ Created: /etc/ssl/sdmcert"

# Create log file
touch "$LOG_DIR/sdm-ssl-client.log"
chmod 644 "$LOG_DIR/sdm-ssl-client.log"

echo ""
echo "🎉 Installation completed successfully!"
echo ""
echo "Installation details:"
echo "  • Application directory: $INSTALL_DIR"
echo "  • Virtual environment: $VENV_DIR"
echo "  • Configuration: $CONFIG_DIR/config.json"
echo "  • Certificates: /etc/ssl/sdmcert"
echo "  • Log file: $LOG_DIR/sdm-ssl-client.log"
echo ""
echo "Next steps:"
echo "1. Edit the configuration file:"
echo "   nano $CONFIG_DIR/config.json"
echo ""
echo "2. Get your API token from:"
echo "   https://sslgen.sanusi.id/register"
echo ""
echo "3. Test the installation:"
echo "   ssl_client.py --interactive"
echo ""
echo "4. Generate a certificate:"
echo "   ssl_client.py --ip 192.168.1.100 --token your_token_here"
echo ""
echo "5. Install certificates for your web server:"
echo "   install_certs.sh 192.168.1.100"
echo ""
echo "6. (Optional) Enable automatic renewal:"
echo "   systemctl enable sdm-ssl-renewal.timer"
echo "   systemctl start sdm-ssl-renewal.timer"
echo ""
echo "For help:"
echo "   ssl_client.py --help"
echo ""
