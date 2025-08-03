#!/bin/bash
# SSL Certificate Installation Script for common web servers

CERT_DIR="/etc/ssl/sdmcert"
IP_ADDRESS="$1"

if [ -z "$IP_ADDRESS" ]; then
    echo "Usage: $0 <ip_address>"
    echo "Example: $0 192.168.1.100"
    exit 1
fi

CERT_PATH="$CERT_DIR/$IP_ADDRESS"

if [ ! -d "$CERT_PATH" ]; then
    echo "Error: Certificate directory not found: $CERT_PATH"
    exit 1
fi

echo "Installing SSL certificates for $IP_ADDRESS..."

# Detect web server
if systemctl is-active --quiet nginx; then
    echo "Detected Nginx - Installing certificates..."
    
    # Create nginx SSL configuration
    cat > "/etc/nginx/sites-available/ssl-$IP_ADDRESS" << EOF
server {
    listen 443 ssl;
    server_name $IP_ADDRESS;
    
    ssl_certificate $CERT_PATH/fullchain.pem;
    ssl_certificate_key $CERT_PATH/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    location / {
        root /var/www/html;
        index index.html index.htm;
    }
}
EOF
    
    # Enable site
    ln -sf "/etc/nginx/sites-available/ssl-$IP_ADDRESS" "/etc/nginx/sites-enabled/"
    
    # Test configuration
    if nginx -t; then
        systemctl reload nginx
        echo "✅ Nginx configuration updated and reloaded"
    else
        echo "❌ Nginx configuration test failed"
        exit 1
    fi

elif systemctl is-active --quiet apache2; then
    echo "Detected Apache2 - Installing certificates..."
    
    # Create apache SSL virtual host
    cat > "/etc/apache2/sites-available/ssl-$IP_ADDRESS.conf" << EOF
<VirtualHost $IP_ADDRESS:443>
    ServerName $IP_ADDRESS
    DocumentRoot /var/www/html
    
    SSLEngine on
    SSLCertificateFile $CERT_PATH/cert.pem
    SSLCertificateKeyFile $CERT_PATH/privkey.pem
    SSLCertificateChainFile $CERT_PATH/chain.pem
    
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    SSLHonorCipherOrder off
</VirtualHost>
EOF
    
    # Enable site and SSL module
    a2enmod ssl
    a2ensite "ssl-$IP_ADDRESS"
    
    # Test configuration
    if apache2ctl configtest; then
        systemctl reload apache2
        echo "✅ Apache2 configuration updated and reloaded"
    else
        echo "❌ Apache2 configuration test failed"
        exit 1
    fi

else
    echo "⚠️  No supported web server detected (nginx/apache2)"
    echo "Certificate files are available at: $CERT_PATH"
    echo ""
    echo "Available files:"
    ls -la "$CERT_PATH"/*.pem 2>/dev/null || echo "No PEM files found"
fi

echo ""
echo "Certificate installation completed!"
echo "Files location: $CERT_PATH"
echo ""
echo "Remember to:"
echo "1. Update your application configuration to use HTTPS"
echo "2. Install the CA certificate on client devices"
echo "3. Set up certificate renewal (certificates expire in 1 year)"
