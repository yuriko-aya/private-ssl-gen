#!/bin/bash
# Package script for SDM SSL Certificate Client

PACKAGE_NAME="sdm-ssl-client"
VERSION="1.0.0"
PACKAGE_DIR="${PACKAGE_NAME}-${VERSION}"

echo "Creating package: ${PACKAGE_NAME}-${VERSION}"

# Create package directory
mkdir -p "$PACKAGE_DIR"

# Copy files
cp ssl_client.py "$PACKAGE_DIR/"
cp install.sh "$PACKAGE_DIR/"
cp install_certs.sh "$PACKAGE_DIR/"
cp config.json.example "$PACKAGE_DIR/"
cp sdm-ssl-renewal.service "$PACKAGE_DIR/"
cp sdm-ssl-renewal.timer "$PACKAGE_DIR/"
cp CLIENT_README.md "$PACKAGE_DIR/README.md"

# Create package info
cat > "$PACKAGE_DIR/VERSION" << EOF
SDM SSL Certificate Client
Version: $VERSION
Build Date: $(date)
API Endpoint: https://sslgen.sanusi.id/api
EOF

# Create checksums
cd "$PACKAGE_DIR"
sha256sum * > checksums.sha256
cd ..

# Create tarball
tar -czf "${PACKAGE_DIR}.tar.gz" "$PACKAGE_DIR"

# Create zip file for Windows users
zip -r "${PACKAGE_DIR}.zip" "$PACKAGE_DIR"

# Cleanup
rm -rf "$PACKAGE_DIR"

echo "Package created:"
echo "  ${PACKAGE_DIR}.tar.gz (Linux/Unix)"
echo "  ${PACKAGE_DIR}.zip (Windows)"

ls -lh "${PACKAGE_DIR}".{tar.gz,zip}
