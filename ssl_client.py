#!/usr/bin/env python3
"""
SSL Certificate Client for Sanusi Digital Media SSL Generator
This script requests SSL certificates from sslgen.sanusi.id API and stores them locally.

Usage:
    python ssl_client.py --ip 192.168.1.100 --token your_api_token
    python ssl_client.py --config /path/to/config.json
    python ssl_client.py --interactive

Requirements:
    - Valid API token from sslgen.sanusi.id/register
    - Python 3.6+ with requests library
    - Write access to /etc/ssl/sdmcert (run as root/sudo)
"""

import os
import sys
import json
import argparse
import requests
import ipaddress
from pathlib import Path
from datetime import datetime
import logging

# Configuration
BASE_URL = "https://sslgen.sanusi.id"
API_ENDPOINT = f"{BASE_URL}/api"
CERT_DIR = Path("/etc/ssl/sdmcert")
CONFIG_FILE = Path.home() / ".config" / "sdm-ssl" / "config.json"

# Setup logging
log_handlers: list[logging.Handler] = [logging.StreamHandler()]

# Try to add file handler, but don't fail if we can't write to /var/log
try:
    log_handlers.append(logging.FileHandler('/var/log/sdm-ssl-client.log', mode='a'))
except PermissionError:
    # If we can't write to /var/log, try user's home directory
    try:
        home_log = Path.home() / '.local' / 'share' / 'sdm-ssl' / 'client.log'
        home_log.parent.mkdir(parents=True, exist_ok=True)
        log_handlers.append(logging.FileHandler(home_log, mode='a'))
    except:
        # If all else fails, just use console logging
        pass

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=log_handlers
)
logger = logging.getLogger(__name__)

class SSLCertificateClient:
    def __init__(self, token=None, base_url=None):
        self.token = token
        self.base_url = base_url or BASE_URL
        self.api_endpoint = f"{self.base_url}/api"
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'SDM-SSL-Client/1.0'
        })
        
        if self.token:
            self.session.headers.update({
                'Authorization': f'Bearer {self.token}'
            })

    def validate_ip(self, ip_str):
        """Validate that the IP address is a valid private IP"""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if not ip_obj.is_private:
                raise ValueError("IP address must be private (RFC 1918)")
            return str(ip_obj)
        except ipaddress.AddressValueError as e:
            raise ValueError(f"Invalid IP address: {e}")

    def request_certificate(self, ip_address):
        """Request SSL certificate from the API"""
        logger.info(f"Requesting certificate for IP: {ip_address}")
        
        # Validate IP address
        try:
            validated_ip = self.validate_ip(ip_address)
        except ValueError as e:
            logger.error(f"IP validation failed: {e}")
            return None
        
        # Prepare request data
        data = {"ip_address": validated_ip}
        
        try:
            response = self.session.post(self.api_endpoint, json=data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                logger.info(f"Certificate generated successfully for {validated_ip}")
                return result
            elif response.status_code == 401:
                logger.error("Authentication failed. Check your API token.")
                return None
            elif response.status_code == 429:
                logger.error("Rate limit exceeded. Please wait before making another request.")
                return None
            else:
                try:
                    error_data = response.json()
                    error_msg = error_data.get('error', f'HTTP {response.status_code}')
                except:
                    error_msg = f'HTTP {response.status_code}'
                logger.error(f"API request failed: {error_msg}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error: {e}")
            return None

    def save_certificates(self, cert_data, ip_address):
        """Save certificates to the filesystem"""
        if not cert_data or 'value' not in cert_data:
            logger.error("Invalid certificate data received")
            return False
        
        # Create directory structure
        ip_dir = CERT_DIR / ip_address
        try:
            ip_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created directory: {ip_dir}")
        except PermissionError:
            logger.error(f"Permission denied creating directory {ip_dir}. Run as root or with sudo.")
            return False
        except Exception as e:
            logger.error(f"Failed to create directory {ip_dir}: {e}")
            return False
        
        # Extract certificate data
        cert_value = cert_data['value']
        cert_content = cert_value.get('cert', '')
        chain_content = cert_value.get('chain', '')
        key_content = cert_value.get('key', '')
        
        # Create full chain (cert + chain)
        fullchain_content = cert_content + '\n' + chain_content
        
        # File paths
        files_to_save = {
            'cert.pem': cert_content,
            'chain.pem': chain_content,
            'fullchain.pem': fullchain_content,
            'privkey.pem': key_content
        }
        
        # Save files
        saved_files = []
        for filename, content in files_to_save.items():
            if not content.strip():
                logger.warning(f"Empty content for {filename}, skipping")
                continue
                
            file_path = ip_dir / filename
            try:
                with open(file_path, 'w') as f:
                    f.write(content)
                
                # Set appropriate permissions
                if 'privkey' in filename:
                    os.chmod(file_path, 0o600)  # Private key should be read-only by owner
                else:
                    os.chmod(file_path, 0o644)  # Certificates can be readable by others
                
                saved_files.append(str(file_path))
                logger.info(f"Saved: {file_path}")
                
            except Exception as e:
                logger.error(f"Failed to save {file_path}: {e}")
                return False
        
        # Save metadata
        metadata = {
            'ip_address': ip_address,
            'generated_at': datetime.now().isoformat(),
            'api_response': cert_data,
            'files': saved_files
        }
        
        metadata_file = ip_dir / 'metadata.json'
        try:
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            logger.info(f"Saved metadata: {metadata_file}")
        except Exception as e:
            logger.warning(f"Failed to save metadata: {e}")
        
        return True

    def list_certificates(self):
        """List all stored certificates"""
        if not CERT_DIR.exists():
            logger.info("No certificates directory found")
            return []
        
        certificates = []
        for ip_dir in CERT_DIR.iterdir():
            if ip_dir.is_dir():
                metadata_file = ip_dir / 'metadata.json'
                if metadata_file.exists():
                    try:
                        with open(metadata_file, 'r') as f:
                            metadata = json.load(f)
                        certificates.append(metadata)
                    except Exception as e:
                        logger.warning(f"Failed to read metadata for {ip_dir.name}: {e}")
                        certificates.append({
                            'ip_address': ip_dir.name,
                            'generated_at': 'unknown',
                            'files': list(str(f) for f in ip_dir.glob('*.pem'))
                        })
        
        return certificates

def load_config():
    """Load configuration from file"""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load config: {e}")
    return {}

def save_config(config):
    """Save configuration to file"""
    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        logger.info(f"Configuration saved to {CONFIG_FILE}")
    except Exception as e:
        logger.error(f"Failed to save config: {e}")

def interactive_mode():
    """Interactive mode for user input"""
    print("=== SDM SSL Certificate Client ===")
    print("Interactive Mode")
    print()
    
    # Load existing config
    config = load_config()
    
    # Get API token
    token = config.get('token')
    if not token:
        token = input("Enter your API token (from sslgen.sanusi.id/register): ").strip()
        if token:
            save_token = input("Save this token for future use? [y/N]: ").strip().lower()
            if save_token == 'y':
                config['token'] = token
                save_config(config)
    
    if not token:
        print("Error: API token is required")
        return False
    
    # Get IP address
    while True:
        ip_address = input("Enter the private IP address: ").strip()
        if ip_address:
            try:
                ipaddress.ip_address(ip_address)
                break
            except:
                print("Invalid IP address format. Please try again.")
        else:
            print("IP address is required")
    
    # Create client and request certificate
    client = SSLCertificateClient(token=token)
    cert_data = client.request_certificate(ip_address)
    
    if cert_data:
        if client.save_certificates(cert_data, ip_address):
            print(f"\n✅ Certificate successfully generated and saved for {ip_address}")
            print(f"📁 Location: {CERT_DIR / ip_address}")
            return True
        else:
            print("\n❌ Failed to save certificates")
            return False
    else:
        print("\n❌ Failed to generate certificate")
        return False

def main():
    global CERT_DIR
    
    parser = argparse.ArgumentParser(
        description='SSL Certificate Client for Sanusi Digital Media',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --ip 192.168.1.100 --token sdm_your_token_here
  %(prog)s --config /path/to/config.json
  %(prog)s --interactive
  %(prog)s --list
        """
    )
    
    parser.add_argument('--ip', '--ip-address', help='Private IP address for certificate')
    parser.add_argument('--token', help='API token from sslgen.sanusi.id')
    parser.add_argument('--config', help='JSON configuration file path')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive mode')
    parser.add_argument('--list', '-l', action='store_true', help='List stored certificates')
    parser.add_argument('--base-url', default=BASE_URL, help='Base URL for the API')
    parser.add_argument('--cert-dir', type=Path, default=CERT_DIR, help='Certificate storage directory')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Update cert directory if specified
    CERT_DIR = args.cert_dir
    
    # List certificates mode
    if args.list:
        client = SSLCertificateClient()
        certificates = client.list_certificates()
        
        if not certificates:
            print("No certificates found")
            return
        
        print("Stored Certificates:")
        print("=" * 50)
        for cert in certificates:
            print(f"IP: {cert['ip_address']}")
            print(f"Generated: {cert.get('generated_at', 'unknown')}")
            print(f"Files: {len(cert.get('files', []))} certificate files")
            print("-" * 30)
        return
    
    # Interactive mode
    if args.interactive:
        interactive_mode()
        return
    
    # Configuration file mode
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
            
            token = config.get('token')
            ip_address = config.get('ip_address')
            
            if not token or not ip_address:
                logger.error("Configuration file must contain 'token' and 'ip_address'")
                return
                
        except Exception as e:
            logger.error(f"Failed to load configuration file: {e}")
            return
    else:
        # Command line arguments mode
        token = args.token
        ip_address = args.ip
        
        if not token:
            logger.error("API token is required. Use --token, --config, or --interactive")
            return
        
        if not ip_address:
            logger.error("IP address is required. Use --ip, --config, or --interactive")
            return
    
    # Create client and request certificate
    # Update the global CERT_DIR for certificate operations
    CERT_DIR = args.cert_dir
    
    client = SSLCertificateClient(token=token, base_url=args.base_url)
    cert_data = client.request_certificate(ip_address)
    
    if cert_data:
        if client.save_certificates(cert_data, ip_address):
            logger.info(f"Certificate successfully generated and saved for {ip_address}")
            print(f"✅ Success! Certificate saved to {CERT_DIR / ip_address}")
        else:
            logger.error("Failed to save certificates")
            sys.exit(1)
    else:
        logger.error("Failed to generate certificate")
        sys.exit(1)

if __name__ == "__main__":
    main()
