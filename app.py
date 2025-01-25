from flask import Flask, render_template, request, jsonify
from datetime import datetime
import re
import logging
from logging.handlers import RotatingFileHandler
import os
import socket
import fcntl
import struct
import array
from dotenv import load_dotenv
import sys
import json
import subprocess
from typing import Tuple

app = Flask(__name__)

# --------------------------------------------------------------------------
# 1. Configuration & Logging
# --------------------------------------------------------------------------
DEBUG_MODE = (os.environ.get('DEBUG_MODE', '0') == '1')
LOG_LEVEL = logging.DEBUG if DEBUG_MODE else logging.INFO
LOG_DIR = 'logs'
LOG_FILENAME = 'scanner.log'
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    handlers=[
        RotatingFileHandler(os.path.join(LOG_DIR, LOG_FILENAME), maxBytes=100_000, backupCount=5),
        logging.StreamHandler()
    ],
    level=LOG_LEVEL,
    format='%(asctime)s %(levelname)s [%(filename)s:%(lineno)d]: %(message)s'
)

# --------------------------------------------------------------------------
# 2. Global Vars & Environment Loading
# --------------------------------------------------------------------------
SETUP_MODE = False

# App info (Open Source placeholders)
APP_NAME_VERSION = "Genopti-OS (v0.34) - Open Source"
REGISTERED_USER = "N/A"
COMPANY_NAME = "N/A"
LOCATION = "N/A"
DISPLAY_SERIAL = "N/A"
CPU_UNIQUE_ID = "N/A"

def get_raspberry_pi_serial():
    """Get the Raspberry Pi CPU serial number from /proc/cpuinfo"""
    try:
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if line.startswith('Serial'):
                    return line.split(':')[1].strip()
    except Exception as e:
        logging.error(f"Error reading CPU serial: {str(e)}")
        return "UNKNOWN"

def load_environment_vars():
    """Load environment variables from .env file"""
    load_dotenv()
    global DISPLAY_SERIAL
    global CPU_UNIQUE_ID

    DISPLAY_SERIAL = os.getenv('DISPLAY_SERIAL', 'N/A')
    CPU_UNIQUE_ID = get_raspberry_pi_serial()

def update_serial_number(suffix):
    """Update the serial number in .env file"""
    try:
        cpu_serial = get_raspberry_pi_serial()
        new_serial = f"{cpu_serial}{suffix}"
        env_path = os.path.join(os.path.dirname(__file__), '.env')

        existing_lines = []
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                existing_lines = f.readlines()

        updated_lines = [line for line in existing_lines if not line.startswith('DISPLAY_SERIAL=')]
        updated_lines.append(f'DISPLAY_SERIAL={new_serial}\n')

        with open(env_path, 'w') as f:
            f.writelines(updated_lines)

        return True, new_serial
    except Exception as e:
        logging.error(f"Error updating serial number: {str(e)}")
        return False, str(e)

def restart_application():
    """Restart the Flask application"""
    try:
        python = sys.executable
        os.execl(python, python, *sys.argv)
    except Exception as e:
        logging.error(f"Error restarting application: {str(e)}")
        return False, str(e)
    return True, "Application restarting..."

# Load environment variables at startup
load_environment_vars()

# --------------------------------------------------------------------------
# 3. Utility: Get Non-Loopback IPs (Linux-specific)
# --------------------------------------------------------------------------
def get_non_loopback_ips():
    """Returns a dict of {interface_name: ip_address} for non-loopback interfaces."""
    ips = {}
    max_possible = 128
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bytes_out = max_possible * 32

    names = array.array('B', b'\0' * bytes_out)
    outbytes = struct.unpack('iL', fcntl.ioctl(
        sock.fileno(),
        0x8912,  # SIOCGIFCONF
        struct.pack('iL', bytes_out, names.buffer_info()[0])
    ))[0]
    namestr = names.tobytes()

    for i in range(0, outbytes, 40):
        iface_name = namestr[i:i+16].split(b'\0', 1)[0].decode('utf-8')
        ip_bytes = namestr[i+20:i+24]
        ip_addr = socket.inet_ntoa(ip_bytes)
        if ip_addr != "127.0.0.1":
            ips[iface_name] = ip_addr
    return ips

# --------------------------------------------------------------------------
# 4. License Parsing & Validation Classes
# --------------------------------------------------------------------------
class LicenseParser:
    @staticmethod
    def parse_aamva(data: str) -> dict:
        try:
            if not data.startswith('@ANSI '):
                raise ValueError("Invalid AAMVA format: Missing @ANSI header")

            fields = {
                'first_name': re.search(r'DAC([^D]+)', data).group(1).strip(),
                'middle_name': re.search(r'DAD([^D]+)', data).group(1).strip(),
                'last_name': re.search(r'DCS([^D]+)', data).group(1).strip(),
                'address': re.search(r'DAG(.+?)D', data).group(1).strip(),
                'city': re.search(r'DAI([^D]+)', data).group(1).strip(),
                'dob': re.search(r'DBB(\d{8})', data).group(1),
                'expiration': re.search(r'DBA(\d{8})', data).group(1),
                'issue_date': re.search(r'DBD(\d{8})', data).group(1)
            }

            fields['dob'] = datetime.strptime(fields['dob'], '%m%d%Y').date()
            fields['expiration'] = datetime.strptime(fields['expiration'], '%m%d%Y').date()
            fields['issue_date'] = datetime.strptime(fields['issue_date'], '%m%d%Y').date()

            return fields

        except Exception as e:
            logging.error(f"Error parsing license data: {str(e)}")
            raise ValueError(f"Error parsing license data: {str(e)}")

    @staticmethod
    def validate_license(parsed_data: dict) -> dict:
        today = datetime.now().date()
        days_old = (today - parsed_data['dob']).days
        age = days_old // 365
        is_expired = parsed_data['expiration'] < today

        result = {
            'is_valid': age >= 21 and not is_expired,
            'age': age,
            'is_expired': is_expired
        }
        return result

def get_validation_message(validation_result):
    if validation_result['is_expired']:
        return "LICENSE EXPIRED"
    elif validation_result['age'] < 21:
        return "UNDER 21"
    return "VALID and 21 or Older"

# --------------------------------------------------------------------------
# 5. Setup & System Service Control
# --------------------------------------------------------------------------
def validate_command(command: str) -> bool:
    """Validates that a command string matches exactly one of our predefined commands."""
    VALID_COMMANDS = {
        "$$setup$$", "$$exit$$", "$$restartapp$$",
        "$$enablessh$$", "$$disablessh$$",
        "$$enablevnc$$", "$$disablevnc$$"
    }
    # Also allow serialnumber commands which have JSON payload
    if command.startswith('$$serialnumber$$'):
        return True
    if command.startswith('$$wifi$$'):
        return True
    return command in VALID_COMMANDS

def control_service(service: str, action: str) -> Tuple[bool, str]:
    """Controls system services safely using systemctl."""
    if service not in ['ssh', 'vnc']:
        return False, "Invalid service specified"
    if action not in ['enable', 'disable']:
        return False, "Invalid action specified"
        
    service_map = {
        'ssh': 'ssh',
        'vnc': 'vncserver-x11-serviced'
    }
    
    system_service = service_map[service]
    
    try:
        # Enable/disable service
        subprocess.run(['sudo', 'systemctl', action, system_service], 
                     check=True, capture_output=True)
        
        # Start/stop service
        start_stop = 'start' if action == 'enable' else 'stop'
        subprocess.run(['sudo', 'systemctl', start_stop, system_service],
                     check=True, capture_output=True)
                     
        return True, f"Successfully {action}d {service}"
    except subprocess.CalledProcessError as e:
        return False, f"Failed to {action} {service}: {e.stderr.decode()}"

def handle_setup_command(scan_str):
    """Handle various setup commands while in setup mode."""
    if not validate_command(scan_str):
        return {
            'success': False,
            'setup_mode': True,
            'error': 'Invalid command format'
        }

    # Handle service control commands
    service_commands = {
        '$$enablessh$$': ('ssh', 'enable'),
        '$$disablessh$$': ('ssh', 'disable'),
        '$$enablevnc$$': ('vnc', 'enable'),
        '$$disablevnc$$': ('vnc', 'disable')
    }
    
    if scan_str in service_commands:
        service, action = service_commands[scan_str]
        success, message = control_service(service, action)
        return {
            'success': success,
            'setup_mode': True,
            'message': message if success else None,
            'error': None if success else message
        }

    if scan_str.startswith('$$serialnumber$$'):
        try:
            json_str = scan_str.replace('$$serialnumber$$', '', 1).strip()
            data = json.loads(json_str)
            suffix = data.get("serial", "")

            success, result = update_serial_number(suffix)
            if success:
                return {
                    'success': True,
                    'setup_mode': True,
                    'message': f'Serial number updated to: {result}',
                    'needs_reload': True
                }
            else:
                return {
                    'success': False,
                    'setup_mode': True,
                    'error': f'Failed to update serial: {result}'
                }
        except Exception as e:
            return {
                'success': False,
                'setup_mode': True,
                'error': f'Invalid serial number JSON: {str(e)}'
            }

    elif scan_str == '$$restartapp$$':
        success, message = restart_application()
        return {
            'success': success,
            'setup_mode': True,
            'message': message,
            'needs_reload': True
        }

    return None

def configure_wifi_json(config: dict):
    """Configure Wi-Fi using provided JSON configuration."""
    ssid = config.get('ssid', '')
    password = config.get('password', '')
    country = config.get('country', 'US').upper()
    encryption = config.get('encryption', 'WPA').upper()
    hidden = bool(config.get('hidden', False))

    if not ssid:
        return (False, "No SSID provided in JSON.")

    wpa_supplicant_path = "/etc/wpa_supplicant/wpa_supplicant.conf"

    network_block = f"""
network={{
    ssid="{ssid}"
    scan_ssid={1 if hidden else 0}
    key_mgmt=WPA-PSK
    psk="{password}"
}}
"""

    try:
        with open(wpa_supplicant_path, "w") as f:
            f.write("ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\n")
            f.write("update_config=1\n")
            f.write(f"country={country}\n")
            f.write(network_block)
    except Exception as e:
        return (False, f"Error writing wpa_supplicant.conf: {str(e)}")

    try:
        subprocess.run(["sudo", "wpa_cli", "-i", "wlan0", "reconfigure"], check=True)
    except subprocess.CalledProcessError as cpe:
        return (False, f"Failed to reconfigure Wi-Fi: {str(cpe)}")

    return (True, f"Wi-Fi configured. SSID: {ssid}, Country: {country}")

# --------------------------------------------------------------------------
# 6. Flask Routes
# --------------------------------------------------------------------------
@app.route('/')
def home():
    """Renders the scanning interface."""
    return render_template('index.html',
                           debug_mode=DEBUG_MODE,
                           scan_reset_seconds=15,
                           scan_inactivity_ms=300)

@app.route('/process_scan', methods=['POST'])
def process_scan():
    global SETUP_MODE

    req_json = request.json or {}
    scan_str = req_json.get('scan_data', '').strip()
    logging.info(f"Received scan: {repr(scan_str)}")

    # Enter Setup Mode
    if scan_str == '$$setup$$':
        SETUP_MODE = True
        logging.info("SYSTEM: Entered Setup Mode (Open Source).")

        ip_info = get_non_loopback_ips()
        return jsonify({
            'success': True,
            'setup_mode': True,
            'message': 'Entered Setup Mode',
            'ips': ip_info,
            'system_name': APP_NAME_VERSION,
            'registered_user': REGISTERED_USER,
            'company_name': COMPANY_NAME,
            'location': LOCATION,
            'display_serial': DISPLAY_SERIAL,
            'cpu_unique_id': CPU_UNIQUE_ID,
        })

    # Handle Setup Mode Commands
    if SETUP_MODE:
        if scan_str == '$$exit$$':
            SETUP_MODE = False
            logging.info("SYSTEM: Exited Setup Mode, returning to normal scanning.")
            return jsonify({
                'success': True,
                'setup_mode': False,
                'message': 'Exited Setup Mode, normal scanning resumed'
            })

        setup_result = handle_setup_command(scan_str)
        if setup_result:
            return jsonify(setup_result)

        if scan_str.startswith("$$wifi$$"):
            wifi_json_str = scan_str.replace("$$wifi$$", "", 1).strip()
            try:
                wifi_config = json.loads(wifi_json_str)
            except json.JSONDecodeError as e:
                return jsonify({
                    'success': False,
                    'setup_mode': True,
                    'error': f"Invalid Wi-Fi JSON: {str(e)}"
                })

            success, message = configure_wifi_json(wifi_config)
            logging.info(f"Wi-Fi config JSON parsed. Result: {message}")

            return jsonify({
                'success': success,
                'setup_mode': True,
                'message': message,
                'ips': get_non_loopback_ips(),
                'system_name': APP_NAME_VERSION,
                'registered_user': REGISTERED_USER,
                'company_name': COMPANY_NAME,
                'location': LOCATION,
                'display_serial': DISPLAY_SERIAL,
                'cpu_unique_id': CPU_UNIQUE_ID
            })

        return jsonify({
            'success': True,
            'setup_mode': True,
            'message': f'Setup command received: {scan_str}',
            'ips': get_non_loopback_ips(),
            'system_name': APP_NAME_VERSION,
            'registered_user': REGISTERED_USER,
            'company_name': COMPANY_NAME,
            'location': LOCATION,
            'display_serial': DISPLAY_SERIAL,
            'cpu_unique_id': CPU_UNIQUE_ID
        })

    # Normal scanning mode
    if not scan_str:
        return jsonify({
            'success': False,
            'error': 'No scan data received.'
        })

    try:
        parsed_data = LicenseParser.parse_aamva(scan_str)
        validation = LicenseParser.validate_license(parsed_data)

        response_data = {
            'success': True,
            'name': f"{parsed_data['first_name']} {parsed_data['middle_name']} {parsed_data['last_name']}",
            'address': f"{parsed_data['address']}, {parsed_data['city']}",
            'dob': parsed_data['dob'].strftime('%B %d, %Y'),
            'issue_date': parsed_data['issue_date'].strftime('%B %d, %Y'),
            'expiration': parsed_data['expiration'].strftime('%B %d, %Y'),
            'is_valid': validation['is_valid'],
            'validation_message': get_validation_message(validation),
        }

        logging.info(f"Processed normal scan: {response_data}")
        return jsonify(response_data)

    except Exception as ex:
        logging.error(f"Error processing scan: {str(ex)}")
        return jsonify({
            'success': False,
            'error': str(ex)
        })

# --------------------------------------------------------------------------
# 7. Main Entry
# --------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=DEBUG_MODE)
