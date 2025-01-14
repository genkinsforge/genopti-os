#!/usr/bin/env python3
import os
import re
import logging
import socket
import fcntl
import struct
from logging.handlers import RotatingFileHandler
from datetime import datetime, date
from flask import Flask, request, jsonify, render_template

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
# 2. Global Vars for Setup Mode & Placeholders
# --------------------------------------------------------------------------
SETUP_MODE = False

# App info (Open Source placeholders)
APP_NAME_VERSION = "Genopti-OS (v0.31) - Open Source"

# For Genkins Forge integration, we use "N/A" in the open source edition
REGISTERED_USER = "N/A"
COMPANY_NAME    = "N/A"
LOCATION        = "N/A"
DISPLAY_SERIAL  = "N/A"
CPU_UNIQUE_ID   = "N/A"

# --------------------------------------------------------------------------
# 3. Utility: Get Non-Loopback IPs (Linux-specific example)
# --------------------------------------------------------------------------
def get_non_loopback_ips():
    """
    Returns a dict of {interface_name: ip_address} for non-loopback interfaces.
    Linux-specific code (using fcntl). 
    Adjust for your environment if needed.
    """
    ips = {}
    max_possible = 128  # arbitrary upper bound
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bytes_out = max_possible * 32
    # Prepare the buffer for the ioctl call
    import array
    names = array.array('B', b'\0' * bytes_out)
    outbytes = struct.unpack('iL', fcntl.ioctl(
        sock.fileno(),
        0x8912,  # SIOCGIFCONF
        struct.pack('iL', bytes_out, names.buffer_info()[0])
    ))[0]
    namestr = names.tobytes()

    # Each interface entry is (ifreq), typically 40 bytes on many systems
    for i in range(0, outbytes, 40):
        iface_name = namestr[i:i+16].split(b'\0', 1)[0].decode('utf-8')
        ip_bytes = namestr[i+20:i+24]
        ip_addr = socket.inet_ntoa(ip_bytes)
        if ip_addr != "127.0.0.1":
            ips[iface_name] = ip_addr

    return ips

# --------------------------------------------------------------------------
# 4. License Parsing & Validation Classes (as before)
# --------------------------------------------------------------------------
class LicenseParser:
    """
    Example AAMVA parse class. You may keep or adapt your existing logic.
    """
    @staticmethod
    def parse_aamva(data: str) -> dict:
        # Basic check
        if not data.startswith('@ANSI '):
            raise ValueError("Invalid AAMVA format: Missing '@ANSI ' prefix")
        # Minimal parse logic for demonstration:
        import re
        from datetime import datetime
        
        fields = {
            'first_name': re.search(r'DAC([^D]+)', data).group(1).strip(),
            'middle_name': re.search(r'DAD([^D]+)', data).group(1).strip(),
            'last_name':  re.search(r'DCS([^D]+)', data).group(1).strip(),
            'dob':        re.search(r'DBB(\d{8})', data).group(1),
            'expiration': re.search(r'DBD(\d{8})', data).group(1),
            'address':    re.search(r'DAG(.+?)D',  data).group(1).strip(),
            'city':       re.search(r'DAI([^D]+)', data).group(1).strip(),
        }
        
        # Convert dates
        fields['dob']        = datetime.strptime(fields['dob'], '%m%d%Y').date()
        fields['expiration'] = datetime.strptime(fields['expiration'], '%m%d%Y').date()
        
        return fields

    @staticmethod
    def validate_license(parsed_data: dict) -> dict:
        from datetime import date
        today = date.today()
        dob = parsed_data['dob']
        age = (today - dob).days // 365
        
        is_expired = (parsed_data['expiration'] < today)
        
        return {
            'is_valid': (age >= 21) and not is_expired,
            'age': age,
            'is_expired': is_expired
        }

def get_validation_message(validation_result):
    if validation_result['is_expired']:
        return "LICENSE EXPIRED"
    elif validation_result['age'] < 21:
        return "UNDER 21"
    return "VALID"

# --------------------------------------------------------------------------
# 5. Flask Routes
# --------------------------------------------------------------------------
@app.route('/')
def home():
    """
    Renders the scanning interface.
    """
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

    # ----------------------------------------------------------------------
    # 5.1 Check if we should ENTER Setup Mode
    # ----------------------------------------------------------------------
    if not SETUP_MODE and scan_str == '$$setup$$':
        SETUP_MODE = True
        logging.info("SYSTEM: Entered Setup Mode (Open Source).")

        # Gather IP addresses
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

    # ----------------------------------------------------------------------
    # 5.2 If ALREADY in Setup Mode, look for $$exit$$ or handle Wi-Fi
    # ----------------------------------------------------------------------
    if SETUP_MODE:
        # If scan_str is $$exit$$, exit Setup Mode
        if scan_str == '$$exit$$':
            SETUP_MODE = False
            logging.info("SYSTEM: Exited Setup Mode, returning to normal scanning.")
            return jsonify({
                'success': True,
                'setup_mode': False,
                'message': 'Exited Setup Mode, normal scanning resumed'
            })

        # Otherwise, handle Wi-Fi or any other setup commands
        # For demonstration, let's look for "WIFI:SSID/PASSWORD"
        if scan_str.startswith("WIFI:"):
            # Example: "WIFI:MyNetwork/MyPassword"
            wifi_data = scan_str.replace("WIFI:", "", 1).strip()
            # You can parse the SSID/PASS here:
            # e.g. ssid, password = wifi_data.split('/', 1)
            # Then do your config. For now, placeholder:
            logging.info(f"Wi-Fi config command: {wifi_data}")

        # Return updated system info while still in Setup Mode
        ip_info = get_non_loopback_ips()

        return jsonify({
            'success': True,
            'setup_mode': True,
            'message': f'Setup command received: {scan_str}',
            'ips': ip_info,
            'system_name': APP_NAME_VERSION,
            'registered_user': REGISTERED_USER,
            'company_name': COMPANY_NAME,
            'location': LOCATION,
            'display_serial': DISPLAY_SERIAL,
            'cpu_unique_id': CPU_UNIQUE_ID
        })

    # ----------------------------------------------------------------------
    # 5.3 Normal scanning (if not in Setup Mode)
    # ----------------------------------------------------------------------
    if not scan_str:
        return jsonify({
            'success': False,
            'error': 'No scan data received.'
        })

    try:
        parsed_data = LicenseParser.parse_aamva(scan_str)
        validation = LicenseParser.validate_license(parsed_data)

        response_data = {
            'name': f"{parsed_data['first_name']} {parsed_data['middle_name']} {parsed_data['last_name']}",
            'address': f"{parsed_data['address']}, {parsed_data['city']}",
            'dob': parsed_data['dob'].strftime('%B %d, %Y'),
            'expiration': parsed_data['expiration'].strftime('%B %d, %Y'),
            'is_valid': validation['is_valid'],
            'validation_message': get_validation_message(validation),
        }

        logging.info(f"Processed normal scan: {response_data}")
        return jsonify({'success': True, **response_data})

    except Exception as ex:
        logging.error(f"Error processing scan: {str(ex)}")
        return jsonify({
            'success': False,
            'error': str(ex)
        })

# --------------------------------------------------------------------------
# 6. Main Entry
# --------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=DEBUG_MODE)

