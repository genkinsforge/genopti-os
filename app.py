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

app = Flask(__name__)

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

SETUP_MODE = False

APP_NAME_VERSION = "Genopti-OS (v0.31) - Open Source"
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
    """Load environment variables from .env file and update global vars."""
    global DISPLAY_SERIAL
    global CPU_UNIQUE_ID
    load_dotenv()

    # Reload from .env
    DISPLAY_SERIAL = os.getenv('DISPLAY_SERIAL', 'N/A')
    CPU_UNIQUE_ID = get_raspberry_pi_serial()


def update_serial_number(suffix):
    """Update the serial number in .env file and return (bool, message_or_new_serial)."""
    try:
        # Generate new serial number
        cpu_serial = get_raspberry_pi_serial()
        new_serial = f"{cpu_serial}{suffix}"

        env_path = os.path.join(os.path.dirname(__file__), '.env')

        # Read existing .env content
        existing_lines = []
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                existing_lines = f.readlines()

        # Filter out any existing DISPLAY_SERIAL= lines
        updated_lines = [line for line in existing_lines if not line.startswith('DISPLAY_SERIAL=')]
        # Add the new one
        updated_lines.append(f'DISPLAY_SERIAL={new_serial}\n')

        with open(env_path, 'w') as f:
            f.writelines(updated_lines)

        return True, new_serial
    except Exception as e:
        logging.error(f"Error updating serial number: {str(e)}")
        return False, str(e)


def restart_application():
    """Restart the Flask application."""
    try:
        python = sys.executable
        os.execl(python, python, *sys.argv)
    except Exception as e:
        logging.error(f"Error restarting application: {str(e)}")
        return False, str(e)
    return True, "Application restarting..."


# Load environment variables at startup
load_environment_vars()


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
        age = (today - parsed_data['dob']).days // 365
        is_expired = parsed_data['expiration'] < today

        return {
            'is_valid': (age >= 21) and (not is_expired),
            'age': age,
            'is_expired': is_expired
        }


def get_validation_message(validation_result):
    if validation_result['is_expired']:
        return "LICENSE EXPIRED"
    elif validation_result['age'] < 21:
        return "UNDER 21"
    return "VALID and 21 or Older"


def configure_wifi_json(config: dict):
    ssid = config.get('ssid', '')
    password = config.get('password', '')
    country = config.get('country', 'US').upper()
    encryption = config.get('encryption', 'WPA').upper()
    hidden = bool(config.get('hidden', False))

    if not ssid:
        return (False, "No SSID provided in JSON.")

    # Basic check
    for field_name, field_value in [('SSID', ssid), ('Password', password)]:
        if not re.match(r'^[\w \-!@#$%^&*\(\)\._+={}\[\]]*$', field_value):
            return (False, f"Invalid characters in {field_name} field.")

    wpa_supplicant_path = "/etc/wpa_supplicant/wpa_supplicant.conf"

    # For WPA/WPA2:
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

    # Reconfigure
    try:
        subprocess.run(["sudo", "wpa_cli", "-i", "wlan0", "reconfigure"], check=True)
    except subprocess.CalledProcessError as cpe:
        return (False, f"Failed to reconfigure Wi-Fi: {str(cpe)}")

    return (True, f"Wi-Fi configured. SSID: {ssid}, Country: {country}")


def _setup_response(success, message):
    """
    Helper to build a consistent JSON response for Setup Mode,
    including full system info each time so the UI can reflect updates.
    """
    return {
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
    }


def handle_setup_command(scan_str):
    """
    Handle setup commands (enable SSH, update serial, etc.).
    Return a dict with success/failure + updated system info.
    """
    global DISPLAY_SERIAL

    # 1) Update Serial Number
    if scan_str.startswith('$$serialnumber$$'):
        try:
            json_str = scan_str.replace('$$serialnumber$$', '', 1).strip()
            data = json.loads(json_str)
            suffix = data.get("serial", "")

            # Basic validation
            if not re.match(r'^[A-Za-z0-9_-]*$', suffix):
                return _setup_response(
                    success=False,
                    message='Invalid characters in serial suffix.'
                )

            success, result = update_serial_number(suffix)
            if success:
                # Re-load environment vars to pick up new DISPLAY_SERIAL
                load_environment_vars()
                return _setup_response(
                    success=True,
                    message=f"Serial number updated to: {DISPLAY_SERIAL}"
                )
            else:
                return _setup_response(
                    success=False,
                    message=f"Failed to update serial: {result}"
                )
        except Exception as e:
            return _setup_response(
                success=False,
                message=f"Invalid serial number JSON: {str(e)}"
            )

    # 2) Restart Application
    elif scan_str == '$$restartapp$$':
        success, msg = restart_application()
        return _setup_response(
            success=success,
            message=msg
        )

    # 3) Enable SSH
    elif scan_str == '$$enablessh$$':
        try:
            # Use raspi-config to enable SSH
            subprocess.run(["sudo", "raspi-config", "nonint", "do_ssh", "0"], check=True)
            # Also ensure systemd start + enable
            subprocess.run(["sudo", "systemctl", "enable", "ssh"], check=True)
            subprocess.run(["sudo", "systemctl", "start", "ssh"], check=True)
            return _setup_response(
                success=True,
                message='SSH service enabled and started.'
            )
        except subprocess.CalledProcessError as e:
            return _setup_response(
                success=False,
                message=f'Failed to enable/start SSH: {str(e)}'
            )

    # 4) Disable SSH
    elif scan_str == '$$disablessh$$':
        try:
            # Use raspi-config to disable SSH
            subprocess.run(["sudo", "raspi-config", "nonint", "do_ssh", "1"], check=True)
            # Also ensure systemd stop + disable
            subprocess.run(["sudo", "systemctl", "disable", "ssh"], check=True)
            subprocess.run(["sudo", "systemctl", "stop", "ssh"], check=True)
            return _setup_response(
                success=True,
                message='SSH service disabled and stopped.'
            )
        except subprocess.CalledProcessError as e:
            return _setup_response(
                success=False,
                message=f'Failed to disable/stop SSH: {str(e)}'
            )

    # 5) Enable VNC
    elif scan_str == '$$enablevnc$$':
        try:
            # Use raspi-config to enable VNC
            subprocess.run(["sudo", "raspi-config", "nonint", "do_vnc", "0"], check=True)
            # Also ensure systemd start + enable
            subprocess.run(["sudo", "systemctl", "enable", "vncserver-x11-serviced"], check=True)
            subprocess.run(["sudo", "systemctl", "start", "vncserver-x11-serviced"], check=True)
            return _setup_response(
                success=True,
                message='VNC service enabled and started.'
            )
        except subprocess.CalledProcessError as e:
            return _setup_response(
                success=False,
                message=f'Failed to enable/start VNC: {str(e)}'
            )

    # 6) Disable VNC
    elif scan_str == '$$disablevnc$$':
        try:
            # Use raspi-config to disable VNC
            subprocess.run(["sudo", "raspi-config", "nonint", "do_vnc", "1"], check=True)
            # Also ensure systemd stop + disable
            subprocess.run(["sudo", "systemctl", "disable", "vncserver-x11-serviced"], check=True)
            subprocess.run(["sudo", "systemctl", "stop", "vncserver-x11-serviced"], check=True)
            return _setup_response(
                success=True,
                message='VNC service disabled and stopped.'
            )
        except subprocess.CalledProcessError as e:
            return _setup_response(
                success=False,
                message=f'Failed to disable/stop VNC: {str(e)}'
            )

    # 7) Wi-Fi JSON Config
    if scan_str.startswith("$$wifi$$"):
        wifi_json_str = scan_str.replace("$$wifi$$", "", 1).strip()
        try:
            wifi_config = json.loads(wifi_json_str)
        except json.JSONDecodeError as e:
            return _setup_response(
                success=False,
                message=f"Invalid Wi-Fi JSON: {str(e)}"
            )

        success, msg = configure_wifi_json(wifi_config)
        return _setup_response(
            success=success,
            message=msg
        )

    # 8) No recognized command
    return _setup_response(
        success=True,
        message=f"Unrecognized setup command: {scan_str}"
    )


@app.route('/')
def home():
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

    if len(scan_str) > 1000:
        return jsonify({
            'success': False,
            'error': 'Scan data too long; potential injection blocked.'
        })

    # ----------------------------------------------------------------
    # Check if we should ENTER Setup Mode
    # ----------------------------------------------------------------
    if scan_str == '$$setup$$':
        SETUP_MODE = True
        logging.info("SYSTEM: Entered Setup Mode.")
        return jsonify({
            'success': True,
            'setup_mode': True,
            'message': 'Entered Setup Mode',
            'ips': get_non_loopback_ips(),
            'system_name': APP_NAME_VERSION,
            'registered_user': REGISTERED_USER,
            'company_name': COMPANY_NAME,
            'location': LOCATION,
            'display_serial': DISPLAY_SERIAL,
            'cpu_unique_id': CPU_UNIQUE_ID
        })

    # ----------------------------------------------------------------
    # If ALREADY in Setup Mode, handle setup commands
    # ----------------------------------------------------------------
    if SETUP_MODE:
        if scan_str == '$$exit$$':
            SETUP_MODE = False
            logging.info("SYSTEM: Exited Setup Mode, returning to normal scanning.")
            return jsonify({
                'success': True,
                'setup_mode': False,
                'message': 'Exited Setup Mode, normal scanning resumed'
            })

        # Process known or unknown setup commands
        setup_result = handle_setup_command(scan_str)
        return jsonify(setup_result)

    # ----------------------------------------------------------------
    # Normal scanning mode (NOT in Setup Mode)
    # ----------------------------------------------------------------
    if not scan_str:
        return jsonify({
            'success': False,
            'error': 'No scan data received.'
        })

    # Attempt to parse as AAMVA data
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


if __name__ == '__main__':
    app.run(debug=DEBUG_MODE)
