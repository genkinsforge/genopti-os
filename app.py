from flask import Flask, render_template, request, jsonify
from datetime import datetime
import re
import logging
from logging.handlers import RotatingFileHandler
import os
import socket
import array
from dotenv import load_dotenv
import sys
import subprocess

app = Flask(__name__)

# --------------------------------------------------------------------------
# 1. Configuration & Logging
# --------------------------------------------------------------------------
DEBUG_MODE = (os.environ.get('DEBUG_MODE', '0') == '1')
LOG_LEVEL = logging.DEBUG if DEBUG_MODE else logging.INFO
LOG_DIR = 'logs'
LOG_FILENAME = 'scanner.log'
os.makedirs(LOG_DIR, exist_ok=True)

formatter = logging.Formatter('%(asctime)s %(levelname)s [%(filename)s:%(lineno)d]: %(message)s')
root_logger = logging.getLogger()
root_logger.setLevel(LOG_LEVEL)

# Clear existing handlers
for handler in root_logger.handlers[:]:
    root_logger.removeHandler(handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(LOG_LEVEL)
console_handler.setFormatter(formatter)
root_logger.addHandler(console_handler)

try:
    log_file_path = os.path.abspath(os.path.join(LOG_DIR, LOG_FILENAME))
    os.makedirs(os.path.dirname(log_file_path), exist_ok=True)

    # Test write
    test_file = os.path.join(LOG_DIR, '.test_write')
    with open(test_file, 'w') as f:
        f.write('test')
    os.remove(test_file)

    file_handler = RotatingFileHandler(log_file_path, maxBytes=100_000, backupCount=5)
    file_handler.setLevel(LOG_LEVEL)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    flask_logger = logging.getLogger('werkzeug')
    flask_logger.setLevel(LOG_LEVEL)
    flask_logger.addHandler(file_handler)
    flask_logger.addHandler(console_handler)

    print(f"Log file will be written to: {log_file_path}")
except Exception as e:
    print(f"Error setting up file logging: {str(e)}")
    print("Continuing with console-only logging")
    flask_logger = logging.getLogger('werkzeug')
    flask_logger.setLevel(LOG_LEVEL)
    flask_logger.addHandler(console_handler)

def log_uncaught_exceptions(exc_type, exc_value, exc_traceback):
    logging.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))
    sys.__excepthook__(exc_type, exc_value, exc_traceback)

sys.excepthook = log_uncaught_exceptions

# --------------------------------------------------------------------------
# 2. Global Vars & Environment Loading
# --------------------------------------------------------------------------
SETUP_MODE = False

APP_NAME_VERSION = "Genopti-OS (v0.35) - Open Source"
REGISTERED_USER = "N/A"
COMPANY_NAME = "N/A"
LOCATION = "N/A"
DISPLAY_SERIAL = "N/A"
CPU_UNIQUE_ID = "N/A"

def get_raspberry_pi_serial():
    """
    More robust parsing of /proc/cpuinfo so that lines with extra
    spacing or indentation won't break detection of 'Serial'.
    """
    try:
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                line = line.strip()  # remove leading/trailing whitespace
                # If the line starts with 'Serial', parse what's after the colon
                if line.startswith('Serial'):
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        return parts[1].strip()
        return "UNKNOWN"
    except Exception as e:
        logging.error(f"Error reading CPU serial: {str(e)}")
        return "UNKNOWN"

def load_environment_vars():
    load_dotenv()
    global DISPLAY_SERIAL
    global CPU_UNIQUE_ID

    # If you have a 'DISPLAY_SERIAL' in .env, use it, otherwise 'N/A'.
    DISPLAY_SERIAL = os.getenv('DISPLAY_SERIAL', 'N/A')

    # Always read CPU serial from /proc/cpuinfo
    CPU_UNIQUE_ID = get_raspberry_pi_serial()

    logging.debug(f"Loaded DISPLAY_SERIAL from .env (or fallback): {DISPLAY_SERIAL}")
    logging.debug(f"Loaded CPU_UNIQUE_ID from /proc/cpuinfo: {CPU_UNIQUE_ID}")

def update_serial_number(suffix):
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

        # Also write to /etc/device_id
        try:
            with open('/etc/device_id', 'w') as f:
                f.write(new_serial)
            logging.info(f"Successfully wrote serial to /etc/device_id: {new_serial}")
        except Exception as e:
            logging.error(f"Error writing to /etc/device_id: {str(e)}")
            return True, f"{new_serial} (warning: failed to write to /etc/device_id: {str(e)})"

        return True, new_serial
    except Exception as e:
        logging.error(f"Error updating serial number: {str(e)}")
        return False, str(e)

def parse_wifi_config(config_string):
    import json
    try:
        wifi_pattern = re.compile(r'^\s*\$\$\s*wifi\s*\$\$\s*', re.IGNORECASE)
        match = wifi_pattern.search(config_string)
        if not match:
            raise ValueError("Invalid WiFi configuration format - must start with $$wifi$$")

        json_str = config_string[match.end():].strip()
        try:
            config = json.loads(json_str)
        except json.JSONDecodeError as e:
            logging.error(f"Invalid WiFi configuration JSON: {e}")
            if '"' not in json_str:
                hint = " - JSON requires double quotes around property names and string values"
            elif json_str.count('{') != json_str.count('}'):
                hint = " - JSON has unbalanced curly braces"
            else:
                hint = " - Please check your JSON syntax"
            raise ValueError(f"Invalid WiFi configuration JSON: {e}{hint}")

        if 'ssid' not in config:
            raise ValueError("Missing required 'ssid' field in WiFi configuration")

        if 'password' not in config:
            config['password'] = ''
        if 'type' not in config:
            config['type'] = 'WPA2'
        if 'hidden' not in config:
            config['hidden'] = False

        config['authentication'] = config.get('type', 'WPA2').upper()

        for key in config:
            if isinstance(config[key], str):
                config[key] = ''.join(c for c in config[key] if ord(c) >= 32 or c in '\t\r\n')

        return config

    except json.JSONDecodeError as e:
        logging.error(f"Invalid WiFi configuration JSON: {e}")
        raise ValueError(f"Invalid WiFi configuration JSON: {e}")

    except Exception as e:
        logging.error(f"Error parsing WiFi configuration: {e}")
        raise

def configure_wifi_with_nmcli(ssid, password):
    nmcli_cmd = [
        'sudo',
        '/usr/bin/nmcli',
        'device',
        'wifi',
        'connect',
        ssid,
        'password',
        password
    ]
    try:
        result = subprocess.run(nmcli_cmd, capture_output=True, text=True, check=True)
        logging.info("nmcli output: " + result.stdout)
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        logging.error("nmcli command failed: " + e.stderr)
        return False, e.stderr

def configure_wifi(wifi_config_string):
    try:
        wifi_params = parse_wifi_config(wifi_config_string)
        logging.info(f"Configuring WiFi for SSID: {wifi_params['ssid']}")

        if not wifi_params.get('ssid'):
            return {'success': False, 'message': 'Missing SSID in WiFi configuration'}

        ssid = wifi_params['ssid']
        password = wifi_params.get('password', '')
        success, nmcli_message = configure_wifi_with_nmcli(ssid, password)

        if success:
            updated_ips = get_non_loopback_ips()
            return {
                'success': True,
                'message': f'WiFi configured successfully for SSID: {ssid}.',
                'ips': updated_ips,
                'requires_restart': False
            }
        else:
            return {
                'success': False,
                'message': f'Failed to configure WiFi: {nmcli_message}'
            }

    except Exception as e:
        logging.error(f"Error configuring WiFi: {str(e)}")
        return {'success': False, 'message': f'Failed to configure WiFi: {str(e)}'}

def restart_application():
    try:
        python_executable = sys.executable
        os.execl(python_executable, python_executable, *sys.argv)
    except Exception as e:
        logging.error(f"Error restarting application: {str(e)}")
        return False, str(e)
    return True, "Application restarting..."

def get_non_loopback_ips():
    try:
        ips = {}
        try:
            import netifaces
            for iface in netifaces.interfaces():
                if iface.startswith('lo'):
                    continue
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        ip = addr['addr']
                        if ip != '127.0.0.1':
                            ips[iface] = ip
        except ImportError:
            import socket
            hostname = socket.gethostname()
            try:
                for ip in socket.gethostbyname_ex(hostname)[2]:
                    if ip != '127.0.0.1':
                        iface = 'unknown'
                        ips[iface] = ip
            except socket.error:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    s.connect(('10.255.255.255', 1))
                    ip = s.getsockname()[0]
                    if ip != '127.0.0.1':
                        ips['default'] = ip
                except Exception:
                    pass
                finally:
                    s.close()
        return ips
    except Exception as e:
        logging.warning(f"Error getting IP addresses: {str(e)}")
        return {"unknown": "unavailable"}

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
        return {
            'is_valid': age >= 21 and not is_expired,
            'age': age,
            'is_expired': is_expired
        }

def get_validation_message(validation_result):
    if validation_result['is_expired']:
        return "LICENSE EXPIRED"
    elif validation_result['age'] < 21:
        return "UNDER 21"
    return "VALID and 21 or Older"

# --------------------------------------------------------------------------
# 5. Flask Routes
# --------------------------------------------------------------------------
@app.route('/')
def home():
    return render_template('index.html',
                           debug_mode=DEBUG_MODE,
                           scan_reset_seconds=15,
                           scan_inactivity_ms=300)

def handle_setup_command(scan_str):
    import json
    serialnum_pattern = re.compile(r'^\s*\$\$\s*serialnumber\s*\$\$\s*', re.IGNORECASE)
    match = serialnum_pattern.search(scan_str)
    if match:
        try:
            json_str = scan_str[match.end():].strip()
            try:
                config = json.loads(json_str)
            except json.JSONDecodeError as e:
                logging.error(f"Invalid serial number JSON: {e}")
                if '"' not in json_str:
                    hint = " - JSON requires double quotes around property names and string values"
                elif json_str.count('{') != json_str.count('}'):
                    hint = " - JSON has unbalanced curly braces"
                else:
                    hint = " - Please check your JSON syntax"
                return {
                    'success': False,
                    'setup_mode': True,
                    'error': f'Invalid JSON format in serial number configuration: {e}{hint}'
                }

            if 'serial' not in config:
                return {
                    'success': False,
                    'setup_mode': True,
                    'error': "Missing 'serial' field in configuration"
                }

            suffix = config['serial']
            if isinstance(suffix, str):
                suffix = ''.join(c for c in suffix if c.isalnum() or c in '-_')

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
            logging.error(f"Error processing serial number command: {str(e)}")
            return {
                'success': False,
                'setup_mode': True,
                'error': f'Error processing serial number command: {str(e)}'
            }
    return None

@app.route('/process_scan', methods=['POST'])
def process_scan():
    global SETUP_MODE
    try:
        logging.debug(f"Received request data: {request.data}")
        req_json = request.json or {}
        if not req_json:
            logging.warning("No JSON data in request or invalid JSON format")
            return jsonify({
                'success': False,
                'error': 'Invalid request format - JSON required'
            }), 400

        scan_str = req_json.get('scan_data', '').strip()
        logging.info(f"Received scan: {repr(scan_str)}")

        setup_command_pattern = re.compile(r'^\s*\$\$.*\$\$', re.IGNORECASE)
        is_setup_command = setup_command_pattern.search(scan_str)

        # Check for $$setup$$
        setup_pattern = re.compile(r'^\s*\$\$\s*setup\s*\$\$\s*$', re.IGNORECASE)
        if setup_pattern.match(scan_str):
            SETUP_MODE = True
            logging.info("SYSTEM: Entered Setup Mode (Open Source).")
            ip_info = get_non_loopback_ips()
            response = {
                'success': True,
                'setup_mode': True,
                'message': 'Entered Setup Mode',
                'ips': ip_info,
                'system_name': APP_NAME_VERSION,
                'registered_user': REGISTERED_USER,
                'company_name': COMPANY_NAME,
                'location': LOCATION,
                'display_serial': DISPLAY_SERIAL,  # from .env or updated serial
                'cpu_unique_id': CPU_UNIQUE_ID,    # read from /proc/cpuinfo
            }
            logging.debug(f"Sending setup mode response: {response}")
            return jsonify(response)

        # If already in setup mode, handle next commands
        if SETUP_MODE:
            exit_pattern = re.compile(r'^\s*\$\$\s*exit\s*\$\$\s*$', re.IGNORECASE)
            if exit_pattern.match(scan_str):
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

            wifi_pattern = re.compile(r'^\s*\$\$\s*wifi\s*\$\$', re.IGNORECASE)
            if wifi_pattern.search(scan_str):
                try:
                    result = configure_wifi(scan_str)
                    return jsonify({
                        'success': result['success'],
                        'setup_mode': True,
                        'message': result['message'],
                        'ips': get_non_loopback_ips(),
                        'system_name': APP_NAME_VERSION,
                        'registered_user': REGISTERED_USER,
                        'company_name': COMPANY_NAME,
                        'location': LOCATION,
                        'display_serial': DISPLAY_SERIAL,
                        'cpu_unique_id': CPU_UNIQUE_ID
                    })
                except Exception as e:
                    logging.error(f"Error configuring WiFi: {str(e)}")
                    return jsonify({
                        'success': False,
                        'setup_mode': True,
                        'message': f'Failed to configure WiFi: {str(e)}',
                        'ips': get_non_loopback_ips()
                    })

            restart_pattern = re.compile(r'^\s*\$\$\s*restartapp\s*\$\$\s*$', re.IGNORECASE)
            if restart_pattern.match(scan_str):
                try:
                    success, message = restart_application()
                    return jsonify({
                        'success': success,
                        'setup_mode': True,
                        'message': message,
                        'needs_reload': True
                    })
                except Exception as e:
                    logging.error(f"Error restarting application: {str(e)}")
                    return jsonify({
                        'success': False,
                        'setup_mode': True,
                        'error': f'Error restarting application: {str(e)}'
                    })

            # If none of the above matched, just echo the command
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

        # Normal scanning (not in setup mode)
        if not scan_str:
            return jsonify({'success': False, 'error': 'No scan data received.'})

        # If it looks like a setup command but we never actually ran $$setup$$
        if is_setup_command:
            logging.warning(f"Detected setup command outside of setup mode: {scan_str}")
            return jsonify({
                'success': False,
                'error': 'This appears to be a setup command. Try scanning $$setup$$ first to enter setup mode.'
            })

        # Otherwise, parse the license
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
            return jsonify({'success': False, 'error': str(ex)})

    except Exception as e:
        logging.exception(f"Uncaught exception in process_scan route: {str(e)}")
        return jsonify({'success': False, 'error': f'Server error processing scan: {str(e)}'}), 500

@app.errorhandler(Exception)
def handle_exception(e):
    logging.exception(f"Unhandled exception: {str(e)}")
    return jsonify({"success": False, "error": f"Server error: {str(e)}"}), 500

# --------------------------------------------------------------------------
# 6. Main Entry
# --------------------------------------------------------------------------
if __name__ == '__main__':
    try:
        # Ensure environment vars (including CPU_UNIQUE_ID) are loaded before starting
        load_environment_vars()

        print("Starting GenOpti-OS application (v0.31)")
        logging.info("Starting GenOpti-OS application (v0.31)")
        logging.info(f"Debug mode: {DEBUG_MODE}")

        def delayed_ip_detection():
            try:
                return get_non_loopback_ips()
            except Exception as ip_error:
                logging.warning(f"Could not detect IP addresses: {str(ip_error)}")
                print(f"Warning: Could not detect IP addresses: {str(ip_error)}")
                return {"unknown": "unavailable"}

        from werkzeug.serving import WSGIRequestHandler
        WSGIRequestHandler.protocol_version = "HTTP/1.1"
        app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
        app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False
        app.config['PROPAGATE_EXCEPTIONS'] = True

        ip_addresses = delayed_ip_detection()
        logging.info(f"IP Addresses: {ip_addresses}")

        # Confirm what CPU_UNIQUE_ID was loaded
        logging.info(f"Using CPU_UNIQUE_ID = {CPU_UNIQUE_ID}")

        app.run(host='127.0.0.1', debug=DEBUG_MODE, threaded=True)

    except Exception as e:
        import traceback
        error_msg = f"FATAL ERROR STARTING APPLICATION: {str(e)}\n{traceback.format_exc()}"
        print(error_msg)
        try:
            with open('genopti_error.log', 'a') as f:
                f.write(f"{datetime.now().isoformat()}: {error_msg}\n")
        except:
            pass
        sys.exit(1)

