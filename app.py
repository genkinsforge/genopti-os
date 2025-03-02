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

app = Flask(__name__)

# --------------------------------------------------------------------------
# 1. Configuration & Logging
# --------------------------------------------------------------------------
DEBUG_MODE = (os.environ.get('DEBUG_MODE', '0') == '1')
LOG_LEVEL = logging.DEBUG if DEBUG_MODE else logging.INFO
LOG_DIR = 'logs'
LOG_FILENAME = 'scanner.log'
os.makedirs(LOG_DIR, exist_ok=True)

# Create custom formatter
formatter = logging.Formatter('%(asctime)s %(levelname)s [%(filename)s:%(lineno)d]: %(message)s')

# Set up root logger (capture all logs)
root_logger = logging.getLogger()
root_logger.setLevel(LOG_LEVEL)

# Clear existing handlers (to avoid duplicates)
for handler in root_logger.handlers[:]:
    root_logger.removeHandler(handler)

# ALWAYS set up console handler first to ensure we can see errors
console_handler = logging.StreamHandler()
console_handler.setLevel(LOG_LEVEL)
console_handler.setFormatter(formatter)
root_logger.addHandler(console_handler)

# Try to create file handler, but don't fail if there's an issue
try:
    # Ensure absolute path and directory exists
    log_file_path = os.path.abspath(os.path.join(LOG_DIR, LOG_FILENAME))
    # Ensure parent directory has correct permissions
    os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
    
    # Attempt to check if directory is writable
    try:
        test_file = os.path.join(LOG_DIR, '.test_write')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
    except Exception as e:
        print(f"Warning: Log directory is not writable: {str(e)}")
        print(f"Falling back to console-only logging")
    else:
        file_handler = RotatingFileHandler(log_file_path, maxBytes=100_000, backupCount=5)
        file_handler.setLevel(LOG_LEVEL)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
        
        # Also add file handler to Flask's logger
        flask_logger = logging.getLogger('werkzeug')
        flask_logger.setLevel(LOG_LEVEL)
        flask_logger.addHandler(file_handler)
        flask_logger.addHandler(console_handler)
        
        print(f"Log file will be written to: {log_file_path}")
except Exception as e:
    print(f"Error setting up file logging: {str(e)}")
    print(f"Continuing with console-only logging")
    # Only set up console handler for Flask
    flask_logger = logging.getLogger('werkzeug')
    flask_logger.setLevel(LOG_LEVEL)
    flask_logger.addHandler(console_handler)

# Log uncaught exceptions
def log_uncaught_exceptions(exc_type, exc_value, exc_traceback):
    logging.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))
    # Call the default exception handler
    sys.__excepthook__(exc_type, exc_value, exc_traceback)

# Set the exception hook
sys.excepthook = log_uncaught_exceptions

# --------------------------------------------------------------------------
# 2. Global Vars & Environment Loading
# --------------------------------------------------------------------------
SETUP_MODE = False

# App info (Open Source placeholders)
APP_NAME_VERSION = "Genopti-OS (v0.35) - Open Source"
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
    
    # Load serial from .env if it exists, otherwise get from CPU
    DISPLAY_SERIAL = os.getenv('DISPLAY_SERIAL', 'N/A')
    CPU_UNIQUE_ID = get_raspberry_pi_serial()

def update_serial_number(suffix):
    """Update the serial number in .env file and /etc/device_id"""
    try:
        # Generate new serial number with suffix
        cpu_serial = get_raspberry_pi_serial()
        new_serial = f"{cpu_serial}{suffix}"
        
        # Update .env file
        env_path = os.path.join(os.path.dirname(__file__), '.env')
        
        # Read existing content
        existing_lines = []
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                existing_lines = f.readlines()
        
        # Filter out DISPLAY_SERIAL line if it exists
        updated_lines = [line for line in existing_lines if not line.startswith('DISPLAY_SERIAL=')]
        
        # Add new serial number
        updated_lines.append(f'DISPLAY_SERIAL={new_serial}\n')
        
        # Write back to file
        with open(env_path, 'w') as f:
            f.writelines(updated_lines)
        
        # Write to /etc/device_id for the genopti-client to read
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
    """Parse WiFi configuration from standardized $$wifi$${"json":"here"} format.
    
    Args:
        config_string: String from QR code in format $$wifi$${"json":"here"}
        
    Returns:
        dict: WiFi configuration parameters
    """
    import json
    import re
    
    try:
        # More flexible pattern matching for wifi config
        wifi_pattern = re.compile(r'^\s*\$\$\s*wifi\s*\$\$\s*', re.IGNORECASE)
        match = wifi_pattern.search(config_string)
        
        if not match:
            raise ValueError("Invalid WiFi configuration format - must start with $$wifi$$")
            
        # Extract JSON part - everything after the matched pattern
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
        
        # Ensure required fields
        if 'ssid' not in config:
            raise ValueError("Missing required 'ssid' field in WiFi configuration")
            
        # Set defaults for optional fields
        if 'password' not in config:
            config['password'] = ''
        if 'type' not in config:
            config['type'] = 'WPA2'
        if 'hidden' not in config:
            config['hidden'] = False
            
        # Authentication type is called 'type' in our JSON format
        config['authentication'] = config.get('type', 'WPA2').upper()
        
        # Sanitize inputs
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

def configure_wifi(wifi_config_string):
    """Store WiFi configuration and notify user to restart the system to apply changes.
    
    Instead of trying to directly configure WiFi (which requires sudo privileges),
    this function stores the configuration and provides instructions for the user.
    
    Args:
        wifi_config_string: WiFi configuration string ($$wifi$${"json":"here"})
        
    Returns:
        dict: Result with success flag and message
    """
    try:
        # Parse the WiFi configuration
        wifi_params = parse_wifi_config(wifi_config_string)
        logging.info(f"Saving WiFi configuration for SSID: {wifi_params['ssid']}")
        
        # Validate SSID
        if not wifi_params['ssid']:
            return {'success': False, 'message': 'Missing SSID in WiFi configuration'}
        
        # Get SSID, password, and whether the network is hidden
        ssid = wifi_params['ssid']
        password = wifi_params.get('password', '')
        hidden = wifi_params.get('hidden', False)
        wifi_type = wifi_params.get('type', 'WPA2')
        
        # Create a wifi-credentials.txt file that the install script can use
        try:
            # Write configuration to a credentials file in the application directory
            # This will be picked up by the install script or manual configuration
            with open('wifi-credentials.txt', 'w') as f:
                f.write(f"SSID={ssid}\n")
                f.write(f"PASSWORD={password}\n")
                f.write(f"TYPE={wifi_type}\n")
                f.write(f"HIDDEN={'yes' if hidden else 'no'}\n")
                
            # Make sure it's only readable by the app user for security
            import os
            try:
                os.chmod('wifi-credentials.txt', 0o600)  # Owner read/write only
            except Exception as chmod_error:
                logging.warning(f"Could not set permissions on wifi-credentials.txt: {str(chmod_error)}")
                
            logging.info("Successfully wrote WiFi credentials to file")
            
            # Get current IP addresses to show in response
            updated_ips = get_non_loopback_ips()
            
            # Provide instructions for manual configuration
            instructions = (
                "WiFi configuration has been saved. To apply the configuration:\n"
                "1. The system must be restarted\n"
                "2. Configuration will be automatically applied on next system boot\n"
                "3. Alternatively, restart network service manually if you have access to the terminal"
            )
            
            return {
                'success': True,
                'message': f'WiFi credentials saved for SSID: {ssid}. Please restart the system to apply changes.',
                'instructions': instructions,
                'ips': updated_ips,
                'requires_restart': True
            }
            
        except Exception as file_error:
            logging.error(f"Error writing WiFi credentials file: {str(file_error)}")
            raise Exception(f"Could not save WiFi configuration: {str(file_error)}")
        
    except Exception as e:
        logging.error(f"Error configuring WiFi: {str(e)}")
        return {'success': False, 'message': f'Failed to configure WiFi: {str(e)}'}

def restart_application():
    """Restart the Flask application"""
    try:
        python_executable = sys.executable
        os.execl(python_executable, python_executable, *sys.argv)
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
    # Safer implementation that doesn't use low-level socket operations
    try:
        ips = {}
        # First try with netifaces if available (more robust)
        try:
            import netifaces
            for iface in netifaces.interfaces():
                # Skip loopback
                if iface.startswith('lo'):
                    continue
                    
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        ip = addr['addr']
                        if ip != '127.0.0.1':
                            ips[iface] = ip
        except ImportError:
            # Fall back to socket approach if netifaces not available
            import socket
            hostname = socket.gethostname()
            try:
                # Get all addresses
                for ip in socket.gethostbyname_ex(hostname)[2]:
                    if ip != '127.0.0.1':
                        iface = 'unknown'  # We don't know the interface name in this method
                        for prefix in ['eth', 'wlan', 'en', 'wl']:
                            if prefix in socket.if_nameindex():
                                iface = prefix
                                break
                        ips[iface] = ip
            except socket.error:
                # If that fails, try one more approach
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    # Doesn't have to be reachable
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
# 5. Flask Routes
# --------------------------------------------------------------------------
@app.route('/')
def home():
    return render_template('index.html',
                         debug_mode=DEBUG_MODE,
                         scan_reset_seconds=15,
                         scan_inactivity_ms=300)

def handle_setup_command(scan_str):
    """Handle setup mode commands"""
    import json
    import re
    
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
        # Log raw request data for debugging
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
        
        import re
        # Check for setup commands (starting with $$)
        setup_command_pattern = re.compile(r'^\s*\$\$.*\$\$', re.IGNORECASE)
        is_setup_command = setup_command_pattern.search(scan_str)
        
        # Check for setup mode entry
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
                'display_serial': DISPLAY_SERIAL,
                'cpu_unique_id': CPU_UNIQUE_ID,
            }
            logging.debug(f"Sending setup mode response: {response}")
            return jsonify(response)
        
        # If already in setup mode, handle setup commands
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

        if not scan_str:
            return jsonify({
                'success': False,
                'error': 'No scan data received.'
            })
            
        # If it looks like a setup command but we're not in setup mode
        if is_setup_command:
            logging.warning(f"Detected setup command outside of setup mode: {scan_str}")
            return jsonify({
                'success': False,
                'error': 'This appears to be a setup command. Try scanning $$setup$$ first to enter setup mode.'
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
    except Exception as e:
        logging.exception(f"Uncaught exception in process_scan route: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Server error processing scan: {str(e)}'
        }), 500

# Register error handler for all unhandled exceptions
@app.errorhandler(Exception)
def handle_exception(e):
    # Log the error
    logging.exception(f"Unhandled exception: {str(e)}")
    
    # Return JSON instead of HTML for HTTP errors
    return jsonify({
        "success": False,
        "error": f"Server error: {str(e)}"
    }), 500

# --------------------------------------------------------------------------
# 6. Main Entry
# --------------------------------------------------------------------------
if __name__ == '__main__':
    try:
        # Log startup information
        print(f"Starting GenOpti-OS application (v0.31)")
        logging.info(f"Starting GenOpti-OS application (v0.31)")
        logging.info(f"Debug mode: {DEBUG_MODE}")
        
        # Defer IP address detection to avoid early segfault
        def delayed_ip_detection():
            try:
                return get_non_loopback_ips()
            except Exception as ip_error:
                logging.warning(f"Could not detect IP addresses: {str(ip_error)}")
                print(f"Warning: Could not detect IP addresses: {str(ip_error)}")
                return {"unknown": "unavailable"}
        
        # Setup WSGI server options to avoid memory issues
        from werkzeug.serving import WSGIRequestHandler
        # Use a simpler request handler that's less likely to cause segfaults
        WSGIRequestHandler.protocol_version = "HTTP/1.1"
        
        # Configure app with safe defaults
        app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max payload
        app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False     # Save memory
        app.config['PROPAGATE_EXCEPTIONS'] = True             # Better error handling
        
        # Run the application - add host parameter to listen on all interfaces
        # This ensures the app is accessible from other devices on the network
        ip_addresses = delayed_ip_detection()  # Get IPs after setup but before run
        logging.info(f"IP Addresses: {ip_addresses}")
        
        app.run(host='0.0.0.0', debug=DEBUG_MODE, threaded=True)
    except Exception as e:
        # Last-ditch error handling to ensure we see errors even if logging isn't working
        import traceback
        error_msg = f"FATAL ERROR STARTING APPLICATION: {str(e)}\n{traceback.format_exc()}"
        print(error_msg)
        
        # Try to write to a simple error file that doesn't use the logging system
        try:
            with open('genopti_error.log', 'a') as f:
                f.write(f"{datetime.now().isoformat()}: {error_msg}\n")
        except:
            pass
        
        # Exit with error code instead of re-raising (which can cause more segfaults)
        import sys
        sys.exit(1)
