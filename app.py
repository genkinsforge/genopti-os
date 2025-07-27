#!/usr/bin/env python3
# app.py - Corrected AAMVA Field Splitting Logic (v0.48 - Known Code Delimiter + Trailer Truncation)

# --- Imports ---
from flask import Flask, render_template, request, jsonify, current_app
from datetime import datetime, date
import time
import re
import logging
from logging.handlers import RotatingFileHandler
import os
import sys
import subprocess
import json
from dotenv import load_dotenv
import netifaces
import shutil
import werkzeug.exceptions
import shlex
import secrets
import hashlib
import uuid
from functools import wraps

# AWS Integration
try:
    from aws_integration import get_aws_client
    AWS_INTEGRATION_AVAILABLE = True
    logging.info("AWS integration module loaded successfully")
except ImportError as e:
    AWS_INTEGRATION_AVAILABLE = False
    logging.warning(f"AWS integration not available: {e}")
    get_aws_client = lambda: None

# --- Globals and Constants ---
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
dotenv_path = os.path.join(APP_ROOT, '.env')
load_dotenv(dotenv_path=dotenv_path, override=False)
DEBUG_MODE = (os.environ.get('DEBUG_MODE', '0') == '1')
LOG_LEVEL = logging.DEBUG if DEBUG_MODE else logging.INFO
LOG_DIR = os.path.join(APP_ROOT, 'logs')
LOG_FILENAME = 'scanner.log'
log_file_path = "File logging not configured yet."
APP_NAME_VERSION = "Genopti-OS (v0.48 - Known Code Delimiter + Trailer Truncation)" # Updated version
DEVICE_ID_FILE = "/etc/device_id"
SETUP_MODE_FLAG_FILE = os.path.join(APP_ROOT, '.setup_mode_active')

# --- Logging Setup ---
# [ Logging setup code remains identical - omitted for brevity ]
try:
    os.makedirs(LOG_DIR, exist_ok=True)
    log_file_path = os.path.join(LOG_DIR, LOG_FILENAME)
    # Formatter
    formatter = logging.Formatter('%(asctime)s %(levelname)s [%(filename)s:%(lineno)d]: %(message)s')
    # Root Logger
    root_logger = logging.getLogger()
    root_logger.setLevel(LOG_LEVEL)
    # Clear existing handlers
    for handler in root_logger.handlers[:]: root_logger.removeHandler(handler); handler.close()
    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(LOG_LEVEL)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    # File Handler
    file_handler = None
    if LOG_DIR:
        try:
            # Test writability explicitly first
            test_log_path = os.path.join(LOG_DIR, '.log_perm_test')
            with open(test_log_path, 'w') as f: f.write('test')
            os.remove(test_log_path)
            print(f"Log directory '{LOG_DIR}' exists and is writable.")

            file_handler = RotatingFileHandler(log_file_path, maxBytes=100_000, backupCount=5, encoding='utf-8')
            file_handler.setLevel(LOG_LEVEL)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
            logging.info(f"File logging configured: {log_file_path}")
        except Exception as e:
            print(f"ERROR setting up file logging to {log_file_path}: {str(e)}", file=sys.stderr)
            log_file_path = "File logging disabled due to error."
            LOG_DIR = None # Indicate logging directory setup failed
    else:
         print("WARN: Log directory setup failed earlier. File logging is disabled.", file=sys.stderr)

    # Flask/Werkzeug Logger
    flask_logger = logging.getLogger('werkzeug')
    flask_logger.setLevel(LOG_LEVEL)
    for handler in flask_logger.handlers[:]: flask_logger.removeHandler(handler)
    flask_logger.addHandler(console_handler)
    if file_handler: flask_logger.addHandler(file_handler)
    flask_logger.propagate = False # Prevent double logging to root

    # Uncaught Exception Handler
    def log_uncaught_exceptions(exc_type, exc_value, exc_traceback):
        logging.critical("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
    sys.excepthook = log_uncaught_exceptions

except Exception as e:
    print(f"CRITICAL ERROR during logging setup: {e}", file=sys.stderr)
    # Fallback to console-only logging if setup fails badly
    logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s %(levelname)s [%(filename)s:%(lineno)d]: %(message)s')
    logging.error("File logging setup failed, continuing with console logging only.")
    log_file_path = "File logging disabled due to critical error."

# --- Flask App Initialization ---
app = Flask(__name__, template_folder=os.path.join(APP_ROOT, 'templates'))

# --- Setup Mode State Management ---
# [ Setup mode functions remain identical - omitted for brevity ]
def is_setup_mode():
    return os.path.exists(SETUP_MODE_FLAG_FILE)

def enter_setup_mode():
    try:
        with open(SETUP_MODE_FLAG_FILE, 'w') as f: f.write('active')
        logging.info("Entered Setup Mode - Flag file created.")
        return True
    except Exception as e:
        logging.error(f"Failed to create setup mode flag file {SETUP_MODE_FLAG_FILE}: {e}", exc_info=True)
        return False

def exit_setup_mode():
    try:
        if os.path.exists(SETUP_MODE_FLAG_FILE):
            os.remove(SETUP_MODE_FLAG_FILE)
            logging.info("Exited Setup Mode - Flag file removed.")
        else:
            logging.info("Attempted to exit setup mode, but flag file was already gone.")
        return True
    except Exception as e:
        logging.error(f"Failed to remove setup mode flag file {SETUP_MODE_FLAG_FILE}: {e}", exc_info=True)
        return False

# --- Environment/Device ID Functions ---
# [ Environment/Device ID functions remain identical - omitted for brevity ]
def get_raspberry_pi_serial():
    try:
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if line.strip().startswith('Serial'):
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        serial = parts[1].strip()
                        # Validate format (16 hex chars) and ensure not zeroed out
                        if re.match(r'^[0-9a-fA-F]{16}$', serial) and serial != '0000000000000000':
                            return serial
                        else:
                            logging.warning(f"Potential CPU Serial '{serial}' found but invalid format or zeroed out.")
                            break # Stop searching if invalid Serial line found
        logging.warning("Valid 'Serial' line not found in /proc/cpuinfo.")
        return "UNKNOWN_CPU"
    except FileNotFoundError:
        logging.error("/proc/cpuinfo not found. Cannot read CPU serial.")
        return "UNKNOWN_CPU_NOFILE"
    except Exception as e:
        logging.error(f"Error reading CPU serial: {e}", exc_info=True)
        return "UNKNOWN_CPU_ERROR"

def get_device_id_from_file():
    try:
        if os.path.exists(DEVICE_ID_FILE):
            with open(DEVICE_ID_FILE, 'r') as f:
                device_id = f.read().strip()
            if not device_id:
                logging.warning(f"{DEVICE_ID_FILE} exists but is empty.")
                return "UNKNOWN_DEVICE_ID_EMPTY"
            return device_id
        else:
            logging.warning(f"{DEVICE_ID_FILE} not found.")
            return "UNKNOWN_DEVICE_ID_FILE_MISSING"
    except Exception as e:
        logging.error(f"Error reading Device ID from {DEVICE_ID_FILE}: {e}", exc_info=True)
        return "UNKNOWN_DEVICE_ID_ERROR"

def load_initial_environment_vars(app_instance):
    """Loads initial config values into app.config at startup."""
    logging.info("Loading initial environment variables into app.config...")
    # Load from .env file (already done globally) or os.environ
    app_instance.config['REGISTERED_USER'] = os.getenv('REGISTERED_USER', 'N/A')
    app_instance.config['COMPANY_NAME'] = os.getenv('COMPANY_NAME', 'N/A')
    app_instance.config['LOCATION'] = os.getenv('LOCATION', 'N/A')

    # Determine CPU ID and Device ID
    cpu_unique_id = get_raspberry_pi_serial()
    device_id = get_device_id_from_file()
    app_instance.config['CPU_UNIQUE_ID'] = cpu_unique_id
    app_instance.config['DEVICE_ID'] = device_id # Store the initially read device_id

    # Determine Display Serial (uses Device ID or CPU ID as fallback)
    display_serial = os.getenv('DISPLAY_SERIAL')
    if not display_serial:
        display_serial = device_id # Use device_id first
        logging.info(f"DISPLAY_SERIAL not set in env, using Device ID: {display_serial}")
        # Only use CPU serial if device ID is also unknown/fallback
        if display_serial.startswith(("UNKNOWN_", "FALLBACK-")):
             if not cpu_unique_id.startswith("UNKNOWN_"):
                 display_serial = cpu_unique_id
                 logging.info(f"Device ID was unknown, using CPU Serial for DISPLAY_SERIAL: {display_serial}")
             else:
                 logging.warning(f"DISPLAY_SERIAL remains unknown/fallback: {display_serial} (Device ID and CPU Serial unknown)")
    else:
        logging.info(f"Loaded DISPLAY_SERIAL from env: {display_serial}")

    app_instance.config['DISPLAY_SERIAL'] = display_serial

    # Load other settings needed globally
    app_instance.config['SCAN_RESET_SECONDS'] = int(os.environ.get('SCAN_RESET_SECONDS', 15))
    app_instance.config['SCAN_INACTIVITY_MS'] = int(os.environ.get('SCAN_INACTIVITY_MS', 300))

    logging.info(f"Initial Config Loaded - User: {app_instance.config['REGISTERED_USER']}, Company: {app_instance.config['COMPANY_NAME']}, Location: {app_instance.config['LOCATION']}")
    logging.info(f"Initial Config Loaded - DisplaySerial: {app_instance.config['DISPLAY_SERIAL']}, DeviceID: {app_instance.config['DEVICE_ID']}, CPU_ID: {app_instance.config['CPU_UNIQUE_ID']}")
    logging.info(f"Initial Config Loaded - ResetSecs: {app_instance.config['SCAN_RESET_SECONDS']}, InactivityMs: {app_instance.config['SCAN_INACTIVITY_MS']}")

# --- WiFi Configuration ---
# [ WiFi functions remain identical - omitted for brevity ]
def validate_wifi_input(ssid, password):
    """Validates WiFi SSID and password for security."""
    # SSID validation
    if not ssid or len(ssid) > 32:
        raise ValueError("SSID must be 1-32 characters")
    
    # Allow printable ASCII and common Unicode chars for SSID
    allowed_ssid_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>? ')
    if not all(c in allowed_ssid_chars for c in ssid):
        raise ValueError("SSID contains invalid characters")
    
    # Password validation
    if password:
        if len(password) < 8 or len(password) > 63:
            raise ValueError("WiFi password must be 8-63 characters")
        # Allow printable ASCII for password
        if not all(32 <= ord(c) <= 126 for c in password):
            raise ValueError("Password contains invalid characters")
    
    return True

def parse_wifi_config(config_string):
    """Parses the $$wifi$${...} command string with enhanced security."""
    try:
        # Limit input size to prevent DoS
        if len(config_string) > 1024:
            raise ValueError("WiFi configuration too large")
        
        # Regex to capture the JSON part after $$wifi$$
        wifi_pattern = re.compile(r'^\s*\$\$\s*wifi\s*\$\$\s*(.*)', re.IGNORECASE | re.DOTALL)
        match = wifi_pattern.search(config_string)
        if not match:
            raise ValueError("Invalid format: must start with $$wifi$$")

        json_str = match.group(1).strip()
        if not json_str:
            raise ValueError("Missing JSON payload after $$wifi$$")

        # Parse the JSON with size limit
        if len(json_str) > 512:
            raise ValueError("JSON payload too large")
        
        try:
            config = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON payload: {e}")

        # Validate required fields exist
        if not isinstance(config, dict):
            raise ValueError("Configuration must be a JSON object")
        
        if 'ssid' not in config or not config['ssid']:
            raise ValueError("Missing or empty 'ssid' field")

        # Get and validate SSID and password
        ssid = str(config['ssid']).strip()
        password = str(config.get('password', '')).strip()
        
        # Validate inputs using security function
        validate_wifi_input(ssid, password)
        
        # Return sanitized config
        sanitized_config = {
            'ssid': ssid,
            'password': password
        }
        
        logging.info(f"Parsed WiFi config: SSID='{ssid}', Password provided: {'yes' if password else 'no'}")
        return sanitized_config

    except Exception as e:
        logging.error(f"Error parsing WiFi config: {e}")
        raise # Re-raise the specific exception (ValueError or other)


def configure_wifi_with_nmcli(ssid, password):
    """Attempts to connect to WiFi using nmcli with enhanced security."""
    nmcli_path = shutil.which("sudo")
    if not nmcli_path:
        logging.error("`sudo` command not found in PATH. Cannot configure WiFi.")
        return False, "`sudo` command not found."

    # Re-validate inputs for extra security
    try:
        validate_wifi_input(ssid, password)
    except ValueError as e:
        logging.error(f"WiFi input validation failed: {e}")
        return False, f"Invalid WiFi credentials: {e}"

    # First perform a WiFi rescan to ensure fresh network list
    rescan_cmd = [nmcli_path, 'nmcli', 'device', 'wifi', 'rescan']
    try:
        logging.debug(f"Running WiFi rescan command: {rescan_cmd}")
        subprocess.run(rescan_cmd, check=True, capture_output=True, text=True, timeout=30)
        time.sleep(3)  # Wait for rescan to complete
    except subprocess.TimeoutExpired:
        logging.warning("WiFi rescan timed out, continuing with connection attempt")
    except Exception as e:
        logging.warning(f"WiFi rescan failed: {e}, continuing with connection attempt")

    # Build command with proper argument separation (prevents injection)
    nmcli_cmd = [nmcli_path, 'nmcli', 'device', 'wifi', 'connect']
    
    # Use shlex.quote for additional safety on SSID
    nmcli_cmd.append(shlex.quote(ssid))
    
    # Add password if provided, with proper quoting
    if password:
        nmcli_cmd.extend(['password', shlex.quote(password)])

    # Log connection attempt without sensitive data
    logging.info(f"Attempting WiFi connection to SSID: '{ssid[:20]}{'...' if len(ssid) > 20 else ''}' (Password: {'yes' if password else 'no'})")

    try:
        # Execute with restricted environment
        env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}
        result = subprocess.run(
            nmcli_cmd, 
            capture_output=True, 
            text=True, 
            check=True, 
            timeout=30,  # Reduced timeout
            env=env  # Restricted environment
        )

        # Log sanitized output (remove potential sensitive data)
        stdout_safe = result.stdout.strip().replace(password, '[REDACTED]') if password else result.stdout.strip()
        stderr_safe = result.stderr.strip().replace(password, '[REDACTED]') if password else result.stderr.strip()
        
        logging.info(f"nmcli completed for SSID '{ssid}'")
        if stderr_safe:
            logging.info(f"nmcli stderr: {stderr_safe}")

        # Check success indicators
        if "successfully activated" in result.stdout or "Connection successfully activated" in result.stdout:
            logging.info(f"Successfully connected to SSID: {ssid}")
            return True, f"Successfully connected to SSID: {ssid}"
        else:
            logging.warning(f"nmcli completed but connection status unclear for SSID '{ssid}'")
            return True, f"Connection command completed. Verify network status manually."

    except subprocess.CalledProcessError as e:
        # Handle nmcli command failures
        stderr_output = e.stderr.strip() if e.stderr else ""
        stdout_output = e.stdout.strip() if e.stdout else ""
        
        # Remove password from error messages
        if password:
            stderr_output = stderr_output.replace(password, '[REDACTED]')
            stdout_output = stdout_output.replace(password, '[REDACTED]')
        
        logging.error(f"nmcli failed with exit code {e.returncode} for SSID '{ssid}'")
        
        # Provide user-friendly error messages
        error_message = stderr_output or stdout_output or "Connection failed"
        if "Secrets were required" in error_message or "Invalid password" in error_message:
            msg = f"Authentication failed for '{ssid}'. Check password."
        elif "Could not find network" in error_message or "No network with SSID" in error_message:
            msg = f"Network '{ssid}' not found. Check SSID."
        elif "Connection activation failed" in error_message:
            msg = f"Failed to connect to '{ssid}'. Check network settings."
        else:
            msg = f"Failed to connect to '{ssid}'. Network error."

        return False, msg

    except subprocess.TimeoutExpired:
        logging.error(f"nmcli timed out for SSID '{ssid}'")
        return False, f"Connection attempt timed out for '{ssid}'"

    except Exception as e:
        logging.error(f"Unexpected error in WiFi configuration: {e}", exc_info=True)
        return False, "An unexpected error occurred during WiFi configuration"


def handle_wifi_command(wifi_config_string):
    """Parses the wifi command and attempts connection."""
    try:
        wifi_params = parse_wifi_config(wifi_config_string)
        # Attempt connection using parsed parameters
        success, message = configure_wifi_with_nmcli(wifi_params['ssid'], wifi_params.get('password')) # Use .get for password

        # Get updated IP info regardless of connection success/failure
        updated_ips = get_non_loopback_ips()

        # Return structured response
        return {'success': success, 'message': message, 'ips': updated_ips, 'requires_restart': False} # Assuming restart is not typically needed

    except ValueError as e:
        # Handle parsing errors from parse_wifi_config
        logging.error(f"Invalid WiFi command format: {e}")
        return {'success': False, 'message': f'Invalid WiFi command: {e}', 'ips': get_non_loopback_ips()} # Include current IPs
    except Exception as e:
        # Handle unexpected errors during processing (e.g., nmcli execution errors if not caught inside)
        logging.error(f"Error handling WiFi command: {e}", exc_info=True)
        return {'success': False, 'message': f'Internal error processing WiFi command: {e}', 'ips': get_non_loopback_ips()}


def handle_ping_command(ping_config_string):
    """Parses the ping command and executes network connectivity test."""
    try:
        # Extract JSON from the ping command string
        ping_match = re.search(r'\$\$\s*ping\s*\$\$\s*(\{.*\})', ping_config_string, re.IGNORECASE | re.DOTALL)
        if not ping_match:
            raise ValueError("Invalid ping command format")
        
        ping_config = json.loads(ping_match.group(1))
        
        # Extract parameters with defaults
        target = ping_config.get('target', '8.8.8.8')
        count = int(ping_config.get('count', 3))
        timeout_ms = int(ping_config.get('timeout', 5000))
        timeout_seconds = timeout_ms / 1000.0
        
        # Validate parameters
        if not target:
            raise ValueError("Target cannot be empty")
        if count < 1 or count > 10:
            raise ValueError("Count must be between 1 and 10")
        if timeout_seconds < 1 or timeout_seconds > 30:
            raise ValueError("Timeout must be between 1000ms and 30000ms")
        
        logging.info(f"Executing ping test: target={target}, count={count}, timeout={timeout_seconds}s")
        
        # Execute ping command
        ping_cmd = ['ping', '-c', str(count), '-W', str(int(timeout_seconds)), target]
        logging.debug(f"Running ping command: {ping_cmd}")
        
        result = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=timeout_seconds + 5)
        
        # Parse ping results
        success = result.returncode == 0
        stdout_lines = result.stdout.strip().split('\n') if result.stdout else []
        stderr_lines = result.stderr.strip().split('\n') if result.stderr else []
        
        if success:
            # Extract statistics from ping output
            stats_info = "Ping successful"
            for line in stdout_lines:
                if 'packet loss' in line:
                    stats_info = line.strip()
                    break
            message = f"Connectivity test passed. {stats_info}"
            logging.info(f"Ping successful: {message}")
        else:
            error_msg = stderr_lines[0] if stderr_lines else "Ping failed"
            message = f"Connectivity test failed: {error_msg}"
            logging.warning(f"Ping failed: {message}")
        
        return {
            'success': success,
            'message': message,
            'target': target,
            'count': count,
            'timeout_ms': timeout_ms,
            'ping_output': stdout_lines[-2:] if stdout_lines else [],  # Last 2 lines typically contain summary
            'ips': get_non_loopback_ips()
        }
        
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON in ping command: {e}")
        return {'success': False, 'message': f'Invalid JSON in ping command: {e}', 'ips': get_non_loopback_ips()}
    except ValueError as e:
        logging.error(f"Invalid ping command parameters: {e}")  
        return {'success': False, 'message': f'Invalid ping parameters: {e}', 'ips': get_non_loopback_ips()}
    except subprocess.TimeoutExpired:
        logging.error(f"Ping command timed out after {timeout_seconds + 5} seconds")
        return {'success': False, 'message': 'Ping command timed out', 'ips': get_non_loopback_ips()}
    except Exception as e:
        logging.error(f"Error handling ping command: {e}", exc_info=True)
        return {'success': False, 'message': f'Internal error processing ping command: {e}', 'ips': get_non_loopback_ips()}


def handle_register_command(register_config_string):
    """Parses the register command and executes device registration."""
    try:
        # Extract JSON from the register command string
        register_match = re.search(r'\$\$\s*register\s*\$\$\s*(\{.*\})', register_config_string, re.IGNORECASE | re.DOTALL)
        if not register_match:
            raise ValueError("Invalid register command format")
        
        register_config = json.loads(register_match.group(1))
        
        # Extract and validate required parameters
        setup_token = register_config.get('setupToken', '').strip()
        bootstrapping_key_id = register_config.get('bootstrappingKeyId', '').strip()
        location_id = register_config.get('locationId', '').strip()
        api_endpoint = register_config.get('apiEndpoint', 'https://api.genkinsforge.com').strip()
        
        # Validate required fields
        if not setup_token:
            raise ValueError("setupToken is required")
        if not setup_token.startswith('ST_'):
            raise ValueError("setupToken must start with 'ST_'")
        if not bootstrapping_key_id:
            raise ValueError("bootstrappingKeyId is required")
        if not location_id:
            raise ValueError("locationId is required")
        if not location_id.startswith('LOC_'):
            raise ValueError("locationId must start with 'LOC_'")
        if not api_endpoint.startswith('https://'):
            raise ValueError("apiEndpoint must be a valid HTTPS URL")
        
        logging.info(f"Starting device registration: bootstrappingKeyId={bootstrapping_key_id}, locationId={location_id}")
        
        # Generate device ID using CPU serial + version suffix
        cpu_serial = get_cpu_serial()
        device_id = f"{cpu_serial}_go20"
        
        # Execute two-phase registration
        registration_result = execute_device_registration(
            device_id=device_id,
            setup_token=setup_token,
            bootstrapping_key_id=bootstrapping_key_id,
            location_id=location_id,
            api_endpoint=api_endpoint
        )
        
        if registration_result['success']:
            # Store registration data locally
            store_device_registration(registration_result['data'])
            message = f"Device {device_id} successfully registered to {location_id}"
            logging.info(f"Registration successful: {message}")
        else:
            message = f"Registration failed: {registration_result.get('error', 'Unknown error')}"
            logging.error(f"Registration failed: {message}")
        
        return {
            'success': registration_result['success'],
            'message': message,
            'device_id': device_id,
            'location_id': location_id,
            'bootstrapping_key_id': bootstrapping_key_id,
            'api_endpoint': api_endpoint,
            'ips': get_non_loopback_ips()
        }
        
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON in register command: {e}")
        return {'success': False, 'message': f'Invalid JSON in register command: {e}', 'ips': get_non_loopback_ips()}
    except ValueError as e:
        logging.error(f"Invalid register command parameters: {e}")  
        return {'success': False, 'message': f'Invalid register parameters: {e}', 'ips': get_non_loopback_ips()}
    except Exception as e:
        logging.error(f"Error handling register command: {e}", exc_info=True)
        return {'success': False, 'message': f'Internal error processing register command: {e}', 'ips': get_non_loopback_ips()}


def get_cpu_serial():
    """Extract CPU serial number from /proc/cpuinfo."""
    try:
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if line.startswith('Serial'):
                    # Extract serial after the colon, strip whitespace
                    serial = line.split(':', 1)[1].strip()
                    if serial and serial != '0000000000000000':
                        return serial
        # Fallback if no valid serial found
        logging.warning("No valid CPU serial found, using fallback")
        return "UNKNOWN_SERIAL"
    except Exception as e:
        logging.error(f"Error reading CPU serial: {e}")
        return "ERROR_SERIAL"


def execute_device_registration(device_id, setup_token, bootstrapping_key_id, location_id, api_endpoint):
    """Execute the two-phase device registration protocol."""
    try:
        import requests
        
        # Phase 1: Setup Request
        logging.info("Phase 1: Sending setup request")
        setup_url = f"{api_endpoint}/webhook/registration"
        setup_payload = {
            "action": "setup",
            "deviceId": device_id,
            "setupToken": setup_token,
            "bootstrappingKeyId": bootstrapping_key_id
        }
        
        setup_response = requests.post(
            setup_url,
            json=setup_payload,
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        
        if setup_response.status_code != 200:
            error_msg = f"Setup request failed with status {setup_response.status_code}"
            try:
                error_detail = setup_response.json().get('message', 'No details provided')
                error_msg += f": {error_detail}"
            except:
                error_msg += f": {setup_response.text}"
            return {'success': False, 'error': error_msg}
        
        setup_data = setup_response.json()
        if not setup_data.get('success'):
            return {'success': False, 'error': setup_data.get('message', 'Setup phase failed')}
        
        # Extract setup response data
        setup_info = setup_data.get('data', {})
        salt = setup_info.get('salt')
        account_uid = setup_info.get('accountUid')
        
        if not salt or not account_uid:
            return {'success': False, 'error': 'Setup response missing required data (salt/accountUid)'}
        
        # Phase 2: Generate challenge and signature
        logging.info("Phase 2: Generating challenge and signature")
        challenge = generate_registration_challenge(device_id, salt)
        signature = generate_registration_signature(challenge, device_id)
        
        # Phase 2: Registration Request
        logging.info("Phase 2: Sending registration request")
        register_payload = {
            "action": "registration",
            "deviceId": device_id,
            "challenge": challenge,
            "signature": signature,
            "locationId": location_id,
            "bootstrappingKeyId": bootstrapping_key_id
        }
        
        register_response = requests.post(
            setup_url,
            json=register_payload,
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        
        if register_response.status_code != 200:
            error_msg = f"Registration request failed with status {register_response.status_code}"
            try:
                error_detail = register_response.json().get('message', 'No details provided')  
                error_msg += f": {error_detail}"
            except:
                error_msg += f": {register_response.text}"
            return {'success': False, 'error': error_msg}
        
        register_data = register_response.json()
        if not register_data.get('success'):
            return {'success': False, 'error': register_data.get('message', 'Registration phase failed')}
        
        # Return success with registration data
        return {
            'success': True,
            'data': {
                'device_id': device_id,
                'account_uid': account_uid,
                'location_id': location_id,
                'jwt': register_data.get('data', {}).get('jwt'),
                'expires_at': register_data.get('data', {}).get('expiresAt'),
                'api_endpoint': api_endpoint
            }
        }
        
    except requests.exceptions.Timeout:
        return {'success': False, 'error': 'Registration request timed out'}
    except requests.exceptions.ConnectionError:
        return {'success': False, 'error': 'Unable to connect to registration API'}
    except Exception as e:
        logging.error(f"Error during device registration: {e}", exc_info=True)
        return {'success': False, 'error': f'Registration error: {str(e)}'}


def generate_registration_challenge(device_id, salt):
    """Generate SHA256 challenge for device registration."""
    import hashlib
    import secrets
    import time
    
    # Generate secure random data
    random_data = secrets.token_hex(32)
    
    # Create challenge string: deviceId + salt + randomData
    challenge_string = f"{device_id}{salt}{random_data}"
    
    # Generate SHA256 hash
    challenge_hash = hashlib.sha256(challenge_string.encode('utf-8')).hexdigest()
    
    # Format challenge as expected by API: REGISTER_{timestamp}_{hash}
    timestamp = int(time.time())
    formatted_challenge = f"REGISTER_{timestamp}_{challenge_hash}"
    
    logging.debug(f"Generated challenge: {formatted_challenge[:32]}...")
    return formatted_challenge


def generate_registration_signature(challenge, device_id):
    """Generate cryptographic signature for registration."""
    import hashlib
    
    # For now, use a simple HMAC-style signature
    # In production, this should use proper cryptographic signing
    signature_string = f"{challenge}{device_id}"
    signature = hashlib.sha256(signature_string.encode('utf-8')).hexdigest()
    
    logging.debug(f"Generated signature: {signature[:16]}...")
    return signature


def store_device_registration(registration_data):
    """Store device registration data locally."""
    try:
        registration_file = "/etc/genopti-device-registration"
        
        # Store essential registration info
        registration_info = {
            'device_id': registration_data.get('device_id'),
            'account_uid': registration_data.get('account_uid'),
            'location_id': registration_data.get('location_id'),
            'api_endpoint': registration_data.get('api_endpoint'),
            'registered_at': time.time()
        }
        
        with open(registration_file, 'w') as f:
            json.dump(registration_info, f, indent=2)
        
        # Set secure permissions
        import os
        os.chmod(registration_file, 0o640)
        
        # Store JWT token separately with more restrictive permissions
        if registration_data.get('jwt'):
            jwt_file = "/etc/genopti-device-token"
            jwt_info = {
                'jwt': registration_data.get('jwt'),
                'expires_at': registration_data.get('expires_at'),
                'created_at': time.time()
            }
            
            with open(jwt_file, 'w') as f:
                json.dump(jwt_info, f, indent=2)
            
            os.chmod(jwt_file, 0o600)
        
        logging.info(f"Device registration data stored successfully")
        
    except Exception as e:
        logging.error(f"Error storing device registration data: {e}", exc_info=True)
        raise


# --- Application Restart ---
# [ Restart function remains identical - omitted for brevity ]
def restart_application():
    """Attempts to restart the current application process."""
    logging.warning("Attempting application restart via os.execl...")
    try:
        # Ensure logs and output buffers are flushed before restarting
        sys.stdout.flush()
        sys.stderr.flush()
        # Flush Flask/Werkzeug log handlers if configured
        werkzeug_logger = logging.getLogger('werkzeug')
        if werkzeug_logger:
            for handler in werkzeug_logger.handlers:
                handler.flush()
        # Flush root logger handlers
        root_logger = logging.getLogger()
        if root_logger:
            for handler in root_logger.handlers:
                handler.flush()

        python_executable = sys.executable
        script_path = sys.argv[0] # The script that was initially run
        args = [python_executable, script_path] + sys.argv[1:] # Include original arguments

        logging.info(f"Executing restart with command: {args}")
        os.execl(python_executable, *args) # Replace the current process

    except Exception as e:
        # This part might not be reached if execl fails badly, but log just in case
        logging.critical(f"FATAL: os.execl failed during restart attempt: {e}", exc_info=True)
        # Exit with an error code if restart fails
        sys.exit(1)

# --- Network Info ---
# [ Network Info function remains identical - omitted for brevity ]
def get_non_loopback_ips():
    """Retrieves non-loopback IPv4 addresses for all interfaces."""
    ips = {}
    try:
        interfaces = netifaces.interfaces()
        logging.debug(f"Available network interfaces: {interfaces}")

        for iface in interfaces:
            # Skip common loopback, virtual, or docker interfaces
            if iface.startswith(('lo', 'docker', 'veth', 'virbr', 'vmnet', 'sit', 'tun')):
                logging.debug(f"Skipping interface: {iface}")
                continue

            addrs = netifaces.ifaddresses(iface)

            # Check for IPv4 addresses
            if netifaces.AF_INET in addrs and addrs[netifaces.AF_INET]:
                # Get the first IPv4 address listed for the interface
                ipv4_info = addrs[netifaces.AF_INET][0]
                ipv4_addr = ipv4_info.get('addr')
                if ipv4_addr:
                    ips[iface] = ipv4_addr
                    logging.debug(f"Found IPv4 {ipv4_addr} on interface {iface}")
                else:
                     logging.warning(f"Interface {iface} has AF_INET entry but no 'addr' field: {ipv4_info}")
            # Optionally, check for IPv6 if needed later

        if not ips:
            logging.warning("No active non-loopback IPv4 interfaces found.")
            return {"status": "No active non-loopback IPv4 interface found"}

        logging.debug(f"Returning non-loopback IPs: {ips}")
        return ips

    except ImportError:
        logging.error("The 'netifaces' library is not installed or failed to import.")
        return {"error": "netifaces library error"}
    except Exception as e:
        logging.warning(f"Error getting IP addresses: {e}", exc_info=True)
        return {"error": f"Could not retrieve IP addresses: {e}"}

# --- Audio and Alert System ---
def play_beep():
    """Plays a system beep for underage alerts."""
    try:
        # Try different methods to play a beep
        beep_commands = [
            ['aplay', '/usr/share/sounds/alsa/Front_Left.wav'],  # ALSA sound
            ['paplay', '/usr/share/sounds/alsa/Front_Left.wav'], # PulseAudio
            ['speaker-test', '-t', 'sine', '-f', '1000', '-l', '1'], # Generate tone
            ['echo', '-e', '\\a']  # Terminal bell fallback
        ]
        
        for cmd in beep_commands:
            if shutil.which(cmd[0]):
                try:
                    subprocess.run(cmd, capture_output=True, timeout=2)
                    logging.info(f"Beep played using {cmd[0]}")
                    return True
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                    continue
        
        # Final fallback - try to write to system bell
        try:
            with open('/dev/console', 'w') as console:
                console.write('\a')
                console.flush()
            logging.info("Beep played via console bell")
            return True
        except (PermissionError, FileNotFoundError):
            logging.warning("Could not play beep - no audio method available")
            return False
            
    except Exception as e:
        logging.error(f"Error playing beep: {e}")
        return False

# In-memory storage for active alerts (cleared on restart)
active_alerts = {}

def create_alert(message, alert_type="warning"):
    """Creates an alert that requires acknowledgment."""
    alert_id = str(uuid.uuid4())[:8]  # Short ID for QR codes
    alert_data = {
        'id': alert_id,
        'message': message,
        'type': alert_type,
        'timestamp': datetime.now().isoformat(),
        'acknowledged': False
    }
    active_alerts[alert_id] = alert_data
    logging.info(f"Alert created: {alert_id} - {message}")
    return alert_id

def acknowledge_alert(alert_id):
    """Acknowledges an alert by ID."""
    if alert_id in active_alerts:
        active_alerts[alert_id]['acknowledged'] = True
        active_alerts[alert_id]['ack_timestamp'] = datetime.now().isoformat()
        logging.info(f"Alert acknowledged: {alert_id}")
        return True
    return False

def get_active_alerts():
    """Returns all unacknowledged alerts."""
    return {aid: alert for aid, alert in active_alerts.items() if not alert['acknowledged']}

def clear_acknowledged_alerts():
    """Removes acknowledged alerts older than 1 hour."""
    now = datetime.now()
    to_remove = []
    for aid, alert in active_alerts.items():
        if alert['acknowledged'] and 'ack_timestamp' in alert:
            ack_time = datetime.fromisoformat(alert['ack_timestamp'])
            if (now - ack_time).total_seconds() > 3600:  # 1 hour
                to_remove.append(aid)
    
    for aid in to_remove:
        del active_alerts[aid]
        logging.debug(f"Removed old acknowledged alert: {aid}")

# --- License Parsing & Validation ---
class LicenseParser:
    """Handles parsing and validation of AAMVA-compliant license data."""
    # [ Field Map, Date Fields, Date Formats, Known Codes remain the same ]
    AAMVA_FIELD_MAP = {
        "DCA": "jurisdiction_vehicle_class", "DCB": "jurisdiction_restriction_codes", "DCD": "jurisdiction_endorsement_codes",
        "DBA": "expiration_date", "DBC": "is_organ_donor", "DBB": "date_of_birth", "DBD": "issue_date", "DBH": "date_of_death",
        "DCH": "federal_commercial_vehicle_codes", "DAU": "height_in_ft_in", "DAY": "eye_color", "DAG": "address_street",
        "DAI": "address_city", "DAJ": "address_state", "DAK": "address_postal_code", "DAQ": "customer_id_number",
        "DCF": "document_discriminator", "DCG": "country_identification", "DDE": "last_name_truncation", "DDF": "first_name_truncation",
        "DDG": "middle_name_truncation", "DAH": "address_street_2", "DAZ": "hair_color", "DCI": "place_of_birth",
        "DCJ": "audit_information", "DCK": "inventory_control_number", "DBN": "other_last_name", "DBG": "other_first_name",
        "DBS": "other_suffix_name", "DCU": "name_suffix", "DCE": "weight_range", "DCL": "race_ethnicity",
        "DCM": "standard_vehicle_classification", "DCN": "standard_endorsement_code", "DCO": "standard_restriction_code",
        "DCP": "jurisdiction_vehicle_classification_description", "DCQ": "jurisdiction_endorsement_code_description",
        "DCR": "jurisdiction_restriction_code_description", "DDA": "compliance_type", "DDB": "card_revision_date",
        "DDC": "hazmat_endorsement_expiration_date", "DDD": "limited_duration_document_indicator", "DAW": "weight_pounds",
        "DAX": "weight_kilograms", "DDH": "under_18_until", "DDI": "under_19_until", "DDJ": "under_21_until",
        "DDK": "organ_donor_indicator", "DDL": "veteran_indicator", "DCS": "last_name", "DAC": "first_name",
        "DAD": "middle_name", "DCT": "full_name",
        "DBJ": "customer_identifier", "DBK": "customer_identifier_alt",
        "DBL": "license_classification_code", "DBM": "license_restriction_code", "DBP": "vehicle_identification_number",
        "DAR": "license_class_code", "DAS": "license_endorsement_code", "DAT": "license_restriction_code", "DAV": "height_cm",
        "DAL": "address_street_1_deprecated",
        "DAM": "address_street_2_deprecated",
    }
    DATE_FIELDS = {"DBA", "DBB", "DBD", "DBH", "DDB", "DDC", "DDH", "DDI", "DDJ"}
    AAMVA_DATE_FORMAT = '%m%d%Y'
    AAMVA_ALT_DATE_FORMAT = '%Y%m%d'
    KNOWN_FIELD_CODES = set(AAMVA_FIELD_MAP.keys())
    # Define potential trailer markers more broadly
    TRAILER_MARKERS = ["ZT", "ZO"] # Add others like ZO if they exist


    @staticmethod
    def _parse_date(field_code, value):
        # [ _parse_date function remains identical - omitted for brevity ]
        logging.debug(f"Attempting to parse date for field {field_code}: '{value}'")
        if not value:
            logging.debug(f"Empty value for date field {field_code}, returning None.")
            return None

        # Try parsing with defined formats
        for fmt in [LicenseParser.AAMVA_DATE_FORMAT, LicenseParser.AAMVA_ALT_DATE_FORMAT]:
            try:
                # Using datetime.strptime correctly returns a datetime object
                parsed_datetime = datetime.strptime(value, fmt)
                # We only need the date part
                parsed_date = parsed_datetime.date()
                logging.debug(f"Successfully parsed {field_code} with format '{fmt}': {parsed_date}")
                return parsed_date
            except ValueError:
                # This format didn't match, try the next one
                logging.debug(f"Format '{fmt}' did not match for value '{value}'.")
                continue # Try the next format

        # If no format matched
        logging.warning(f"Could not parse date field {field_code} with value '{value}' using any known format.")
        return value


    # --- THIS METHOD CONTAINS THE REVISED PARSING LOGIC (v0.48) ---
    @staticmethod
    def sanitize_field_value(field_code: str, value: str) -> str:
        """Sanitizes individual field values for security and data integrity."""
        if not isinstance(value, str):
            value = str(value)
        
        # Length limits for different field types
        length_limits = {
            'name': 50,      # Names
            'address': 100,  # Address fields
            'id': 50,        # ID numbers
            'code': 10,      # Codes and classifications
            'default': 200   # Default limit
        }
        
        # Categorize fields for appropriate limits
        name_fields = {'last_name', 'first_name', 'middle_name', 'full_name', 'other_last_name', 'other_first_name'}
        address_fields = {'address_street', 'address_street_2', 'address_city', 'address_state', 'place_of_birth'}
        id_fields = {'customer_id_number', 'document_discriminator', 'customer_identifier'}
        code_fields = {'jurisdiction_vehicle_class', 'license_class_code', 'eye_color', 'hair_color'}
        
        field_name = LicenseParser.AAMVA_FIELD_MAP.get(field_code, '')
        
        if field_name in name_fields:
            max_len = length_limits['name']
        elif field_name in address_fields:
            max_len = length_limits['address']
        elif field_name in id_fields:
            max_len = length_limits['id']
        elif field_name in code_fields:
            max_len = length_limits['code']
        else:
            max_len = length_limits['default']
        
        # Truncate if too long
        if len(value) > max_len:
            logging.warning(f"Field {field_code} ({field_name}) value truncated from {len(value)} to {max_len} characters")
            value = value[:max_len]
        
        # Remove potentially dangerous characters but preserve normal text
        # Allow printable ASCII plus common accented characters
        safe_chars = set()
        for c in value:
            # Printable ASCII (space through tilde)
            if 32 <= ord(c) <= 126:
                safe_chars.add(c)
            # Common accented characters for names
            elif 128 <= ord(c) <= 255 and field_name in name_fields:
                safe_chars.add(c)
        
        sanitized = ''.join(c for c in value if c in safe_chars)
        
        # Remove control characters and normalize whitespace
        sanitized = re.sub(r'\s+', ' ', sanitized.strip())
        
        return sanitized

    @staticmethod
    def parse_aamva(data: str) -> dict:
        """Parses an AAMVA PDF417 barcode string with enhanced security validation."""
        parsed_data = {}
        data_start_index = -1

        # Ensure data is a string
        if not isinstance(data, str):
            logging.error(f"Invalid input type for parse_aamva: expected string, got {type(data)}")
            raise ValueError("Invalid input data type.")
        
        # Input size validation to prevent DoS
        if len(data) > 10000:  # Reasonable limit for barcode data
            logging.error(f"Input data too large: {len(data)} characters")
            raise ValueError("Barcode data exceeds maximum size limit.")
        
        if len(data) < 10:  # Too small to be valid AAMVA data
            logging.error(f"Input data too small: {len(data)} characters")
            raise ValueError("Barcode data too small to be valid AAMVA format.")

        # --- Find Start Marker / Header (Same logic as v0.47) ---
        ansi_marker = "ANSI "
        data_start_index = data.find(ansi_marker)
        found_header = False

        if data_start_index != -1:
            found_header = True
            logging.debug(f"Found standard '{ansi_marker}' marker at index {data_start_index}.")
            search_start_pos = data_start_index + len(ansi_marker)
            # Adjusted regex slightly for flexibility
            match_header_details = re.match(r'\s*\d{6}\d{2}(\d{2}\d{2})?[A-Z]{2}\d{4}\d{4}[A-Z]{2}(?:\d{4}\d{4}[A-Z]{2})?', data[search_start_pos:])
            if match_header_details:
                logging.debug(f"Found and skipping standard header details: '{match_header_details.group(0)}'")
                data_start_index = search_start_pos + match_header_details.end()
            else:
                data_start_index = search_start_pos
                logging.debug("No standard header details matched after ANSI marker, proceeding.")
        else:
            common_headers = ["@", "%"]
            for header in common_headers:
                 if data.startswith(header):
                      logging.warning(f"Standard '{ansi_marker}' marker not found, but found alternative header '{header.encode('unicode_escape').decode('ascii')}'. Attempting parse.")
                      data_start_index = len(header)
                      found_header = True
                      break
            if not found_header:
                logging.error(f"Invalid AAMVA data: Standard '{ansi_marker}' marker not found, and no known alternative header detected.")
                logging.warning("Attempting parse from beginning despite missing header/marker.")
                data_start_index = 0

        # --- Find the first actual *known* data field code ---
        current_index = -1
        first_field_code = None
        temp_index = data_start_index
        while temp_index < len(data) - 2:
            potential_code = data[temp_index : temp_index + 3]
            if potential_code in LicenseParser.KNOWN_FIELD_CODES:
                 current_index = temp_index
                 first_field_code = potential_code
                 logging.info(f"Starting AAMVA parse loop at actual data index {current_index} (First *known* code: '{first_field_code}')")
                 break
            temp_index += 1

        if current_index == -1:
            error_context = data[data_start_index:data_start_index+50].encode('unicode_escape').decode('ascii')
            logging.error(f"Could not find any *known* AAMVA field code after header/marker (effective start index {data_start_index}). Data starts: '{error_context}...'")
            raise ValueError("Parsing failed: Could not find initial *known* field code.")

        data_len = len(data)

        # --- Main Parsing Loop (v0.48 - Known Code Delimiter + Trailer Truncation) ---
        field_count = 0
        while current_index < data_len:
            field_code = data[current_index : current_index + 3]
            logging.debug(f"Loop Iteration {field_count+1}: Index={current_index}, Processing Known Field Code='{field_code}'")

            value_start_index = current_index + 3

            # --- Find the start of the NEXT *KNOWN* field code ---
            next_known_code_index = -1
            next_known_code = None
            search_pos = value_start_index
            while search_pos < data_len - 2:
                potential_code = data[search_pos : search_pos + 3]
                if potential_code in LicenseParser.KNOWN_FIELD_CODES:
                    next_known_code_index = search_pos
                    next_known_code = potential_code
                    logging.debug(f"Next *known* field code '{next_known_code}' found starting at index {next_known_code_index}")
                    break
                search_pos += 1

            # Determine the end index for the current field's value
            if next_known_code_index != -1:
                value_end_index = next_known_code_index
                next_loop_start_index = next_known_code_index
            else:
                value_end_index = data_len
                next_loop_start_index = data_len
                logging.debug(f"No further *known* field codes found after {field_code}. Value potentially goes to end ({value_end_index}).")

            # Extract the initial raw value
            raw_value = data[value_start_index : value_end_index]
            logging.debug(f"Field: {field_code}, Initial Raw Value Length: {len(raw_value)}, Initial Raw Value: '{raw_value}'")

            # --- **NEW: Trailer Truncation Step** ---
            final_value = raw_value
            # Check if this is the last known field identified, or if the raw value is suspiciously long
            is_potentially_last_field = (next_known_code_index == -1)
            if is_potentially_last_field:
                logging.debug(f"Checking for trailers in potentially last field '{field_code}' with value '{raw_value}'")
                trailer_found_at = -1
                found_trailer_marker = None
                # Search for known trailer markers within the raw value
                for marker in LicenseParser.TRAILER_MARKERS:
                    try:
                        idx = raw_value.index(marker)
                        # If found, keep track of the earliest trailer occurrence
                        if trailer_found_at == -1 or idx < trailer_found_at:
                            trailer_found_at = idx
                            found_trailer_marker = marker
                    except ValueError:
                        continue # Marker not found in this value

                if trailer_found_at != -1:
                    # If a trailer was found, truncate the value before it
                    final_value = raw_value[:trailer_found_at]
                    logging.info(f"Trailer marker '{found_trailer_marker}' found within field '{field_code}' value at relative index {trailer_found_at}. Truncating value to: '{final_value}'")
                else:
                    logging.debug(f"No known trailer markers found in value for field '{field_code}'.")
            # --- End Trailer Truncation ---


            # Clean and sanitize the potentially truncated value
            cleaned_value = final_value.strip()
            sanitized_value = LicenseParser.sanitize_field_value(field_code, cleaned_value)
            logging.debug(f"Field: {field_code}, Final Sanitized Value: '{sanitized_value}'")

            # Map field code to meaningful name
            field_name = LicenseParser.AAMVA_FIELD_MAP[field_code]
            parsed_value = LicenseParser._parse_date(field_code, sanitized_value) if field_code in LicenseParser.DATE_FIELDS else sanitized_value

            if field_name in parsed_data:
                logging.warning(f"Duplicate field code {field_code} ('{field_name}') encountered. Overwriting previous value '{parsed_data[field_name]}' with '{parsed_value}'.")
            parsed_data[field_name] = parsed_value
            field_count += 1
            logging.debug(f"Mapped {field_code} to {field_name}. Mapped count: {field_count}")

            # Move to the start index for the next iteration
            current_index = next_loop_start_index
            logging.debug(f"Moving to next potential field start index: {current_index}")

        logging.info(f"AAMVA parse loop finished. Total mapped fields extracted: {field_count}")

        # --- Log Raw Parsed Data (Before Construction) ---
        # [ Logging logic remains the same ]
        logging.debug("--- AAMVA Raw Parsed Data (Before Construction) ---")
        for key, value in parsed_data.items():
             log_val = value.isoformat() if isinstance(value, date) else value # Format dates for logging
             logging.debug(f"Raw Key: {key}, Value: '{log_val}', Type: {type(value)}")
        logging.debug("--- End AAMVA Raw Parsed Data ---")

        # --- Post-parsing processing (Constructing Full Name and Address) ---
        # [ Construction logic remains the same ]
        if not parsed_data.get('full_name'):
            fname = parsed_data.get('first_name', '')
            mname = parsed_data.get('middle_name', '')
            lname = parsed_data.get('last_name', '')
            sfx = parsed_data.get('name_suffix', '') # e.g., JR, SR, III
            logging.debug(f"Constructing full name from: F='{fname}', M='{mname}', L='{lname}', Sfx='{sfx}'")
            constructed_name = ' '.join(filter(None, [fname, mname, lname, sfx])).strip()
            if constructed_name:
                 parsed_data['full_name'] = constructed_name
                 logging.info(f"Successfully constructed full name: '{constructed_name}'")
            else:
                 logging.warning("Constructed full name resulted in empty string. Check if DCS/DAC/DAD fields were parsed.")

        if not parsed_data.get('full_address'):
             street1 = parsed_data.get('address_street', '') or parsed_data.get('address_street_1_deprecated', '')
             street2 = parsed_data.get('address_street_2', '') or parsed_data.get('address_street_2_deprecated', '')
             city = parsed_data.get('address_city', '')
             state = parsed_data.get('address_state', '')
             zipcode = parsed_data.get('address_postal_code', '')
             logging.debug(f"Constructing full address from: S1='{street1}', S2='{street2}', C='{city}', S='{state}', Z='{zipcode}'")

             city_state_parts = filter(None, [city, state])
             city_state = ", ".join(city_state_parts)
             full_city_state_zip = ' '.join(filter(None, [city_state, zipcode])).strip()

             addr_parts = filter(None, [street1, street2, full_city_state_zip])
             constructed_address = ' '.join(addr_parts).strip()
             if constructed_address:
                 parsed_data['full_address'] = constructed_address
                 logging.info(f"Successfully constructed full address: '{constructed_address}'")
             else:
                  logging.warning("Constructed full address resulted in empty string. Check if DAG/DAI/DAJ/DAK fields were parsed.")

        # Final Check
        if not field_count > 0:
            logging.error("AAMVA parsing finished, but no mapped data fields were extracted.")
            raise ValueError("Parsing failed: No standard/mapped fields extracted from data.")

        logging.info(f"Finished parsing AAMVA data. Final field count in dict: {len(parsed_data)}")
        return parsed_data


    @staticmethod
    def validate_license(parsed_data: dict) -> dict:
        """Validates license based on DOB and expiration date."""
        # [ validate_license function remains identical - omitted for brevity ]
        validation_result = {
            'is_valid': False, # Overall validity (meets age and not expired)
            'age': None,       # Calculated age
            'is_expired': None,# Boolean indicating if expired
            'meets_age_requirement': None, # Boolean for age >= MINIMUM_AGE
            'errors': []       # List of specific validation errors
        }
        today = date.today()
        MINIMUM_AGE = 21 # Define minimum age requirement

        # --- Validate Date of Birth and Calculate Age ---
        dob_value = parsed_data.get('date_of_birth')
        logging.info(f"Validating Date of Birth (DOB). Value from parser: '{dob_value}', Type: {type(dob_value)}")

        if isinstance(dob_value, date):
            dob = dob_value
            # Calculate age based on today's date
            try:
                # Basic age calculation
                age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
                validation_result['age'] = age
                logging.info(f"DOB is a valid date object ({dob}). Calculated Age: {age}")

                # Check for logical errors (e.g., future date, unreasonably old)
                if dob > today:
                    logging.error("Validation Error: Date of Birth is in the future.")
                    validation_result['errors'].append("Invalid Date of Birth (Future Date)")
                elif age < 0: # Should be caught by dob > today, but double-check
                     logging.error(f"Validation Error: Calculated age is negative ({age}). DOB: {dob}")
                     validation_result['errors'].append("Invalid Date of Birth (Resulting in negative age)")

                # Determine if age requirement is met
                validation_result['meets_age_requirement'] = (age >= MINIMUM_AGE) if age >= 0 else False

            except Exception as e: # Catch potential errors during age calculation itself
                logging.error(f"Error calculating age from DOB '{dob}': {e}", exc_info=True)
                validation_result['errors'].append("Error calculating age from Date of Birth")
                validation_result['meets_age_requirement'] = False
        else:
            # DOB is missing or wasn't parsed correctly (or was returned as string from _parse_date)
            logging.warning(f"DOB validation failed: Value '{dob_value}' is missing or not a valid date object.")
            validation_result['errors'].append("Missing or invalid Date of Birth")
            validation_result['meets_age_requirement'] = False # Cannot meet requirement without valid DOB

        # --- Validate Expiration Date ---
        expiration_value = parsed_data.get('expiration_date')
        logging.info(f"Validating Expiration Date. Value from parser: '{expiration_value}', Type: {type(expiration_value)}")

        if isinstance(expiration_value, date):
            exp_date = expiration_value
            # Check if the expiration date is strictly before today's date
            is_expired = exp_date < today
            validation_result['is_expired'] = is_expired
            logging.info(f"Expiration date is a valid date object ({exp_date}). Is expired: {is_expired}")
            if is_expired:
                 logging.warning("Validation Result: License is expired.")
                 # Optionally add to errors if expiry itself constitutes an error in your context
                 # validation_result['errors'].append("License Expired")
        else:
            # Expiration date is missing or wasn't parsed correctly
            logging.warning(f"Expiration date validation failed: Value '{expiration_value}' is missing or not a valid date object.")
            validation_result['errors'].append("Missing or invalid Expiration Date")
            validation_result['is_expired'] = True # Assume invalid/expired if date is missing/invalid for safety

        # --- Validate Issue Date (Check if it's in the future) ---
        issue_value = parsed_data.get('issue_date')
        logging.info(f"Validating Issue Date. Value from parser: '{issue_value}', Type: {type(issue_value)}")
        if isinstance(issue_value, date):
            issue_date = issue_value
            if issue_date > today:
                 logging.error("Validation Error: Issue Date is in the future.")
                 validation_result['errors'].append("Invalid Issue Date (Future Date)")
        # else: # Missing issue date might now be parsed correctly
             # logging.debug("Issue date missing or invalid format, skipping future date check.")


        # --- Determine Overall Validity ---
        # Valid if: No errors occurred AND meets age requirement AND is not expired
        validation_result['is_valid'] = (
            not validation_result['errors'] and
            validation_result.get('meets_age_requirement', False) and
            not validation_result.get('is_expired', True) # Treat None/missing as expired for safety
        )

        logging.info(f"Final Validation Result: Age={validation_result['age']}, Meets Age Req={validation_result['meets_age_requirement']}, Expired={validation_result['is_expired']}, Errors={validation_result['errors']}, Overall Valid={validation_result['is_valid']}")
        return validation_result

    @staticmethod
    def get_validation_message(validation_result):
        """Generates a user-friendly validation message based on the result."""
        # [ get_validation_message function remains identical - omitted for brevity ]
        if validation_result.get('errors'):
            # Prioritize showing specific errors if they exist
            error_summary = '; '.join(validation_result['errors'])
            logging.warning(f"Validation Message: Errors found - {error_summary}")
            if len(error_summary) > 100: error_summary = error_summary[:97] + "..."
            return f"VALIDATION ERROR: {error_summary}"

        # If no errors, check expiration status
        is_expired = validation_result.get('is_expired')
        if is_expired is True: # Explicit check for True
            logging.warning("Validation Message: License Expired.")
            return "LICENSE EXPIRED"
        elif is_expired is None: # Handle case where expiration couldn't be determined (should ideally be in errors)
            logging.warning("Validation Message: Expiration status unknown (treated as error).")
            return "EXPIRATION UNKNOWN" # Or treat as error?

        # If no errors and not expired, check age requirement
        age = validation_result.get('age')
        meets_age_req = validation_result.get('meets_age_requirement')
        MINIMUM_AGE = 21 # Ensure consistency

        if age is not None and meets_age_req is not None:
            if meets_age_req:
                # Meets age requirement and passed other checks
                logging.info(f"Validation Message: Valid and Meets Age Requirement (Age: {age}).")
                return f"VALID and {MINIMUM_AGE}+ (Age: {age})" # Dynamic age req
            else:
                # Does not meet age requirement
                logging.warning(f"Validation Message: Under Age Requirement (Age: {age}).")
                return f"UNDER {MINIMUM_AGE} (Age: {age})" # Dynamic age req
        elif age is not None: # Age known, but requirement status unknown (shouldn't happen with current logic)
             logging.warning(f"Validation Message: Age is {age}, but requirement status unknown.")
             return f"AGE: {age} (Status Unknown)"
        else: # Age is unknown (should be caught by DOB error)
             logging.error("Validation Message: Age could not be determined.")
             return "AGE UNKNOWN"

        # Fallback message if none of the above conditions matched (should be unreachable)
        logging.error("Validation Message: Validation logic reached inconclusive state.")
        return "Validation Inconclusive"

# --- Flask Routes ---
# [ Flask routes (/ , /process_scan), error handler, and main entry point remain identical - omitted for brevity ]
@app.route('/')
def home():
    """Renders the main scanner interface page."""
    try:
        debug_mode = DEBUG_MODE
        scan_reset_seconds = current_app.config.get('SCAN_RESET_SECONDS', 15)
        scan_inactivity_ms = current_app.config.get('SCAN_INACTIVITY_MS', 300)
        initial_setup_mode = is_setup_mode()
    except Exception as e:
        logging.error(f"Error reading config values in / route: {e}", exc_info=True)
        debug_mode = False
        scan_reset_seconds = 15
        scan_inactivity_ms = 300
        initial_setup_mode = False

    return render_template('index.html',
                           debug_mode=debug_mode,
                           scan_reset_seconds=scan_reset_seconds,
                           scan_inactivity_ms=scan_inactivity_ms,
                           initial_setup_mode=initial_setup_mode)


def build_setup_mode_response(message="", success=True, extra_data=None):
    """Helper to build the standard JSON response for setup mode actions."""
    try:
        ip_info = get_non_loopback_ips()
        registered_user = current_app.config.get('REGISTERED_USER', 'N/A')
        company_name = current_app.config.get('COMPANY_NAME', 'N/A')
        location = current_app.config.get('LOCATION', 'N/A')
        display_serial = current_app.config.get('DISPLAY_SERIAL', 'N/A')
        cpu_unique_id = current_app.config.get('CPU_UNIQUE_ID', 'N/A')
    except Exception as e:
        logging.error(f"Error getting system info for setup response: {e}", exc_info=True)
        ip_info = {"error": "Failed to get system info"}
        registered_user, company_name, location, display_serial, cpu_unique_id = ('Error',) * 5

    response = {
        'success': success,
        'setup_mode': True,
        'message': message,
        'ips': ip_info,
        'system_name': APP_NAME_VERSION,
        'registered_user': registered_user,
        'company_name': company_name,
        'location': location,
        'display_serial': display_serial,
        'cpu_unique_id': cpu_unique_id,
        'log_file_path': log_file_path
    }
    if extra_data:
        response.update(extra_data)

    logging.debug(f"Sending setup mode response: Success={success}, Message='{message}'")
    return jsonify(response)

@app.route('/process_scan', methods=['POST'])
def process_scan():
    """Handles incoming scan data, parses, validates, and returns results."""
    response_data = {}
    try:
        req_json = request.json
        if not req_json or 'scan_data' not in req_json:
            logging.warning(f"Invalid request to /process_scan: Missing or invalid JSON body. Data: {request.data}")
            return jsonify({'success': False, 'setup_mode': is_setup_mode(), 'error': 'Invalid JSON request'}), 400

        scan_str = req_json.get('scan_data', '').strip()
        logging.info(f"Received scan data (length {len(scan_str)}): '{scan_str[:50]}...'")

        # --- Setup Mode Command Handling ---
        setup_enter_pattern = re.compile(r'^\s*\$\$\s*setup\s*\$\$\s*$', re.IGNORECASE)
        setup_exit_pattern = re.compile(r'^\s*\$\$\s*exit\s*\$\$\s*$', re.IGNORECASE)
        setup_serial_pattern = re.compile(r'^\s*\$\$\s*serialnumber\s*\$\$\s*(\{.*\})\s*$', re.IGNORECASE | re.DOTALL)
        setup_wifi_pattern = re.compile(r'^\s*\$\$\s*wifi\s*\$\$\s*(\{.*\})\s*$', re.IGNORECASE | re.DOTALL)
        setup_ping_pattern = re.compile(r'^\s*\$\$\s*ping\s*\$\$\s*(\{.*\})\s*$', re.IGNORECASE | re.DOTALL)  
        setup_register_pattern = re.compile(r'^\s*\$\$\s*register\s*\$\$\s*(\{.*\})\s*$', re.IGNORECASE | re.DOTALL)
        setup_restart_pattern = re.compile(r'^\s*\$\$\s*restartapp\s*\$\$\s*$', re.IGNORECASE)
        generic_setup_pattern = re.compile(r'^\s*\$\$.*\$\$')

        # --- Enter Setup Mode ---
        if setup_enter_pattern.match(scan_str):
            logging.info("Setup command received: ENTER setup mode.")
            if enter_setup_mode():
                return build_setup_mode_response(message='Entered Setup Mode')
            else:
                return build_setup_mode_response(message='ERROR: Failed to enter setup mode', success=False)

        # --- Handle Commands *While In* Setup Mode ---
        if is_setup_mode():
            logging.debug("Processing command while in Setup Mode.")
            # Exit Setup Mode
            if setup_exit_pattern.match(scan_str):
                logging.info("Setup command received: EXIT setup mode.")
                exit_setup_mode()
                return jsonify({'success': True, 'setup_mode': False, 'message': 'Exited Setup Mode'})
            # Update Serial Number
            serial_match = setup_serial_pattern.match(scan_str)
            if serial_match:
                logging.info("Setup command received: UPDATE serial number.")
                try:
                    json_str = serial_match.group(1).strip()
                    config = json.loads(json_str)
                    suffix = config['serial']
                    success, result = update_serial_number_command(suffix)
                    msg = f"Serial number updated to: {result}" if success else f"Serial update failed: {result}"
                    return build_setup_mode_response(message=msg, success=success)
                except (json.JSONDecodeError, KeyError, TypeError) as e:
                    logging.error(f"Invalid serial command JSON payload: {e}. Payload: '{serial_match.group(1)}'")
                    return build_setup_mode_response(message=f'Invalid serial command format. Error: {e}', success=False)
                except Exception as e:
                    logging.error(f"Unexpected error during serial update: {e}", exc_info=True)
                    return build_setup_mode_response(message=f'Internal error during serial update: {e}', success=False)
            # Configure WiFi
            wifi_match = setup_wifi_pattern.match(scan_str)
            if wifi_match:
                logging.info("Setup command received: CONFIGURE WiFi.")
                wifi_result = handle_wifi_command(scan_str)
                return build_setup_mode_response(
                    message=wifi_result.get('message', 'WiFi command processed.'),
                    success=wifi_result.get('success', False)
                )
            # Ping Connectivity Test
            ping_match = setup_ping_pattern.match(scan_str)
            if ping_match:
                logging.info("Setup command received: PING connectivity test.")
                ping_result = handle_ping_command(scan_str)
                return build_setup_mode_response(
                    message=ping_result.get('message', 'Ping command processed.'),
                    success=ping_result.get('success', False),
                    extra_data={
                        'ping_target': ping_result.get('target'),
                        'ping_count': ping_result.get('count'),
                        'ping_timeout_ms': ping_result.get('timeout_ms'),
                        'ping_output': ping_result.get('ping_output', [])
                    }
                )
            # Device Registration
            register_match = setup_register_pattern.match(scan_str)
            if register_match:
                logging.info("Setup command received: DEVICE registration.")
                register_result = handle_register_command(scan_str)
                return build_setup_mode_response(
                    message=register_result.get('message', 'Register command processed.'),
                    success=register_result.get('success', False),
                    extra_data={
                        'device_id': register_result.get('device_id'),
                        'location_id': register_result.get('location_id'),
                        'bootstrapping_key_id': register_result.get('bootstrapping_key_id'),
                        'api_endpoint': register_result.get('api_endpoint')
                    }
                )
            # Restart Application
            if setup_restart_pattern.match(scan_str):
                logging.info("Setup command received: RESTART application.")
                response = build_setup_mode_response(message='Restarting application...', extra_data={'needs_reload': True})
                from threading import Timer
                Timer(1.0, restart_application).start()
                return response
            # Unrecognized Setup Command or Normal Data Scanned in Setup Mode
            if generic_setup_pattern.match(scan_str):
                logging.warning(f"Unrecognized setup command received: {scan_str[:50]}...")
                return build_setup_mode_response(message=f'Unrecognized setup command: {scan_str[:50]}...')
            else:
                logging.info(f"Non-command data received while in setup mode, ignoring: {scan_str[:50]}...")
                return build_setup_mode_response(message=f'Setup Mode Active. Scan data ignored: {scan_str[:50]}...')

        # --- Normal Scan Processing (Not in Setup Mode) ---
        else:
            logging.debug("Processing scan in Normal Mode.")
            if generic_setup_pattern.match(scan_str):
                logging.warning(f"Setup command '{scan_str[:50]}...' scanned outside setup mode. Ignored.")
                return jsonify({'success': False, 'setup_mode': False, 'error': "Command ignored. Not in setup mode."}), 400

            if not scan_str:
                logging.warning("Received empty scan data in normal mode.")
                return jsonify({'success': False, 'setup_mode': False, 'error': 'Empty scan data received.'}), 400

            # --- Attempt AAMVA Parsing and Validation ---
            try:
                logging.info("-> Entering Normal Scan Processing: Parsing AAMVA data...")
                parsed_data = LicenseParser.parse_aamva(scan_str)
                logging.info("-> AAMVA Parsing Attempted. Validating license...")
                validation = LicenseParser.validate_license(parsed_data)
                logging.info("-> License Validation Attempted.")

                logging.debug("--- Preparing Response Data ---")
                # Use the constructed 'full_name' and 'full_address' fields
                name_to_send = parsed_data.get('full_name', 'N/A')
                if name_to_send == 'N/A': logging.warning("Full name is 'N/A' after parsing.")
                logging.debug(f"Name to Send: '{name_to_send}'")

                address_to_send = parsed_data.get('full_address', 'N/A')
                if address_to_send == 'N/A': logging.warning("Full address is 'N/A' after parsing.")
                logging.debug(f"Address to Send: '{address_to_send}'")

                dob_obj = parsed_data.get('date_of_birth')
                dob_display = dob_obj.strftime('%B %d, %Y') if isinstance(dob_obj, date) else str(dob_obj or 'N/A')
                logging.debug(f"DOB Object: {dob_obj} ({type(dob_obj)}), Display: {dob_display}")

                issue_obj = parsed_data.get('issue_date')
                issue_display = issue_obj.strftime('%B %d, %Y') if isinstance(issue_obj, date) else str(issue_obj or 'N/A')
                logging.debug(f"Issue Date Object: {issue_obj} ({type(issue_obj)}), Display: {issue_display}")

                exp_obj = parsed_data.get('expiration_date')
                exp_display = exp_obj.strftime('%B %d, %Y') if isinstance(exp_obj, date) else str(exp_obj or 'N/A')
                logging.debug(f"Expiration Date Object: {exp_obj} ({type(exp_obj)}), Display: {exp_display}")

                validation_msg = LicenseParser.get_validation_message(validation)
                logging.debug(f"Validation Message: {validation_msg}")

                # Handle underage alerts and beeps
                alert_id = None
                if not validation.get('meets_age_requirement', False) and validation.get('age') is not None:
                    # Underage person detected
                    age = validation.get('age')
                    name = name_to_send or 'Unknown'
                    alert_message = f"Underage person detected: {name}, Age: {age}"
                    alert_id = create_alert(alert_message, "underage")
                    
                    # Play beep for underage detection
                    beep_success = play_beep()
                    logging.warning(f"Underage scan detected: {name}, Age: {age}, Beep: {'Success' if beep_success else 'Failed'}")
                
                # Clean up old acknowledged alerts
                clear_acknowledged_alerts()

                # AWS Integration - Log scan result
                if AWS_INTEGRATION_AVAILABLE:
                    try:
                        aws_client = get_aws_client()
                        if aws_client and aws_client.is_registered():
                            aws_client.log_scan_result(parsed_data, validation)
                            logging.debug("Scan result logged to AWS backend")
                    except Exception as e:
                        logging.error(f"AWS integration error: {e}")

                response_data = {
                    'success': True,
                    'setup_mode': False,
                    'name': name_to_send,
                    'address': address_to_send,
                    'dob': dob_display,
                    'issue_date': issue_display,
                    'expiration': exp_display,
                    'age': validation.get('age'),
                    'is_valid': validation.get('is_valid', False),
                    'is_expired': validation.get('is_expired'),
                    'validation_message': validation_msg,
                    'alert_id': alert_id,  # Include alert ID if underage
                    'active_alerts': get_active_alerts(),  # Include all active alerts
                    'raw_data': None  # Never send raw scan data to client for security
                }
                logging.info(f"Normal Scan Result: {response_data.get('validation_message')}")
                
                # Log redacted response data for security
                redacted_response = {
                    'success': response_data['success'],
                    'setup_mode': response_data['setup_mode'],
                    'is_valid': response_data['is_valid'],
                    'is_expired': response_data['is_expired'],
                    'validation_message': response_data['validation_message'],
                    'age': response_data.get('age'),
                    'name': '[REDACTED]' if response_data.get('name') else None,
                    'address': '[REDACTED]' if response_data.get('address') else None,
                    'dob': '[REDACTED]' if response_data.get('dob') else None,
                    'raw_data': '[REDACTED]' if response_data.get('raw_data') else None
                }
                logging.debug(f"Sending scan response (personal data redacted): {json.dumps(redacted_response)}")
                return jsonify(response_data)

            except ValueError as ve:
                logging.warning(f"License processing failed (ValueError): {ve}")
                # Provide specific error message to frontend
                return jsonify({'success': False, 'setup_mode': False, 'error': f'Processing Error: {str(ve)}'}), 400
            except Exception as ex:
                logging.error(f"Unexpected error during normal scan processing: {ex}", exc_info=True)
                return jsonify({'success': False, 'setup_mode': False, 'error': 'Internal Server Error during scan processing.'}), 500

    except Exception as e:
        logging.exception(f"Unhandled exception in /process_scan route: {e}")
        current_setup_status = is_setup_mode()
        response_data = {
            'success': False,
            'error': 'Internal Server Error.',
            'setup_mode': current_setup_status
        }
        return jsonify(response_data), 500


# --- Alert Management Routes ---
@app.route('/api/alerts', methods=['GET'])
def get_alerts_api():
    """Returns all active alerts."""
    try:
        clear_acknowledged_alerts()  # Clean up old alerts
        alerts = get_active_alerts()
        return jsonify({
            'success': True,
            'alerts': alerts,
            'count': len(alerts)
        })
    except Exception as e:
        logging.error(f"Error getting alerts: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'Failed to retrieve alerts'}), 500

@app.route('/api/alerts/acknowledge', methods=['POST'])
def acknowledge_alert_api():
    """Acknowledges an alert by ID or QR code command."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        # Handle QR code format: $$ack$$alert_id
        if 'scan_str' in data:
            scan_str = data['scan_str'].strip()
            # Check if it's an acknowledgment QR code
            ack_pattern = re.match(r'^\s*\$\$\s*ack\s*\$\$\s*(\w+)', scan_str, re.IGNORECASE)
            if ack_pattern:
                alert_id = ack_pattern.group(1).strip()
            else:
                return jsonify({'success': False, 'error': 'Invalid acknowledgment QR code format'}), 400
        elif 'alert_id' in data:
            alert_id = data['alert_id'].strip()
        else:
            return jsonify({'success': False, 'error': 'Missing alert_id or scan_str'}), 400
        
        # Validate alert ID format (alphanumeric, max 8 chars)
        if not re.match(r'^[a-zA-Z0-9]{1,8}$', alert_id):
            return jsonify({'success': False, 'error': 'Invalid alert ID format'}), 400
        
        success = acknowledge_alert(alert_id)
        if success:
            return jsonify({
                'success': True,
                'message': f'Alert {alert_id} acknowledged',
                'active_alerts': get_active_alerts()
            })
        else:
            return jsonify({'success': False, 'error': f'Alert {alert_id} not found or already acknowledged'}), 404
            
    except Exception as e:
        logging.error(f"Error acknowledging alert: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'Failed to acknowledge alert'}), 500

@app.route('/api/alerts/clear', methods=['POST'])
def clear_alerts_api():
    """Clears all acknowledged alerts."""
    try:
        clear_acknowledged_alerts()
        return jsonify({
            'success': True,
            'message': 'Acknowledged alerts cleared',
            'active_alerts': get_active_alerts()
        })
    except Exception as e:
        logging.error(f"Error clearing alerts: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'Failed to clear alerts'}), 500


# --- AWS Integration Routes ---
@app.route('/api/aws/status', methods=['GET'])
def aws_status():
    """Get AWS integration status."""
    try:
        if not AWS_INTEGRATION_AVAILABLE:
            return jsonify({
                'aws_integration': False,
                'error': 'AWS integration module not available'
            })
        
        aws_client = get_aws_client()
        if aws_client:
            status = aws_client.get_status()
            return jsonify({
                'aws_integration': True,
                'status': status
            })
        else:
            return jsonify({
                'aws_integration': False,
                'error': 'AWS client not initialized'
            })
    except Exception as e:
        logging.error(f"Error getting AWS status: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'Failed to get AWS status'}), 500

@app.route('/api/aws/register', methods=['POST'])
def aws_register():
    """Register device with AWS backend."""
    try:
        if not AWS_INTEGRATION_AVAILABLE:
            return jsonify({'success': False, 'error': 'AWS integration not available'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        setup_token = data.get('setup_token')
        location_id = data.get('location_id')
        
        if not setup_token or not location_id:
            return jsonify({'success': False, 'error': 'setup_token and location_id required'}), 400
        
        aws_client = get_aws_client()
        success = aws_client.register_device(setup_token, location_id)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Device registered successfully',
                'status': aws_client.get_status()
            })
        else:
            return jsonify({'success': False, 'error': 'Registration failed'}), 500
            
    except Exception as e:
        logging.error(f"Error registering device: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'Failed to register device'}), 500

@app.route('/api/aws/force-batch', methods=['POST'])
def force_batch_send():
    """Force send current batch to AWS."""
    try:
        if not AWS_INTEGRATION_AVAILABLE:
            return jsonify({'success': False, 'error': 'AWS integration not available'}), 400
        
        aws_client = get_aws_client()
        if aws_client and aws_client.is_registered():
            aws_client.force_batch_send()
            return jsonify({'success': True, 'message': 'Batch sent successfully'})
        else:
            return jsonify({'success': False, 'error': 'Device not registered'}), 400
            
    except Exception as e:
        logging.error(f"Error forcing batch send: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'Failed to send batch'}), 500


# --- Error Handler ---
@app.errorhandler(Exception)
def handle_exception(e):
    """Handles uncaught exceptions gracefully."""
    # [ Error handler remains identical - omitted for brevity ]
    logging.exception(f"Unhandled application exception caught by error handler: {e}")
    current_setup_status = is_setup_mode()
    response = {
        "success": False,
        "error": "An internal server error occurred.",
        "setup_mode": current_setup_status
    }
    status_code = 500
    if isinstance(e, werkzeug.exceptions.HTTPException):
        status_code = e.code or 500
        response["error"] = getattr(e, 'description', str(e))
    elif isinstance(e, (ValueError, TypeError)):
         response["error"] = f"Request processing error: {e}"
         status_code = 400
         logging.warning(f"Mapping {type(e).__name__} to 400 Bad Request: {e}")

    return jsonify(response), status_code


# --- Main Entry Point ---
if __name__ == '__main__':
    try:
        # [ Main entry point remains identical - omitted for brevity ]
        logging.info(f"--- Starting {APP_NAME_VERSION} ---")
        load_initial_environment_vars(app)

        logging.info(f"Flask Debug mode: {DEBUG_MODE}")
        logging.info(f"Log Level: {logging.getLevelName(LOG_LEVEL)}")
        logging.info(f"Log File Path: {log_file_path}")
        logging.info(f"Setup Mode Active at Startup: {is_setup_mode()}")

        host = '127.0.0.1'
        port = 5000
        logging.info(f"Attempting Flask development server on http://{host}:{port}")
        logging.warning("NOTE: Using Flask development server. Use Gunicorn/systemd service for production deployment.")

        app.run(host=host, port=port, debug=DEBUG_MODE, threaded=True)

    except Exception as e:
        import traceback
        error_msg = f"FATAL STARTUP ERROR: {e} {traceback.format_exc()}"
        print(error_msg, file=sys.stderr)
        try:
            logging.critical(error_msg)
        except Exception as log_e:
            print(f"Logging critical startup error also failed: {log_e}", file=sys.stderr)
        sys.exit(1)
