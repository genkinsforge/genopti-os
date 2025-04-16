#!/usr/bin/env python3
# app.py - Corrected AAMVA Field Splitting Logic (v0.48 - Known Code Delimiter + Trailer Truncation)

# --- Imports ---
from flask import Flask, render_template, request, jsonify, current_app
from datetime import datetime, date
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
def parse_wifi_config(config_string):
    """Parses the $$wifi$${...} command string."""
    try:
        # Regex to capture the JSON part after $$wifi$$
        wifi_pattern = re.compile(r'^\s*\$\$\s*wifi\s*\$\$\s*(.*)', re.IGNORECASE | re.DOTALL)
        match = wifi_pattern.search(config_string)
        if not match:
            raise ValueError("Invalid format: must start with $$wifi$$")

        json_str = match.group(1).strip()
        if not json_str:
            raise ValueError("Missing JSON payload after $$wifi$$")

        # Parse the JSON
        try:
            config = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON payload: {e}")

        # Validate essential fields
        if 'ssid' not in config or not config['ssid']:
            raise ValueError("Missing or empty 'ssid' field in JSON payload")

        # Ensure password is treated as optional (default to empty string for open networks)
        if 'password' not in config:
            config['password'] = ''

        # Basic sanitization (remove potential non-printable characters, allow common whitespace)
        for key in config:
            if isinstance(config[key], str):
                config[key] = ''.join(c for c in config[key] if 32 <= ord(c) <= 126 or c in '')

        logging.debug(f"Parsed WiFi config: SSID='{config.get('ssid')}', Password provided: {'yes' if config.get('password') else 'no'}")
        return config

    except Exception as e:
        logging.error(f"Error parsing WiFi config string '{config_string[:50]}...': {e}", exc_info=True)
        raise # Re-raise the specific exception (ValueError or other)


def configure_wifi_with_nmcli(ssid, password):
    """Attempts to connect to WiFi using nmcli."""
    nmcli_path = shutil.which("nmcli")
    if not nmcli_path:
        logging.error("`nmcli` command not found in PATH. Cannot configure WiFi.")
        return False, "`nmcli` command not found."

    # Base command
    nmcli_cmd = [nmcli_path, 'device', 'wifi', 'connect', ssid]
    # Add password if provided
    if password:
        nmcli_cmd.extend(['password', password])

    # Security: Avoid logging the full command with password if possible,
    # but log that we are attempting connection.
    logging.info(f"Executing nmcli to connect to SSID: '{ssid}' (Password: {'Provided' if password else 'Not Provided'})")

    try:
        # Execute the command with timeout
        result = subprocess.run(nmcli_cmd, capture_output=True, text=True, check=True, timeout=60) # 60s timeout

        # Log output (be careful with sensitive info if any slips through stderr/stdout)
        logging.info("nmcli stdout: " + result.stdout.strip())
        logging.info("nmcli stderr: " + result.stderr.strip())

        # Check common success indicators
        if "successfully activated" in result.stdout or "Connection successfully activated" in result.stdout:
            logging.info(f"nmcli reported success connecting to SSID: {ssid}")
            return True, f"Successfully connected to SSID: {ssid}"
        else:
            # Command succeeded (exit code 0) but might not have connected as expected
            logging.warning(f"nmcli command succeeded for SSID '{ssid}', but activation message not found. Check status manually.")
            # Return success=True but provide the output for user context
            return True, f"nmcli command completed. Status uncertain. Output: {result.stdout.strip()}"

    except subprocess.CalledProcessError as e:
        # nmcli command failed (non-zero exit code)
        stderr_output = e.stderr.strip() if e.stderr else ""
        stdout_output = e.stdout.strip() if e.stdout else ""
        logging.error(f"nmcli command failed with exit code {e.returncode} for SSID '{ssid}'")
        logging.error("nmcli stderr: " + stderr_output)
        logging.error("nmcli stdout: " + stdout_output)

        # Provide more specific error messages based on output
        error_message = stderr_output or stdout_output or "nmcli command failed." # Default message
        if "Secrets were required" in error_message or "Invalid password" in error_message or "802.1X supplicant failed" in error_message:
             msg = f"Authentication failed for '{ssid}'. Check password or security settings."
        elif "Could not find network" in error_message or "No network with SSID" in error_message:
             msg = f"Network '{ssid}' not found. Check SSID or scan again."
        elif "Connection activation failed" in error_message:
             # Generic activation failure, provide details if possible
             details = error_message.split(':')[-1].strip() # Get reason after last colon
             msg = f"Failed to activate connection to '{ssid}'. Reason: {details}"
        else:
             # General failure message (take first line)
             msg = f"Failed to connect to '{ssid}'. Detail: {error_message.splitlines()[0].strip() if error_message else 'Unknown nmcli error'}"

        return False, msg

    except subprocess.TimeoutExpired:
        logging.error(f"nmcli command timed out after 60 seconds for SSID '{ssid}'.")
        return False, f"Connection attempt to '{ssid}' timed out."

    except Exception as e:
        # Catch any other unexpected errors during subprocess execution
        logging.error(f"Unexpected error executing nmcli for SSID '{ssid}': {e}", exc_info=True)
        return False, f"An unexpected error occurred: {e}"


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
    def parse_aamva(data: str) -> dict:
        """Parses an AAMVA PDF417 barcode string based on finding consecutive KNOWN field codes, with trailer truncation."""
        parsed_data = {}
        data_start_index = -1

        # Ensure data is a string
        if not isinstance(data, str):
            logging.error(f"Invalid input type for parse_aamva: expected string, got {type(data)}")
            raise ValueError("Invalid input data type.")

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


            # Clean the potentially truncated value
            cleaned_value = final_value.strip()
            logging.debug(f"Field: {field_code}, Final Cleaned Value: '{cleaned_value}'")

            # Map field code to meaningful name
            field_name = LicenseParser.AAMVA_FIELD_MAP[field_code]
            parsed_value = LicenseParser._parse_date(field_code, cleaned_value) if field_code in LicenseParser.DATE_FIELDS else cleaned_value

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
                    'raw_data': scan_str if DEBUG_MODE else None
                }
                logging.info(f"Normal Scan Result: {response_data.get('validation_message')}")
                logging.debug(f"Sending JSON response: {json.dumps(response_data)}")
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
