#!/usr/bin/env python3
# scanner_app.py

import os
import json
import re
import logging
import time
from datetime import datetime, date
from logging.handlers import RotatingFileHandler
from flask import Flask, request, jsonify, render_template

# ------------------------------------------------------------------------------
# 1. Load Config File from Environment Variable
# ------------------------------------------------------------------------------
DEFAULT_CONFIG_PATH = 'app_config.json'
config_path = os.environ.get('APP_CONFIG_PATH', DEFAULT_CONFIG_PATH)

CONFIG = {}
if os.path.exists(config_path):
    try:
        with open(config_path, 'r') as f:
            CONFIG = json.load(f)
        print(f"Loaded config from {config_path}: {CONFIG}")
    except Exception as e:
        print(f"Warning: could not load config file {config_path}: {e}")
else:
    print("No config file found; using defaults.")

SCANNER_MODEL = str(CONFIG.get('scanner_model', '')).strip().upper()  # e.g. "NT-1228BL"
SCAN_TIMEOUT_SECS = float(CONFIG.get('scan_timeout_secs', 5.0))

# ------------------------------------------------------------------------------
# 2. Flask App & Logging Configuration
# ------------------------------------------------------------------------------
app = Flask(__name__)

LOG_DIR = 'logs'
LOG_FILENAME = 'scanner.log'
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    handlers=[
        RotatingFileHandler(os.path.join(LOG_DIR, LOG_FILENAME), maxBytes=100_000, backupCount=5),
        logging.StreamHandler()
    ],
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s [%(filename)s:%(lineno)d]: %(message)s'
)

# ------------------------------------------------------------------------------
# 3. Memory Store for Partial Scans
# ------------------------------------------------------------------------------
SCAN_SESSIONS = {}
END_MARKER = "ZTZTANZTBNZTCZTDNZTE1ZTFNZTG00"

# For "NT-1228BL" mode, we’ll assume these AAMVA fields must exist before we finalize.
# Adjust as needed for your environment.
_MANDATORY_FIELDS = ['DCS', 'DAC', 'DBB', 'DBA']  # Example: last_name, first_name, dob, expiration

# ------------------------------------------------------------------------------
# 4. LicenseParser (AAMVA)
# ------------------------------------------------------------------------------
class LicenseParser:
    VALID_AAMVA_CODES = [
        'DCA','DCB','DCD','DBA','DCS','DAC','DAD','DBB','DBC','DBD','DAU','DAY','DAG','DAH','DAI',
        'DAJ','DAK','DAQ','DCF','DCG','DDE','DDF','DDG'
    ]

    AAMVA_FIELD_MAP = {
        'DCS': 'last_name',
        'DAC': 'first_name',
        'DAD': 'middle_name',
        'DBB': 'dob',
        'DBA': 'expiration',
        'DBD': 'issue_date',
        'DAG': 'address',
        'DAH': 'address_2',
        'DAI': 'city',
        'DAJ': 'state',
        'DAK': 'postal_code',
        'DAQ': 'license_number',
        'DDE': 'family_name_truncation',
        'DDF': 'first_name_truncation',
        'DDG': 'middle_name_truncation',
    }

    @staticmethod
    def parse_aamva(data: str) -> dict:
        """Parse the raw data into fields, including partial error tracking."""
        if not (data.startswith('@ANSI ') or data.startswith('@')):
            raise ValueError("Invalid AAMVA format: Missing '@ANSI ' or '@' prefix.")

        valid_code_pattern = '|'.join(LicenseParser.VALID_AAMVA_CODES)
        pattern = rf'(?P<code>(?:{valid_code_pattern}))(?P<value>.*?)(?=(?:{valid_code_pattern})|$)'
        matches = list(re.finditer(pattern, data, flags=re.DOTALL))

        parsed_fields = {}
        parse_errors = []  # Collect parse issues here

        for match in matches:
            code = match.group('code')
            value = match.group('value').strip()
            if code in LicenseParser.AAMVA_FIELD_MAP:
                friendly_key = LicenseParser.AAMVA_FIELD_MAP[code]
                parsed_fields[friendly_key] = value

        # Convert known date fields from MMDDYYYY -> date objects
        for date_key in ['dob', 'expiration', 'issue_date']:
            raw_val = parsed_fields.get(date_key)
            if raw_val and re.match(r'^\d{8}$', raw_val):
                try:
                    parsed_val = datetime.strptime(raw_val, '%m%d%Y').date()
                    parsed_fields[date_key] = parsed_val
                except ValueError:
                    msg = f"Could not parse {date_key} from '{raw_val}'"
                    logging.warning(msg)
                    parse_errors.append(msg)
            elif raw_val:
                # It's some unexpected format, keep as string but note the error
                msg = f"Unexpected format for {date_key}: '{raw_val}'"
                logging.warning(msg)
                parse_errors.append(msg)

        # Attach parse errors if any
        if parse_errors:
            parsed_fields['_parse_errors'] = parse_errors

        return parsed_fields

    @staticmethod
    def validate_license(parsed_data: dict) -> dict:
        today = date.today()

        dob = parsed_data.get('dob')
        if isinstance(dob, date):
            age = (today - dob).days // 365
        else:
            age = 0

        exp = parsed_data.get('expiration')
        if isinstance(exp, date):
            is_expired = (exp < today)
        else:
            is_expired = True  # If no valid expiration, treat as expired

        return {
            'is_valid': (age >= 21) and not is_expired,
            'age': age,
            'is_expired': is_expired
        }

# ------------------------------------------------------------------------------
# 5. Flask Routes
# ------------------------------------------------------------------------------
@app.route('/')
def home():
    """Render the main page (index.html)."""
    return render_template('index.html', current_date=datetime.now().strftime('%B %d, %Y'))

@app.route('/process_scan', methods=['POST'])
def process_scan():
    """
    Receives scanning data from the client. Behavior depends on SCANNER_MODEL:
      - If SCANNER_MODEL != "NT-1228BL", we wait for an END_MARKER.
      - If SCANNER_MODEL == "NT-1228BL", we finalize once mandatory fields are found.
    """
    req_json = request.json or {}
    session_id = req_json.get("session_id", "default")
    chunk = req_json.get("scan_data", "")

    logging.info(f"Received scan data for session '{session_id}': {repr(chunk)}")

    # If session doesn't exist, create it
    if session_id not in SCAN_SESSIONS:
        SCAN_SESSIONS[session_id] = {"data": "", "last_update": time.time()}

    # Accumulate the new chunk
    SCAN_SESSIONS[session_id]["data"] += chunk
    SCAN_SESSIONS[session_id]["last_update"] = time.time()

    # --- Normal (non-NT-1228BL) Logic ---
    if SCANNER_MODEL != "NT-1228BL":
        if END_MARKER in SCAN_SESSIONS[session_id]["data"]:
            logging.debug(f"End marker detected for session '{session_id}'.")
            full_data = SCAN_SESSIONS[session_id]["data"]
            full_data = full_data.replace(END_MARKER, "").strip()
            return finish_scan(session_id, full_data)

        return jsonify({
            "success": True,
            "complete": False,
            "message": "Chunk received; waiting for end marker or more data."
        })

    # --- NT-1228BL Logic ---
    # We'll parse on-the-fly to see if mandatory fields are present
    current_data = SCAN_SESSIONS[session_id]["data"]
    # Quick parse attempt to see which raw AAMVA codes appear
    found_codes = re.findall('|'.join(LicenseParser.VALID_AAMVA_CODES), current_data)
    unique_codes = set(found_codes)  # deduplicate

    # If we've seen all mandatory codes, let's finalize
    all_mandatory_present = all(code in unique_codes for code in _MANDATORY_FIELDS)

    if all_mandatory_present:
        logging.debug(f"NT-1228BL: All mandatory codes found for session {session_id}, finalizing.")
        return finish_scan(session_id, current_data.strip())

    # Otherwise, partial success
    return jsonify({
        "success": True,
        "complete": False,
        "message": "NT-1228BL partial data received; mandatory fields not all present yet."
    })

@app.route('/check_stale', methods=['GET', 'POST'])
def check_stale():
    """
    Optional route to remove stale sessions after SCAN_TIMEOUT_SECS.
    You can call this periodically or rely on some external job.
    """
    now = time.time()
    removed_sessions = []

    for sid, info in list(SCAN_SESSIONS.items()):
        if (now - info["last_update"]) > SCAN_TIMEOUT_SECS:
            del SCAN_SESSIONS[sid]
            removed_sessions.append(sid)
            logging.warning(f"Removed stale session '{sid}' due to timeout.")

    return jsonify({"success": True, "removed_sessions": removed_sessions})

# ------------------------------------------------------------------------------
# 6. Finalizing the Scan
# ------------------------------------------------------------------------------
def finish_scan(session_id, raw_data):
    """
    Once we decide a scan is complete, parse & validate, then respond.
    """
    if session_id in SCAN_SESSIONS:
        del SCAN_SESSIONS[session_id]

    # Normalize line breaks, tabs, etc.
    data = (raw_data
            .replace('\r\n', '\n')
            .replace('\r', '\n')
            .replace('\t', '\n')
            .strip())

    # Ensure it starts with '@ANSI ' or '@'
    if not (data.startswith('@ANSI ') or data.startswith('@')):
        logging.warning("Data missing '@ANSI ' or '@' prefix. Attempting to fix.")
        if len(data) > 50:
            data = '@ANSI ' + data
        else:
            logging.error("Scan data too short for reconstruction; invalid.")
            return jsonify({"success": False, "error": "Invalid scan data."}), 400

    try:
        parsed_data = LicenseParser.parse_aamva(data)
        logging.debug(f"Parsed data (session {session_id}): {parsed_data}")

        # Validate license
        validation_result = LicenseParser.validate_license(parsed_data)
        logging.debug(f"Validation (session {session_id}): {validation_result}")

        # If state not found, set to UNKNOWN
        if not parsed_data.get('state'):
            parsed_data['state'] = 'UNKNOWN'

        response_data = prepare_response_data(parsed_data, validation_result)
        logging.info(f"Finished scan session {session_id} -> {response_data}")

        return jsonify({"success": True, **response_data})

    except Exception as e:
        logging.exception(f"Error while finalizing session {session_id}")
        return jsonify({"success": False, "error": str(e)}), 500

def prepare_response_data(parsed_data, validation_result):
    """
    Build the final JSON structure to return, including any parse errors.
    """
    first_name = parsed_data.get('first_name', '')
    middle_name = parsed_data.get('middle_name', '')
    last_name = parsed_data.get('last_name', '')

    addr1 = parsed_data.get('address', '')
    addr2 = parsed_data.get('address_2', '')
    city = parsed_data.get('city', '')
    state = parsed_data.get('state', 'UNKNOWN')
    postal_code = parsed_data.get('postal_code', '')

    full_address = f"{addr1} {addr2}".strip()

    def fmt_date(d):
        if isinstance(d, date):
            return d.strftime('%B %d, %Y')
        return str(d)

    dob_str = fmt_date(parsed_data.get('dob'))
    exp_str = fmt_date(parsed_data.get('expiration'))
    iss_str = fmt_date(parsed_data.get('issue_date'))

    # Build final object
    out = {
        'name': f"{first_name} {middle_name} {last_name}".strip(),
        'address': f"{full_address}, {city}, {state} {postal_code}".strip().rstrip(','),
        'dob': dob_str,
        'expiration': exp_str,
        'issue_date': iss_str,
        'is_valid': validation_result['is_valid'],
        'validation_message': get_validation_message(validation_result)
    }

    # If parse errors exist, include them
    if '_parse_errors' in parsed_data:
        out['parse_errors'] = parsed_data['_parse_errors']

    return out

def get_validation_message(validation_result):
    if validation_result['is_expired']:
        return "LICENSE EXPIRED"
    elif validation_result['age'] < 21:
        return "UNDER 21"
    return "VALID"

# ------------------------------------------------------------------------------
# 7. Run the Flask App
# ------------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)

