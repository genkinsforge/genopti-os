#!/usr/bin/env python3
# scanner_app.py

from flask import Flask, request, jsonify, render_template
from datetime import datetime, date
import re
import logging
from logging.handlers import RotatingFileHandler
import os
import time

app = Flask(__name__)

# ------------------------------------------------------------------------------
# 1. Logging Configuration
# ------------------------------------------------------------------------------
LOG_DIR = 'logs'
LOG_FILENAME = 'scanner.log'
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logging.basicConfig(
    handlers=[
        RotatingFileHandler(os.path.join(LOG_DIR, LOG_FILENAME), maxBytes=100000, backupCount=5),
        logging.StreamHandler()
    ],
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s [%(filename)s:%(lineno)d]: %(message)s'
)

# ------------------------------------------------------------------------------
# 2. Memory Store for Partial Scans
# ------------------------------------------------------------------------------
SCAN_SESSIONS = {}
SCAN_TIMEOUT_SECS = 5.0
END_MARKER = "ZTZTANZTBNZTCZTDNZTE1ZTFNZTG00"

# ------------------------------------------------------------------------------
# 3. LicenseParser (AAMVA)
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
        if not (data.startswith('@ANSI ') or data.startswith('@')):
            raise ValueError("Invalid AAMVA format: Missing '@ANSI ' or '@' prefix.")

        valid_code_pattern = '|'.join(LicenseParser.VALID_AAMVA_CODES)
        pattern = rf'(?P<code>(?:{valid_code_pattern}))(?P<value>.*?)(?=(?:{valid_code_pattern})|$)'
        matches = list(re.finditer(pattern, data, flags=re.DOTALL))

        parsed_fields = {}
        for match in matches:
            code = match.group('code')
            value = match.group('value').strip()
            if code in LicenseParser.AAMVA_FIELD_MAP:
                friendly_key = LicenseParser.AAMVA_FIELD_MAP[code]
                parsed_fields[friendly_key] = value

        # Convert known date fields from MMDDYYYY to date objects
        for date_key in ['dob', 'expiration', 'issue_date']:
            raw_val = parsed_fields.get(date_key)
            if raw_val and re.match(r'^\d{8}$', raw_val):
                try:
                    parsed_val = datetime.strptime(raw_val, '%m%d%Y').date()
                    parsed_fields[date_key] = parsed_val
                except ValueError:
                    logging.warning(f"Could not parse date field '{date_key}': {raw_val}")
            elif raw_val:
                # It's some unexpected format, keep as string
                logging.warning(f"Unexpected date format for '{date_key}': {raw_val}")
        return parsed_fields

    @staticmethod
    def validate_license(parsed_data: dict) -> dict:
        today = date.today()

        # Age
        dob = parsed_data.get('dob')
        if isinstance(dob, date):
            age = (today - dob).days // 365
        else:
            age = 0

        # Expired?
        exp = parsed_data.get('expiration')
        if isinstance(exp, date):
            is_expired = (exp < today)
        else:
            # If we don't have a valid date object, assume expired
            is_expired = True

        return {
            'is_valid': (age >= 21) and not is_expired,
            'age': age,
            'is_expired': is_expired
        }

# ------------------------------------------------------------------------------
# 4. Routes
# ------------------------------------------------------------------------------

@app.route('/')
def home():
    return render_template('index.html', current_date=datetime.now().strftime('%B %d, %Y'))

@app.route('/process_scan', methods=['POST'])
def process_scan():
    """
    Single endpoint to handle both FULL scans and PARTIAL scans with end marker.
    """
    req_json = request.json or {}
    session_id = req_json.get("session_id", "default")
    chunk = req_json.get("scan_data", "")

    logging.info(f"Received scan data for session '{session_id}': {repr(chunk)}")

    if session_id not in SCAN_SESSIONS:
        SCAN_SESSIONS[session_id] = {"data": "", "last_update": time.time()}

    # Accumulate chunk
    SCAN_SESSIONS[session_id]["data"] += chunk
    SCAN_SESSIONS[session_id]["last_update"] = time.time()

    # If we detect the end marker, parse the entire data
    if END_MARKER in SCAN_SESSIONS[session_id]["data"]:
        logging.debug(f"End marker detected for session '{session_id}'.")
        full_data = SCAN_SESSIONS[session_id]["data"]
        # Remove the end marker
        full_data = full_data.replace(END_MARKER, "").strip()
        return finish_scan(session_id, full_data)

    # Otherwise, just return partial-OK
    return jsonify({
        "success": True,
        "complete": False,
        "message": "Chunk received; waiting for end marker or more data."
    })

@app.route('/check_stale', methods=['GET', 'POST'])
def check_stale():
    """
    Optional route to remove stale sessions
    """
    now = time.time()
    removed_sessions = []
    for sid, info in list(SCAN_SESSIONS.items()):
        if (now - info["last_update"]) > SCAN_TIMEOUT_SECS:
            del SCAN_SESSIONS[sid]
            removed_sessions.append(sid)
            logging.warning(f"Removed stale session '{sid}' due to timeout.")

    return jsonify({"success": True, "removed_sessions": removed_sessions})


def finish_scan(session_id, raw_data):
    """
    Once the full scan is assembled, parse & validate.
    """
    if session_id in SCAN_SESSIONS:
        del SCAN_SESSIONS[session_id]

    # Normalize
    data = (raw_data
            .replace('\r\n', '\n')
            .replace('\r', '\n')
            .replace('\t', '\n')
            .strip())

    # If missing '@ANSI' or '@', attempt reconstruction
    if not (data.startswith('@ANSI ') or data.startswith('@')):
        logging.warning("Data missing '@ANSI ' or '@' prefix. Trying to fix.")
        if len(data) > 50:
            data = '@ANSI ' + data
        else:
            logging.error("Scan data too short for reconstruction; invalid.")
            return jsonify({"success": False, "error": "Invalid scan data."}), 400

    try:
        parsed_data = LicenseParser.parse_aamva(data)
        logging.debug(f"Parsed data (session {session_id}): {parsed_data}")

        # Validate
        validation_result = LicenseParser.validate_license(parsed_data)
        logging.debug(f"Validation (session {session_id}): {validation_result}")

        # Fill missing fields
        if not parsed_data.get('state'):
            parsed_data['state'] = 'UNKNOWN'

        response_data = prepare_response_data(parsed_data, validation_result)
        logging.info(f"Finished scan session {session_id} -> {response_data}")

        return jsonify({"success": True, **response_data})

    except Exception as e:
        logging.exception(f"Error while finalizing session {session_id}")
        return jsonify({"success": False, "error": str(e)}), 500


def prepare_response_data(parsed_data, validation_result):
    first_name = parsed_data.get('first_name', '')
    middle_name = parsed_data.get('middle_name', '')
    last_name = parsed_data.get('last_name', '')

    addr1 = parsed_data.get('address', '')
    addr2 = parsed_data.get('address_2', '')
    city = parsed_data.get('city', '')
    state = parsed_data.get('state', 'UNKNOWN')
    postal_code = parsed_data.get('postal_code', '')

    full_address = f"{addr1} {addr2}".strip()

    # Format dates
    def fmt_date(d):
        if isinstance(d, date):
            return d.strftime('%B %d, %Y')
        return str(d)

    dob_str = fmt_date(parsed_data.get('dob'))
    exp_str = fmt_date(parsed_data.get('expiration'))
    iss_str = fmt_date(parsed_data.get('issue_date'))

    validation_msg = get_validation_message(validation_result)

    return {
        'name': f"{first_name} {middle_name} {last_name}".strip(),
        'address': f"{full_address}, {city}, {state} {postal_code}".strip().rstrip(','),
        'dob': dob_str,
        'expiration': exp_str,
        'issue_date': iss_str,
        'is_valid': validation_result['is_valid'],
        'validation_message': validation_msg
    }

def get_validation_message(validation_result):
    if validation_result['is_expired']:
        return "LICENSE EXPIRED"
    elif validation_result['age'] < 21:
        return "UNDER 21"
    return "VALID"

# ------------------------------------------------------------------------------
# 5. Run the Flask App
# ------------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)

