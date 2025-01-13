#!/usr/bin/env python3
import os
import re
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, date
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

# ------------------------------------------------------------------------------
# 1. Environment & Logging
# ------------------------------------------------------------------------------
DEBUG_MODE = (os.environ.get('DEBUG_MODE', '0') == '1')
SCAN_RESET_SECONDS = int(os.environ.get('SCAN_RESET_SECONDS', '15'))
SCAN_INACTIVITY_MS = int(os.environ.get('SCAN_INACTIVITY_MS', '300'))  # default 300 ms

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

# ------------------------------------------------------------------------------
# 2. Improved AAMVA Parsing Logic
# ------------------------------------------------------------------------------
class LicenseParser:
    VALID_AAMVA_CODES = [
        'DCA', 'DCB', 'DCD', 'DBA', 'DCS', 'DAC', 'DAD', 'DBB', 'DBC', 'DBD', 'DAU', 'DAY',
        'DAG', 'DAH', 'DAI', 'DAJ', 'DAK', 'DAQ', 'DCF', 'DCG', 'DDE', 'DDF', 'DDG'
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
        'DDG': 'middle_name_truncation'
    }

    @staticmethod
    def parse_aamva(data: str) -> dict:
        """
        Enhanced parsing logic to handle varying AAMVA formats with robust error handling.
        """
        if not (data.startswith('@ANSI ') or data.startswith('@')):
            raise ValueError("Invalid AAMVA format: Missing '@ANSI ' or '@' prefix.")

        valid_code_pattern = '|'.join(LicenseParser.VALID_AAMVA_CODES)
        pattern = rf'(?P<code>{valid_code_pattern})(?P<value>.*?)(?=(?:{valid_code_pattern})|$)'
        matches = list(re.finditer(pattern, data, flags=re.DOTALL))

        parsed_fields = {}
        unmatched_data = data

        for match in matches:
            code = match.group('code')
            value = match.group('value').strip()
            unmatched_data = unmatched_data.replace(f"{code}{value}", '', 1)

            if code in LicenseParser.AAMVA_FIELD_MAP:
                friendly_key = LicenseParser.AAMVA_FIELD_MAP[code]
                parsed_fields[friendly_key] = value
            else:
                logging.warning(f"Unknown AAMVA field code encountered: {code} with value: {value}")

        # Log any data that wasn't matched
        if unmatched_data.strip():
            logging.warning(f"Unmatched data: {unmatched_data.strip()}")

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
                logging.warning(f"Unexpected date format for '{date_key}': {raw_val}")

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
# 3. Single Endpoint for Final Scans
# ------------------------------------------------------------------------------
@app.route('/')
def home():
    """
    Renders index.html. The front-end uses inactivity-based scanning logic:
    it accumulates keystrokes and, after SCAN_INACTIVITY_MS ms of silence,
    sends one final POST to /process_scan.
    """
    return render_template('index.html',
                           debug_mode=DEBUG_MODE,
                           scan_reset_seconds=SCAN_RESET_SECONDS,
                           scan_inactivity_ms=SCAN_INACTIVITY_MS)

@app.route('/process_scan', methods=['POST'])
def process_scan():
    """
    Receives the entire final scanned string from the client.
    Then uses the original parse_aamva logic to parse it once.
    """
    req_json = request.json or {}
    scan_str = req_json.get('scan_data', '').strip()

    logging.info(f"Received final scan => {repr(scan_str)}")

    if not scan_str:
        return jsonify({
            "success": False,
            "complete": True,
            "error": "No scan data received.",
            "raw_scanned_data": scan_str if DEBUG_MODE else ""
        }), 400

    # Debug log if needed
    if DEBUG_MODE:
        logging.debug(f"Raw scanned data => {scan_str}")

    try:
        # 1) Parse with your old logic
        parsed_data = LicenseParser.parse_aamva(scan_str)

        # 2) Validate
        validation = LicenseParser.validate_license(parsed_data)

        # 3) Remove license_number if not debug
        if not DEBUG_MODE and 'license_number' in parsed_data:
            parsed_data.pop('license_number')

        # 4) Build final response
        resp = prepare_response_data(parsed_data, validation)
        logging.info(f"Final parse => {resp['name']} (Valid={resp['is_valid']})")

        return jsonify({
            "success": True,
            "complete": True,
            "raw_scanned_data": scan_str if DEBUG_MODE else "",
            **resp
        })

    except Exception as ex:
        logging.exception("Error parsing final scan data")
        return jsonify({
            "success": False,
            "complete": True,
            "error": str(ex),
            "raw_scanned_data": scan_str if DEBUG_MODE else ""
        }), 500

def prepare_response_data(parsed_data, validation_result):
    """
    The same final response structure you had before:
    name, address, dob, expiration, etc., plus validity info.
    """
    first_name = parsed_data.get('first_name', '')
    middle_name = parsed_data.get('middle_name', '')
    last_name  = parsed_data.get('last_name', '')

    addr1 = parsed_data.get('address', '')
    addr2 = parsed_data.get('address_2', '')
    city  = parsed_data.get('city', '')
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

    validation_msg = get_validation_message(validation_result)

    return {
        "name": f"{first_name} {middle_name} {last_name}".strip(),
        "address": f"{full_address}, {city}, {state} {postal_code}".strip().rstrip(','),
        "dob": dob_str,
        "expiration": exp_str,
        "issue_date": iss_str,
        "is_valid": validation_result['is_valid'],
        "validation_message": validation_msg
    }

def get_validation_message(validation_result):
    if validation_result['is_expired']:
        return "LICENSE EXPIRED"
    elif validation_result['age'] < 21:
        return "UNDER 21"
    return "VALID"

# ------------------------------------------------------------------------------
# 4. Run
# ------------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=DEBUG_MODE)

