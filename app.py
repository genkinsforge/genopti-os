from flask import Flask, render_template, request, jsonify
from datetime import datetime
import re
import logging
from logging.handlers import RotatingFileHandler
import os

app = Flask(__name__)

# ------------------------------------------------------------------------------
# 1. Configure Logging
# ------------------------------------------------------------------------------
if not os.path.exists('logs'):
    os.makedirs('logs')
logging.basicConfig(
    handlers=[
        RotatingFileHandler('logs/scanner.log', maxBytes=100000, backupCount=5),
        logging.StreamHandler()  # Also log to console
    ],
    level=logging.DEBUG,  # Set to DEBUG level
    format='%(asctime)s %(levelname)s [%(filename)s:%(lineno)d]: %(message)s'
)

# ------------------------------------------------------------------------------
# 2. LicenseParser Class With Single-Pass Regex Parsing of Known Codes
# ------------------------------------------------------------------------------
class LicenseParser:

    # AAMVA field codes you expect to see (expand as needed).
    # For example, here we include common codes plus the DD-series.
    VALID_AAMVA_CODES = [
        'DCA','DCB','DCD','DBA','DCS','DAC','DAD','DBB','DBC','DBD','DAU','DAY','DAG','DAH','DAI',
        'DAJ','DAK','DAQ','DCF','DCG','DDE','DDF','DDG'
    ]
    
    # Map the relevant codes to your friendly keys (only map the ones you care about).
    AAMVA_FIELD_MAP = {
        'DCS': 'last_name',
        'DAC': 'first_name',
        'DAD': 'middle_name',
        'DBB': 'dob',                # Date of Birth
        'DBA': 'expiration',         # License Expiration
        'DBD': 'issue_date',         # Issue Date
        'DAG': 'address',            # Street Address 1
        'DAH': 'address_2',          # Street Address 2
        'DAI': 'city',
        'DAJ': 'state',
        'DAK': 'postal_code',
        'DAQ': 'license_number',
        # (If you need to parse the "DD" codes for truncation, add them here)
        'DDE': 'family_name_truncation',
        'DDF': 'first_name_truncation',
        'DDG': 'middle_name_truncation',
        # etc.
    }

    @staticmethod
    def parse_aamva(data: str) -> dict:
        """
        Parses AAMVA-compliant PDF417 text data by matching *only known codes* in one pass.
        This prevents confusion if part of a name looks like 'DD'.
        """
        # ----------------------------------------------------------------------
        # 1) Basic Format Check (optional, depending on your real data)
        # ----------------------------------------------------------------------
        if not data.startswith('@ANSI ') and not data.startswith('@'):
            raise ValueError("Invalid AAMVA format: Missing '@ANSI ' or '@' prefix.")

        # ----------------------------------------------------------------------
        # 2) Build a pattern that matches *only* known AAMVA codes in VALID_AAMVA_CODES.
        #
        #    Example:  (?P<code>(?:DCS|DAC|DAD|DBB|...))(?P<value>.*?)(?=(?:DCS|DAC|DAD|DBB|...)|$)
        #
        #    Explanation:
        #      - (?P<code>(?:...)) => Named capture group 'code' which must be one of the known codes.
        #      - (?P<value>.*?)   => Named capture group 'value' for everything until...
        #      - (?=(?:...)+|$)   => Lookahead for the next known code OR the end of the string.
        # ----------------------------------------------------------------------
        valid_code_pattern = '|'.join(LicenseParser.VALID_AAMVA_CODES)
        # Escape if needed, but these are plain uppercase strings so it’s fine
        pattern = rf'(?P<code>(?:{valid_code_pattern}))(?P<value>.*?)(?=(?:{valid_code_pattern})|$)'

        # Use DOTALL so '.' matches newlines
        matches = list(re.finditer(pattern, data, flags=re.DOTALL))

        # Prepare a dict for the parsed fields
        parsed_fields = {}

        for match in matches:
            code = match.group('code')
            value = match.group('value').strip()

            if code in LicenseParser.AAMVA_FIELD_MAP:
                friendly_key = LicenseParser.AAMVA_FIELD_MAP[code]
                parsed_fields[friendly_key] = value

        # ----------------------------------------------------------------------
        # 3) Parse Known Date Fields (assuming 'MMDDYYYY' format)
        # ----------------------------------------------------------------------
        for date_key in ['dob', 'expiration', 'issue_date']:
            if date_key in parsed_fields:
                raw_date = parsed_fields[date_key]
                # If exactly 8 digits => try to parse as MMDDYYYY
                if re.match(r'^\d{8}$', raw_date):
                    try:
                        parsed_date = datetime.strptime(raw_date, '%m%d%Y').date()
                        parsed_fields[date_key] = parsed_date
                    except ValueError:
                        logging.warning(f"Could not parse date field '{date_key}' -> {raw_date}")
                else:
                    logging.warning(f"Unexpected date format for '{date_key}': {raw_date}")

        return parsed_fields

    @staticmethod
    def validate_license(parsed_data: dict) -> dict:
        """
        Example validation that checks if person is >= 21 and if license is not expired.
        """
        today = datetime.now().date()

        # 1) Age Calculation
        dob = parsed_data.get('dob')
        age = None
        if dob and isinstance(dob, datetime):
            dob = dob.date()  # if it’s a datetime
        if dob and hasattr(dob, 'year'):
            # Rough approach: integer division of days by 365
            days_old = (today - dob).days
            age = days_old // 365
        else:
            age = 0

        # 2) Check Expiration
        exp = parsed_data.get('expiration')
        is_expired = False
        if exp and isinstance(exp, datetime):
            exp = exp.date()
        if exp and hasattr(exp, 'year'):
            is_expired = (exp < today)

        return {
            'is_valid': (age >= 21) and not is_expired,
            'age': age,
            'is_expired': is_expired
        }

# ------------------------------------------------------------------------------
# 3. Flask Routes
# ------------------------------------------------------------------------------
@app.route('/')
def home():
    return render_template('index.html', current_date=datetime.now().strftime('%B %d, %Y'))

@app.route('/process_scan', methods=['POST'])
def process_scan():
    scan_data = request.json.get('scan_data', '')
    logging.info(f"Received scan: {scan_data}")
    
    try:
        # 1) Parse with our new, code-specific Regex
        parsed_data = LicenseParser.parse_aamva(scan_data)
        logging.debug(f"Parsed Data: {parsed_data}")

        # 2) Validate
        validation_result = LicenseParser.validate_license(parsed_data)

        # 3) Safely gather output fields
        first_name = parsed_data.get('first_name', '')
        middle_name = parsed_data.get('middle_name', '')
        last_name = parsed_data.get('last_name', '')

        addr1 = parsed_data.get('address', '')
        addr2 = parsed_data.get('address_2', '')
        city = parsed_data.get('city', '')
        state = parsed_data.get('state', '')
        postal_code = parsed_data.get('postal_code', '')

        # Combine address lines
        full_address = f"{addr1} {addr2}".strip()

        # Format date fields to strings if they're datetime.date objects
        dob_obj = parsed_data.get('dob')
        exp_obj = parsed_data.get('expiration')
        issue_obj = parsed_data.get('issue_date')

        dob_str = dob_obj.strftime('%B %d, %Y') if dob_obj and hasattr(dob_obj, 'strftime') else ''
        exp_str = exp_obj.strftime('%B %d, %Y') if exp_obj and hasattr(exp_obj, 'strftime') else ''
        issue_str = issue_obj.strftime('%B %d, %Y') if issue_obj and hasattr(issue_obj, 'strftime') else ''

        # 4) Build response
        response_data = {
            'name': f"{first_name} {middle_name} {last_name}".strip(),
            'address': f"{full_address}, {city}, {state} {postal_code}".strip().rstrip(','),
            'dob': dob_str,
            'expiration': exp_str,
            'issue_date': issue_str,
            'is_valid': validation_result['is_valid'],
            'validation_message': get_validation_message(validation_result)
        }
        
        logging.info(f"Processed scan successfully: {response_data}")
        return jsonify({'success': True, **response_data})
    
    except Exception as e:
        logging.error(f"Error processing scan: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        })

def get_validation_message(validation_result):
    if validation_result['is_expired']:
        return "LICENSE EXPIRED"
    elif validation_result['age'] < 21:
        return "UNDER 21"
    return "VALID"

# ------------------------------------------------------------------------------
# 4. Run the Flask App
# ------------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)

