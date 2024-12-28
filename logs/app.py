from flask import Flask, render_template, request, jsonify
from datetime import datetime
import re
import logging
from logging.handlers import RotatingFileHandler
import os

app = Flask(__name__)

# Configure logging
if not os.path.exists('logs'):
    os.makedirs('logs')

# Set up logging to both file and console
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)

# File handler
file_handler = RotatingFileHandler('logs/scanner.log', maxBytes=100000, backupCount=5)
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - %(levelname)s [%(filename)s:%(lineno)d] - %(message)s')
file_handler.setFormatter(file_formatter)

# Add both handlers
logger.addHandler(console_handler)
logger.addHandler(file_handler)

# Test log message
logging.debug("Logging system initialized")

class LicenseParser:
    @staticmethod
    def parse_aamva(data):
        try:
            # Basic format validation
            if not data.startswith('@ANSI '):
                raise ValueError("Invalid AAMVA format: Missing @ANSI header")

            # Extract fields using regex
            fields = {
                'first_name': re.search(r'DAC([^D]+)', data).group(1),    # Match everything until next D
                'middle_name': re.search(r'DAD([^D]+)', data).group(1),   # Match everything until next D
                'last_name': re.search(r'DCS([^D]+)', data).group(1),     # Match everything until next D
                'address': re.search(r'DAG(.+?)D', data).group(1),
                'city': re.search(r'DAI([^D]+)', data).group(1),
                'dob': re.search(r'DBB(\d{8})', data).group(1),
                'expiration': re.search(r'DBD(\d{8})', data).group(1)  # Using DBD for expiration
            }
            
            logging.info("Parsed name fields:")
            logging.info(f"First: '{fields['first_name']}'")
            logging.info(f"Middle: '{fields['middle_name']}'")
            logging.info(f"Last: '{fields['last_name']}'")


            # Format dates
            fields['dob'] = datetime.strptime(fields['dob'], '%m%d%Y').date()
            fields['expiration'] = datetime.strptime(fields['expiration'], '%m%d%Y').date()
            
            return fields
        except Exception as e:
            logging.error(f"Error parsing license data: {str(e)}")
            raise ValueError(f"Error parsing license data: {str(e)}")

    @staticmethod
    def validate_license(parsed_data):
        today = datetime.now().date()
        
        # Calculate age - this is the corrected calculation with detailed logging
        dob = parsed_data['dob']
        days_old = (today - dob).days
        age = days_old // 365
        
        logging.info(f"Age Calculation Debug:")
        logging.info(f"DOB: {dob}")
        logging.info(f"Today: {today}")
        logging.info(f"Days old: {days_old}")
        logging.info(f"Calculated age: {age}")
        
        # Check expiration
        is_expired = parsed_data['expiration'] < today
        logging.info(f"Expiration date: {parsed_data['expiration']}")
        logging.info(f"Is expired: {is_expired}")
        
        result = {
            'is_valid': age >= 21 and not is_expired,
            'age': age,
            'is_expired': is_expired
        }
        logging.info(f"Validation result: {result}")
        return result

        # Check expiration
        is_expired = parsed_data['expiration'] < today
        
        return {
            'is_valid': age >= 21 and not is_expired,
            'age': age,
            'is_expired': is_expired
        }

@app.route('/')
def home():
    return render_template('index.html', current_date=datetime.now().strftime('%B %d, %Y'))

@app.route('/test_scan', methods=['POST'])
def test_scan():
    scan_data = request.json.get('scan_data', '')
    logging.critical(f"TEST ENDPOINT - Received scan data: {scan_data}")
    return jsonify({'received': scan_data})

@app.route('/process_scan', methods=['POST'])
def process_scan():
    scan_data = request.json.get('scan_data', '')
    logging.info(f"Received scan: {scan_data}")
    
    try:
        # Parse the license data
        parsed_data = LicenseParser.parse_aamva(scan_data)
        validation_result = LicenseParser.validate_license(parsed_data)
        
        # Format the response data
        response_data = {
            'name': f"{parsed_data['first_name']} {parsed_data['middle_name']} {parsed_data['last_name']}",
            'address': f"{parsed_data['address']}, {parsed_data['city']}",
            'dob': parsed_data['dob'].strftime('%B %d, %Y'),
            'expiration': parsed_data['expiration'].strftime('%B %d, %Y'),
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

if __name__ == '__main__':
    app.run(debug=True)
