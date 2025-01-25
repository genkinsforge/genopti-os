# Genopti-OS (v0.34)

**Genopti-OS** is a Raspberry Pi-based customizable operating system enhancement. It provides a streamlined environment for automated license scanning, validation, and a kiosk-style web interface. Designed for simplicity and reliability, it is perfect for applications such as age verification and document validation in public or private settings.

## Table of Contents

- [About](#about)
- [Features](#features)
- [Hardware Requirements](#hardware-requirements)
- [Software Prerequisites](#software-prerequisites)
- [Installation](#installation)
- [Usage Instructions](#usage-instructions)
- [Setup Mode](#setup-mode)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## About

Genopti-OS simplifies the deployment of license validation systems by integrating hardware and software into a seamless user experience. It leverages the American Association of Motor Vehicle Administrators (AAMVA) standards for license scanning and validation, making it ideal for use cases requiring compliance, such as age verification for alcohol purchases, entry to restricted areas, or identity validation.

## Features

- **AAMVA-Compliant License Parsing**: 
  - Extracts fields including first name, middle name, last name, address, city, date of birth, expiration date, and issue date
  - Validates age requirements (default: 21 years) and license expiration
  - Provides formatted validation messages for underage and expired licenses
- **Flask-Based Web Interface**: 
  - Real-time scanning results
  - Configurable scan reset (15 seconds default)
  - Inactivity timeout (300ms default)
- **Setup Mode**: 
  - Serial number configuration
  - Wi-Fi configuration with WPA/WPA2 support
  - SSH and VNC service management
  - System information display (IP addresses, system name, CPU ID)
- **Extensive Logging**:
  - Rotating log files with 100KB size limit
  - 5 backup files maintained
  - Configurable debug mode via environment variables
  - Detailed error tracking and reporting

## Hardware Requirements

The following hardware components are tested and recommended:

1. **Raspberry Pi 3B or Higher**: Minimum 1GB RAM.
2. **Netum L8 Wireless 1D/2D Barcode Scanner** or **Tera HW0009 Barcode Scanner Wireless with Screen**: For license scanning.
3. **HMTECH 7" Mini HDMI Monitor**:
   - Part Number: HCTG070V.PK91.
   - Includes necessary cables.
4. **Dedicated USB Wall Adapter**: Ensure sufficient power supply.

## Software Prerequisites

- **Operating System**: Raspberry Pi OS (Debian-based)
- **Python**: Version 3.7 or later
- **Browser**: Chromium for kiosk functionality
- **Required Python Packages**:
  - Flask==2.2.5
  - gunicorn==20.1.0
  - requests==2.28.1
  - python-dotenv==0.21.1

## Installation

### Step 1: Clone the Repository
```bash
git clone https://github.com/genkinsforge/genopti-os.git
cd genopti-os
```

### Step 2: Install Dependencies
Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 3: Environment Configuration
1. Create a `.env` file in the application directory
2. Set `DEBUG_MODE=1` for development (optional)
3. Configure `DISPLAY_SERIAL` if needed (automatically uses CPU serial if not set)

### Step 4: Set Up Services
Run the installation scripts:
```bash
sudo ./install_genopti-os.sh
./ui_setup.sh
```

## Setup Mode Commands

Access setup mode by scanning `$$setup$$`. Available commands:

1. **Serial Number Configuration**:
   ```
   $$serialnumber$${"serial": "suffix"}
   ```

2. **Wi-Fi Configuration**:
   ```
   $$wifi$${"ssid": "networkName", "password": "pass", "country": "US", "encryption": "WPA", "hidden": false}
   ```

3. **Service Management**:
   - Enable SSH: `$$enablessh$$`
   - Disable SSH: `$$disablessh$$`
   - Enable VNC: `$$enablevnc$$`
   - Disable VNC: `$$disablevnc$$`

4. **Application Control**:
   - Restart Application: `$$restartapp$$`
   - Exit Setup Mode: `$$exit$$`

## Usage Instructions

### Launch the Service
```bash
sudo systemctl start genopti-os.service
```

### Monitor Service Status
```bash
sudo systemctl status genopti-os.service
```

### Access Web Interface
```
http://localhost:5000
```

## Troubleshooting

### Log Locations
- Main log file: `logs/scanner.log`
- Maximum log size: 100KB
- Rotates after reaching size limit
- Keeps 5 backup files

### Debug Mode
Set `DEBUG_MODE=1` in `.env` file for verbose logging.

### Common Issues
1. **Kiosk Mode Not Launching**: Ensure `ui_setup.sh` completed successfully
2. **Scanner Not Responding**: Check USB connections
3. **Wi-Fi Issues**: Verify configuration JSON format

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a new branch for your feature or bug fix
3. Submit a pull request with detailed changes

## License

Genopti-OS is licensed under the [GNU General Public License v3.0](LICENSE). Refer to the `LICENSE` file for more details.

---

Genopti-OS is designed and maintained by **Genkins Forge**. For support, feature requests, or reporting issues, contact us or submit a GitHub issue.
