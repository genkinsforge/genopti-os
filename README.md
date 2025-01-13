# Genopti-OS

**Genopti-OS** is a Raspberry Pi-based customizable operating system enhancement. It provides a streamlined environment for automated license scanning, validation, and a kiosk-style web interface. Designed for simplicity and reliability, it is perfect for applications such as age verification and document validation in public or private settings.

---

## Table of Contents

- [About](#about)
- [Features](#features)
- [Hardware Requirements](#hardware-requirements)
- [Software Prerequisites](#software-prerequisites)
- [Installation](#installation)
- [Usage Instructions](#usage-instructions)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## About

Genopti-OS simplifies the deployment of license validation systems by integrating hardware and software into a seamless user experience. It leverages the American Association of Motor Vehicle Administrators (AAMVA) standards for license scanning and validation, making it ideal for use cases requiring compliance, such as age verification for alcohol purchases, entry to restricted areas, or identity validation.

---

## Features

- **AAMVA-Compliant License Parsing**: Supports AAMVA-compliant barcode scanning and parsing to extract critical details like name, address, date of birth, and expiration date.
- **Validation Engine**: Automatically checks age and license expiration.
- **Flask-Based Web Interface**: Provides an intuitive, user-friendly web interface for real-time scanning results.
- **Kiosk Mode**: Configurable Chromium kiosk mode for a clean, dedicated interface.
- **Automated Setup**: Includes shell scripts for quick environment setup and deployment.
- **Extensive Logging**: Logs key events and debugging information for troubleshooting.

---

## Hardware Requirements

The following hardware components are tested and recommended:

1. **Raspberry Pi 3B or Higher**: Minimum 2GB RAM.
2. **Netum L8 Wireless 1D/2D Barcode Scanner**: For license scanning.
3. **HMTECH 7" Mini HDMI Monitor**:
   - Part Number: HCTG070V.PK91.
   - Includes necessary cables.
4. **Dedicated USB Wall Adapter**: Ensure sufficient power supply (e.g., Toast printers may not provide enough power).

---

## Software Prerequisites

- **Operating System**: Raspberry Pi OS (Debian-based).
- **Python**: Version 3.7 or later.
- **Browser**: Chromium for kiosk functionality.

Python dependencies are managed via `pip` and specified in `requirements.txt`:
```plaintext
Flask==2.2.5
gunicorn==20.1.0
requests==2.28.1
```

---

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

### Step 3: Set Up the Environment
Run the setup scripts for services and the kiosk UI:

#### License Scanner Service
```bash
sudo ./install_genopti-os.sh
```
This script:
- Creates a dedicated system user.
- Sets up the application directory at `/opt/genopti-os`.
- Configures and enables a systemd service for the application.

#### Kiosk UI Setup
```bash
./ui_setup.sh
```
This sets up Chromium to launch in kiosk mode on startup.

---

## Usage Instructions

### Launch the Service
Start the license scanner service:
```bash
sudo systemctl start genopti-os.service
```
Verify its status:
```bash
sudo systemctl status genopti-os.service
```

### Access the Web Interface
Open a browser and navigate to:
```
http://localhost:5000
```
If kiosk mode is enabled, the interface will launch automatically on boot.

### Scan and Validate Licenses
- Place the barcode scanner over the license to input data.
- The system validates:
  - **Date of Birth**: Ensures the individual meets the age requirement (default: 21 years).
  - **Expiration Date**: Checks license validity.
- Results, including name, address, and validation status, are displayed on the interface.

---

## Troubleshooting

### Logs
View logs for debugging:
```bash
tail -f logs/scanner.log
```

### Restart the Service
To restart the service:
```bash
sudo systemctl restart genopti-os.service
```

### Common Issues
1. **Kiosk Mode Not Launching**: Ensure `ui_setup.sh` completed successfully and reboot the system.
2. **Scanner Not Responding**: Check hardware connections and test with a different USB port.

---

## Contributing

Contributions are welcome! Please:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Submit a pull request with detailed changes.

---

## License

Genopti-OS is licensed under the [GNU General Public License v3.0](LICENSE). Refer to the `LICENSE` file for more details.

---

Genopti-OS is designed and maintained by **Genkins Forge**. For support, feature requests, or reporting issues, contact us or submit a GitHub issue.


