# Genopti-OS

**Genopti-OS** is a powerful, customizable operating system enhancement tailored for Raspberry Pi. It includes pre-configured tools and scripts to streamline setup and execution of key features like license scanning, automated validation, and web-based kiosk environments.

---

## Table of Contents

- [Features](#features)
- [Hardware Used](#hardware-used)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- AAMVA-compliant license scanning and validation
- Flask-based web interface for managing scanned data
- Automated environment setup with shell scripts
- Chromium kiosk mode for standalone deployment

---

## Hardware Used

This setup has been tested with the following hardware:

1. **Raspberry Pi 3B** (2GB RAM)
2. **Netum L8 Wireless 1D/2D Barcode Scanner**
3. **HMTECH 7" Mini HDMI Monitor**
   - Part Number: HCTG070V.PK91
   - Includes necessary cables for setup
4. **USB Wall Adapter** (to power the system)
   - **Note**: The Raspberry Pi cannot draw sufficient power from devices like a Toast Printer. A dedicated USB wall adapter is required.

---

## Requirements

1. **Hardware**: Raspberry Pi 3B or higher
2. **Operating System**: Raspberry Pi OS (Debian-based)
3. **Software Dependencies**:
   - Python 3.7 or later
   - `pip` for Python package management
   - Chromium browser (for kiosk mode)

---

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/genkinsforge/genopti-os.git
cd genopti-os
```

### Step 2: Install Required Libraries

Ensure Python dependencies are installed:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 3: Set Up the Environment

Run the provided setup scripts:

#### License Scanner Service

```bash
sudo ./install_license_scanner.sh
```

This script will:
- Create a `dl_scanner` system user
- Configure the application directory in `/opt/license_scanner`
- Set up and enable a systemd service for automatic startup

#### Kiosk UI Setup

For a Chromium-based kiosk:

```bash
./ui_setup.sh
```

This creates an autostart entry to launch Chromium in kiosk mode, pointing to the local web interface.

---

## Usage

### Launch the Service

Start the license scanner service:

```bash
sudo systemctl start license_scanner.service
```

Check its status:

```bash
sudo systemctl status license_scanner.service
```

### Access the Web Interface

Open a browser and navigate to:

```
http://localhost:5000
```

If the kiosk mode is enabled, Chromium will launch automatically after a reboot.

### Scanning a License

- Use the input field on the web interface to scan and validate licenses.
- Validations include date of birth checks and license expiration checks.

---

## Troubleshooting

### Viewing Logs

Logs are stored in the `logs/` directory. Use the following command to view them:

```bash
tail -f logs/scanner.log
```

### Restarting the Service

```bash
sudo systemctl restart license_scanner.service
```

---

## Contributing

Contributions are welcome! Please fork the repository, make your changes, and submit a pull request.

---

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

---
