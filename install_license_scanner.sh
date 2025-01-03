#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Variables
APP_DIR="/opt/license_scanner"
VENV_DIR="$APP_DIR/venv"
SERVICE_FILE="/etc/systemd/system/license_scanner.service"
REQUIREMENTS_FILE="$APP_DIR/requirements.txt"
APP_SCRIPT="$APP_DIR/app.py"

# Ensure running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

echo "Installing License Scanner..."

# Step 1: Create application directory if it doesn't exist
if [ ! -d "$APP_DIR" ]; then
    echo "Creating application directory at $APP_DIR..."
    mkdir -p "$APP_DIR"
fi

# Step 2: Copy application files to the target directory
echo "Copying application files to $APP_DIR..."
cp -r ./* "$APP_DIR"

# Step 3: Install Python and dependencies
echo "Installing Python dependencies..."
apt-get update
apt-get install -y python3 python3-venv python3-pip

# Step 4: Set up the virtual environment
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment in $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
fi

echo "Activating virtual environment and installing dependencies..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install -r "$REQUIREMENTS_FILE"
deactivate

# Step 5: Create systemd service
echo "Setting up systemd service..."

cat > "$SERVICE_FILE" <<EOL
[Unit]
Description=License Scanner Flask App Service
After=network.target

[Service]
User=root
WorkingDirectory=$APP_DIR
ExecStart=$VENV_DIR/bin/python $APP_SCRIPT
Restart=always
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOL

# Step 6: Reload systemd, enable and start the service
echo "Reloading systemd, enabling, and starting the service..."
systemctl daemon-reload
systemctl enable license_scanner.service
systemctl start license_scanner.service

# Step 7: Verify service status
echo "Verifying service status..."
systemctl status license_scanner.service

echo "License Scanner installed and started successfully!"

