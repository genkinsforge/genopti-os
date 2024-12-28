#!/bin/bash

# Detect current script location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
APP_SOURCE_DIR="$SCRIPT_DIR"

# Configuration variables
DESTINATION_DIR="/opt/license_scanner"
SERVICE_NAME="license_scanner.service"

# Create a new user 'dl_scanner' with no shell access
echo "Creating dl_scanner user..."
sudo adduser --system --no-create-home --shell /usr/sbin/nologin dl_scanner

# Set up the folder in /opt with dl_scanner permissions
echo "Setting up directory structure under /opt..."
sudo mkdir -p "$DESTINATION_DIR"
sudo chown dl_scanner:dl_scanner "$DESTINATION_DIR"

# Copy over the app and all of the subfolders
echo "Copying application to $DESTINATION_DIR..."
sudo rsync -av --chown=dl_scanner:dl_scanner "$APP_SOURCE_DIR/" "$DESTINATION_DIR/"

# Create the systemd service file
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME"
echo "Creating systemd service file at $SERVICE_FILE..."
sudo bash -c "cat << EOF > $SERVICE_FILE
[Unit]
Description=License Scanner Flask App Service
After=network.target

[Service]
User=dl_scanner
WorkingDirectory=$DESTINATION_DIR
ExecStart=/opt/license_scanner/venv/bin/python3 /opt/license_scanner/app.py
Restart=always
Environment=\"PATH=/opt/license_scanner/venv/bin\"

[Install]
WantedBy=multi-user.target
EOF"

# Reload systemd, enable and start the service using sudo
echo "Configuring systemd to manage the service..."
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"
sudo systemctl start "$SERVICE_NAME"

echo "Installation complete. The license scanner app should now be running as a service."
