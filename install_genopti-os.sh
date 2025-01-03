#!/usr/bin/env bash

set -e

# Variables
SERVICE_NAME="genopti-os"
INSTALL_DIR="/opt/$SERVICE_NAME"
SERVICE_FILE="$SERVICE_NAME.service"

echo "Installing $SERVICE_NAME to $INSTALL_DIR..."

# 1. Create or update the directory
if [ ! -d "$INSTALL_DIR" ]; then
    mkdir -p "$INSTALL_DIR"
fi

# 2. Copy project files to the install directory
# (Replace "src" with your project’s source directory)
cp -r src/* "$INSTALL_DIR"/

# 3. Create a Python virtual environment if needed
if [ ! -d "$INSTALL_DIR/venv" ]; then
    python3 -m venv "$INSTALL_DIR/venv"
fi

# 4. Install requirements
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

# 5. Copy the systemd service file to the correct location
cp "$SERVICE_FILE" "/etc/systemd/system/$SERVICE_FILE"

# 6. Reload systemd to read the new service file
systemctl daemon-reload

# 7. Enable and start the new service
systemctl enable "$SERVICE_FILE"
systemctl start "$SERVICE_FILE"

echo "Installation complete. The $SERVICE_NAME service has been started."

