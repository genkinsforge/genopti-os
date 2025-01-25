#!/bin/bash

# Exit immediately on error
set -e

# --[ Configuration Variables ]-----------------------------------------------
# MUST match install script values
SERVICE_USER="genopti-svc"
SERVICE_GROUP="genopti-svc"
APP_DIR="/opt/genopti-os"
SERVICE_NAME="genopti-os"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SUDOERS_FILE="/etc/sudoers.d/${SERVICE_NAME}"

# --[ Root Check ]------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root."
   exit 1
fi

# --[ Service Removal ]-------------------------------------------------------
echo "Stopping and disabling service..."
if systemctl is-active --quiet "$SERVICE_NAME"; then
    systemctl stop "$SERVICE_NAME"
fi

if systemctl is-enabled --quiet "$SERVICE_NAME"; then
    systemctl disable "$SERVICE_NAME"
fi

echo "Removing systemd service file..."
rm -f "$SERVICE_FILE"
systemctl daemon-reload
systemctl reset-failed

# --[ Application Files Removal ]---------------------------------------------
echo "Removing application files..."
if [ -d "$APP_DIR" ]; then
    rm -rf "$APP_DIR"
    echo "Deleted application directory: $APP_DIR"
else
    echo "Application directory not found: $APP_DIR"
fi

# --[ Sudoers Cleanup ]-------------------------------------------------------
echo "Removing sudo configuration..."
if [ -f "$SUDOERS_FILE" ]; then
    rm -f "$SUDOERS_FILE"
    # Validate sudo configuration
    visudo -c
    echo "Removed sudoers file: $SUDOERS_FILE"
else
    echo "Sudoers file not found: $SUDOERS_FILE"
fi

# --[ User Account Removal ]--------------------------------------------------
echo "Removing service user account..."
if id "$SERVICE_USER" &>/dev/null; then
    userdel --remove "$SERVICE_USER"
    echo "Deleted user: $SERVICE_USER"
else
    echo "User account not found: $SERVICE_USER"
fi

# --[ Final Cleanup ]---------------------------------------------------------
echo "Resetting systemd..."
systemctl daemon-reload

echo "Genopti-OS uninstallation complete."
