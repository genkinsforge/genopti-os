#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Variables
SERVICE_USER="genopti-svc"
SERVICE_GROUP="genopti-svc"
APP_DIR="/opt/genopti-os"
VENV_DIR="$APP_DIR/venv"
SERVICE_NAME="genopti-os"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
REQUIREMENTS_FILE="$APP_DIR/requirements.txt"
APP_SCRIPT="$APP_DIR/app.py"
SUDOERS_FILE="/etc/sudoers.d/${SERVICE_NAME}"

# Default Environment Variable Values
DEFAULT_DEBUG_MODE="0"            # 0=normal mode, 1=debug
DEFAULT_SCAN_RESET_SECONDS="15"   # Time in seconds before clearing the screen
DEFAULT_SCAN_INACTIVITY_MS="300"  # Inactivity timeout in ms before finalizing the scan

# --[ Root Check ]------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."
   exit 1
fi

echo "Installing $SERVICE_NAME..."

# --[ Create or update system user ]------------------------------------------
#  - system user
#  - no home directory
#  - no shell (for security)
if ! id "$SERVICE_USER" &>/dev/null; then
    echo "Creating user: $SERVICE_USER..."
    useradd --system \
            --no-create-home \
            --shell /usr/sbin/nologin \
            "$SERVICE_USER"
fi

# --[ Create application directory if it doesn't exist ]----------------------
if [ ! -d "$APP_DIR" ]; then
    echo "Creating application directory at $APP_DIR..."
    mkdir -p "$APP_DIR"
fi

# --[ Copy application files to the target directory ]------------------------
echo "Copying application files to $APP_DIR..."
cp -r ./* "$APP_DIR"

# --[ Install system packages for Python ]------------------------------------
echo "Installing Python dependencies..."
apt-get update
apt-get install -y python3 python3-venv python3-pip

# --[ Create/Update Python virtual environment ]------------------------------
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment in $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
fi

echo "Activating virtual environment and installing dependencies..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install -r "$REQUIREMENTS_FILE"
deactivate

# --[ Adjust ownership to new service user ]----------------------------------
# This ensures the service user can read and execute files as needed.
echo "Setting ownership of $APP_DIR to $SERVICE_USER:$SERVICE_GROUP..."
chown -R "$SERVICE_USER":"$SERVICE_GROUP" "$APP_DIR"
chmod -R 750 "$APP_DIR"

# --[ Allow specific sudo command for service user ]--------------------------
echo "Configuring sudoers file to allow $SERVICE_USER to execute wpa_cli without password..."
cat > "$SUDOERS_FILE" <<EOL
# Allow $SERVICE_USER to run wpa_cli without a password
$SERVICE_USER ALL=(ALL) NOPASSWD: /usr/bin/wpa_cli -i wlan0 reconfigure
EOL

# Ensure correct permissions for the sudoers file
chmod 440 "$SUDOERS_FILE"

# --[ Create or update systemd service file ]---------------------------------
echo "Setting up systemd service at $SERVICE_FILE..."

cat > "$SERVICE_FILE" <<EOL
[Unit]
Description=Genopti-OS Flask App Service
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$APP_DIR
ExecStart=$VENV_DIR/bin/python $APP_SCRIPT
Restart=always
Environment=PYTHONUNBUFFERED=1

# New environment variables
Environment=DEBUG_MODE=${DEFAULT_DEBUG_MODE}
Environment=SCAN_RESET_SECONDS=${DEFAULT_SCAN_RESET_SECONDS}
Environment=SCAN_INACTIVITY_MS=${DEFAULT_SCAN_INACTIVITY_MS}

# Security Hardening
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ProtectControlGroups=true
ProtectKernelTunables=true
ProtectKernelModules=true

[Install]
WantedBy=multi-user.target
EOL

# --[ Reload systemd and start the service ]----------------------------------
echo "Reloading systemd daemon and enabling the $SERVICE_NAME service..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME".service
systemctl start "$SERVICE_NAME".service

# --[ Verify service status ]-------------------------------------------------
echo "Verifying service status..."
systemctl status "$SERVICE_NAME".service || true

echo "$SERVICE_NAME installed and started successfully under user '$SERVICE_USER'."
echo "Default ENV Vars: DEBUG_MODE=${DEFAULT_DEBUG_MODE}, SCAN_RESET_SECONDS=${DEFAULT_SCAN_RESET_SECONDS}, SCAN_INACTIVITY_MS=${DEFAULT_SCAN_INACTIVITY_MS}"
