#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# --[ Configuration Variables ]-----------------------------------------------
SERVICE_USER="genopti-svc"
SERVICE_GROUP="genopti-svc"
APP_DIR="/opt/genopti-os"
VENV_DIR="$APP_DIR/venv"
SERVICE_NAME="genopti-os"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
REQUIREMENTS_FILE="$APP_DIR/requirements.txt"
APP_SCRIPT="$APP_DIR/app.py"
SUDOERS_FILE="/etc/sudoers.d/${SERVICE_NAME}"

# Default Environment Variables
DEFAULT_DEBUG_MODE="0"
DEFAULT_SCAN_RESET_SECONDS="15"
DEFAULT_SCAN_INACTIVITY_MS="300"

# --[ Root Check ]------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root."
   exit 1
fi

echo "Starting Genopti-OS installation..."

# --[ System User Creation ]--------------------------------------------------
if ! id "$SERVICE_USER" &>/dev/null; then
    echo "Creating service user: $SERVICE_USER..."
    useradd --system \
            --no-create-home \
            --shell /usr/sbin/nologin \
            "$SERVICE_USER"
fi

# --[ Application Directory Setup ]-------------------------------------------
echo "Configuring application directory: $APP_DIR"
mkdir -p "$APP_DIR"
cp -r ./* "$APP_DIR"
chown -R "$SERVICE_USER":"$SERVICE_GROUP" "$APP_DIR"
chmod -R 750 "$APP_DIR"

# --[ Python Environment Setup ]----------------------------------------------
echo "Configuring Python virtual environment..."
apt-get update
apt-get install -y python3 python3-venv python3-pip

if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install -r "$REQUIREMENTS_FILE"
deactivate

# --[ Sudoers Configuration ]-------------------------------------------------
echo "Configuring secure sudo access..."
cat > "$SUDOERS_FILE" <<EOL
# Genopti-OS limited privilege configuration
Cmnd_Alias VNC_CTL = /usr/bin/systemctl enable vncserver-x11-serviced, \\
                    /usr/bin/systemctl start vncserver-x11-serviced, \\
                    /usr/bin/systemctl disable vncserver-x11-serviced, \\
                    /usr/bin/systemctl stop vncserver-x11-serviced

Cmnd_Alias SSH_CTL = /usr/bin/systemctl enable ssh, \\
                   /usr/bin/systemctl start ssh, \\
                   /usr/bin/systemctl disable ssh, \\
                   /usr/bin/systemctl stop ssh

Cmnd_Alias RASPI_CFG = /usr/bin/raspi-config nonint do_ssh 0, \\
                     /usr/bin/raspi-config nonint do_ssh 1, \\
                     /usr/bin/raspi-config nonint do_vnc 0, \\
                     /usr/bin/raspi-config nonint do_vnc 1

$SERVICE_USER ALL=(root) NOPASSWD: \\
    /usr/bin/wpa_cli -i wlan0 reconfigure, \\
    VNC_CTL, \\
    SSH_CTL, \\
    RASPI_CFG
EOL

chmod 440 "$SUDOERS_FILE"

# --[ Systemd Service Configuration ]-----------------------------------------
echo "Creating systemd service: $SERVICE_NAME"
cat > "$SERVICE_FILE" <<EOL
[Unit]
Description=Genopti-OS Service
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$APP_DIR
ExecStart=$VENV_DIR/bin/python $APP_SCRIPT
Restart=always
Environment=PYTHONUNBUFFERED=1

# Application Configuration
Environment=DEBUG_MODE=${DEFAULT_DEBUG_MODE}
Environment=SCAN_RESET_SECONDS=${DEFAULT_SCAN_RESET_SECONDS}
Environment=SCAN_INACTIVITY_MS=${DEFAULT_SCAN_INACTIVITY_MS}

# Security Configuration
NoNewPrivileges=no
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
RestrictSUIDSGID=yes
RemoveIPC=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
EOL

# --[ Service Activation ]----------------------------------------------------
echo "Starting system service..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

# --[ Verification ]----------------------------------------------------------
echo "Installation complete. Service status:"
systemctl status "$SERVICE_NAME" --no-pager || true

echo "Successfully installed Genopti-OS"
echo "Access logs with: journalctl -u $SERVICE_NAME -f"
