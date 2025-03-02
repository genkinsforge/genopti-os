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
WIFI_CREDENTIALS_FILE="wifi-credentials.txt"

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

# --[ WiFi Setup ]------------------------------------------------------------
configure_wifi() {
    local SSID="$1"
    local PASSWORD="$2"

    echo "Configuring WiFi for SSID: $SSID"

    # Check if NetworkManager is available
    if command -v nmcli &> /dev/null; then
        echo "Using NetworkManager to configure WiFi..."
        
        # Connect to WiFi using nmcli
        if nmcli device wifi connect "$SSID" password "$PASSWORD"; then
            echo "WiFi connected successfully using NetworkManager!"
            return 0
        else
            echo "Failed to connect using NetworkManager. Trying wpa_supplicant method..."
        fi
    fi

    # Fallback to wpa_supplicant method
    echo "Using wpa_supplicant method to configure WiFi..."
    
    # Identify wireless interface
    WIRELESS_INTERFACE=$(ip -br link | grep -Eo 'wlan[0-9]' | head -n 1)
    if [ -z "$WIRELESS_INTERFACE" ]; then
        echo "No wireless interface found. Using default wlan0."
        WIRELESS_INTERFACE="wlan0"
    fi
    
    echo "Using wireless interface: $WIRELESS_INTERFACE"
    
    # Create wpa_supplicant.conf
    cat > /etc/wpa_supplicant/wpa_supplicant.conf << EOF
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=US

network={
    ssid="$SSID"
    psk="$PASSWORD"
    key_mgmt=WPA-PSK
}
EOF

    # Restart wireless interface
    echo "Restarting wireless interface..."
    wpa_cli -i "$WIRELESS_INTERFACE" reconfigure || true
    
    # Additional restart methods that might help
    systemctl restart wpa_supplicant.service || true
    ifconfig "$WIRELESS_INTERFACE" down && ifconfig "$WIRELESS_INTERFACE" up || true

    # Wait a moment for connection
    echo "Waiting for WiFi connection..."
    sleep 10

    # Check connection
    if ping -c 1 8.8.8.8 > /dev/null 2>&1; then
        echo "WiFi connected successfully!"
        return 0
    else
        echo "WiFi connection might not be established. Continuing installation..."
        return 1
    fi
}

# Check if WiFi credentials file exists
if [ -f "$WIFI_CREDENTIALS_FILE" ]; then
    echo "Found WiFi credentials file. Configuring WiFi..."

    # Read credentials
    WIFI_SSID=$(grep -oP '^SSID=\K.*' "$WIFI_CREDENTIALS_FILE")
    WIFI_PASSWORD=$(grep -oP '^PASSWORD=\K.*' "$WIFI_CREDENTIALS_FILE")

    if [ -n "$WIFI_SSID" ] && [ -n "$WIFI_PASSWORD" ]; then
        configure_wifi "$WIFI_SSID" "$WIFI_PASSWORD"

        # Remove credentials file for security
        echo "Removing WiFi credentials file for security..."
        shred -u "$WIFI_CREDENTIALS_FILE"
    else
        echo "WiFi credentials file format incorrect. Expected SSID=xxxx and PASSWORD=yyyy."
        echo "Continuing without WiFi setup."
    fi
else
    # If no credentials file, prompt for credentials
    echo "No WiFi credentials file found."
    read -p "Do you want to set up WiFi now? (y/n): " SETUP_WIFI

    if [[ "$SETUP_WIFI" =~ ^[Yy]$ ]]; then
        read -p "Enter WiFi SSID: " WIFI_SSID
        read -sp "Enter WiFi Password: " WIFI_PASSWORD
        echo

        if [ -n "$WIFI_SSID" ] && [ -n "$WIFI_PASSWORD" ]; then
            configure_wifi "$WIFI_SSID" "$WIFI_PASSWORD"
        else
            echo "Invalid WiFi credentials. Continuing without WiFi setup."
        fi
    else
        echo "Skipping WiFi setup."
    fi
fi

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

# Add user to netdev group to allow WiFi management
echo "Adding $SERVICE_USER to netdev group for WiFi management..."
usermod -a -G netdev "$SERVICE_USER"

# Create sudoers file for WiFi configuration permissions
echo "Setting up sudo permissions for WiFi configuration..."
cat > "/etc/sudoers.d/$SERVICE_USER" <<SUDOERS
# Allow $SERVICE_USER to manage WiFi without password
$SERVICE_USER ALL=(ALL) NOPASSWD: /sbin/wpa_cli -i wlan0 reconfigure
$SERVICE_USER ALL=(ALL) NOPASSWD: /sbin/wpa_cli -i wlan* reconfigure
$SERVICE_USER ALL=(ALL) NOPASSWD: /bin/cp /tmp/tmp* /etc/wpa_supplicant/wpa_supplicant.conf
$SERVICE_USER ALL=(ALL) NOPASSWD: /usr/bin/nmcli device wifi connect *
$SERVICE_USER ALL=(ALL) NOPASSWD: /usr/bin/nmcli
$SERVICE_USER ALL=(ALL) NOPASSWD: /usr/bin/nmcli device wifi connect *
$SERVICE_USER ALL=(ALL) NOPASSWD: /usr/bin/nmcli device wifi rescan
$SERVICE_USER ALL=(ALL) NOPASSWD: /usr/bin/nmcli device wifi list
$SERVICE_USER ALL=(ALL) NOPASSWD: /usr/bin/nmcli connection
$SERVICE_USER ALL=(ALL) NOPASSWD: /usr/bin/nmcli connection delete *
$SERVICE_USER ALL=(ALL) NOPASSWD: /bin/systemctl restart NetworkManager.service
$SERVICE_USER ALL=(ALL) NOPASSWD: /bin/systemctl restart wpa_supplicant.service
SUDOERS
chmod 440 "/etc/sudoers.d/$SERVICE_USER"

# --[ Create or clean application directory ]----------------------------------
if [ ! -d "$APP_DIR" ]; then
    echo "Creating application directory at $APP_DIR..."
    mkdir -p "$APP_DIR"
else
    echo "Cleaning application directory for reinstallation..."
    # Preserve any user configuration files if they exist
    if [ -f "$APP_DIR/config.json" ]; then
        echo "Backing up existing config.json..."
        cp "$APP_DIR/config.json" "/tmp/genopti-config-backup.json"
    fi
    
    # Remove old files but keep the directory
    find "$APP_DIR" -mindepth 1 -not -path "$APP_DIR/venv*" -delete
    
    # Restore configuration if backed up
    if [ -f "/tmp/genopti-config-backup.json" ]; then
        echo "Restoring config.json..."
        mkdir -p "$APP_DIR"
        cp "/tmp/genopti-config-backup.json" "$APP_DIR/config.json"
        rm "/tmp/genopti-config-backup.json"
    fi
fi

# --[ Copy application files to the target directory ]------------------------
echo "Copying application files to $APP_DIR..."
cp -r ./* "$APP_DIR"

# --[ Install system packages for Python ]------------------------------------
echo "Installing Python dependencies..."
apt-get update
apt-get install -y python3 python3-venv python3-pip

# --[ Create/Update Python virtual environment ]------------------------------
# Clean up existing venv if it exists to allow for clean reinstallation
if [ -d "$VENV_DIR" ]; then
    echo "Removing existing virtual environment for clean reinstall..."
    rm -rf "$VENV_DIR"
fi

echo "Creating virtual environment in $VENV_DIR..."
python3 -m venv "$VENV_DIR"

echo "Activating virtual environment and installing dependencies..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip

# Handle externally-managed-environment error by using --break-system-packages if needed
if pip install -r "$REQUIREMENTS_FILE" 2>&1 | grep -q "externally-managed-environment"; then
    echo "Detected externally-managed-environment restriction, using workaround..."
    pip install --break-system-packages -r "$REQUIREMENTS_FILE"
else
    echo "Standard pip install completed successfully."
fi
deactivate

# --[ Adjust ownership to new service user ]----------------------------------
# This ensures the service user can read and execute files as needed.
echo "Setting ownership of $APP_DIR to $SERVICE_USER:$SERVICE_GROUP..."
chown -R "$SERVICE_USER":"$SERVICE_GROUP" "$APP_DIR"
chmod -R 750 "$APP_DIR"

# --[ Create device ID file with proper permissions ]--------------------------
echo "Creating /etc/device_id file with proper permissions..."
# Create the file if it doesn't exist
touch /etc/device_id

# Set initial content based on CPU serial if the file is empty
if [ ! -s /etc/device_id ]; then
    # Get CPU serial from /proc/cpuinfo
    CPU_SERIAL=$(grep -i "Serial" /proc/cpuinfo | awk '{print $3}')
    if [ -n "$CPU_SERIAL" ]; then
        echo "$CPU_SERIAL" > /etc/device_id
    else
        echo "UNKNOWN" > /etc/device_id
    fi
fi

# Set permissions so genopti-svc can read and write to it
chown "$SERVICE_USER":"$SERVICE_GROUP" /etc/device_id
chmod 660 /etc/device_id

# --[ Stop existing service if running ]---------------------------------------
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "Stopping existing $SERVICE_NAME service..."
    systemctl stop "$SERVICE_NAME".service
fi

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

# --[ Final Network Connectivity Check ]---------------------------------------
if ! ping -c 1 8.8.8.8 > /dev/null 2>&1; then
    echo ""
    echo "========================================================================"
    echo "WARNING: No internet connectivity detected after installation."
    echo ""
    echo "If any package installation steps failed, you may need to:"
    echo "1. Create a 'wifi-credentials.txt' file with the following content:"
    echo "   SSID=your_network_name"
    echo "   PASSWORD=your_network_password"
    echo ""
    echo "2. Run this installation script again."
    echo "========================================================================"
fi
