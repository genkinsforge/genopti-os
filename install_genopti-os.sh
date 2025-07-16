#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# ANSI color codes for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables
SERVICE_USER="genopti-svc"
SERVICE_GROUP="genopti-svc"
APP_DIR="/opt/genopti-os"
VENV_DIR="$APP_DIR/venv"
SERVICE_NAME="genopti-os"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
APP_SCRIPT="$APP_DIR/app.py"
PYTHON_EXEC="$VENV_DIR/bin/python" # Define python executable path

# Default Environment Variable Values from systemd unit file
DEFAULT_DEBUG_MODE="0"            # 0=normal mode, 1=debug
DEFAULT_SCAN_RESET_SECONDS="15"   # Time in seconds before clearing the screen
DEFAULT_SCAN_INACTIVITY_MS="300"  # Inactivity timeout in ms before finalizing the scan

# Polkit Variables
POLKIT_RULE_DIR="/etc/polkit-1/rules.d"
POLKIT_RULE_FILE_NAME="46-genopti-wifi-manage.rules" # Specific name for our rule
POLKIT_RULE_PATH="$POLKIT_RULE_DIR/$POLKIT_RULE_FILE_NAME"

# --[ Root Check ]------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root.${NC}"
   exit 1
fi

echo -e "${BLUE}Installing $SERVICE_NAME...${NC}"

# --[ Initial WiFi Check/Setup Attempt (Optional) ]---------------------------
if [ -f "wifi-credentials.txt" ]; then
    echo "Found WiFi credentials file (wifi-credentials.txt)."
    chmod 600 "wifi-credentials.txt"
    WIFI_SSID=$(grep -oP '^SSID=\K.*' "wifi-credentials.txt" || true)
    WIFI_PASSWORD=$(grep -oP '^PASSWORD=\K.*' "wifi-credentials.txt" || true)
    if [ -n "$WIFI_SSID" ] && [ -n "$WIFI_PASSWORD" ]; then
        echo "Attempting to configure WiFi using NetworkManager (nmcli)..."
        if command -v nmcli &> /dev/null; then
            # We need root privileges here during install if using this method
            if nmcli device wifi connect "$WIFI_SSID" password "$WIFI_PASSWORD"; then
                echo -e "${GREEN}WiFi connected successfully via nmcli during installation!${NC}"
                echo "Removing temporary wifi-credentials.txt for security..."
                shred -u "wifi-credentials.txt" || rm -f "wifi-credentials.txt"
            else
                echo -e "${YELLOW}WARN: Failed to connect using nmcli during installation (may require network config later).${NC}"
            fi
        else
            echo -e "${YELLOW}WARN: nmcli command not found. Cannot attempt WiFi setup during installation.${NC}"
        fi
    else
        echo -e "${YELLOW}WARN: wifi-credentials.txt format incorrect or incomplete.${NC}"
    fi
elif [ -f "wifi-credentials.txt.template" ]; then
     echo "INFO: wifi-credentials.txt not found. Copy template to configure."
else
     echo "INFO: No WiFi credentials file or template found. Skipping initial WiFi setup."
fi

# --[ Create or update system user ]------------------------------------------
if ! getent group "$SERVICE_GROUP" > /dev/null; then echo "Creating system group: $SERVICE_GROUP..."; groupadd --system "$SERVICE_GROUP"; fi
if ! id "$SERVICE_USER" &>/dev/null; then echo "Creating system user: $SERVICE_USER..."; useradd --system --no-create-home --shell /usr/sbin/nologin --gid "$SERVICE_GROUP" "$SERVICE_USER"; echo "User $SERVICE_USER created."; else echo "User $SERVICE_USER already exists."; usermod -g "$SERVICE_GROUP" "$SERVICE_USER"; fi
echo "Adding $SERVICE_USER to 'netdev' group for NetworkManager permissions (may not be sufficient for modification)..."
usermod -a -G netdev "$SERVICE_USER" || echo -e "${YELLOW}WARN: Failed to add $SERVICE_USER to netdev group.${NC}"

# --[ Remove dangerous sudoers configuration ]--------------------------------
SUDOERS_FILE="/etc/sudoers.d/$SERVICE_USER"
if [ -f "$SUDOERS_FILE" ]; then echo "Removing potentially insecure sudoers file: $SUDOERS_FILE"; rm -f "$SUDOERS_FILE"; fi

# --[ Polkit Setup for NetworkManager Permissions ]---------------------------
echo -e "${BLUE}Setting up Polkit rule for NetworkManager access...${NC}"
# Check if Polkit seems to be available
if ! command -v pkexec &> /dev/null && ! systemctl list-units --type=service | grep -q 'polkit.service'; then
  echo -e "${YELLOW}WARN: Polkit (pkexec/polkit.service) not detected. WiFi setup via QR code might fail due to permissions.${NC}"
else
  # Create the rule directory if it doesn't exist
  mkdir -p "$POLKIT_RULE_DIR"

  # Create the Polkit rule file using a here document
  echo "Creating Polkit rule at $POLKIT_RULE_PATH..."
  cat > "$POLKIT_RULE_PATH" << EOF
/*
 * Allow the '$SERVICE_USER' user (running the Genopti-OS application)
 * to perform specific WiFi operations via NetworkManager without password.
 * This provides minimal necessary permissions for QR code WiFi setup.
 */
polkit.addRule(function(action, subject) {
    if (subject.user === "$SERVICE_USER") {
        // Allow specific WiFi-related actions only
        if (action.id == "org.freedesktop.NetworkManager.wifi.share.open" ||
            action.id == "org.freedesktop.NetworkManager.wifi.share.protected" ||
            action.id == "org.freedesktop.NetworkManager.network-control") {
            // Grant permission for WiFi connection operations
            return polkit.Result.YES;
        }
        // Deny broader system settings modification
        if (action.id == "org.freedesktop.NetworkManager.settings.modify.system") {
            return polkit.Result.NO;
        }
    }
    // Default: ask for authentication
    return polkit.Result.NOT_HANDLED;
});
EOF

  # Set correct ownership and permissions for the rule file
  echo "Setting ownership and permissions for Polkit rule..."
  chown root:root "$POLKIT_RULE_PATH"
  chmod 644 "$POLKIT_RULE_PATH"
  echo "Polkit rule created and permissions set."

  # Reload Polkit service to apply the new rule
  echo "Reloading Polkit service..."
  if systemctl reload polkit.service; then
      echo "Polkit service reloaded successfully."
  elif systemctl restart polkit.service; then
      echo "Polkit service restarted successfully (reload failed)."
  else
      echo -e "${YELLOW}WARN: Failed to reload or restart polkit.service. Rule may not be active until next reboot.${NC}"
  fi
  sleep 1 # Brief pause to allow service reload
fi
# --[ End Polkit Setup ]------------------------------------------------------

# --[ Stop Service Before Cleaning ]-------------------------------------------
if systemctl is-active --quiet "$SERVICE_NAME"; then echo "Stopping existing $SERVICE_NAME service..."; systemctl stop "$SERVICE_NAME".service || true; fi
if systemctl is-enabled --quiet "$SERVICE_NAME"; then echo "Disabling $SERVICE_NAME service temporarily..."; systemctl disable "$SERVICE_NAME".service || true; fi

# --[ Create or clean application directory (Force Clean Venv) ]---------------
if [ ! -d "$APP_DIR" ]; then echo "Creating application directory at $APP_DIR..."; mkdir -p "$APP_DIR"; else
    echo "Cleaning application directory $APP_DIR for reinstallation..."
    LOG_BACKUP_DIR="/tmp/genopti-logs-backup"
    if [ -d "$APP_DIR/logs" ]; then echo "Backing up logs to $LOG_BACKUP_DIR..."; rm -rf "$LOG_BACKUP_DIR"; mv "$APP_DIR/logs" "$LOG_BACKUP_DIR"; fi
    echo "Removing existing virtual environment $VENV_DIR..."; rm -rf "$VENV_DIR"
    find "$APP_DIR" -mindepth 1 -maxdepth 1 -path "$VENV_DIR" -prune -o -exec rm -rf {} \;
fi

# --[ Copy application files explicitly ]-------------------------------------
echo "Copying application files to $APP_DIR..."
if [ ! -f "app.py" ] || [ ! -f "requirements.txt" ] || [ ! -d "templates" ]; then echo -e "${RED}ERROR: Core application files missing.${NC}"; exit 1; fi
cp app.py "$APP_DIR/"; cp requirements.txt "$APP_DIR/"; cp -r templates "$APP_DIR/"
[ -f README.md ] && cp README.md "$APP_DIR/"; [ -f LICENSE ] && cp LICENSE "$APP_DIR/"
[ -f wifi-credentials.txt.template ] && cp wifi-credentials.txt.template "$APP_DIR/"
mkdir -p "$APP_DIR/logs"

# --[ Ensure app.py has Shebang ]---------------------------------------------
echo "Ensuring $APP_SCRIPT has correct shebang..."
if ! head -n 1 "$APP_SCRIPT" | grep -q -E '^#!/usr/bin/env python|^#!/usr/bin/python'; then echo -e "#!/usr/bin/env python3\n$(cat "$APP_SCRIPT")" > "$APP_SCRIPT"; echo "Added #!/usr/bin/env python3 shebang to $APP_SCRIPT"; fi

# --[ Install system packages for Python ]------------------------------------
echo "Updating package list and installing/verifying Python dependencies..."
apt-get update
# Ensure network-manager and policykit-1 are included for dependencies
REQUIRED_PKGS="python3 python3-venv python3-pip network-manager policykit-1"
INSTALL_PKGS=""; for PKG in $REQUIRED_PKGS; do if ! dpkg -s "$PKG" &> /dev/null; then echo "Package $PKG not found, scheduling for installation."; INSTALL_PKGS="$INSTALL_PKGS $PKG"; else echo "Package $PKG already installed."; fi; done
if [ -n "$INSTALL_PKGS" ]; then echo "Installing missing packages: $INSTALL_PKGS"; apt-get install -y $INSTALL_PKGS; else echo "All required system packages are already installed."; fi

# --[ Create/Update Python virtual environment (USING --copies) ]-------------
echo "Removing existing virtual environment $VENV_DIR (if any)..."
rm -rf "$VENV_DIR"
echo "Creating new Python virtual environment in $VENV_DIR using --copies..."
# *** Use the --copies flag ***
python3 -m venv --copies "$VENV_DIR"
if [ $? -ne 0 ]; then echo -e "${RED}ERROR: Failed to create virtual environment with --copies.${NC}"; exit 1; fi
echo "Virtual environment created successfully with copies."

echo "Activating virtual environment and installing dependencies..."
source "$VENV_DIR/bin/activate"
echo "Upgrading pip within virtual environment (using --break-system-packages)..."
pip install --upgrade pip --break-system-packages || echo -e "${YELLOW}WARN: Failed to upgrade pip. Continuing...${NC}"
REQUIREMENTS_FILE_PATH="$APP_DIR/requirements.txt"
echo "Installing Python dependencies using pip (with --break-system-packages)..."
pip install --break-system-packages -r "$REQUIREMENTS_FILE_PATH"
if [ $? -ne 0 ]; then echo -e "${RED}ERROR: Failed to install Python dependencies.${NC}"; deactivate; exit 1; fi
echo "Python dependencies installed successfully."
deactivate

# --[ Adjust ownership and permissions ]--------------------------------------
echo "Setting ownership of $APP_DIR to $SERVICE_USER:$SERVICE_GROUP..."
chown -R "$SERVICE_USER":"$SERVICE_GROUP" "$APP_DIR"

echo "Setting permissions for $APP_DIR..."
# Dirs: rwxr-x--- (750)
# Files: rw-r----- (640)
find "$APP_DIR" -type d -exec chmod 750 {} \;
find "$APP_DIR" -type f -exec chmod 640 {} \;

# Grant execute permission specifically to the application script
if [ -f "$APP_SCRIPT" ]; then chmod 750 "$APP_SCRIPT"; echo "Execute permission granted for $APP_SCRIPT"; fi

# Grant execute permissions for the venv bin directory and its contents
if [ -d "$VENV_DIR/bin" ]; then
    echo "Setting execute permissions (ug+x) on $VENV_DIR/bin and its contents..."
    chmod 750 "$VENV_DIR/bin" # Ensure bin dir is traversable/executable
    find "$VENV_DIR/bin/" -type f -exec chmod ug+x {} \; # Ensure files inside are executable
    echo "Execute permissions set for $VENV_DIR/bin contents."
else
    echo -e "${YELLOW}WARN: $VENV_DIR/bin directory not found within venv.${NC}"
fi
if [ -d "$APP_DIR/logs" ]; then chmod g+w "$APP_DIR/logs"; echo "Write permissions granted to group for $APP_DIR/logs"; fi
echo "File permissions set."

# --[ Permission Verification ]-----------------------------------------------
echo "Verifying permissions for Python executable..."
if [ -f "$PYTHON_EXEC" ]; then
    ls -l "$PYTHON_EXEC"
    # Check if it's a symlink (it shouldn't be with --copies)
    if [ -L "$PYTHON_EXEC" ]; then
        echo -e "${YELLOW}WARN: $PYTHON_EXEC is still a symbolic link despite using --copies?${NC}"
        ls -l /opt/genopti-os/venv/bin/python* # Show all python links/files
    fi
    if sudo -u "$SERVICE_USER" "$PYTHON_EXEC" --version > /dev/null 2>&1; then
        echo -e "${GREEN}Successfully verified execute permission for $PYTHON_EXEC as user $SERVICE_USER.${NC}"
    else
        echo -e "${RED}ERROR: Failed to verify execute permission for $PYTHON_EXEC as user $SERVICE_USER even after using --copies.${NC}"
        echo -e "${RED}This indicates a deeper system issue or restriction.${NC}"
    fi
else
    echo -e "${RED}ERROR: Python executable not found at $PYTHON_EXEC after venv creation!${NC}"; exit 1
fi

# --[ Create device ID file with proper permissions ]--------------------------
DEVICE_ID_FILE="/etc/device_id"
echo "Ensuring $DEVICE_ID_FILE file exists with proper permissions..."
touch "$DEVICE_ID_FILE"
if [ ! -s "$DEVICE_ID_FILE" ]; then CPU_SERIAL=$(grep -i "^Serial" /proc/cpuinfo | awk '{print $3}' || true); if [ -n "$CPU_SERIAL" ] && [ "$CPU_SERIAL" != "0000000000000000" ]; then echo "$CPU_SERIAL" > "$DEVICE_ID_FILE"; echo "Initialized $DEVICE_ID_FILE with CPU Serial: $CPU_SERIAL"; else FALLBACK_ID=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16); echo "FALLBACK-$FALLBACK_ID" > "$DEVICE_ID_FILE"; echo -e "${YELLOW}WARN: Could not determine valid CPU serial. Initialized $DEVICE_ID_FILE with fallback ID.${NC}"; fi; fi
chown "$SERVICE_USER":"$SERVICE_GROUP" "$DEVICE_ID_FILE"; chmod 660 "$DEVICE_ID_FILE"

# --[ Create or update systemd service file ]--------
# NOTE: No change needed here vs previous Polkit version, the Polkit rule handles permissions externally
echo "Setting up systemd service at $SERVICE_FILE..."
cat > "$SERVICE_FILE" <<EOL
[Unit]
Description=Genopti-OS Flask App Service
After=network-online.target polkit.service
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$APP_DIR
ExecStart=$PYTHON_EXEC $APP_SCRIPT
Restart=on-failure
RestartSec=5s
Environment=PYTHONUNBUFFERED=1

Environment=DEBUG_MODE=${DEFAULT_DEBUG_MODE}
Environment=SCAN_RESET_SECONDS=${DEFAULT_SCAN_RESET_SECONDS}
Environment=SCAN_INACTIVITY_MS=${DEFAULT_SCAN_INACTIVITY_MS}

# Consider re-enabling security options after testing
# PrivateTmp=true
# ProtectSystem=strict
# ProtectHome=true
# NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOL

# --[ Reload systemd and start the service ]----------------------------------
echo "Reloading systemd daemon..."
systemctl daemon-reload
echo "Re-enabling the $SERVICE_NAME service..."
systemctl enable "$SERVICE_NAME".service
echo "Starting $SERVICE_NAME service..."
sleep 1
systemctl start "$SERVICE_NAME".service

# --[ Verify service status ]-------------------------------------------------
echo "Verifying service status (waiting a few seconds)..."
sleep 4
if systemctl is-active --quiet "$SERVICE_NAME"; then
     echo -e "${GREEN}SUCCESS: Service $SERVICE_NAME is active and running.${NC}"
     echo -e "${GREEN}Polkit rule for NetworkManager access has been configured.${NC}"
     systemctl status "$SERVICE_NAME".service --no-pager || true
else
     echo -e "${RED}ERROR: Service $SERVICE_NAME failed to start.${NC}"
     systemctl status "$SERVICE_NAME".service --no-pager -l || true
     echo -e "${RED}Check logs: journalctl -u $SERVICE_NAME -n 50 -l ${NC}"
     echo -e "${RED}Also check Polkit status: systemctl status polkit.service${NC}"
     echo -e "${RED}And Polkit logs: journalctl -u polkit.service -n 50${NC}"
fi

# --[ Final Output & Checks ]-------------------------------------------------
echo "$SERVICE_NAME installed and expected to run under user '$SERVICE_USER'."
echo "Default ENV Vars: DEBUG_MODE=${DEFAULT_DEBUG_MODE}, SCAN_RESET_SECONDS=${DEFAULT_SCAN_RESET_SECONDS}, SCAN_INACTIVITY_MS=${DEFAULT_SCAN_INACTIVITY_MS}"
echo "App Directory: $APP_DIR"
echo "Log Directory: $APP_DIR/logs"
echo "Device ID File: $DEVICE_ID_FILE"
echo "Polkit Rule File: $POLKIT_RULE_PATH (if Polkit detected)"
echo "Performing final network connectivity check..."
PING_HOST="8.8.8.8"
if ping -c 1 -W 3 "$PING_HOST" > /dev/null 2>&1; then echo -e "${GREEN}Network connectivity check successful (ping $PING_HOST).${NC}"; else echo ""; echo -e "${YELLOW}================ WARN: No internet connectivity (ping $PING_HOST failed) ================${NC}"; echo -e "${YELLOW}Use Setup Mode ('$$setup$$') and '$$wifi$$' command to configure network.${NC}"; echo -e "${YELLOW}================================================================================${NC}"; fi
echo -e "${GREEN}Installation complete.${NC}"
