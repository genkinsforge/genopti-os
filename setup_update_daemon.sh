#!/bin/bash
# Setup script for GenOpti-User Update Daemon

set -e

echo "Setting up GenOpti-User Update Daemon..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

# Paths
SERVICE_FILE="/etc/systemd/system/genopti-update-daemon.service"
SOURCE_SERVICE="/home/genopti-user/genopti-os/genopti-update-daemon.service"
DAEMON_SCRIPT="/home/genopti-user/genopti-os/genopti_user_update_daemon.py"

# Check if daemon script exists
if [ ! -f "$DAEMON_SCRIPT" ]; then
    echo "ERROR: Daemon script not found at $DAEMON_SCRIPT"
    exit 1
fi

# Make daemon script executable
chmod +x "$DAEMON_SCRIPT"
echo "Made daemon script executable"

# Copy service file
if [ -f "$SOURCE_SERVICE" ]; then
    cp "$SOURCE_SERVICE" "$SERVICE_FILE"
    echo "Copied service file to $SERVICE_FILE"
else
    echo "ERROR: Service file not found at $SOURCE_SERVICE"
    exit 1
fi

# Set proper permissions for service file
chmod 644 "$SERVICE_FILE"

# Create communication directory with proper permissions
mkdir -p /tmp/genopti-updates
chmod 755 /tmp/genopti-updates
echo "Created communication directory: /tmp/genopti-updates"

# Ensure genopti-user has sudo access for system updates
# Check if genopti-user already has sudo access
if ! sudo -u genopti-user sudo -n echo "test" > /dev/null 2>&1; then
    echo "Setting up sudo access for genopti-user..."
    
    # Create sudoers file for genopti-user
    cat > /etc/sudoers.d/genopti-user-updates << 'EOF'
# Allow genopti-user to run install scripts and manage systemd service
genopti-user ALL=(ALL) NOPASSWD: /home/genopti-user/genopti-os/install_genopti-os.sh
genopti-user ALL=(ALL) NOPASSWD: /bin/systemctl restart genopti-os.service
genopti-user ALL=(ALL) NOPASSWD: /bin/systemctl stop genopti-os.service
genopti-user ALL=(ALL) NOPASSWD: /bin/systemctl start genopti-os.service
genopti-user ALL=(ALL) NOPASSWD: /bin/systemctl is-active genopti-os.service
genopti-user ALL=(ALL) NOPASSWD: /bin/systemctl status genopti-os.service
EOF
    
    chmod 440 /etc/sudoers.d/genopti-user-updates
    echo "Configured sudo access for genopti-user"
else
    echo "genopti-user already has sudo access"
fi

# Reload systemd
systemctl daemon-reload
echo "Reloaded systemd configuration"

# Enable the service
systemctl enable genopti-update-daemon.service
echo "Enabled genopti-update-daemon service"

# Start the service
systemctl start genopti-update-daemon.service
echo "Started genopti-update-daemon service"

# Wait a moment and check status
sleep 2
if systemctl is-active --quiet genopti-update-daemon.service; then
    echo "✓ GenOpti-User Update Daemon is running successfully"
    
    # Show service status
    echo ""
    echo "Service Status:"
    systemctl status genopti-update-daemon.service --no-pager -l
    
    # Check communication files
    echo ""
    echo "Communication Directory:"
    ls -la /tmp/genopti-updates/ 2>/dev/null || echo "No communication files yet (this is normal)"
    
else
    echo "✗ Failed to start GenOpti-User Update Daemon"
    echo "Service logs:"
    journalctl -u genopti-update-daemon.service --no-pager -l
    exit 1
fi

echo ""
echo "=========================================="
echo "GenOpti-User Update Daemon Setup Complete"
echo "=========================================="
echo ""
echo "The daemon is now running and will:"
echo "  • Check for updates every hour"
echo "  • Communicate with genopti-svc via files in /tmp/genopti-updates/"
echo "  • Handle update installations with proper genopti-user permissions"
echo ""
echo "Service commands:"
echo "  sudo systemctl status genopti-update-daemon.service    # Check status"
echo "  sudo systemctl restart genopti-update-daemon.service   # Restart daemon"
echo "  sudo journalctl -u genopti-update-daemon.service -f    # View logs"
echo ""