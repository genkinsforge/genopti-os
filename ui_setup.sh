#!/bin/bash

# Create a shell script to launch Chromium in kiosk mode
LAUNCH_SCRIPT="$HOME/launch_chromium.sh"
echo "Creating launch script for Chromium at $LAUNCH_SCRIPT..."
cat << 'EOF' > "$LAUNCH_SCRIPT"
#!/bin/bash
# Launch Chromium in kiosk mode
/usr/bin/chromium-browser --kiosk http://localhost:5000
EOF

chmod +x "$LAUNCH_SCRIPT"

# Create an autostart entry for launching Chromium
AUTOSTART_FILE="$HOME/.config/autostart/launch-chromium.desktop"
echo "Creating autostart entry for launching Chromium at $AUTOSTART_FILE..."
mkdir -p "$(dirname "$AUTOSTART_FILE")"

cat << EOF > "$AUTOSTART_FILE"
[Desktop Entry]
Type=Application
Exec=$LAUNCH_SCRIPT
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Name=Launch Chromium in Kiosk Mode
EOF

echo "Chromium kiosk mode setup complete."
