#!/bin/bash
#
# ui_setup.sh
# Sets up Chromium to launch automatically in kiosk mode at system startup,
# with recommended flags to hide error dialogs, address bar, etc.

set -e

# Variables
LAUNCH_SCRIPT="$HOME/launch_chromium.sh"
AUTOSTART_FILE="$HOME/.config/autostart/launch-chromium.desktop"
KIOSK_URL="http://localhost:5000"  # Adjust to your actual URL if needed

echo "Creating launch script for Chromium at $LAUNCH_SCRIPT..."
cat << 'EOF' > "$LAUNCH_SCRIPT"
#!/bin/bash

# Disable screen blanking and power management
xset s off
xset -dpms
xset s noblank

# Optionally hide the mouse pointer after a short idle
# (uncomment if you want to install/unclutter)
# sudo apt-get install -y unclutter
# unclutter -idle 0.5 -root &

# Launch Chromium in kiosk mode with various flags:
# --kiosk:        launch in full screen without UI
# --incognito:    avoid saving session data
# --noerrdialogs: suppress certain Chromium error dialogs
# --disable-infobars: hide the "Chrome is being controlled by automated test software" bar
# --autoplay-policy=no-user-gesture-required: allow certain media interactions without gestures
# --start-fullscreen: ensures we are truly fullscreen
# --test-type:    suppress warnings about missing security features
/usr/bin/chromium-browser \
  --kiosk \
  --incognito \
  --noerrdialogs \
  --disable-infobars \
  --autoplay-policy=no-user-gesture-required \
  --start-fullscreen \
  --test-type \
  "$KIOSK_URL"
EOF

chmod +x "$LAUNCH_SCRIPT"

echo "Creating autostart entry for Chromium at $AUTOSTART_FILE..."
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
echo "Script created at: $LAUNCH_SCRIPT"
echo "Autostart desktop file created at: $AUTOSTART_FILE"
echo "You may need to log out/in or reboot to see the effect."

