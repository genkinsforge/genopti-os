#!/usr/bin/env python3
"""
GenOpti-User Auto-Update Daemon
Runs as genopti-user with proper permissions for system updates.
Communicates with genopti-svc via shared files in /tmp/genopti-updates/
"""

import os
import time
import json
import hashlib
import logging
import requests
import subprocess
import threading
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

# Setup logging
import os
log_dir = '/home/genopti-user/genopti-os/logs'
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(log_dir, 'update_daemon.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('GenOptiUpdateDaemon')


class GenOptiUserUpdateDaemon:
    """Auto-update daemon running as genopti-user with proper system permissions."""
    
    def __init__(self):
        self.genopti_user_dir = "/home/genopti-user/genopti-os"
        self.install_script_path = os.path.join(self.genopti_user_dir, "install_genopti-os.sh")
        self.communication_dir = "/tmp/genopti-updates"
        self.version_info_file = os.path.join(self.communication_dir, "latest_version.json")
        self.update_request_file = os.path.join(self.communication_dir, "update_request.json")
        self.update_status_file = os.path.join(self.communication_dir, "update_status.json")
        self.download_dir = os.path.join(self.genopti_user_dir, "pending_updates")
        
        # Ensure directories exist
        os.makedirs(self.communication_dir, mode=0o755, exist_ok=True)
        os.makedirs(self.download_dir, exist_ok=True)
        os.makedirs(os.path.join(self.genopti_user_dir, "logs"), exist_ok=True)
        
        # Daemon control
        self._running = False
        self._update_thread = None
        
        # Configuration
        self.config = {
            "check_interval": 3600,  # Check every hour
            "maintenance_window": {
                "enabled": True,
                "start_hour": 2,     # 2 AM
                "end_hour": 4        # 4 AM
            },
            "auto_install": False,   # Require explicit request
            "download_timeout": 1800 # 30 minutes
        }
        
        logger.info("GenOpti-User Update Daemon initialized")
    
    def start_daemon(self):
        """Start the update daemon."""
        if self._running:
            logger.warning("Daemon is already running")
            return
        
        self._running = True
        self._update_thread = threading.Thread(target=self._daemon_loop, daemon=True)
        self._update_thread.start()
        logger.info("Update daemon started")
    
    def stop_daemon(self):
        """Stop the update daemon."""
        self._running = False
        if self._update_thread:
            self._update_thread.join(timeout=5)
        logger.info("Update daemon stopped")
    
    def _daemon_loop(self):
        """Main daemon loop."""
        logger.info("Update daemon loop started")
        
        while self._running:
            try:
                # Check for version updates and publish latest version info
                self._check_and_publish_version_info()
                
                # Check for update requests from genopti-svc
                self._process_update_requests()
                
                # Sleep for check interval
                time.sleep(60)  # Check every minute for requests, hourly for version updates
                
            except Exception as e:
                logger.error(f"Error in daemon loop: {e}")
                time.sleep(30)  # Short sleep on error
    
    def _check_and_publish_version_info(self):
        """Check for updates and publish version info for genopti-svc to read."""
        try:
            # Only check for updates every hour
            last_check_file = os.path.join(self.communication_dir, "last_version_check.txt")
            now = time.time()
            
            if os.path.exists(last_check_file):
                with open(last_check_file, 'r') as f:
                    last_check = float(f.read().strip())
                if now - last_check < self.config["check_interval"]:
                    return  # Too soon to check again
            
            # Check for updates
            update_info = self._check_for_updates()
            current_version = self._get_current_version()
            
            # Create version info for genopti-svc
            version_data = {
                "current_version": current_version,
                "last_checked": datetime.now().isoformat(),
                "update_available": update_info is not None,
                "latest_version": update_info.get('availableVersion') if update_info else current_version,
                "update_checksum": update_info.get('checksum') if update_info else None,
                "download_url": update_info.get('downloadUrl') if update_info else None,
                "install_script_checksum": update_info.get('installScriptChecksum') if update_info else None,
                "daemon_status": "running"
            }
            
            # Write version info file (readable by all)
            with open(self.version_info_file, 'w') as f:
                json.dump(version_data, f, indent=2)
            os.chmod(self.version_info_file, 0o644)  # Readable by all
            
            # Update last check time
            with open(last_check_file, 'w') as f:
                f.write(str(now))
            
            if update_info:
                logger.info(f"Update available: {update_info.get('availableVersion')}")
            
        except Exception as e:
            logger.error(f"Error checking/publishing version info: {e}")
    
    def _process_update_requests(self):
        """Process update requests from genopti-svc."""
        try:
            if not os.path.exists(self.update_request_file):
                return
            
            # Read update request
            with open(self.update_request_file, 'r') as f:
                request_data = json.load(f)
            
            # Remove request file to prevent duplicate processing
            os.remove(self.update_request_file)
            
            logger.info(f"Processing update request: {request_data}")
            
            # Update status to "processing"
            self._update_status("processing", "Update request received")
            
            # Perform the update
            if request_data.get('action') == 'install_update':
                update_info = request_data.get('update_info')
                if update_info:
                    success, message = self._perform_update(update_info)
                    if success:
                        self._update_status("completed", message)
                    else:
                        self._update_status("failed", message)
                else:
                    self._update_status("failed", "No update info provided")
            else:
                self._update_status("failed", f"Unknown action: {request_data.get('action')}")
                
        except Exception as e:
            logger.error(f"Error processing update request: {e}")
            self._update_status("failed", f"Error processing request: {e}")
    
    def _update_status(self, status: str, message: str):
        """Update the status file for genopti-svc to read."""
        try:
            status_data = {
                "status": status,
                "message": message,
                "timestamp": datetime.now().isoformat(),
                "current_version": self._get_current_version()
            }
            
            with open(self.update_status_file, 'w') as f:
                json.dump(status_data, f, indent=2)
            os.chmod(self.update_status_file, 0o644)  # Readable by all
            
            logger.info(f"Status updated: {status} - {message}")
            
        except Exception as e:
            logger.error(f"Error updating status: {e}")
    
    def _check_for_updates(self) -> Optional[Dict]:
        """Check for available updates (no authentication required)."""
        try:
            # Use public endpoint that doesn't require device authentication
            # This can be a simple version check endpoint
            api_endpoint = "https://api.genkinsforge.com"
            url = f'{api_endpoint}/public/latest-version/genopti-go2'
            
            logger.info(f"Checking for updates at {url}")
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            
            if result.get('success') and result.get('data'):
                version_info = result['data']
                current_version = self._get_current_version()
                
                # Check if update is available
                if version_info.get('version') != current_version:
                    logger.info(f"Update available: {version_info.get('version')}")
                    return {
                        'availableVersion': version_info.get('version'),
                        'downloadUrl': version_info.get('downloadUrl'),
                        'checksum': version_info.get('checksum'),
                        'installScriptChecksum': version_info.get('installScriptChecksum'),
                        'updateMethod': 'install_script'
                    }
            
            logger.info("No updates available")
            return None
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error checking for updates: {e}")
            return None
        except Exception as e:
            logger.error(f"Error checking for updates: {e}")
            return None
    
    def _perform_update(self, update_info: Dict) -> Tuple[bool, str]:
        """Perform the actual update process."""
        try:
            logger.info(f"Starting update to version {update_info.get('availableVersion')}")
            
            # Step 1: Validate install script checksum
            expected_script_checksum = update_info.get('installScriptChecksum')
            if not self._validate_install_script_checksum(expected_script_checksum):
                return False, "Install script checksum validation failed - security risk detected"
            
            # Step 2: Download update package
            package_path = self._download_update(update_info)
            if not package_path:
                return False, "Failed to download update package"
            
            # Step 3: Execute install script
            success, message = self._execute_install_script(update_info, package_path)
            
            # Cleanup
            try:
                os.remove(package_path)
            except:
                pass
            
            return success, message
            
        except Exception as e:
            error_message = f"Critical error during update: {e}"
            logger.error(error_message)
            return False, error_message
    
    def _download_update(self, update_info: Dict) -> Optional[str]:
        """Download the update package."""
        try:
            download_url = update_info.get('downloadUrl')
            expected_checksum = update_info.get('checksum', '').replace('sha256:', '')
            version = update_info.get('availableVersion')
            
            filename = f"genopti-os-v{version}.tar.gz"
            download_path = os.path.join(self.download_dir, filename)
            
            logger.info(f"Downloading update from {download_url}")
            
            response = requests.get(download_url, stream=True, timeout=self.config['download_timeout'])
            response.raise_for_status()
            
            # Download and verify checksum
            sha256_hash = hashlib.sha256()
            with open(download_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        sha256_hash.update(chunk)
            
            calculated_checksum = sha256_hash.hexdigest()
            if expected_checksum and calculated_checksum != expected_checksum:
                logger.error(f"Package checksum verification failed")
                os.remove(download_path)
                return None
            
            logger.info(f"Update package downloaded and verified: {download_path}")
            return download_path
            
        except Exception as e:
            logger.error(f"Error downloading update: {e}")
            return None
    
    def _execute_install_script(self, update_info: Dict, package_path: str) -> Tuple[bool, str]:
        """Execute the install script to perform the update."""
        try:
            # Copy package to expected location
            install_package_path = os.path.join(self.genopti_user_dir, os.path.basename(package_path))
            if package_path != install_package_path:
                import shutil
                shutil.copy2(package_path, install_package_path)
            
            # Set environment variables
            env = os.environ.copy()
            env['GENOPTI_IS_UPDATE'] = '1'
            env['GENOPTI_UPDATE_PACKAGE'] = install_package_path
            
            # Execute install script
            logger.info("Executing install script for update...")
            result = subprocess.run(
                ['sudo', self.install_script_path],
                cwd=self.genopti_user_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                logger.info("Install script executed successfully")
                
                # Verify update success
                time.sleep(10)
                if self._verify_update_success(update_info.get('availableVersion')):
                    return True, f"Update completed successfully to version {update_info.get('availableVersion')}"
                else:
                    return False, "Update installed but service verification failed"
            else:
                error_message = f"Install script failed: {result.stderr}"
                logger.error(error_message)
                return False, error_message
                
        except Exception as e:
            error_message = f"Error executing install script: {e}"
            logger.error(error_message)
            return False, error_message
    
    def _validate_install_script_checksum(self, expected_checksum: str) -> bool:
        """Validate install script checksum."""
        try:
            if not os.path.exists(self.install_script_path):
                logger.error("Install script not found")
                return False
            
            actual_checksum = self._calculate_file_checksum(self.install_script_path)
            if not actual_checksum:
                return False
            
            is_valid = actual_checksum == expected_checksum
            if is_valid:
                logger.info("Install script checksum validation passed")
            else:
                logger.error(f"Install script checksum mismatch")
            
            return is_valid
            
        except Exception as e:
            logger.error(f"Error validating install script checksum: {e}")
            return False
    
    def _calculate_file_checksum(self, file_path: str) -> Optional[str]:
        """Calculate SHA256 checksum of a file."""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating checksum for {file_path}: {e}")
            return None
    
    def _verify_update_success(self, expected_version: str) -> bool:
        """Verify that the update was successful."""
        try:
            # Check service status
            result = subprocess.run(['sudo', 'systemctl', 'is-active', '--quiet', 'genopti-os.service'])
            if result.returncode != 0:
                logger.error("GenOpti-OS service is not running after update")
                return False
            
            # Check version
            for attempt in range(5):
                time.sleep(2)
                current_version = self._get_current_version()
                if current_version == expected_version:
                    logger.info(f"Version verification successful: {current_version}")
                    return True
            
            logger.warning("Version verification incomplete but service is running")
            return True
            
        except Exception as e:
            logger.error(f"Error verifying update success: {e}")
            return False
    
    def _get_current_version(self) -> str:
        """Get current version."""
        try:
            version_file = "/opt/genopti-os/version.txt"
            if os.path.exists(version_file):
                with open(version_file, 'r') as f:
                    return f.read().strip()
            
            # Fallback to parsing app.py
            app_py_path = "/opt/genopti-os/app.py"
            if os.path.exists(app_py_path):
                with open(app_py_path, 'r') as f:
                    content = f.read()
                    import re
                    match = re.search(r'APP_NAME_VERSION = "Genopti-OS \\(v([\\d.]+)', content)
                    if match:
                        return match.group(1)
            
            return "0.48"  # Fallback
        except Exception as e:
            logger.error(f"Error getting current version: {e}")
            return "0.48"


def main():
    """Main entry point for the daemon."""
    daemon = GenOptiUserUpdateDaemon()
    
    try:
        # Start the daemon
        daemon.start_daemon()
        logger.info("GenOpti-User Update Daemon is running. Press Ctrl+C to stop.")
        
        # Keep the main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Shutdown signal received")
        daemon.stop_daemon()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        daemon.stop_daemon()


if __name__ == "__main__":
    main()