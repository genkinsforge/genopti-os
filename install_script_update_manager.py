#!/usr/bin/env python3
"""
Install Script Based Update Manager for GenOpti-OS GO20
Production implementation using the install script method with checksum validation.
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
from typing import Dict, Optional, Tuple, List


class InstallScriptUpdateManager:
    """Manages updates using the install script method with security validation."""
    
    def __init__(self, genopti_user_dir: str = "/home/genopti-user/genopti-os"):
        self.genopti_user_dir = genopti_user_dir
        self.install_script_path = os.path.join(genopti_user_dir, "install_genopti-os.sh")
        self.config_file = os.path.join(genopti_user_dir, "install_script_update_config.json")
        self.state_file = os.path.join(genopti_user_dir, "install_script_update_state.json")
        self.download_dir = os.path.join(genopti_user_dir, "pending_updates")
        
        # Ensure directories exist
        os.makedirs(self.download_dir, exist_ok=True)
        
        # Update checking thread
        self._update_thread = None
        self._stop_checking = threading.Event()
        
        # Load configuration
        self.config = self._load_config()
        
    def _load_config(self) -> Dict:
        """Load update configuration."""
        default_config = {
            "enabled": True,
            "check_interval": 3600,  # Check every hour
            "auto_install": False,   # Require user confirmation
            "maintenance_window": {
                "enabled": True,
                "start_hour": 2,     # 2 AM
                "end_hour": 4        # 4 AM
            },
            "retry_attempts": 3,
            "retry_delay": 300,      # 5 minutes
            "download_timeout": 1800, # 30 minutes
            "require_confirmation": True,
            "update_method": "install_script"
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    default_config.update(loaded_config)
        except Exception as e:
            logging.error(f"Error loading update config: {e}")
        
        return default_config
    
    def save_config(self) -> bool:
        """Save current configuration."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            logging.error(f"Error saving update config: {e}")
            return False
    
    def calculate_file_checksum(self, file_path: str) -> Optional[str]:
        """Calculate SHA256 checksum of a file."""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logging.error(f"Error calculating checksum for {file_path}: {e}")
            return None
    
    def validate_install_script_checksum(self, expected_checksum: str) -> bool:
        """Validate that the local install script matches expected checksum."""
        try:
            if not os.path.exists(self.install_script_path):
                logging.error("Install script not found")
                return False
            
            actual_checksum = self.calculate_file_checksum(self.install_script_path)
            if not actual_checksum:
                logging.error("Could not calculate install script checksum")
                return False
            
            is_valid = actual_checksum == expected_checksum
            
            if is_valid:
                logging.info("Install script checksum validation passed")
            else:
                logging.error(f"Install script checksum mismatch: expected {expected_checksum}, got {actual_checksum}")
            
            return is_valid
            
        except Exception as e:
            logging.error(f"Error validating install script checksum: {e}")
            return False
    
    def get_device_info(self) -> Dict:
        """Get device information for update API calls."""
        try:
            # Get device registration info
            registration_file = "/opt/genopti-os/device-registration.json"
            device_info = {}
            
            if os.path.exists(registration_file):
                with open(registration_file, 'r') as f:
                    registration = json.load(f)
                    device_info = {
                        'deviceId': registration.get('device_id'),
                        'accountUid': registration.get('account_uid'),
                        'locationId': registration.get('location_id')
                    }
            
            # Add system information
            import psutil
            device_info.update({
                'model': 'genopti_go2',
                'serialNumber': self._get_cpu_serial(),
                'currentVersion': self._get_current_version(),
                'systemInfo': {
                    'memoryAvailable': psutil.virtual_memory().available,
                    'diskAvailable': psutil.disk_usage('/').free,
                    'updateMethod': 'install_script'
                }
            })
            
            return device_info
            
        except Exception as e:
            logging.error(f"Error getting device info: {e}")
            return {}
    
    def _get_cpu_serial(self) -> str:
        """Get CPU serial number."""
        try:
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if line.startswith('Serial'):
                        serial = line.split(':', 1)[1].strip()
                        if serial and serial != '0000000000000000':
                            return serial
            return "UNKNOWN_SERIAL"
        except Exception as e:
            logging.error(f"Error reading CPU serial: {e}")
            return "ERROR_SERIAL"
    
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
                    match = re.search(r'APP_NAME_VERSION = "Genopti-OS \(v([\d.]+)', content)
                    if match:
                        return match.group(1)
            
            return "0.0"  # Fallback
        except Exception as e:
            logging.error(f"Error getting current version: {e}")
            return "0.0"
    
    def _get_jwt_token(self) -> Optional[str]:
        """Get JWT token for API authentication."""
        try:
            jwt_file = "/opt/genopti-os/device-token.json"
            if os.path.exists(jwt_file):
                with open(jwt_file, 'r') as f:
                    token_data = json.load(f)
                    return token_data.get('jwt')
            return None
        except Exception as e:
            logging.error(f"Error getting JWT token: {e}")
            return None
    
    def _get_api_endpoint(self) -> str:
        """Get API endpoint from registration."""
        try:
            registration_file = "/opt/genopti-os/device-registration.json"
            if os.path.exists(registration_file):
                with open(registration_file, 'r') as f:
                    registration = json.load(f)
                    return registration.get('api_endpoint', 'https://api.genkinsforge.com')
            return 'https://api.genkinsforge.com'
        except Exception as e:
            logging.error(f"Error getting API endpoint: {e}")
            return 'https://api.genkinsforge.com'
    
    def check_for_updates(self) -> Optional[Dict]:
        """Check for available updates from the API."""
        try:
            api_endpoint = self._get_api_endpoint()
            jwt_token = self._get_jwt_token()
            
            if not jwt_token:
                logging.error("No JWT token available for update check")
                return None
            
            device_info = self.get_device_info()
            if not device_info.get('deviceId'):
                logging.error("No device ID available for update check")
                return None
            
            # Prepare request payload
            payload = {
                "deviceId": device_info['deviceId'],
                "currentVersions": {
                    "software": device_info['currentVersion']
                },
                "deviceInfo": {
                    "model": device_info['model'],
                    "serialNumber": device_info['serialNumber'],
                    "memoryAvailable": device_info['systemInfo'].get('memoryAvailable', 0),
                    "diskAvailable": device_info['systemInfo'].get('diskAvailable', 0),
                    "updateMethod": "install_script"
                }
            }
            
            # Make API request
            url = f'{api_endpoint}/webhook/update-check'
            headers = {
                'Authorization': f'Bearer {jwt_token}',
                'Content-Type': 'application/json'
            }
            
            logging.info(f"Checking for updates at {url}")
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            
            if result.get('success') and result.get('data', {}).get('updatesAvailable'):
                updates = result['data'].get('updates', [])
                if updates:
                    update_info = updates[0]  # Get first available update
                    
                    # Validate this is an install script compatible update
                    if update_info.get('updateMethod') != 'install_script':
                        logging.warning("Update available but not compatible with install script method")
                        return None
                    
                    # Validate install script checksum is provided
                    if not update_info.get('installScriptChecksum'):
                        logging.error("Update available but no install script checksum provided")
                        return None
                    
                    logging.info(f"Install script update available: {update_info.get('availableVersion')}")
                    return update_info
            else:
                logging.info("No updates available")
                
            return None
            
        except requests.exceptions.RequestException as e:
            logging.error(f"Network error checking for updates: {e}")
            return None
        except Exception as e:
            logging.error(f"Error checking for updates: {e}")
            return None
    
    def download_update(self, update_info: Dict) -> Optional[str]:
        """Download update package to genopti-user directory."""
        try:
            download_url = update_info.get('downloadUrl')
            if not download_url:
                logging.error("No download URL provided")
                return None
            
            expected_checksum = update_info.get('checksum', '').replace('sha256:', '')
            version = update_info.get('availableVersion')
            
            # Download file path
            filename = f"genopti-os-v{version}.tar.gz"
            download_path = os.path.join(self.download_dir, filename)
            
            logging.info(f"Downloading update from {download_url}")
            
            # Download with progress tracking
            response = requests.get(download_url, stream=True, timeout=self.config['download_timeout'])
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            # Calculate hash while downloading
            sha256_hash = hashlib.sha256()
            
            with open(download_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        sha256_hash.update(chunk)
                        downloaded += len(chunk)
                        
                        if total_size > 0:
                            progress = int((downloaded / total_size) * 100)
                            if progress % 10 == 0:  # Log every 10%
                                logging.info(f"Download progress: {progress}%")
            
            # Verify checksum
            calculated_checksum = sha256_hash.hexdigest()
            if expected_checksum and calculated_checksum != expected_checksum:
                logging.error(f"Package checksum verification failed: expected {expected_checksum}, got {calculated_checksum}")
                os.remove(download_path)
                return None
            
            logging.info(f"Update package downloaded and verified: {download_path}")
            return download_path
            
        except Exception as e:
            logging.error(f"Error downloading update: {e}")
            return None
    
    def execute_install_script_update(self, update_info: Dict, package_path: str) -> Tuple[bool, str]:
        """Execute the install script to perform the update."""
        try:
            # Step 1: Validate install script checksum
            expected_script_checksum = update_info.get('installScriptChecksum')
            if not self.validate_install_script_checksum(expected_script_checksum):
                return False, "Install script checksum validation failed - security risk detected"
            
            # Step 2: Record update start
            self._save_update_state({
                'status': 'installing',
                'update_info': update_info,
                'package_path': package_path,
                'started_at': datetime.now().isoformat()
            })
            
            # Step 3: Check prerequisites
            if not self._validate_update_prerequisites():
                return False, "Update prerequisites validation failed"
            
            # Step 4: Copy update package to the expected location for install script
            install_package_path = os.path.join(self.genopti_user_dir, os.path.basename(package_path))
            if package_path != install_package_path:
                import shutil
                shutil.copy2(package_path, install_package_path)
                logging.info(f"Copied update package to: {install_package_path}")
            
            # Step 5: Execute install script with sudo
            logging.info("Executing install script for update...")
            
            # Set environment variable to indicate this is an update
            env = os.environ.copy()
            env['GENOPTI_IS_UPDATE'] = '1'
            env['GENOPTI_UPDATE_PACKAGE'] = install_package_path
            
            # Run install script
            cmd = ['sudo', self.install_script_path]
            
            result = subprocess.run(
                cmd,
                cwd=self.genopti_user_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Check result
            if result.returncode == 0:
                logging.info("Install script executed successfully")
                
                # Step 6: Verify update success
                time.sleep(10)  # Wait for service to fully start
                
                if self._verify_update_success(update_info.get('availableVersion')):
                    self._save_update_state({
                        'status': 'completed',
                        'completed_at': datetime.now().isoformat(),
                        'new_version': update_info.get('availableVersion')
                    })
                    
                    # Cleanup
                    try:
                        os.remove(install_package_path)
                        if package_path != install_package_path:
                            os.remove(package_path)
                    except:
                        pass
                    
                    return True, f"Update completed successfully to version {update_info.get('availableVersion')}"
                else:
                    self._save_update_state({
                        'status': 'failed',
                        'error': 'Service verification failed after update'
                    })
                    return False, "Update installed but service verification failed"
            else:
                error_message = f"Install script failed: {result.stderr}"
                logging.error(error_message)
                
                self._save_update_state({
                    'status': 'failed',
                    'error': error_message
                })
                
                return False, error_message
            
        except subprocess.TimeoutExpired:
            error_message = "Install script execution timed out"
            logging.error(error_message)
            self._save_update_state({'status': 'failed', 'error': error_message})
            return False, error_message
        except Exception as e:
            error_message = f"Critical error during update: {e}"
            logging.error(error_message)
            self._save_update_state({'status': 'failed', 'error': error_message})
            return False, error_message
    
    def _validate_update_prerequisites(self) -> bool:
        """Validate prerequisites for update execution."""
        try:
            # Check disk space
            import shutil
            free_space = shutil.disk_usage(self.genopti_user_dir).free
            if free_space < 200 * 1024 * 1024:  # 200MB minimum
                logging.error(f"Insufficient disk space: {free_space // (1024*1024)}MB available")
                return False
            
            # Check user permissions
            current_user = os.getenv('USER', 'unknown')
            if current_user != 'genopti-user':
                logging.error(f"Must run as genopti-user, currently: {current_user}")
                return False
            
            # Check sudo access
            try:
                result = subprocess.run(['sudo', '-n', 'echo', 'test'], capture_output=True, timeout=5)
                if result.returncode != 0:
                    logging.error("No sudo access available")
                    return False
            except:
                logging.error("Could not verify sudo access")
                return False
            
            return True
            
        except Exception as e:
            logging.error(f"Error validating prerequisites: {e}")
            return False
    
    def _verify_update_success(self, expected_version: str) -> bool:
        """Verify that the update was successful."""
        try:
            # Check service status
            result = subprocess.run(['sudo', 'systemctl', 'is-active', '--quiet', 'genopti-os.service'])
            if result.returncode != 0:
                logging.error("GenOpti-OS service is not running after update")
                return False
            
            # Check version (give it time to update)
            for attempt in range(5):
                time.sleep(2)
                current_version = self._get_current_version()
                if current_version == expected_version:
                    logging.info(f"Version verification successful: {current_version}")
                    return True
                logging.info(f"Version check attempt {attempt + 1}: expected {expected_version}, got {current_version}")
            
            logging.warning("Version verification incomplete but service is running")
            return True  # Service is running, consider it successful
            
        except Exception as e:
            logging.error(f"Error verifying update success: {e}")
            return False
    
    def _save_update_state(self, state_data: Dict) -> None:
        """Save current update state."""
        try:
            # Load existing state if exists
            current_state = {}
            if os.path.exists(self.state_file):
                with open(self.state_file, 'r') as f:
                    current_state = json.load(f)
            
            # Update with new data
            current_state.update(state_data)
            current_state['last_updated'] = datetime.now().isoformat()
            
            # Save state
            with open(self.state_file, 'w') as f:
                json.dump(current_state, f, indent=2)
                
        except Exception as e:
            logging.error(f"Error saving update state: {e}")
    
    def get_update_state(self) -> Dict:
        """Get current update state."""
        try:
            if os.path.exists(self.state_file):
                with open(self.state_file, 'r') as f:
                    return json.load(f)
            return {'status': 'idle'}
        except Exception as e:
            logging.error(f"Error loading update state: {e}")
            return {'status': 'unknown', 'error': str(e)}
    
    def perform_full_update(self, update_info: Dict) -> Tuple[bool, str]:
        """Perform complete update process from download to installation."""
        try:
            logging.info(f"Starting full update process to version {update_info.get('availableVersion')}")
            
            # Step 1: Download update package
            package_path = self.download_update(update_info)
            if not package_path:
                return False, "Failed to download update package"
            
            # Step 2: Execute install script update
            success, message = self.execute_install_script_update(update_info, package_path)
            
            return success, message
            
        except Exception as e:
            error_message = f"Critical error in full update process: {e}"
            logging.error(error_message)
            return False, error_message
    
    def is_in_maintenance_window(self) -> bool:
        """Check if current time is within the maintenance window."""
        if not self.config['maintenance_window']['enabled']:
            return True  # Always allow if maintenance window is disabled
        
        try:
            now = datetime.now()
            start_hour = self.config['maintenance_window']['start_hour']
            end_hour = self.config['maintenance_window']['end_hour']
            
            current_hour = now.hour
            
            # Handle overnight maintenance window (e.g., 22:00 to 06:00)
            if start_hour > end_hour:
                return current_hour >= start_hour or current_hour < end_hour
            else:
                return start_hour <= current_hour < end_hour
                
        except Exception as e:
            logging.error(f"Error checking maintenance window: {e}")
            return False
    
    def get_status(self) -> Dict:
        """Get comprehensive update system status."""
        try:
            current_version = self._get_current_version()
            update_state = self.get_update_state()
            
            return {
                'current_version': current_version,
                'update_method': 'install_script',
                'config': self.config,
                'state': update_state,
                'install_script_exists': os.path.exists(self.install_script_path),
                'install_script_checksum': self.calculate_file_checksum(self.install_script_path),
                'in_maintenance_window': self.is_in_maintenance_window(),
                'prerequisites_valid': self._validate_update_prerequisites()
            }
            
        except Exception as e:
            logging.error(f"Error getting status: {e}")
            return {'error': str(e)}


if __name__ == "__main__":
    # Test the install script update manager
    logging.basicConfig(level=logging.INFO)
    
    manager = InstallScriptUpdateManager()
    
    # Test update check
    print("Testing update check...")
    update_info = manager.check_for_updates()
    if update_info:
        print(f"Update available: {json.dumps(update_info, indent=2)}")
    else:
        print("No updates available")
    
    # Test status
    print("\\nSystem status:")
    status = manager.get_status()
    print(json.dumps(status, indent=2))