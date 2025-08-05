#!/usr/bin/env python3
"""
Update Manager for GenOpti-OS GO20 Device
Handles update checking, downloading, and coordination with backend API.
"""

import os
import time
import json
import logging
import hashlib
import requests
import threading
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, List
from version_manager import VersionManager, get_system_info


class UpdateManager:
    """Manages automatic updates for GenOpti-OS."""
    
    def __init__(self, app_dir: str = "/opt/genopti-os"):
        self.app_dir = app_dir
        self.version_manager = VersionManager(app_dir)
        self.config_file = os.path.join(app_dir, "update_config.json")
        self.download_dir = os.path.join(app_dir, "downloads")
        self.backup_dir = os.path.join(app_dir, "backups")
        
        # Ensure directories exist
        os.makedirs(self.download_dir, exist_ok=True)
        os.makedirs(self.backup_dir, exist_ok=True)
        
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
            "require_confirmation": True
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
    
    def get_device_info(self) -> Dict:
        """Get device information for update API calls."""
        try:
            # Get device registration info
            registration_file = os.path.join(self.app_dir, "device-registration.json")
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
            system_info = get_system_info()
            device_info.update({
                'model': 'genopti_go2',
                'serialNumber': self._get_cpu_serial(),
                'currentVersion': self.version_manager.get_current_version(),
                'systemInfo': system_info
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
    
    def _get_jwt_token(self) -> Optional[str]:
        """Get JWT token for API authentication."""
        try:
            jwt_file = os.path.join(self.app_dir, "device-token.json")
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
            registration_file = os.path.join(self.app_dir, "device-registration.json")
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
                    "memoryAvailable": device_info['systemInfo'].get('memory_available', 0),
                    "diskAvailable": device_info['systemInfo'].get('disk_free', 0)
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
                    available_version = update_info.get('availableVersion')
                    
                    # Record the update check
                    self.version_manager.record_update_check(available_version)
                    
                    logging.info(f"Update available: {available_version}")
                    return update_info
            else:
                # No updates available
                self.version_manager.record_update_check()
                logging.info("No updates available")
                
            return None
            
        except requests.exceptions.RequestException as e:
            logging.error(f"Network error checking for updates: {e}")
            return None
        except Exception as e:
            logging.error(f"Error checking for updates: {e}")
            return None
    
    def download_update(self, update_info: Dict, progress_callback=None) -> Optional[str]:
        """Download update package with integrity verification."""
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
                        
                        if progress_callback and total_size > 0:
                            progress = int((downloaded / total_size) * 100)
                            progress_callback(progress)
            
            # Verify checksum
            calculated_checksum = sha256_hash.hexdigest()
            if expected_checksum and calculated_checksum != expected_checksum:
                logging.error(f"Checksum verification failed: expected {expected_checksum}, got {calculated_checksum}")
                os.remove(download_path)
                return None
            
            logging.info(f"Download completed and verified: {download_path}")
            return download_path
            
        except Exception as e:
            logging.error(f"Error downloading update: {e}")
            return None
    
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
    
    def start_automatic_checking(self) -> None:
        """Start automatic update checking in background thread."""
        if self._update_thread and self._update_thread.is_alive():
            logging.warning("Update checking thread already running")
            return
        
        if not self.config['enabled']:
            logging.info("Automatic updates disabled")
            return
        
        self._stop_checking.clear()
        self._update_thread = threading.Thread(target=self._update_check_loop, daemon=True)
        self._update_thread.start()
        logging.info("Started automatic update checking")
    
    def stop_automatic_checking(self) -> None:
        """Stop automatic update checking."""
        self._stop_checking.set()
        if self._update_thread:
            self._update_thread.join(timeout=5)
        logging.info("Stopped automatic update checking")
    
    def _update_check_loop(self) -> None:
        """Background thread loop for checking updates."""
        while not self._stop_checking.is_set():
            try:
                if self.config['enabled']:
                    update_info = self.check_for_updates()
                    
                    if update_info and self.config['auto_install']:
                        if self.is_in_maintenance_window():
                            logging.info("Auto-installing update during maintenance window")
                            # TODO: Implement auto-installation
                        else:
                            logging.info("Update available but outside maintenance window")
                
                # Wait for next check
                self._stop_checking.wait(self.config['check_interval'])
                
            except Exception as e:
                logging.error(f"Error in update check loop: {e}")
                self._stop_checking.wait(300)  # Wait 5 minutes on error
    
    def get_update_status(self) -> Dict:
        """Get current update status."""
        version_info = self.version_manager.get_version_info()
        system_info = get_system_info()
        
        return {
            'current_version': version_info['current_version'],
            'update_available': version_info.get('update_available', False),
            'available_version': version_info.get('available_version'),
            'last_checked': version_info.get('last_checked'),
            'auto_update_enabled': self.config['enabled'],
            'in_maintenance_window': self.is_in_maintenance_window(),
            'system_info': system_info,
            'update_history': self.version_manager.get_update_history()[-5:]  # Last 5 updates
        }
    
    def report_update_progress(self, update_id: str, status: str, progress: int, error: str = None) -> bool:
        """Report update progress to the API."""
        try:
            api_endpoint = self._get_api_endpoint()
            jwt_token = self._get_jwt_token()
            
            if not jwt_token:
                logging.error("No JWT token available for progress report")
                return False
            
            device_info = self.get_device_info()
            
            payload = {
                "deviceId": device_info['deviceId'],
                "updateId": update_id,
                "status": status,
                "progress": progress
            }
            
            if error:
                payload["error"] = error
            
            url = f'{api_endpoint}/webhook/update-progress'
            headers = {
                'Authorization': f'Bearer {jwt_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            
            logging.info(f"Reported update progress: {status} ({progress}%)")
            return True
            
        except Exception as e:
            logging.error(f"Error reporting update progress: {e}")
            return False


if __name__ == "__main__":
    # Test the update manager
    logging.basicConfig(level=logging.DEBUG)
    
    um = UpdateManager("/home/genopti-user/genopti-os")  # Use dev path for testing
    
    # Test update check
    update_info = um.check_for_updates()
    if update_info:
        print(f"Update available: {json.dumps(update_info, indent=2)}")
    else:
        print("No updates available")
    
    # Test status
    status = um.get_update_status()
    print(f"Update status: {json.dumps(status, indent=2)}")