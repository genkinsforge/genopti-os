#!/usr/bin/env python3
"""
Version Management System for GenOpti-OS GO20 Device
Handles version detection, tracking, and comparison for auto-updates.
"""

import os
import re
import json
import logging
from datetime import datetime
from typing import Dict, Optional, Tuple


class VersionManager:
    """Manages version information and update tracking for GenOpti-OS."""
    
    def __init__(self, app_dir: str = "/opt/genopti-os"):
        self.app_dir = app_dir
        self.version_file = os.path.join(app_dir, "version.txt")
        self.version_info_file = os.path.join(app_dir, "version_info.json")
        self.update_history_file = os.path.join(app_dir, "update_history.json")
        
    def get_current_version(self) -> str:
        """Get the current GenOpti-OS version."""
        try:
            # Method 1: Check version.txt file (preferred for updates)
            if os.path.exists(self.version_file):
                with open(self.version_file, 'r') as f:
                    version = f.read().strip()
                    if version:
                        logging.debug(f"Found version in version.txt: {version}")
                        return version
            
            # Method 2: Parse from app.py APP_NAME_VERSION
            app_py_path = os.path.join(self.app_dir, "app.py")
            if os.path.exists(app_py_path):
                with open(app_py_path, 'r') as f:
                    content = f.read()
                    match = re.search(r'APP_NAME_VERSION = "Genopti-OS \(v([\d.]+)', content)
                    if match:
                        version = match.group(1)
                        logging.debug(f"Found version in app.py: {version}")
                        return version
            
            # Method 3: Parse from comment in app.py
            if os.path.exists(app_py_path):
                with open(app_py_path, 'r') as f:
                    first_line = f.readline()
                    match = re.search(r'\(v([\d.]+)', first_line)
                    if match:
                        version = match.group(1)
                        logging.debug(f"Found version in app.py comment: {version}")
                        return version
            
            # Fallback version
            logging.warning("Could not determine current version, using fallback")
            return "0.0"
            
        except Exception as e:
            logging.error(f"Error getting current version: {e}")
            return "0.0"
    
    def set_current_version(self, version: str) -> bool:
        """Set the current version and update version info."""
        try:
            # Write version to version.txt
            with open(self.version_file, 'w') as f:
                f.write(version)
            
            # Update version_info.json
            version_info = {
                'version': version,
                'updated_at': datetime.now().isoformat(),
                'update_method': 'auto_update'
            }
            
            with open(self.version_info_file, 'w') as f:
                json.dump(version_info, f, indent=2)
            
            logging.info(f"Version updated to {version}")
            return True
            
        except Exception as e:
            logging.error(f"Error setting current version: {e}")
            return False
    
    def compare_versions(self, version1: str, version2: str) -> int:
        """
        Compare two version strings.
        Returns: -1 if version1 < version2, 0 if equal, 1 if version1 > version2
        """
        try:
            # Parse version strings
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]
            
            # Normalize length by padding with zeros
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            # Compare each part
            for v1, v2 in zip(v1_parts, v2_parts):
                if v1 < v2:
                    return -1
                elif v1 > v2:
                    return 1
            
            return 0
            
        except Exception as e:
            logging.error(f"Error comparing versions {version1} and {version2}: {e}")
            return 0
    
    def is_update_available(self, available_version: str) -> bool:
        """Check if an update is available."""
        current_version = self.get_current_version()
        return self.compare_versions(current_version, available_version) < 0
    
    def get_version_info(self) -> Dict:
        """Get detailed version information."""
        current_version = self.get_current_version()
        
        version_info = {
            'current_version': current_version,
            'version_file_exists': os.path.exists(self.version_file),
            'last_checked': None,
            'update_available': False,
            'available_version': None
        }
        
        # Load version info if exists
        if os.path.exists(self.version_info_file):
            try:
                with open(self.version_info_file, 'r') as f:
                    stored_info = json.load(f)
                    version_info.update(stored_info)
            except Exception as e:
                logging.error(f"Error loading version info: {e}")
        
        return version_info
    
    def record_update_check(self, available_version: Optional[str] = None) -> None:
        """Record that an update check was performed."""
        try:
            current_version = self.get_current_version()
            update_available = False
            
            if available_version:
                update_available = self.is_update_available(available_version)
            
            version_info = {
                'current_version': current_version,
                'last_checked': datetime.now().isoformat(),
                'update_available': update_available,
                'available_version': available_version
            }
            
            with open(self.version_info_file, 'w') as f:
                json.dump(version_info, f, indent=2)
                
            logging.debug(f"Recorded update check: available={update_available}")
            
        except Exception as e:
            logging.error(f"Error recording update check: {e}")
    
    def add_update_history(self, from_version: str, to_version: str, 
                          status: str, error: Optional[str] = None) -> None:
        """Add an entry to the update history."""
        try:
            history_entry = {
                'timestamp': datetime.now().isoformat(),
                'from_version': from_version,
                'to_version': to_version,
                'status': status,  # 'started', 'completed', 'failed', 'rolled_back'
                'error': error
            }
            
            # Load existing history
            history = []
            if os.path.exists(self.update_history_file):
                try:
                    with open(self.update_history_file, 'r') as f:
                        history = json.load(f)
                except:
                    history = []
            
            # Add new entry
            history.append(history_entry)
            
            # Keep only last 50 entries
            history = history[-50:]
            
            # Save history
            with open(self.update_history_file, 'w') as f:
                json.dump(history, f, indent=2)
                
            logging.info(f"Added update history: {from_version} -> {to_version} ({status})")
            
        except Exception as e:
            logging.error(f"Error adding update history: {e}")
    
    def get_update_history(self) -> list:
        """Get the update history."""
        try:
            if os.path.exists(self.update_history_file):
                with open(self.update_history_file, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            logging.error(f"Error getting update history: {e}")
            return []
    
    def get_last_successful_update(self) -> Optional[Dict]:
        """Get the last successful update from history."""
        try:
            history = self.get_update_history()
            for entry in reversed(history):
                if entry.get('status') == 'completed':
                    return entry
            return None
        except Exception as e:
            logging.error(f"Error getting last successful update: {e}")
            return None
    
    def validate_version_format(self, version: str) -> bool:
        """Validate that a version string is in the correct format."""
        try:
            # Check format: X.Y or X.Y.Z etc.
            pattern = r'^\d+(\.\d+)*$'
            return bool(re.match(pattern, version))
        except Exception as e:
            logging.error(f"Error validating version format: {e}")
            return False


def get_system_info() -> Dict:
    """Get system information for update compatibility checking."""
    try:
        import psutil
        import platform
        
        return {
            'platform': platform.platform(),
            'architecture': platform.architecture()[0],
            'python_version': platform.python_version(),
            'memory_total': psutil.virtual_memory().total,
            'memory_available': psutil.virtual_memory().available,
            'disk_total': psutil.disk_usage('/').total,
            'disk_free': psutil.disk_usage('/').free,
            'cpu_count': psutil.cpu_count()
        }
    except Exception as e:
        logging.error(f"Error getting system info: {e}")
        return {}


if __name__ == "__main__":
    # Test the version manager
    logging.basicConfig(level=logging.DEBUG)
    
    vm = VersionManager("/home/genopti-user/genopti-os")  # Use dev path for testing
    
    current = vm.get_current_version()
    print(f"Current version: {current}")
    
    # Test version comparison
    print(f"1.0 vs 1.1: {vm.compare_versions('1.0', '1.1')}")
    print(f"1.1 vs 1.0: {vm.compare_versions('1.1', '1.0')}")
    print(f"1.0 vs 1.0: {vm.compare_versions('1.0', '1.0')}")
    
    # Test update check
    vm.record_update_check("1.0")
    
    info = vm.get_version_info()
    print(f"Version info: {json.dumps(info, indent=2)}")