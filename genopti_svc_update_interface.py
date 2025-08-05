#!/usr/bin/env python3
"""
GenOpti-SVC Update Interface
Simple interface for genopti-svc to communicate with genopti-user update daemon.
Uses file-based communication in /tmp/genopti-updates/
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, Optional, Tuple


class GenOptiSvcUpdateInterface:
    """Interface for genopti-svc to communicate with the genopti-user update daemon."""
    
    def __init__(self):
        self.communication_dir = "/tmp/genopti-updates"
        self.version_info_file = os.path.join(self.communication_dir, "latest_version.json")
        self.update_request_file = os.path.join(self.communication_dir, "update_request.json")
        self.update_status_file = os.path.join(self.communication_dir, "update_status.json")
        
        # Ensure communication directory exists
        os.makedirs(self.communication_dir, mode=0o755, exist_ok=True)
    
    def get_version_info(self) -> Dict:
        """Get latest version information from the update daemon."""
        try:
            if not os.path.exists(self.version_info_file):
                return {
                    'daemon_status': 'not_running',
                    'current_version': 'unknown',
                    'update_available': False,
                    'error': 'Version info file not found - daemon may not be running'
                }
            
            with open(self.version_info_file, 'r') as f:
                version_data = json.load(f)
            
            # Check if data is recent (within last 2 hours)
            last_checked = version_data.get('last_checked')
            if last_checked:
                try:
                    from datetime import datetime
                    last_check_time = datetime.fromisoformat(last_checked)
                    now = datetime.now()
                    if (now - last_check_time).total_seconds() > 7200:  # 2 hours
                        version_data['warning'] = 'Version info may be stale'
                except:
                    pass
            
            return version_data
            
        except Exception as e:
            logging.error(f"Error reading version info: {e}")
            return {
                'daemon_status': 'error',
                'current_version': 'unknown',
                'update_available': False,
                'error': str(e)
            }
    
    def get_update_status(self) -> Dict:
        """Get current update status from the daemon."""
        try:
            if not os.path.exists(self.update_status_file):
                return {
                    'status': 'idle',
                    'message': 'No update operations in progress'
                }
            
            with open(self.update_status_file, 'r') as f:
                status_data = json.load(f)
            
            return status_data
            
        except Exception as e:
            logging.error(f"Error reading update status: {e}")
            return {
                'status': 'error',
                'message': f'Error reading status: {e}'
            }
    
    def request_update(self, update_info: Dict) -> Tuple[bool, str]:
        """Request the daemon to perform an update."""
        try:
            # Check if daemon is running
            version_info = self.get_version_info()
            if version_info.get('daemon_status') != 'running':
                return False, "Update daemon is not running"
            
            # Check if an update is already in progress
            current_status = self.get_update_status()
            if current_status.get('status') == 'processing':
                return False, "Update already in progress"
            
            # Create update request
            request_data = {
                'action': 'install_update',
                'update_info': update_info,
                'requested_at': datetime.now().isoformat(),
                'requested_by': 'genopti-svc'
            }
            
            # Write request file
            with open(self.update_request_file, 'w') as f:
                json.dump(request_data, f, indent=2)
            
            logging.info(f"Update request submitted for version {update_info.get('availableVersion')}")
            return True, "Update request submitted successfully"
            
        except Exception as e:
            error_msg = f"Error submitting update request: {e}"
            logging.error(error_msg)
            return False, error_msg
    
    def is_daemon_running(self) -> bool:
        """Check if the update daemon is running."""
        version_info = self.get_version_info()
        return version_info.get('daemon_status') == 'running'
    
    def get_comprehensive_status(self) -> Dict:
        """Get comprehensive status for API responses."""
        version_info = self.get_version_info()
        update_status = self.get_update_status()
        
        return {
            'current_version': version_info.get('current_version', 'unknown'),
            'daemon_running': self.is_daemon_running(),
            'update_available': version_info.get('update_available', False),
            'latest_version': version_info.get('latest_version'),
            'update_status': update_status.get('status', 'idle'),
            'update_message': update_status.get('message', ''),
            'last_checked': version_info.get('last_checked'),
            'update_method': 'install_script_decoupled',
            'communication_method': 'file_based'
        }


# Factory function for easy import
def create_update_interface():
    """Create and return an update interface instance."""
    return GenOptiSvcUpdateInterface()


# Test functionality
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    interface = GenOptiSvcUpdateInterface()
    
    print("Testing GenOpti-SVC Update Interface...")
    print("\nVersion Info:")
    version_info = interface.get_version_info()
    print(json.dumps(version_info, indent=2))
    
    print("\nUpdate Status:")
    status = interface.get_update_status()
    print(json.dumps(status, indent=2))
    
    print("\nDaemon Running:", interface.is_daemon_running())
    
    print("\nComprehensive Status:")
    comp_status = interface.get_comprehensive_status()
    print(json.dumps(comp_status, indent=2))