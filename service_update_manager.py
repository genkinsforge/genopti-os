#!/usr/bin/env python3
"""
Service Update Manager for GenOpti-OS GO20
Simplified version for use in the Flask service running as genopti-svc.
Delegates actual update work to genopti-user via script execution.
"""

import os
import json
import logging
import subprocess
from typing import Dict, Optional, Tuple


class ServiceUpdateManager:
    """Simplified update manager for service environment."""
    
    def __init__(self):
        self.genopti_user_dir = "/home/genopti-user/genopti-os"
        self.update_script = os.path.join(self.genopti_user_dir, "install_script_update_manager.py")
        
    def _run_user_command(self, command: list, timeout: int = 30) -> Tuple[bool, str, str]:
        """Run a command as genopti-user."""
        try:
            # Build the full command to run as genopti-user
            full_cmd = ['sudo', '-u', 'genopti-user'] + command
            
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self.genopti_user_dir
            )
            
            return result.returncode == 0, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)
    
    def check_for_updates(self) -> Optional[Dict]:
        """Check for available updates via genopti-user script."""
        try:
            # Run the update manager as genopti-user to check for updates
            success, stdout, stderr = self._run_user_command([
                'python3', 'install_script_update_manager.py', '--check-updates'
            ])
            
            if success and stdout:
                try:
                    result = json.loads(stdout)
                    return result.get('update_info')
                except json.JSONDecodeError:
                    logging.error(f"Invalid JSON response from update check: {stdout}")
            
            if stderr:
                logging.error(f"Update check error: {stderr}")
            
            return None
            
        except Exception as e:
            logging.error(f"Error checking for updates: {e}")
            return None
    
    def get_status(self) -> Dict:
        """Get update system status."""
        try:
            # Basic status that we can determine from service context
            status = {
                'update_method': 'install_script',
                'service_user': 'genopti-svc',
                'update_user': 'genopti-user',
                'genopti_user_dir_exists': os.path.exists(self.genopti_user_dir),
                'update_script_exists': os.path.exists(self.update_script),
                'current_version': self._get_current_version()
            }
            
            # Try to get detailed status from genopti-user script
            success, stdout, stderr = self._run_user_command([
                'python3', 'install_script_update_manager.py', '--status'
            ], timeout=10)
            
            if success and stdout:
                try:
                    detailed_status = json.loads(stdout)
                    status.update(detailed_status)
                except json.JSONDecodeError:
                    status['detailed_status_error'] = "Could not parse detailed status"
            
            return status
            
        except Exception as e:
            logging.error(f"Error getting status: {e}")
            return {
                'error': str(e),
                'update_method': 'install_script',
                'service_user': 'genopti-svc'
            }
    
    def _get_current_version(self) -> str:
        """Get current version from production files."""
        try:
            # Check version.txt in production
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
            
            return "0.48"  # Fallback
        except Exception as e:
            logging.error(f"Error getting current version: {e}")
            return "unknown"
    
    def trigger_update(self, update_info: Dict) -> Tuple[bool, str]:
        """Trigger an update process via genopti-user script."""
        try:
            # Save update info to a temporary file for the script to read
            import tempfile
            import json
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(update_info, f, indent=2)
                temp_file = f.name
            
            try:
                # Run the update as genopti-user
                success, stdout, stderr = self._run_user_command([
                    'python3', 'install_script_update_manager.py', '--perform-update', temp_file
                ], timeout=600)  # 10 minute timeout for updates
                
                if success:
                    return True, f"Update triggered successfully: {stdout}"
                else:
                    return False, f"Update failed: {stderr}"
                    
            finally:
                # Cleanup temp file
                try:
                    os.unlink(temp_file)
                except:
                    pass
            
        except Exception as e:
            error_msg = f"Error triggering update: {e}"
            logging.error(error_msg)
            return False, error_msg
    
    def is_available(self) -> bool:
        """Check if the update system is available."""
        return (
            os.path.exists(self.genopti_user_dir) and
            os.path.exists(self.update_script)
        )


# Command-line interface for the update manager script
if __name__ == "__main__":
    import sys
    
    # This script can be called from the service update manager
    # with specific commands
    
    if len(sys.argv) < 2:
        print("Usage: python3 install_script_update_manager.py <command>")
        sys.exit(1)
    
    command = sys.argv[1]
    
    # Import the full update manager
    from install_script_update_manager import InstallScriptUpdateManager
    
    manager = InstallScriptUpdateManager()
    
    if command == "--check-updates":
        update_info = manager.check_for_updates()
        result = {
            'update_available': update_info is not None,
            'update_info': update_info
        }
        print(json.dumps(result, indent=2))
        
    elif command == "--status":
        status = manager.get_status()
        print(json.dumps(status, indent=2))
        
    elif command == "--perform-update":
        if len(sys.argv) < 3:
            print("Error: Update info file required")
            sys.exit(1)
            
        update_info_file = sys.argv[2]
        
        try:
            with open(update_info_file, 'r') as f:
                update_info = json.load(f)
            
            success, message = manager.perform_full_update(update_info)
            
            result = {
                'success': success,
                'message': message
            }
            
            print(json.dumps(result, indent=2))
            sys.exit(0 if success else 1)
            
        except Exception as e:
            result = {
                'success': False,
                'error': str(e)
            }
            print(json.dumps(result, indent=2))
            sys.exit(1)
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)