#!/usr/bin/env python3
"""
Update Installer for GenOpti-OS GO20 Device
Handles atomic updates with checksum validation, rollback capability, and security verification.
"""

import os
import time
import json
import shutil
import tarfile
import hashlib
import logging
import subprocess
from datetime import datetime
from typing import Dict, Optional, List, Tuple
from version_manager import VersionManager
from backup_manager import BackupManager


class UpdateInstaller:
    """Handles secure atomic updates with rollback capability."""
    
    def __init__(self, app_dir: str = "/opt/genopti-os"):
        self.app_dir = app_dir
        self.staging_dir = os.path.join(app_dir, "update_staging")
        self.version_manager = VersionManager(app_dir)
        self.backup_manager = BackupManager(app_dir)
        
        # Ensure staging directory exists
        os.makedirs(self.staging_dir, exist_ok=True)
        
        # Files that require checksum validation
        self.critical_files = [
            "app.py",
            "aws_integration.py",
            "version_manager.py",
            "update_manager.py",
            "backup_manager.py",
            "update_installer.py",
            "requirements.txt"
        ]
        
        # Update states
        self.update_state_file = os.path.join(app_dir, "update_state.json")
    
    def validate_update_package(self, package_path: str, expected_checksum: str = None) -> Tuple[bool, str]:
        """Validate update package integrity and format."""
        try:
            logging.info(f"Validating update package: {package_path}")
            
            # Check file exists
            if not os.path.exists(package_path):
                return False, "Update package file not found"
            
            # Validate package checksum
            if expected_checksum:
                calculated_checksum = self._calculate_file_checksum(package_path)
                if calculated_checksum != expected_checksum.replace('sha256:', ''):
                    return False, f"Package checksum mismatch: expected {expected_checksum}, got {calculated_checksum}"
                logging.info("Package checksum validation passed")
            
            # Verify it's a valid tar.gz file
            try:
                with tarfile.open(package_path, 'r:gz') as tar:
                    members = tar.getnames()
                    if not members:
                        return False, "Update package is empty"
                    
                    # Check for required files
                    required_files = ['version.txt', 'checksums.txt']
                    for required_file in required_files:
                        if required_file not in members:
                            return False, f"Missing required file in package: {required_file}"
                    
                    logging.info(f"Package contains {len(members)} files")
            except tarfile.TarError as e:
                return False, f"Invalid tar.gz package: {e}"
            
            return True, "Package validation successful"
            
        except Exception as e:
            logging.error(f"Error validating update package: {e}")
            return False, f"Validation error: {e}"
    
    def extract_and_validate_contents(self, package_path: str) -> Tuple[bool, str, Dict]:
        """Extract package and validate individual file checksums."""
        try:
            # Clear staging directory
            if os.path.exists(self.staging_dir):
                shutil.rmtree(self.staging_dir)
            os.makedirs(self.staging_dir)
            
            # Extract package
            logging.info("Extracting update package")
            with tarfile.open(package_path, 'r:gz') as tar:
                tar.extractall(self.staging_dir)
            
            # Load and validate checksums
            checksums_file = os.path.join(self.staging_dir, "checksums.txt")
            if not os.path.exists(checksums_file):
                return False, "Checksums file not found in package", {}
            
            # Parse checksums file
            expected_checksums = {}
            with open(checksums_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split('  ', 1)  # SHA256 uses two spaces
                        if len(parts) == 2:
                            checksum, filename = parts
                            expected_checksums[filename] = checksum
            
            logging.info(f"Found checksums for {len(expected_checksums)} files")
            
            # Validate each file's checksum
            validation_results = {}
            for filename, expected_checksum in expected_checksums.items():
                file_path = os.path.join(self.staging_dir, filename)
                
                if not os.path.exists(file_path):
                    validation_results[filename] = {
                        'status': 'missing',
                        'error': f"File not found: {filename}"
                    }
                    continue
                
                calculated_checksum = self._calculate_file_checksum(file_path)
                
                if calculated_checksum == expected_checksum:
                    validation_results[filename] = {
                        'status': 'valid',
                        'checksum': calculated_checksum
                    }
                    logging.debug(f"Checksum valid for {filename}")
                else:
                    validation_results[filename] = {
                        'status': 'invalid',
                        'expected': expected_checksum,
                        'calculated': calculated_checksum,
                        'error': f"Checksum mismatch for {filename}"
                    }
                    logging.error(f"Checksum mismatch for {filename}")
            
            # Check if all critical files passed validation
            failed_files = [f for f, r in validation_results.items() if r['status'] != 'valid']
            if failed_files:
                return False, f"Checksum validation failed for files: {', '.join(failed_files)}", validation_results
            
            # Load version information
            version_file = os.path.join(self.staging_dir, "version.txt")
            new_version = "unknown"
            if os.path.exists(version_file):
                with open(version_file, 'r') as f:
                    new_version = f.read().strip()
            
            logging.info(f"Update package validation successful for version {new_version}")
            return True, f"All files validated successfully for version {new_version}", validation_results
            
        except Exception as e:
            logging.error(f"Error extracting and validating contents: {e}")
            return False, f"Content validation error: {e}", {}
    
    def install_update(self, package_path: str, expected_checksum: str = None, 
                      force: bool = False) -> Tuple[bool, str]:
        """Perform atomic update installation with rollback capability."""
        try:
            current_version = self.version_manager.get_current_version()
            
            # Record update start
            self._save_update_state({
                'status': 'started',
                'current_version': current_version,
                'package_path': package_path,
                'started_at': datetime.now().isoformat(),
                'force': force
            })
            
            logging.info(f"Starting update installation from {package_path}")
            
            # Step 1: Validate package
            valid, message = self.validate_update_package(package_path, expected_checksum)
            if not valid:
                self._save_update_state({'status': 'failed', 'error': message})
                return False, f"Package validation failed: {message}"
            
            # Step 2: Extract and validate contents
            valid, message, validation_results = self.extract_and_validate_contents(package_path)
            if not valid:
                self._save_update_state({'status': 'failed', 'error': message})
                return False, f"Content validation failed: {message}"
            
            # Step 3: Get new version
            version_file = os.path.join(self.staging_dir, "version.txt")
            if not os.path.exists(version_file):
                error = "No version.txt found in update package"
                self._save_update_state({'status': 'failed', 'error': error})
                return False, error
            
            with open(version_file, 'r') as f:
                new_version = f.read().strip()
            
            # Check version compatibility
            if not force and self.version_manager.compare_versions(current_version, new_version) >= 0:
                error = f"Cannot downgrade from {current_version} to {new_version} (use force=True to override)"
                self._save_update_state({'status': 'failed', 'error': error})
                return False, error
            
            # Step 4: Create backup before update
            logging.info("Creating backup before update")
            backup_name = f"pre_update_{current_version}_to_{new_version}_{int(time.time())}"
            backup_path = self.backup_manager.create_backup(backup_name, include_logs=False)
            
            if not backup_path:
                error = "Failed to create backup - aborting update"
                self._save_update_state({'status': 'failed', 'error': error})
                return False, error
            
            self._save_update_state({
                'status': 'backup_created',
                'backup_path': backup_path,
                'new_version': new_version
            })
            
            # Step 5: Stop the service
            logging.info("Stopping genopti-os service for update")
            stop_result = subprocess.run(['sudo', 'systemctl', 'stop', 'genopti-os.service'], 
                                       capture_output=True, text=True)
            if stop_result.returncode != 0:
                logging.warning(f"Service stop warning: {stop_result.stderr}")
            
            try:
                # Step 6: Apply update files
                logging.info("Applying update files")
                self._save_update_state({'status': 'installing'})
                
                updated_files = []
                for filename in os.listdir(self.staging_dir):
                    src_path = os.path.join(self.staging_dir, filename)
                    dst_path = os.path.join(self.app_dir, filename)
                    
                    # Skip metadata files
                    if filename in ['checksums.txt']:
                        continue
                    
                    if os.path.isfile(src_path):
                        # Ensure destination directory exists
                        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                        shutil.copy2(src_path, dst_path)
                        updated_files.append(filename)
                        logging.debug(f"Updated file: {filename}")
                    elif os.path.isdir(src_path):
                        # Handle directories
                        if os.path.exists(dst_path):
                            shutil.rmtree(dst_path)
                        shutil.copytree(src_path, dst_path)
                        updated_files.append(f"{filename}/")
                        logging.debug(f"Updated directory: {filename}")
                
                # Step 7: Update Python dependencies if requirements.txt changed
                requirements_path = os.path.join(self.app_dir, "requirements.txt")
                if "requirements.txt" in updated_files and os.path.exists(requirements_path):
                    logging.info("Updating Python dependencies")
                    pip_path = os.path.join(self.app_dir, "venv", "bin", "pip")
                    if os.path.exists(pip_path):
                        result = subprocess.run([pip_path, 'install', '-r', requirements_path], 
                                              capture_output=True, text=True)
                        if result.returncode != 0:
                            logging.warning(f"Dependency update warning: {result.stderr}")
                
                # Step 8: Set proper permissions
                self._fix_permissions()
                
                # Step 9: Update version information
                self.version_manager.set_current_version(new_version)
                
                # Step 10: Start the service and verify
                logging.info("Starting genopti-os service after update")
                start_result = subprocess.run(['sudo', 'systemctl', 'start', 'genopti-os.service'], 
                                            capture_output=True, text=True)
                
                if start_result.returncode != 0:
                    raise Exception(f"Failed to start service: {start_result.stderr}")
                
                # Wait and verify service is running
                time.sleep(5)
                status_result = subprocess.run(['sudo', 'systemctl', 'is-active', '--quiet', 'genopti-os.service'])
                
                if status_result.returncode != 0:
                    raise Exception("Service is not running after update")
                
                # Step 11: Record successful update
                self.version_manager.add_update_history(current_version, new_version, 'completed')
                
                self._save_update_state({
                    'status': 'completed',
                    'updated_files': updated_files,
                    'completed_at': datetime.now().isoformat()
                })
                
                # Cleanup staging directory
                shutil.rmtree(self.staging_dir, ignore_errors=True)
                
                logging.info(f"Update completed successfully: {current_version} -> {new_version}")
                return True, f"Update completed successfully to version {new_version}"
                
            except Exception as e:
                # Update failed - attempt rollback
                logging.error(f"Update failed, attempting rollback: {e}")
                
                self._save_update_state({'status': 'rolling_back', 'error': str(e)})
                
                rollback_success, rollback_message = self._rollback_update(backup_path, current_version, new_version)
                
                if rollback_success:
                    error_message = f"Update failed but rollback successful: {e}"
                    self._save_update_state({'status': 'rolled_back', 'error': str(e)})
                else:
                    error_message = f"Update failed and rollback failed: {e}. Manual intervention required."
                    self._save_update_state({'status': 'rollback_failed', 'error': str(e)})
                
                return False, error_message
            
        except Exception as e:
            logging.error(f"Critical error during update: {e}")
            self._save_update_state({'status': 'failed', 'error': str(e)})
            return False, f"Critical update error: {e}"
    
    def _rollback_update(self, backup_path: str, original_version: str, failed_version: str) -> Tuple[bool, str]:
        """Rollback failed update."""
        try:
            logging.info(f"Rolling back from failed update to version {original_version}")
            
            # Extract backup name from path
            backup_name = os.path.basename(backup_path)
            
            # Restore from backup
            success = self.backup_manager.restore_backup(backup_name, confirm=True)
            
            if success:
                # Record rollback in history
                self.version_manager.add_update_history(failed_version, original_version, 'rolled_back')
                logging.info("Rollback completed successfully")
                return True, "Rollback successful"
            else:
                logging.error("Rollback failed")
                return False, "Rollback failed"
                
        except Exception as e:
            logging.error(f"Error during rollback: {e}")
            return False, f"Rollback error: {e}"
    
    def _calculate_file_checksum(self, file_path: str) -> str:
        """Calculate SHA256 checksum of a file."""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logging.error(f"Error calculating checksum for {file_path}: {e}")
            return ""
    
    def _save_update_state(self, state_data: Dict) -> None:
        """Save current update state."""
        try:
            # Load existing state if exists
            current_state = {}
            if os.path.exists(self.update_state_file):
                with open(self.update_state_file, 'r') as f:
                    current_state = json.load(f)
            
            # Update with new data
            current_state.update(state_data)
            current_state['last_updated'] = datetime.now().isoformat()
            
            # Save state
            with open(self.update_state_file, 'w') as f:
                json.dump(current_state, f, indent=2)
                
        except Exception as e:
            logging.error(f"Error saving update state: {e}")
    
    def get_update_state(self) -> Dict:
        """Get current update state."""
        try:
            if os.path.exists(self.update_state_file):
                with open(self.update_state_file, 'r') as f:
                    return json.load(f)
            return {'status': 'idle'}
        except Exception as e:
            logging.error(f"Error loading update state: {e}")
            return {'status': 'unknown', 'error': str(e)}
    
    def clear_update_state(self) -> None:
        """Clear update state file."""
        try:
            if os.path.exists(self.update_state_file):
                os.remove(self.update_state_file)
        except Exception as e:
            logging.error(f"Error clearing update state: {e}")
    
    def _fix_permissions(self) -> None:
        """Fix file permissions after update."""
        try:
            # Set ownership to genopti-svc user if running as root
            if os.getuid() == 0:
                subprocess.run(['chown', '-R', 'genopti-svc:genopti-svc', self.app_dir], 
                             capture_output=True)
            
            # Set executable permissions for key files
            executable_files = ['app.py']
            for filename in executable_files:
                file_path = os.path.join(self.app_dir, filename)
                if os.path.exists(file_path):
                    os.chmod(file_path, 0o755)
            
            # Set proper permissions for virtual environment
            venv_bin = os.path.join(self.app_dir, "venv", "bin")
            if os.path.exists(venv_bin):
                subprocess.run(['chmod', '-R', 'ug+x', venv_bin], capture_output=True)
            
        except Exception as e:
            logging.error(f"Error fixing permissions: {e}")
    
    def verify_installation(self) -> Tuple[bool, str]:
        """Verify the current installation integrity."""
        try:
            current_version = self.version_manager.get_current_version()
            
            # Check critical files exist
            missing_files = []
            for filename in self.critical_files:
                file_path = os.path.join(self.app_dir, filename)
                if not os.path.exists(file_path):
                    missing_files.append(filename)
            
            if missing_files:
                return False, f"Missing critical files: {', '.join(missing_files)}"
            
            # Check service status
            status_result = subprocess.run(['sudo', 'systemctl', 'is-active', '--quiet', 'genopti-os.service'])
            if status_result.returncode != 0:
                return False, "GenOpti-OS service is not running"
            
            return True, f"Installation verified successfully (version {current_version})"
            
        except Exception as e:
            logging.error(f"Error verifying installation: {e}")
            return False, f"Verification error: {e}"


if __name__ == "__main__":
    # Test the update installer
    logging.basicConfig(level=logging.DEBUG)
    
    installer = UpdateInstaller("/home/genopti-user/genopti-os")  # Use dev path for testing
    
    # Test verification
    valid, message = installer.verify_installation()
    print(f"Installation verification: {valid} - {message}")
    
    # Test update state
    state = installer.get_update_state()
    print(f"Update state: {json.dumps(state, indent=2)}")