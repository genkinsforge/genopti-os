#!/usr/bin/env python3
"""
Backup Manager for GenOpti-OS GO20 Device
Handles backup and restore operations for safe updates.
"""

import os
import shutil
import tarfile
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple


class BackupManager:
    """Manages backup and restore operations for safe updates."""
    
    def __init__(self, app_dir: str = "/opt/genopti-os"):
        self.app_dir = app_dir
        self.backup_base_dir = os.path.join(app_dir, "backups")
        self.backup_manifest_file = os.path.join(self.backup_base_dir, "backup_manifest.json")
        
        # Ensure backup directory exists
        os.makedirs(self.backup_base_dir, exist_ok=True)
        
        # Critical files/directories to backup
        self.critical_files = [
            "device-registration.json",
            "device-token.json",
            "version.txt",
            "version_info.json",
            "update_history.json",
            "update_config.json",
            # Configuration files
            "config.json",
            # Application files (full backup)
            "app.py",
            "aws_integration.py",
            "version_manager.py",
            "update_manager.py",
            "backup_manager.py",
            "requirements.txt"
        ]
        
        # Directories to backup
        self.critical_directories = [
            "templates",
            "static",
            "logs"
        ]
        
        # Files to exclude from backups
        self.exclude_patterns = [
            "*.pyc",
            "__pycache__",
            "*.tmp",
            "*.log",  # Individual log files (but keep logs directory structure)
            "downloads/*",
            "backups/*"
        ]
    
    def create_backup(self, backup_name: Optional[str] = None, include_logs: bool = False) -> Optional[str]:
        """Create a full backup of the system."""
        try:
            if not backup_name:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_name = f"backup_{timestamp}"
            
            backup_dir = os.path.join(self.backup_base_dir, backup_name)
            os.makedirs(backup_dir, exist_ok=True)
            
            logging.info(f"Creating backup: {backup_name}")
            
            # Backup critical files
            files_backed_up = []
            for filename in self.critical_files:
                src_path = os.path.join(self.app_dir, filename)
                if os.path.exists(src_path):
                    dst_path = os.path.join(backup_dir, filename)
                    # Ensure destination directory exists
                    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                    shutil.copy2(src_path, dst_path)
                    files_backed_up.append(filename)
                    logging.debug(f"Backed up file: {filename}")
            
            # Backup critical directories
            dirs_backed_up = []
            for dirname in self.critical_directories:
                src_path = os.path.join(self.app_dir, dirname)
                if os.path.exists(src_path):
                    # Special handling for logs directory
                    if dirname == "logs" and not include_logs:
                        # Create logs directory structure but skip large log files
                        dst_path = os.path.join(backup_dir, dirname)
                        os.makedirs(dst_path, exist_ok=True)
                        # Only backup small config files in logs, not large .log files
                        for item in os.listdir(src_path):
                            item_path = os.path.join(src_path, item)
                            if os.path.isfile(item_path) and not item.endswith('.log'):
                                shutil.copy2(item_path, os.path.join(dst_path, item))
                    else:
                        dst_path = os.path.join(backup_dir, dirname)
                        shutil.copytree(src_path, dst_path, dirs_exist_ok=True)
                    
                    dirs_backed_up.append(dirname)
                    logging.debug(f"Backed up directory: {dirname}")
            
            # Create backup manifest
            manifest = {
                'backup_name': backup_name,
                'created_at': datetime.now().isoformat(),
                'app_dir': self.app_dir,
                'files_backed_up': files_backed_up,
                'directories_backed_up': dirs_backed_up,
                'include_logs': include_logs,
                'backup_size': self._get_directory_size(backup_dir)
            }
            
            manifest_path = os.path.join(backup_dir, "backup_manifest.json")
            with open(manifest_path, 'w') as f:
                json.dump(manifest, f, indent=2)
            
            # Update global backup manifest
            self._update_backup_manifest(manifest)
            
            logging.info(f"Backup created successfully: {backup_dir}")
            return backup_dir
            
        except Exception as e:
            logging.error(f"Error creating backup: {e}")
            return None
    
    def create_compressed_backup(self, backup_name: Optional[str] = None) -> Optional[str]:
        """Create a compressed tar.gz backup."""
        try:
            # First create regular backup
            backup_dir = self.create_backup(backup_name)
            if not backup_dir:
                return None
            
            # Create compressed archive
            backup_archive = f"{backup_dir}.tar.gz"
            
            with tarfile.open(backup_archive, 'w:gz') as tar:
                tar.add(backup_dir, arcname=os.path.basename(backup_dir))
            
            # Remove uncompressed backup directory
            shutil.rmtree(backup_dir)
            
            logging.info(f"Compressed backup created: {backup_archive}")
            return backup_archive
            
        except Exception as e:
            logging.error(f"Error creating compressed backup: {e}")
            return None
    
    def restore_backup(self, backup_name: str, confirm: bool = False) -> bool:
        """Restore from a backup."""
        try:
            if not confirm:
                logging.error("Restore operation requires explicit confirmation")
                return False
            
            backup_dir = os.path.join(self.backup_base_dir, backup_name)
            backup_archive = f"{backup_dir}.tar.gz"
            
            # Check if backup exists (directory or archive)
            if os.path.exists(backup_archive):
                # Extract compressed backup
                with tarfile.open(backup_archive, 'r:gz') as tar:
                    tar.extractall(self.backup_base_dir)
                backup_path = backup_dir
            elif os.path.exists(backup_dir):
                backup_path = backup_dir
            else:
                logging.error(f"Backup not found: {backup_name}")
                return False
            
            # Load backup manifest
            manifest_path = os.path.join(backup_path, "backup_manifest.json")
            if not os.path.exists(manifest_path):
                logging.error(f"Backup manifest not found: {manifest_path}")
                return False
            
            with open(manifest_path, 'r') as f:
                manifest = json.load(f)
            
            logging.info(f"Restoring backup: {backup_name} (created: {manifest['created_at']})")
            
            # Stop the service before restore
            logging.info("Stopping genopti-os service for restore")
            os.system('sudo systemctl stop genopti-os.service')
            
            try:
                # Restore files
                for filename in manifest['files_backed_up']:
                    src_path = os.path.join(backup_path, filename)
                    dst_path = os.path.join(self.app_dir, filename)
                    
                    if os.path.exists(src_path):
                        # Ensure destination directory exists
                        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                        shutil.copy2(src_path, dst_path)
                        logging.debug(f"Restored file: {filename}")
                
                # Restore directories
                for dirname in manifest['directories_backed_up']:
                    src_path = os.path.join(backup_path, dirname)
                    dst_path = os.path.join(self.app_dir, dirname)
                    
                    if os.path.exists(src_path):
                        # Remove existing directory if it exists
                        if os.path.exists(dst_path):
                            shutil.rmtree(dst_path)
                        shutil.copytree(src_path, dst_path)
                        logging.debug(f"Restored directory: {dirname}")
                
                # Set proper permissions
                self._fix_permissions()
                
                logging.info("Backup restored successfully")
                return True
                
            finally:
                # Always try to restart the service
                logging.info("Starting genopti-os service after restore")
                os.system('sudo systemctl start genopti-os.service')
            
        except Exception as e:
            logging.error(f"Error restoring backup: {e}")
            return False
    
    def list_backups(self) -> List[Dict]:
        """List all available backups."""
        try:
            backups = []
            
            if not os.path.exists(self.backup_base_dir):
                return backups
            
            for item in os.listdir(self.backup_base_dir):
                item_path = os.path.join(self.backup_base_dir, item)
                
                # Check for backup directories
                if os.path.isdir(item_path) and item.startswith('backup_'):
                    manifest_path = os.path.join(item_path, "backup_manifest.json")
                    if os.path.exists(manifest_path):
                        with open(manifest_path, 'r') as f:
                            manifest = json.load(f)
                            manifest['type'] = 'directory'
                            manifest['path'] = item_path
                            backups.append(manifest)
                
                # Check for compressed backups
                elif item.endswith('.tar.gz') and item.startswith('backup_'):
                    backup_info = {
                        'backup_name': item.replace('.tar.gz', ''),
                        'type': 'compressed',
                        'path': item_path,
                        'size': os.path.getsize(item_path),
                        'created_at': datetime.fromtimestamp(os.path.getctime(item_path)).isoformat()
                    }
                    backups.append(backup_info)
            
            # Sort by creation date (newest first)
            backups.sort(key=lambda x: x.get('created_at', ''), reverse=True)
            
            return backups
            
        except Exception as e:
            logging.error(f"Error listing backups: {e}")
            return []
    
    def delete_backup(self, backup_name: str) -> bool:
        """Delete a backup."""
        try:
            backup_dir = os.path.join(self.backup_base_dir, backup_name)
            backup_archive = f"{backup_dir}.tar.gz"
            
            deleted = False
            
            # Delete directory backup
            if os.path.exists(backup_dir):
                shutil.rmtree(backup_dir)
                logging.info(f"Deleted backup directory: {backup_dir}")
                deleted = True
            
            # Delete compressed backup
            if os.path.exists(backup_archive):
                os.remove(backup_archive)
                logging.info(f"Deleted backup archive: {backup_archive}")
                deleted = True
            
            if not deleted:
                logging.warning(f"Backup not found: {backup_name}")
                return False
            
            return True
            
        except Exception as e:
            logging.error(f"Error deleting backup: {e}")
            return False
    
    def cleanup_old_backups(self, keep_count: int = 10) -> None:
        """Clean up old backups, keeping only the most recent ones."""
        try:
            backups = self.list_backups()
            
            if len(backups) <= keep_count:
                return
            
            # Delete oldest backups
            backups_to_delete = backups[keep_count:]
            
            for backup in backups_to_delete:
                backup_name = backup['backup_name']
                if self.delete_backup(backup_name):
                    logging.info(f"Cleaned up old backup: {backup_name}")
            
        except Exception as e:
            logging.error(f"Error cleaning up old backups: {e}")
    
    def _update_backup_manifest(self, backup_info: Dict) -> None:
        """Update the global backup manifest."""
        try:
            manifest = []
            
            # Load existing manifest
            if os.path.exists(self.backup_manifest_file):
                with open(self.backup_manifest_file, 'r') as f:
                    manifest = json.load(f)
            
            # Add new backup info
            manifest.append(backup_info)
            
            # Keep only last 50 entries
            manifest = manifest[-50:]
            
            # Save updated manifest
            with open(self.backup_manifest_file, 'w') as f:
                json.dump(manifest, f, indent=2)
                
        except Exception as e:
            logging.error(f"Error updating backup manifest: {e}")
    
    def _get_directory_size(self, path: str) -> int:
        """Get the total size of a directory."""
        try:
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(path):
                for filename in filenames:
                    file_path = os.path.join(dirpath, filename)
                    if os.path.exists(file_path):
                        total_size += os.path.getsize(file_path)
            return total_size
        except Exception as e:
            logging.error(f"Error calculating directory size: {e}")
            return 0
    
    def _fix_permissions(self) -> None:
        """Fix file permissions after restore."""
        try:
            # Set ownership to genopti-svc user if running as root
            if os.getuid() == 0:
                os.system(f'chown -R genopti-svc:genopti-svc {self.app_dir}')
            
            # Set executable permissions for key files
            executable_files = ['app.py']
            for filename in executable_files:
                file_path = os.path.join(self.app_dir, filename)
                if os.path.exists(file_path):
                    os.chmod(file_path, 0o755)
            
        except Exception as e:
            logging.error(f"Error fixing permissions: {e}")
    
    def get_backup_status(self) -> Dict:
        """Get backup system status."""
        try:
            backups = self.list_backups()
            total_backup_size = sum(backup.get('backup_size', backup.get('size', 0)) for backup in backups)
            
            return {
                'backup_count': len(backups),
                'total_backup_size': total_backup_size,
                'backup_directory': self.backup_base_dir,
                'latest_backup': backups[0] if backups else None,
                'disk_usage': {
                    'total': shutil.disk_usage(self.backup_base_dir).total,
                    'free': shutil.disk_usage(self.backup_base_dir).free,
                    'used': shutil.disk_usage(self.backup_base_dir).total - shutil.disk_usage(self.backup_base_dir).free
                }
            }
        except Exception as e:
            logging.error(f"Error getting backup status: {e}")
            return {}


if __name__ == "__main__":
    # Test the backup manager
    logging.basicConfig(level=logging.DEBUG)
    
    bm = BackupManager("/home/genopti-user/genopti-os")  # Use dev path for testing
    
    # Test backup creation
    backup_path = bm.create_backup("test_backup")
    if backup_path:
        print(f"Backup created: {backup_path}")
    
    # List backups
    backups = bm.list_backups()
    print(f"Available backups: {len(backups)}")
    for backup in backups:
        print(f"  - {backup['backup_name']} ({backup['created_at']})")
    
    # Test backup status
    status = bm.get_backup_status()
    print(f"Backup status: {json.dumps(status, indent=2)}")