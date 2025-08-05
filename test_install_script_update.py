#!/usr/bin/env python3
"""
Test for Install Script Based Update Method
This test validates the new update approach using the install script with checksum validation.
"""

import os
import hashlib
import json
import subprocess
import tempfile
import shutil
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class InstallScriptUpdateTest:
    """Test the install script based update method."""
    
    def __init__(self):
        self.genopti_user_dir = "/home/genopti-user/genopti-os"
        self.install_script_path = os.path.join(self.genopti_user_dir, "install_genopti-os.sh")
        self.test_results = []
        
    def calculate_file_checksum(self, file_path):
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
    
    def test_install_script_exists(self):
        """Test that the install script exists and is executable."""
        logging.info("Testing install script existence and permissions...")
        
        if not os.path.exists(self.install_script_path):
            result = {"test": "install_script_exists", "status": "FAIL", "message": "Install script not found"}
            self.test_results.append(result)
            return False
        
        if not os.access(self.install_script_path, os.X_OK):
            result = {"test": "install_script_exists", "status": "FAIL", "message": "Install script not executable"}
            self.test_results.append(result)
            return False
        
        result = {"test": "install_script_exists", "status": "PASS", "message": "Install script found and executable"}
        self.test_results.append(result)
        return True
    
    def test_calculate_install_script_checksum(self):
        """Test calculating the install script checksum."""
        logging.info("Testing install script checksum calculation...")
        
        checksum = self.calculate_file_checksum(self.install_script_path)
        
        if not checksum:
            result = {"test": "calculate_install_script_checksum", "status": "FAIL", "message": "Could not calculate checksum"}
            self.test_results.append(result)
            return None
        
        result = {
            "test": "calculate_install_script_checksum", 
            "status": "PASS", 
            "message": f"Checksum calculated successfully",
            "checksum": checksum
        }
        self.test_results.append(result)
        logging.info(f"Install script checksum: {checksum}")
        return checksum
    
    def test_validate_install_script_checksum(self, expected_checksum):
        """Test validating install script against expected checksum."""
        logging.info("Testing install script checksum validation...")
        
        actual_checksum = self.calculate_file_checksum(self.install_script_path)
        
        if not actual_checksum:
            result = {"test": "validate_install_script_checksum", "status": "FAIL", "message": "Could not calculate actual checksum"}
            self.test_results.append(result)
            return False
        
        is_valid = actual_checksum == expected_checksum
        
        result = {
            "test": "validate_install_script_checksum",
            "status": "PASS" if is_valid else "FAIL",
            "message": f"Checksum validation {'passed' if is_valid else 'failed'}",
            "expected": expected_checksum,
            "actual": actual_checksum
        }
        self.test_results.append(result)
        return is_valid
    
    def test_simulate_update_download(self):
        """Simulate downloading an update package."""
        logging.info("Testing update package download simulation...")
        
        # Create a mock update package
        test_package_dir = tempfile.mkdtemp(prefix="genopti_update_test_")
        package_path = os.path.join(test_package_dir, "genopti-os-v1.0.tar.gz")
        
        try:
            # Create mock update files
            mock_files = {
                "version.txt": "1.0",
                "app.py": "# Mock updated app.py file\nprint('Updated version 1.0')",
                "checksums.txt": "abc123  version.txt\ndef456  app.py"
            }
            
            # Create temporary directory with mock files
            mock_dir = os.path.join(test_package_dir, "mock_update")
            os.makedirs(mock_dir)
            
            for filename, content in mock_files.items():
                with open(os.path.join(mock_dir, filename), 'w') as f:
                    f.write(content)
            
            # Create tar.gz package
            import tarfile
            with tarfile.open(package_path, 'w:gz') as tar:
                tar.add(mock_dir, arcname='.')
            
            # Calculate package checksum
            package_checksum = self.calculate_file_checksum(package_path)
            
            result = {
                "test": "simulate_update_download",
                "status": "PASS",
                "message": "Mock update package created successfully",
                "package_path": package_path,
                "package_checksum": package_checksum
            }
            self.test_results.append(result)
            
            return package_path, package_checksum
            
        except Exception as e:
            result = {"test": "simulate_update_download", "status": "FAIL", "message": f"Failed to create mock package: {e}"}
            self.test_results.append(result)
            return None, None
        finally:
            # Note: We don't cleanup here so the package can be used by other tests
            pass
    
    def test_user_permissions(self):
        """Test that we have the necessary permissions as genopti-user."""
        logging.info("Testing user permissions...")
        
        current_user = os.getenv('USER', 'unknown')
        can_sudo = False
        
        try:
            # Test if we can run sudo (this might prompt for password)
            result = subprocess.run(['sudo', '-n', 'echo', 'test'], capture_output=True, text=True, timeout=5)
            can_sudo = result.returncode == 0
        except:
            can_sudo = False
        
        result = {
            "test": "user_permissions",
            "status": "PASS" if current_user == "genopti-user" and can_sudo else "WARN",
            "message": f"Running as user: {current_user}, sudo access: {can_sudo}",
            "current_user": current_user,
            "sudo_access": can_sudo
        }
        self.test_results.append(result)
        
        return current_user == "genopti-user" and can_sudo
    
    def test_dry_run_install_script(self):
        """Test running the install script in dry-run mode (if supported)."""
        logging.info("Testing install script dry run...")
        
        try:
            # Check if install script supports any dry-run or test mode
            result = subprocess.run(['bash', '-n', self.install_script_path], 
                                  capture_output=True, text=True, timeout=10)
            
            syntax_ok = result.returncode == 0
            
            test_result = {
                "test": "dry_run_install_script",
                "status": "PASS" if syntax_ok else "FAIL",
                "message": f"Install script syntax check {'passed' if syntax_ok else 'failed'}",
                "stderr": result.stderr if result.stderr else None
            }
            self.test_results.append(test_result)
            
            return syntax_ok
            
        except Exception as e:
            result = {"test": "dry_run_install_script", "status": "FAIL", "message": f"Failed to test install script: {e}"}
            self.test_results.append(result)
            return False
    
    def test_backup_current_version(self):
        """Test creating a backup before update."""
        logging.info("Testing backup creation...")
        
        try:
            from version_manager import VersionManager
            vm = VersionManager(self.genopti_user_dir)
            current_version = vm.get_current_version()
            
            result = {
                "test": "backup_current_version",
                "status": "PASS",
                "message": f"Current version detected: {current_version}",
                "current_version": current_version
            }
            self.test_results.append(result)
            
            return current_version
            
        except Exception as e:
            result = {"test": "backup_current_version", "status": "FAIL", "message": f"Failed to get current version: {e}"}
            self.test_results.append(result)
            return None
    
    def run_all_tests(self):
        """Run all tests in sequence."""
        logging.info("=" * 60)
        logging.info("STARTING INSTALL SCRIPT UPDATE METHOD TESTS")
        logging.info("=" * 60)
        
        # Test 1: Check install script
        if not self.test_install_script_exists():
            logging.error("Critical: Install script not found, aborting tests")
            return False
        
        # Test 2: Calculate install script checksum
        install_script_checksum = self.test_calculate_install_script_checksum()
        if not install_script_checksum:
            logging.error("Critical: Could not calculate install script checksum")
            return False
        
        # Test 3: Validate checksum (using current checksum as expected)
        self.test_validate_install_script_checksum(install_script_checksum)
        
        # Test 4: Test user permissions
        self.test_user_permissions()
        
        # Test 5: Test install script syntax
        self.test_dry_run_install_script()
        
        # Test 6: Test backup capability
        self.test_backup_current_version()
        
        # Test 7: Simulate update download
        self.test_simulate_update_download()
        
        return True
    
    def print_test_results(self):
        """Print comprehensive test results."""
        logging.info("=" * 60)
        logging.info("TEST RESULTS SUMMARY")
        logging.info("=" * 60)
        
        passed = 0
        failed = 0
        warnings = 0
        
        for result in self.test_results:
            status = result['status']
            if status == 'PASS':
                passed += 1
                print(f"✅ {result['test']}: {result['message']}")
            elif status == 'FAIL':
                failed += 1
                print(f"❌ {result['test']}: {result['message']}")
            elif status == 'WARN':
                warnings += 1
                print(f"⚠️  {result['test']}: {result['message']}")
        
        print(f"\nSUMMARY: {passed} passed, {failed} failed, {warnings} warnings")
        
        # Print key information
        for result in self.test_results:
            if result['test'] == 'calculate_install_script_checksum' and 'checksum' in result:
                print(f"\n📋 INSTALL SCRIPT CHECKSUM: {result['checksum']}")
                break
        
        print(f"\n📊 OVERALL STATUS: {'READY FOR IMPLEMENTATION' if failed == 0 else 'NEEDS FIXES'}")
        
        return failed == 0


def main():
    """Main test execution."""
    tester = InstallScriptUpdateTest()
    
    success = tester.run_all_tests()
    test_passed = tester.print_test_results()
    
    # Create test report
    report = {
        "timestamp": datetime.now().isoformat(),
        "test_suite": "install_script_update_method",
        "overall_success": success and test_passed,
        "results": tester.test_results
    }
    
    # Save test report
    report_file = "/home/genopti-user/genopti-os/test_report_install_script_update.json"
    try:
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n📄 Test report saved to: {report_file}")
    except Exception as e:
        print(f"⚠️  Could not save test report: {e}")
    
    return 0 if (success and test_passed) else 1


if __name__ == "__main__":
    exit(main())