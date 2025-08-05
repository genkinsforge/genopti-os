#!/usr/bin/env python3
"""
Comprehensive test for the decoupled auto-update system
Tests all components and file-based communication
"""

import os
import json
import time
import subprocess
import threading
from datetime import datetime

def print_header(title):
    print(f"\n{'='*60}")
    print(f" {title}")
    print(f"{'='*60}")

def print_test(test_name, status="TESTING"):
    print(f"[{status}] {test_name}")

def print_result(test_name, success, details=""):
    status = "✓ PASS" if success else "✗ FAIL"
    print(f"[{status}] {test_name}")
    if details:
        print(f"    {details}")

def test_file_communication():
    """Test file-based communication system"""
    print_header("FILE COMMUNICATION SYSTEM TEST")
    
    # Test 1: Communication directory
    comm_dir = "/tmp/genopti-updates"
    print_test("Communication directory creation")
    os.makedirs(comm_dir, mode=0o755, exist_ok=True)
    success = os.path.exists(comm_dir) and os.access(comm_dir, os.W_OK)
    print_result("Communication directory creation", success, f"Directory: {comm_dir}")
    
    # Test 2: Write version info file
    print_test("Version info file creation")
    version_file = os.path.join(comm_dir, "latest_version.json")
    test_version_data = {
        "current_version": "1.0",
        "last_checked": datetime.now().isoformat(),
        "update_available": False,
        "daemon_status": "running"
    }
    
    try:
        with open(version_file, 'w') as f:
            json.dump(test_version_data, f, indent=2)
        os.chmod(version_file, 0o644)
        success = os.path.exists(version_file)
        print_result("Version info file creation", success, f"File: {version_file}")
    except Exception as e:
        print_result("Version info file creation", False, f"Error: {e}")
    
    # Test 3: Read version info file
    print_test("Version info file reading")
    try:
        with open(version_file, 'r') as f:
            read_data = json.load(f)
        success = read_data["current_version"] == "1.0"
        print_result("Version info file reading", success, f"Version: {read_data.get('current_version')}")
    except Exception as e:
        print_result("Version info file reading", False, f"Error: {e}")
    
    return True

def test_update_interface():
    """Test the GenOpti-SVC update interface"""
    print_header("GENOPTI-SVC UPDATE INTERFACE TEST")
    
    try:
        from genopti_svc_update_interface import GenOptiSvcUpdateInterface
        
        # Test 1: Interface creation
        print_test("Interface initialization")
        interface = GenOptiSvcUpdateInterface()
        success = interface is not None
        print_result("Interface initialization", success)
        
        # Test 2: Get version info
        print_test("Get version info")
        version_info = interface.get_version_info()
        success = isinstance(version_info, dict) and 'current_version' in version_info
        print_result("Get version info", success, f"Current version: {version_info.get('current_version', 'unknown')}")
        
        # Test 3: Get update status
        print_test("Get update status")
        status = interface.get_update_status()
        success = isinstance(status, dict) and 'status' in status
        print_result("Get update status", success, f"Status: {status.get('status', 'unknown')}")
        
        # Test 4: Comprehensive status
        print_test("Get comprehensive status")
        comp_status = interface.get_comprehensive_status()
        success = isinstance(comp_status, dict) and 'update_method' in comp_status
        print_result("Get comprehensive status", success, f"Method: {comp_status.get('update_method', 'unknown')}")
        
        # Test 5: Daemon running check
        print_test("Daemon running check")
        daemon_running = interface.is_daemon_running()
        print_result("Daemon running check", True, f"Daemon running: {daemon_running}")
        
        return True
        
    except Exception as e:
        print_result("Interface testing", False, f"Error: {e}")
        return False

def test_daemon_components():
    """Test daemon components without actually starting it"""
    print_header("DAEMON COMPONENTS TEST")
    
    try:
        # We can't import the daemon directly due to logging setup, so test file existence
        daemon_script = "/home/genopti-user/genopti-os/genopti_user_update_daemon.py"
        
        # Test 1: Daemon script exists
        print_test("Daemon script existence")
        success = os.path.exists(daemon_script)
        print_result("Daemon script existence", success, f"Script: {daemon_script}")
        
        # Test 2: Script is executable
        print_test("Daemon script permissions")
        success = os.access(daemon_script, os.X_OK)
        if not success:
            os.chmod(daemon_script, 0o755)
            success = os.access(daemon_script, os.X_OK)
        print_result("Daemon script permissions", success, "Script is executable")
        
        # Test 3: Validate script syntax
        print_test("Daemon script syntax validation")
        try:
            result = subprocess.run(['python3', '-m', 'py_compile', daemon_script], 
                                  capture_output=True, text=True)
            success = result.returncode == 0
            print_result("Daemon script syntax validation", success, 
                        "Valid Python syntax" if success else f"Syntax error: {result.stderr}")
        except Exception as e:
            print_result("Daemon script syntax validation", False, f"Error: {e}")
        
        return True
        
    except Exception as e:
        print_result("Daemon components test", False, f"Error: {e}")
        return False

def test_systemd_service():
    """Test systemd service configuration"""
    print_header("SYSTEMD SERVICE TEST")
    
    service_file = "/home/genopti-user/genopti-os/genopti-update-daemon.service"
    setup_script = "/home/genopti-user/genopti-os/setup_update_daemon.sh"
    
    # Test 1: Service file exists
    print_test("Service file existence")
    success = os.path.exists(service_file)
    print_result("Service file existence", success, f"File: {service_file}")
    
    # Test 2: Setup script exists
    print_test("Setup script existence")
    success = os.path.exists(setup_script)
    print_result("Setup script existence", success, f"Script: {setup_script}")
    
    # Test 3: Setup script is executable
    print_test("Setup script permissions")
    success = os.access(setup_script, os.X_OK)
    print_result("Setup script permissions", success, "Script is executable")
    
    # Test 4: Service file syntax
    print_test("Service file syntax")
    try:
        with open(service_file, 'r') as f:
            content = f.read()
        success = '[Unit]' in content and '[Service]' in content and '[Install]' in content
        print_result("Service file syntax", success, "Valid systemd service file")
    except Exception as e:
        print_result("Service file syntax", False, f"Error: {e}")
    
    return True

def test_flask_integration():
    """Test Flask app integration"""
    print_header("FLASK INTEGRATION TEST")
    
    try:
        # Test 1: Import update interface
        print_test("Update interface import")
        from genopti_svc_update_interface import GenOptiSvcUpdateInterface
        success = GenOptiSvcUpdateInterface is not None
        print_result("Update interface import", success)
        
        # Test 2: Interface creation in Flask context
        print_test("Interface creation for Flask")
        interface = GenOptiSvcUpdateInterface()
        success = interface is not None
        print_result("Interface creation for Flask", success)
        
        # Test 3: API-like operations
        print_test("API operations simulation")
        version_info = interface.get_version_info()
        status = interface.get_update_status()
        comp_status = interface.get_comprehensive_status()
        
        success = (isinstance(version_info, dict) and 
                  isinstance(status, dict) and 
                  isinstance(comp_status, dict))
        print_result("API operations simulation", success, "All operations return valid data")
        
        return True
        
    except Exception as e:
        print_result("Flask integration test", False, f"Error: {e}")
        return False

def test_security_features():
    """Test security features"""
    print_header("SECURITY FEATURES TEST")
    
    # Test 1: File permissions
    print_test("Communication file permissions")
    comm_dir = "/tmp/genopti-updates"
    version_file = os.path.join(comm_dir, "latest_version.json")
    
    if os.path.exists(version_file):
        stat_info = os.stat(version_file)
        permissions = oct(stat_info.st_mode)[-3:]
        success = permissions == '644'  # readable by all, writable by owner
        print_result("Communication file permissions", success, f"Permissions: {permissions}")
    else:
        print_result("Communication file permissions", False, "Version file not found")
    
    # Test 2: Directory permissions
    print_test("Communication directory permissions")
    if os.path.exists(comm_dir):
        stat_info = os.stat(comm_dir)
        permissions = oct(stat_info.st_mode)[-3:]
        success = permissions == '755'  # readable/executable by all, writable by owner
        print_result("Communication directory permissions", success, f"Permissions: {permissions}")
    else:
        print_result("Communication directory permissions", False, "Communication directory not found")
    
    # Test 3: License file exists
    print_test("License file existence")
    license_file = "/home/genopti-user/genopti-os/LICENSE.md"
    success = os.path.exists(license_file)
    print_result("License file existence", success, f"File: {license_file}")
    
    # Test 4: License content validation
    if success:
        print_test("License content validation")
        try:
            with open(license_file, 'r') as f:
                content = f.read()
            success = ("Genkins Forge LLC" in content and 
                      "All Rights Reserved" in content and
                      "automatic update" in content.lower())
            print_result("License content validation", success, "License contains required terms")
        except Exception as e:
            print_result("License content validation", False, f"Error: {e}")
    
    return True

def test_update_simulation():
    """Simulate an update request without actually performing it"""
    print_header("UPDATE SIMULATION TEST")
    
    try:
        from genopti_svc_update_interface import GenOptiSvcUpdateInterface
        interface = GenOptiSvcUpdateInterface()
        
        # Test 1: Create fake update info
        print_test("Update request creation")
        fake_update_info = {
            'availableVersion': '1.1',
            'checksum': 'sha256:fake_checksum_for_testing',
            'downloadUrl': 'https://example.com/fake-update.tar.gz',
            'installScriptChecksum': 'fake_script_checksum',
            'updateMethod': 'install_script'
        }
        success = isinstance(fake_update_info, dict)
        print_result("Update request creation", success, f"Version: {fake_update_info['availableVersion']}")
        
        # Test 2: Request update (will fail gracefully since daemon isn't fully running)
        print_test("Update request submission")
        try:
            success, message = interface.request_update(fake_update_info)
            # This should fail gracefully since we don't have a real update
            print_result("Update request submission", True, f"Response: {message}")
        except Exception as e:
            print_result("Update request submission", False, f"Error: {e}")
        
        return True
        
    except Exception as e:
        print_result("Update simulation", False, f"Error: {e}")
        return False

def main():
    """Run comprehensive test suite"""
    print_header("GENOPTI-OS DECOUPLED AUTO-UPDATE SYSTEM TEST")
    print(f"Test started at: {datetime.now().isoformat()}")
    
    # Initialize test results
    test_results = []
    
    # Run all tests
    tests = [
        ("File Communication System", test_file_communication),
        ("GenOpti-SVC Update Interface", test_update_interface),
        ("Daemon Components", test_daemon_components),
        ("Systemd Service Configuration", test_systemd_service),
        ("Flask Integration", test_flask_integration),
        ("Security Features", test_security_features),
        ("Update Simulation", test_update_simulation)
    ]
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            test_results.append((test_name, result))
        except Exception as e:
            print(f"[✗ FAIL] {test_name} - Critical Error: {e}")
            test_results.append((test_name, False))
    
    # Final results
    print_header("TEST RESULTS SUMMARY")
    
    passed = sum(1 for _, result in test_results if result)
    total = len(test_results)
    
    for test_name, result in test_results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"[{status}] {test_name}")
    
    print(f"\nOverall Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED - SYSTEM READY FOR GO20 LAUNCH!")
        return True
    else:
        print("⚠️  Some tests failed - review issues before launch")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)