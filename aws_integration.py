#!/usr/bin/env python3
"""
GenOpti-OS AWS Integration Module
Connects to GenKins Forge API backend services
"""

import json
import time
import hashlib
import hmac
import requests
import logging
import threading
import queue
import psutil
import os
from datetime import datetime, timezone
from pathlib import Path

class GenOptiAWSClient:
    """Client for GenKins Forge API integration."""
    
    def __init__(self, config=None):
        """Initialize AWS client with configuration."""
        self.config = config or self._load_config()
        self.base_url = self.config.get('api_base_url', 'https://api.genkinsforge.com')
        self.device_id = None
        self.jwt_token = None
        self.jwt_expires_at = None
        self.location_id = None
        self.account_uid = None
        
        # Offline queue for failed requests
        self.offline_queue = queue.Queue()
        self.batch_queue = []
        self.batch_size = 10
        self.batch_timeout = 300  # 5 minutes
        self.last_batch_time = time.time()
        
        # Health monitoring
        self.last_health_check = 0
        self.health_check_interval = 300  # 5 minutes
        
        # Start background workers
        self._start_background_workers()
        
        logging.info("GenOpti AWS client initialized")
    
    def _load_config(self):
        """Load configuration from file or environment."""
        config_file = os.path.join(os.path.dirname(__file__), 'aws_config.json')
        
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = json.load(f)
        else:
            config = {}
        
        # Override with environment variables
        config.update({
            'api_base_url': os.getenv('GENOPTI_API_URL', config.get('api_base_url', 'https://api.genkinsforge.com')),
            'device_model': os.getenv('GENOPTI_DEVICE_MODEL', 'genopti_go2'),
            'location_id': os.getenv('GENOPTI_LOCATION_ID', config.get('location_id')),
            'setup_token': os.getenv('GENOPTI_SETUP_TOKEN', config.get('setup_token')),
            'batch_upload': config.get('batch_upload', True),
            'health_monitoring': config.get('health_monitoring', True),
            'underage_alerts': config.get('underage_alerts', True)
        })
        
        return config
    
    def _start_background_workers(self):
        """Start background threads for batch processing and health monitoring."""
        # Batch processor thread
        batch_thread = threading.Thread(target=self._batch_processor, daemon=True)
        batch_thread.start()
        
        # Offline queue processor thread  
        offline_thread = threading.Thread(target=self._offline_processor, daemon=True)
        offline_thread.start()
        
        # Health monitor thread
        if self.config.get('health_monitoring', True):
            health_thread = threading.Thread(target=self._health_monitor, daemon=True)
            health_thread.start()
    
    def _make_request(self, method, endpoint, data=None, auth_required=True, timeout=30):
        """Make HTTP request with error handling and retry logic."""
        url = f"{self.base_url}{endpoint}"
        headers = {'Content-Type': 'application/json'}
        
        if auth_required and self.jwt_token:
            headers['Authorization'] = f'Bearer {self.jwt_token}'
        
        try:
            response = requests.request(
                method=method,
                url=url, 
                headers=headers,
                json=data,
                timeout=timeout
            )
            
            if response.status_code == 401 and auth_required:
                # Token expired, try to refresh
                if self._refresh_token():
                    headers['Authorization'] = f'Bearer {self.jwt_token}'
                    response = requests.request(method, url, headers=headers, json=data, timeout=timeout)
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logging.error(f"API request failed: {e}")
            
            # Add to offline queue for retry
            if method == 'POST' and data:
                self.offline_queue.put({
                    'method': method,
                    'endpoint': endpoint, 
                    'data': data,
                    'timestamp': time.time(),
                    'retry_count': 0
                })
            
            raise
    
    def register_device(self, setup_token=None, location_id=None):
        """Register device with AWS backend (two-phase process)."""
        setup_token = setup_token or self.config.get('setup_token')
        location_id = location_id or self.config.get('location_id')
        
        if not setup_token or not location_id:
            raise ValueError("Setup token and location ID required for registration")
        
        # Get device ID from hardware
        device_serial = self._get_device_serial()
        
        try:
            # Phase 1: Setup
            setup_data = {
                'action': 'setup',
                'setupToken': setup_token,
                'deviceId': device_serial,
                'deviceModel': self.config.get('device_model', 'genopti_go2')
            }
            
            setup_response = self._make_request('POST', '/webhook/registration', setup_data, auth_required=False)
            salt = setup_response['data']['salt']
            
            # Phase 2: Registration with cryptographic challenge
            challenge = f"{device_serial}:{location_id}:{int(time.time())}"
            signature = self._sign_challenge(challenge, salt)
            
            registration_data = {
                'action': 'registration',
                'challengeSignature': signature,
                'locationId': location_id,
                'challenge': challenge
            }
            
            reg_response = self._make_request('POST', '/webhook/registration', registration_data, auth_required=False)
            
            # Store registration details
            self.device_id = reg_response['data']['deviceId']
            self.jwt_token = reg_response['data']['jwt']
            self.jwt_expires_at = reg_response['data']['expiresAt']
            self.location_id = location_id
            self.account_uid = reg_response['data']['accountUid']
            
            # Save to persistent storage
            self._save_device_config()
            
            logging.info(f"Device registered successfully: {self.device_id}")
            return True
            
        except Exception as e:
            logging.error(f"Device registration failed: {e}")
            return False
    
    def _get_device_serial(self):
        """Get device serial number for identification."""
        try:
            # Try to read from device ID file first
            device_id_file = "/etc/device_id"
            if os.path.exists(device_id_file):
                with open(device_id_file, 'r') as f:
                    return f.read().strip()
        except:
            pass
        
        # Fallback to CPU serial
        try:
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if line.startswith('Serial'):
                        return line.split(':')[1].strip()
        except:
            pass
        
        # Final fallback
        return f"genopti_{int(time.time())}"
    
    def _sign_challenge(self, challenge, salt):
        """Sign challenge with salt for cryptographic verification."""
        combined = f"{challenge}:{salt}"
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def _save_device_config(self):
        """Save device configuration to persistent storage."""
        config_data = {
            'device_id': self.device_id,
            'jwt_token': self.jwt_token,
            'jwt_expires_at': self.jwt_expires_at,
            'location_id': self.location_id,
            'account_uid': self.account_uid,
            'last_updated': time.time()
        }
        
        config_file = os.path.join(os.path.dirname(__file__), 'device_config.json')
        with open(config_file, 'w') as f:
            json.dump(config_data, f, indent=2)
        
        # Secure the file
        os.chmod(config_file, 0o600)
    
    def _load_device_config(self):
        """Load device configuration from persistent storage."""
        config_file = os.path.join(os.path.dirname(__file__), 'device_config.json')
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                
                self.device_id = config.get('device_id')
                self.jwt_token = config.get('jwt_token')
                self.jwt_expires_at = config.get('jwt_expires_at')
                self.location_id = config.get('location_id')
                self.account_uid = config.get('account_uid')
                
                # Check if token needs refresh
                if self.jwt_expires_at and time.time() > self.jwt_expires_at - 3600:  # Refresh 1 hour early
                    self._refresh_token()
                
                return True
            except Exception as e:
                logging.error(f"Failed to load device config: {e}")
        
        return False
    
    def _refresh_token(self):
        """Refresh JWT token when it's about to expire."""
        if not self.device_id:
            return False
        
        try:
            # Use setup token to get new JWT
            if self.config.get('setup_token'):
                return self.register_device()
        except Exception as e:
            logging.error(f"Token refresh failed: {e}")
        
        return False
    
    def log_scan_result(self, scan_data, validation_result):
        """Log scan result to AWS backend."""
        if not self.config.get('batch_upload', True):
            return True
        
        # Prepare scan data for batch
        scan_record = {
            'scanId': f"SCAN_{int(time.time())}_{len(self.batch_queue)+1:03d}",
            'timestamp': int(time.time()),
            'scanType': 'drivers_license',
            'aamvaData': {
                'firstName': scan_data.get('first_name', ''),
                'lastName': scan_data.get('last_name', ''),
                'dateOfBirth': scan_data.get('date_of_birth', ''),
                'address': {
                    'street': scan_data.get('address_street', ''),
                    'city': scan_data.get('address_city', ''),
                    'state': scan_data.get('address_state', ''),
                    'zipCode': scan_data.get('address_postal_code', '')
                },
                'licenseNumber': scan_data.get('customer_id_number', ''),
                'issueDate': scan_data.get('issue_date', ''),
                'expirationDate': scan_data.get('expiration_date', '')
            },
            'verification': {
                'isValid': validation_result.get('is_valid', False),
                'isExpired': validation_result.get('is_expired', True),
                'age': validation_result.get('age'),
                'isUnderage': not validation_result.get('meets_age_requirement', False)
            }
        }
        
        # Add to batch queue
        self.batch_queue.append(scan_record)
        
        # Send underage alert immediately if needed
        if scan_record['verification']['isUnderage'] and self.config.get('underage_alerts', True):
            self._send_underage_alert(scan_record, validation_result)
        
        # Check if batch should be sent
        if (len(self.batch_queue) >= self.batch_size or 
            time.time() - self.last_batch_time >= self.batch_timeout):
            self._send_batch()
        
        return True
    
    def _send_batch(self):
        """Send batch of scan data to AWS backend."""
        if not self.batch_queue:
            return
        
        batch_data = {
            'deviceId': self.device_id,
            'locationId': self.location_id,
            'timestamp': int(time.time()),
            'batchId': f"BATCH_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'scans': self.batch_queue.copy()
        }
        
        try:
            response = self._make_request('POST', '/webhook/batchupdate', batch_data)
            logging.info(f"Batch sent successfully: {len(self.batch_queue)} scans")
            
            # Clear batch on success
            self.batch_queue.clear()
            self.last_batch_time = time.time()
            
        except Exception as e:
            logging.error(f"Batch send failed: {e}")
    
    def _send_underage_alert(self, scan_record, validation_result):
        """Send underage alert to AWS backend."""
        alert_data = {
            'deviceId': self.device_id,
            'locationId': self.location_id,
            'incidentId': f"INC_{scan_record['scanId']}",
            'timestamp': scan_record['timestamp'],
            'scanId': scan_record['scanId'],
            'detectedAge': validation_result.get('age', 0),
            'severity': 'medium',
            'attemptedPurchase': 'alcohol'  # Default, could be configurable
        }
        
        try:
            self._make_request('POST', '/webhook/underage-alert', alert_data)
            logging.info(f"Underage alert sent: Age {alert_data['detectedAge']}")
        except Exception as e:
            logging.error(f"Underage alert failed: {e}")
    
    def _send_health_check(self):
        """Send health metrics to AWS backend."""
        try:
            # Collect system metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Get CPU temperature (Pi-specific)
            cpu_temp = 0
            try:
                with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                    cpu_temp = int(f.read()) / 1000.0
            except:
                pass
            
            # Get uptime
            uptime = int(time.time() - psutil.boot_time())
            
            health_data = {
                'deviceId': self.device_id,
                'timestamp': int(time.time()),
                'metrics': {
                    'cpu': {
                        'usage': cpu_percent,
                        'temperature': cpu_temp,
                        'cores': psutil.cpu_count()
                    },
                    'memory': {
                        'total': memory.total // (1024*1024),  # MB
                        'used': memory.used // (1024*1024),
                        'available': memory.available // (1024*1024)
                    },
                    'disk': {
                        'total': disk.total // (1024*1024),  # MB
                        'used': disk.used // (1024*1024),
                        'available': disk.free // (1024*1024)
                    },
                    'network': {
                        'latency': 0,  # Could add ping test
                        'downloadSpeed': 0,  # Could add speed test
                        'uploadSpeed': 0
                    }
                },
                'diagnostics': {
                    'scannerStatus': 'healthy',
                    'cameraStatus': 'healthy',
                    'errorCount': 0,
                    'lastError': None,
                    'uptime': uptime
                }
            }
            
            # Send without JWT (uses device ID validation)
            self._make_request('POST', '/webhook/health-check', health_data, auth_required=False)
            logging.debug("Health check sent successfully")
            
        except Exception as e:
            logging.error(f"Health check failed: {e}")
    
    def _batch_processor(self):
        """Background thread to process batches periodically."""
        while True:
            try:
                time.sleep(60)  # Check every minute
                
                # Send batch if timeout reached
                if (self.batch_queue and 
                    time.time() - self.last_batch_time >= self.batch_timeout):
                    self._send_batch()
                    
            except Exception as e:
                logging.error(f"Batch processor error: {e}")
    
    def _offline_processor(self):
        """Background thread to retry failed requests."""
        while True:
            try:
                # Get item from queue (blocks until available)
                item = self.offline_queue.get(timeout=60)
                
                # Skip if too old (1 hour)
                if time.time() - item['timestamp'] > 3600:
                    continue
                
                # Exponential backoff
                retry_delay = min(300, 2 ** item['retry_count'])  # Max 5 minutes
                time.sleep(retry_delay)
                
                # Retry the request
                try:
                    self._make_request(item['method'], item['endpoint'], item['data'])
                    logging.info(f"Offline request retried successfully")
                except:
                    item['retry_count'] += 1
                    if item['retry_count'] < 5:  # Max 5 retries
                        self.offline_queue.put(item)
                
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"Offline processor error: {e}")
    
    def _health_monitor(self):
        """Background thread for periodic health monitoring."""
        while True:
            try:
                time.sleep(self.health_check_interval)
                
                if self.device_id:  # Only send if registered
                    self._send_health_check()
                    
            except Exception as e:
                logging.error(f"Health monitor error: {e}")
    
    def is_registered(self):
        """Check if device is registered with AWS backend."""
        return bool(self.device_id and self.jwt_token)
    
    def force_batch_send(self):
        """Force send current batch (useful for shutdown)."""
        if self.batch_queue:
            self._send_batch()
    
    def get_status(self):
        """Get current AWS integration status."""
        return {
            'registered': self.is_registered(),
            'device_id': self.device_id,
            'location_id': self.location_id,
            'token_expires': self.jwt_expires_at,
            'batch_size': len(self.batch_queue),
            'offline_queue_size': self.offline_queue.qsize()
        }

# Singleton instance
aws_client = None

def get_aws_client():
    """Get singleton AWS client instance."""
    global aws_client
    if aws_client is None:
        aws_client = GenOptiAWSClient()
        # Try to load existing config
        aws_client._load_device_config()
    return aws_client

def initialize_aws_integration(config=None):
    """Initialize AWS integration with optional config."""
    global aws_client
    aws_client = GenOptiAWSClient(config)
    return aws_client