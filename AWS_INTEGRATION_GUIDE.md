# GenOpti-OS AWS Integration Guide

## Overview

GenOpti-OS now integrates with your GenKins Forge API backend to provide:
- **Device Registration** - Two-phase cryptographic registration
- **Scan Data Logging** - Batch upload with PII anonymization  
- **Underage Alerts** - Real-time SMS notifications via Twilio
- **Health Monitoring** - System metrics and diagnostics
- **Offline Queue** - Reliable delivery with retry mechanisms

## Architecture Integration

### Your Backend Services (Node.js + Supabase)
- **Registration Service** (Port 3001) - Device onboarding
- **Batch Update Service** (Port 3003) - Scan data processing  
- **Underage Alert Service** (Port 3004) - SMS notifications
- **Health Check Service** (Port 3005) - Device monitoring
- **Portal API Service** (Port 3006) - Customer dashboard

### GenOpti-OS Integration Points
```
┌─────────────────┐    ┌──────────────────────┐    ┌─────────────────┐
│   GenOpti-OS    │───▶│  GenKins Forge API   │───▶│  Customer Portal │
│   (Raspberry Pi)│    │  (AWS/Supabase)      │    │  (React Dashboard)│
└─────────────────┘    └──────────────────────┘    └─────────────────┘
```

## Setup Instructions

### 1. Device Registration

**Option A: QR Code Registration (Recommended)**
1. Generate setup QR code from your portal containing:
   ```json
   {
     "setup_token": "SETUP_TOKEN_FROM_PORTAL",
     "location_id": "LOC_STORE_001"
   }
   ```
2. Scan QR code with GenOpti-OS in setup mode
3. Device automatically registers and receives JWT token

**Option B: Manual Registration via API**
```bash
curl -X POST http://127.0.0.1:5000/api/aws/register \
  -H "Content-Type: application/json" \
  -d '{
    "setup_token": "YOUR_SETUP_TOKEN", 
    "location_id": "LOC_STORE_001"
  }'
```

### 2. Configuration File (Optional)

Create `/opt/genopti-os/aws_config.json`:
```json
{
  "api_base_url": "https://api.genkinsforge.com",
  "device_model": "genopti_go2",
  "location_id": "LOC_STORE_001",
  "batch_upload": true,
  "health_monitoring": true,
  "underage_alerts": true,
  "batch_size": 10,
  "batch_timeout_seconds": 300
}
```

### 3. Environment Variables (Alternative)

Set in `/opt/genopti-os/.env`:
```bash
GENOPTI_API_URL=https://api.genkinsforge.com
GENOPTI_DEVICE_MODEL=genopti_go2
GENOPTI_LOCATION_ID=LOC_STORE_001
GENOPTI_SETUP_TOKEN=your_setup_token
```

## API Endpoints

### Device Status
```http
GET /api/aws/status
```
**Response:**
```json
{
  "aws_integration": true,
  "status": {
    "registered": true,
    "device_id": "100000008c250466_go20",
    "location_id": "LOC_STORE_001", 
    "token_expires": 1721145600,
    "batch_size": 3,
    "offline_queue_size": 0
  }
}
```

### Manual Device Registration  
```http
POST /api/aws/register
Content-Type: application/json

{
  "setup_token": "SETUP_TOKEN_FROM_PORTAL",
  "location_id": "LOC_STORE_001"
}
```

### Force Batch Send
```http
POST /api/aws/force-batch
```

## Data Flow

### 1. Scan Processing
```
License Scan ──▶ AAMVA Parse ──▶ Validation ──▶ AWS Batch Queue
                                      │
                                      ▼
                              Underage Alert ──▶ SMS Notification
```

### 2. Batch Upload (Every 5 minutes or 10 scans)
```json
{
  "deviceId": "100000008c250466_go20",
  "locationId": "LOC_STORE_001",
  "batchId": "BATCH_20250715_001",
  "scans": [
    {
      "scanId": "SCAN_1721059200_001",
      "aamvaData": {
        "firstName": "John", "lastName": "Smith",
        "dateOfBirth": "1990-01-15",
        "licenseNumber": "D1234567"
      },
      "verification": {
        "isValid": true, "age": 35, "isUnderage": false
      }
    }
  ]
}
```

### 3. Health Monitoring (Every 5 minutes)
```json
{
  "deviceId": "100000008c250466_go20",
  "metrics": {
    "cpu": {"usage": 45.2, "temperature": 68.5},
    "memory": {"total": 8192, "used": 3456},
    "disk": {"total": 64000, "used": 32000}
  },
  "diagnostics": {
    "scannerStatus": "healthy",
    "errorCount": 0,
    "uptime": 86400
  }
}
```

## Security Features

### 1. Two-Phase Registration
- **Phase 1**: Setup token validation and salt exchange
- **Phase 2**: Cryptographic challenge/response verification
- **Result**: 24-hour JWT token for API authentication

### 2. PII Anonymization
- All personal data SHA256 hashed before transmission
- Geographic coordinates generalized to ~500ft accuracy
- Only birth year transmitted (not full date)

### 3. Offline Queue
- Failed requests automatically queued for retry
- Exponential backoff (max 5 minutes between retries)
- Maximum 5 retry attempts per request
- Automatic cleanup of old requests (1 hour)

### 4. Token Management
- JWT tokens refresh automatically before expiration
- Secure storage in `/opt/genopti-os/device_config.json` (600 permissions)
- Graceful fallback when backend unavailable

## Monitoring and Troubleshooting

### Check Integration Status
```bash
curl http://127.0.0.1:5000/api/aws/status | python3 -m json.tool
```

### View Logs
```bash
sudo tail -f /opt/genopti-os/logs/scanner.log | grep -i aws
```

### Common Issues

**Device Not Registered**
- Check setup token and location ID
- Verify network connectivity to api.genkinsforge.com
- Check logs for registration errors

**Batch Upload Failures**
- Verify JWT token hasn't expired
- Check network connectivity
- Review offline queue status

**Health Check Failures**
- Ensure device ID is valid
- Check backend health service status
- Verify device registration

### Manual Batch Send
```bash
curl -X POST http://127.0.0.1:5000/api/aws/force-batch
```

### Check Backend Connectivity
```bash
curl -I https://api.genkinsforge.com/health
```

## Customer Portal Integration

### Dashboard Features
- **Real-time Analytics** - Scan counts, age demographics
- **Device Management** - Health status, location mapping
- **Alert Management** - Underage incident tracking
- **User Administration** - Role-based permissions
- **Compliance Reports** - PDF generation for incidents

### Data Available in Portal
- **Anonymized Scan Data** - Age trends, validation rates
- **Device Health Metrics** - CPU, memory, disk usage
- **Incident Reports** - Underage detection alerts
- **Location Analytics** - Per-store performance data

## Advanced Configuration

### Batch Settings
```json
{
  "batch_size": 25,           // Send after N scans
  "batch_timeout_seconds": 180, // Send after N seconds
  "retry_attempts": 3,        // Max retry attempts
  "request_timeout_seconds": 45 // HTTP request timeout
}
```

### Health Monitoring
```json
{
  "health_check_interval_seconds": 600, // 10 minutes
  "include_network_tests": false,       // Skip speed tests
  "cpu_temp_threshold": 85.0           // Alert threshold
}
```

### Feature Toggles
```json
{
  "batch_upload": true,        // Enable scan data upload
  "health_monitoring": true,   // Enable device monitoring  
  "underage_alerts": true,     // Enable SMS notifications
  "offline_queue": true        // Enable retry mechanism
}
```

## Production Deployment

### System Service Integration
- AWS integration runs as background threads
- Automatic startup with GenOpti-OS service
- Graceful shutdown with batch flush
- Error recovery and logging

### Performance Impact
- **Memory Usage**: +5-10MB for background threads
- **CPU Usage**: Minimal (batch processing only)
- **Network Usage**: ~1KB per scan (batched)
- **Storage**: JWT tokens and offline queue

### Scalability
- Supports 1000+ scans per day per device
- Automatic load balancing via NGINX
- Horizontal scaling across multiple devices
- Centralized analytics and reporting

---

## Support

For issues with AWS integration:
1. Check GenOpti-OS logs: `/opt/genopti-os/logs/scanner.log`
2. Verify backend service status: `https://api.genkinsforge.com/health`
3. Review device registration status: `GET /api/aws/status`
4. Contact support with correlation IDs from logs

**Integration Version**: 1.0.0  
**Compatible with**: GenKins Forge API v2.1.0  
**Last Updated**: 2025-07-15