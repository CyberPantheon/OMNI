# OMNI
An advanced multi thread and concurrent bruteforcing tool 
# Ultimate Brute Force Framework




A powerful and flexible brute force tool with proxy support, concurrent requests, and multiple success detection methods, built for high speed bruteforcing , 80% faster than traditional bruteforcing tools.

## Features

- ✅ **Multiple Request Types**: Supports both form submissions and JSON API endpoints
- 🔄 **Proxy Support**: Rotates through authenticated proxies for anonymity
- ⚡ **Concurrent Requests**: Speeds up attacks using multiple threads
- 🔍 **Advanced Detection**: 5+ methods to detect successful logins
- 🛡️ **CSRF Support**: Automatically handles CSRF protected forms
- 📊 **Detailed Reporting**: Provides comprehensive success/failure analysis
- 🧩 **Modular Design**: Easy to extend with new detection methods

## Installation

1. Clone the repository:
```bash
[git clone https://github.com/CyberPantheon/OMNI.git]
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Attack
```bash
python OMNI.py
```

Follow the interactive prompts to configure your attack.

### Command Line Arguments
For non-interactive use:
```bash
python omni.py \
  --url https://target.com/login \
  --username admin \
  --wordlist passwords.txt \
  --threads 10 \
  --proxies proxies.txt
```

### Proxy File Format
Create a text file with proxies in either format:
```
ip:port:username:password
ip:port
```

Example:
```
185.199.228.220:7300:jgxikuyc:5exdq77b4bd1
203.45.112.180:8080
```

## Configuration Options

| Setting | Description | Default |
|---------|-------------|---------|
| Request Type | form/json/auto | auto |
| Success Keyword | Text indicating success | "Login successful" |
| Failure Keyword | Text indicating failure | "Invalid credentials" |
| Delay | Seconds between attempts | 1 |
| Threads | Concurrent requests | 10 |
| Timeout | Request timeout (seconds) | 10 |
| Verify SSL | Validate SSL certificates | False |

## Detection Methods

The tool uses multiple techniques to identify successful logins:

1. **HTTP Status Codes**: 200-299 range
2. **Keyword Matching**: Presence of success/failure strings
3. **Redirect Detection**: 300-399 status codes
4. **Cookie Analysis**: New session cookies
5. **JSON Responses**: Success flags in API responses
6. **Response Time**: Significant time differences

## Examples

### Basic Form Attack
```
python omni.py \
  --url https://example.com/login \
  --username admin \
  --wordlist rockyou.txt \
  --type form
```

### JSON API Attack with Proxies
```
python omni.py \
  --url https://api.example.com/auth \
  --username user@domain.com \
  --wordlist passwords.txt \
  --type json \
  --proxies my_proxies.txt \
  --threads 20
```

## Troubleshooting

**Problem**: Proxies not working  
**Solution**: Verify proxy format and credentials. Test with:
```python
import requests
proxy = {'http': 'http://user:pass@ip:port'}
requests.get('http://httpbin.org/ip', proxies=proxy)
```

**Problem**: CSRF detection failing  
**Solution**: Manually specify CSRF field name or disable CSRF protection

**Problem**: False positives  
**Solution**: Adjust success/failure keywords and enable more detection methods

## Legal Disclaimer

This tool is for educational and authorized penetration testing purposes only. Unauthorized use against systems you don't own or have permission to test is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

