import requests, random, socket, ssl, socks
from pathlib import Path
from urllib.parse import urlparse
from Dependencies.displays import M, W, R, Y, G, C, handle_error

# =========================================================
# DEFAUT & RANDOM HEADERS
# =========================================================
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
                  " Chrome/121.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "DNT": "1"
}

BASE_DIR = Path(__file__).resolve().parent
UA_FILE = BASE_DIR / "Payloads" / "user_agents.txt"


def load_user_agents(path=UA_FILE):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError as e:
        handle_error(e, f"{UA_FILE} not found")
        return []

USER_AGENTS = load_user_agents()

def build_headers(args):
    headers = DEFAULT_HEADERS.copy()

    parsed_headers = parse_headers(args.headers)
    headers.update(parsed_headers)
    extra_headers = {}
    if hasattr(args, "extra_headers"):
        extra_headers = args.extra_headers or {}
    headers.update(extra_headers)

    # --- RANDOM USER AGENT ---
    if getattr(args, "random_headers", False):
        if USER_AGENTS:
            headers["User-Agent"] = random.choice(USER_AGENTS)
    return headers
    
    
# =========================================================
# TOR
# =========================================================
SOCKS_PROXY = { # h added for DNS resolution
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}

def is_tor_working(timeout=20):
    try:
        r = requests.get(
            "https://check.torproject.org/api/ip",
            proxies=SOCKS_PROXY,
            timeout=timeout,
            verify=False
        )
        return r.json().get("IsTor", False)
    except Exception:
        return False

def ensure_tor_or_exit():
    print(f"{Y}[!] {C}Checking Tor connexion...")
    if not is_tor_working():
        print(f"{R}[!] Tor isn't running, closing...")
        exit(0)
    print(f"{Y}[!] {G}Tor is running")


# =========================================================
# HEADERS & COOKIES ARGS
# =========================================================
def parse_headers(raw_headers):
    if not raw_headers:
        return {}

    headers = {}
    for item in raw_headers.split(","):
        item = item.strip()

        if "=" in item:
            k, v = item.split("=", 1)
        elif ":" in item:
            k, v = item.split(":", 1)
        else:
            continue

        headers[k.strip()] = v.strip()
    return headers

def parse_cookies(raw_cookies):
    """
    Convert: "key=value,key2=value2"
    -> dict
    """
    if not raw_cookies:
        return {}

    cookies = {}
    for item in raw_cookies.split(","):
        if "=" in item:
            key, value = item.split("=", 1)
            cookies[key.strip()] = value.strip()

    return cookies


# =========================================================
# REQUEST
# =========================================================
def get_request(args, url, **kwargs):
    # --- HEADERS ---
    #parsed_headers = parse_headers(args.headers)
    #final_headers = {**DEFAULT_HEADERS, **parsed_headers}
    final_headers = build_headers(args)

    # MERGE HEADERS FROM KWARGS
    extra_headers = kwargs.pop("headers", {})
    final_headers.update(extra_headers)

    # --- COOKIES ---
    final_cookies = parse_cookies(args.cookies)

    # --- PROXY LOGIC ---
    proxies = None

    if args.tor:
        proxies = SOCKS_PROXY

    elif args.proxy:
        active_proxy = args.proxy.strip()
        if active_proxy.lower() == "socks":
            proxies = SOCKS_PROXY

        else:
            proxies = {
                "http": active_proxy,
                "https": active_proxy
            }

    # --- METHOD ---
    method = getattr(args, "method", "GET").upper()

    # --- REQUEST ---
    try:
        response = requests.request(
            method=method,
            url=url,
            params=kwargs.get("params", getattr(args, "params", None)),
            headers=final_headers,
            cookies=final_cookies,
            proxies=proxies,
            timeout=kwargs.get("timeout", args.timeout),
            verify=kwargs.get("verify", False),
            allow_redirects=kwargs.get("allow_redirects", True)
        )
        return response
    except requests.exceptions.ConnectionError:
        return None

    except requests.exceptions.ConnectTimeout:
        return None

    except requests.exceptions.ReadTimeout:
        return "timeout"

    except Exception as e:
        handle_error(e, "Request error", args.verbose)
        return None


# =========================================================
# REQUEST FOR CRLF
# =========================================================
def get_request_socket(args, url, headers=None):
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        method = getattr(args, "method", "GET").upper()

        # =====================================================
        # HEADERS
        # =====================================================
        final_headers = build_headers(args)
        if headers:
            final_headers.update(headers)

        # Add Host if missing
        if "Host" not in final_headers:
            final_headers["Host"] = host

        # Force connection close for simpler recv logic
        if "Connection" not in final_headers:
            final_headers["Connection"] = "close"

        # =====================================================
        # BUILD RAW REQUEST
        # =====================================================
        request = f"{method} {path} HTTP/1.1\r\n"
        for k, v in final_headers.items():
            request += f"{k}: {v}\r\n"

        request += "\r\n"

        # =====================================================
        # SOCKET
        # =====================================================
        timeout = getattr(args, "timeout", 15)

        # --- TOR SOCKS5 ---
        if getattr(args, "tor", False):
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, "127.0.0.1", 9050, rdns=True)

        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # =====================================================
        # CONNECT
        # =====================================================
        sock.connect((host, port))

        # =====================================================
        # TLS
        # =====================================================
        if parsed.scheme == "https":
            context = ssl.create_default_context()

            # Better OPSEC than verify=False
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            sock = context.wrap_socket(sock, server_hostname=host)

        # =====================================================
        # SEND
        # =====================================================
        sock.sendall(request.encode())

        # =====================================================
        # RECEIVE FULL RESPONSE
        # =====================================================
        chunks = []
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break

                chunks.append(chunk)
            except socket.timeout:
                break

        raw_response = b"".join(chunks).decode(errors="ignore")
        sock.close()

        # =====================================================
        # RESPONSE WRAPPER
        # =====================================================
        class ResponseWrapper:
            def __init__(self, raw):
                self.text = raw
                try:
                    self.status_code = int(raw.split("\r\n")[0].split(" ")[1])
                except Exception:
                    self.status_code = 0

                self.headers = {}
                try:
                    header_block = raw.split("\r\n\r\n", 1)[0]
                    lines = header_block.split("\r\n")[1:]
                    for line in lines:
                        if ":" in line:
                            k, v = line.split(":", 1)
                            self.headers[k.strip()] = v.strip()
                except Exception:
                    pass

        return ResponseWrapper(raw_response)
    except Exception as e:
        handle_error(e, "SOCKET Request error", args.verbose)
        return None
        

# =========================================================
# RESOLVE DOMAIN IP
# =========================================================
def resolve_ip(args, domain):
    try:
        if args.tor:
            sock = socks.socksocket()
            sock.set_proxy(
                socks.SOCKS5,
                "127.0.0.1",
                9050,
                rdns=True
            )
            socket.connect((domain, 80)) 
            return socket.getpeername()[0] 
        return socket.gethostbyname(domain)
    except Exception as e:
        handle_error(e, "resolve_ip error", args.verbose)
        return None
