import socket, argparse, time, base64, yaml, threading, socks
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from Dependencies.displays import M, W, R, Y, G, C
from Dependencies.save_output import add_result


def log(msg):
    tqdm.write(msg)

def parse_value(value):
    if not value.startswith("@"):
        return [value]

    path = value[1:]
    encodings = ("utf-8-sig", "cp1252", "iso-8859-1")
    for encoding in encodings:
        try:
            with open(path, "r", encoding=encoding) as f:
                return [line.strip() for line in f if line.strip()]
        except UnicodeDecodeError:
            continue
        except FileNotFoundError:
            raise SystemExit(f"[!] File not found: {path}")
    raise SystemExit(f"[!] Unable to decode file: {path}. Supported encodings: {', '.join(encodings)}")


def setup_proxy(args):
    if args.tor:
        proxy_host, proxy_port = "127.0.0.1", 9050
    elif args.proxy:
        proxy_host, proxy_port = args.proxy.rsplit(":", 1)
        proxy_port = int(proxy_port)
    else:
        return

    socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port, rdns=True)
    socket.socket = socks.socksocket

    def _proxied_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, **kwargs):
        host, port = address
        s = socks.socksocket()
        if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
            s.settimeout(timeout)
        s.connect((host, port))
        return s

    socket.create_connection = _proxied_create_connection
    log(f"{C}[*] SOCKS5 proxy:{W} {proxy_host}:{proxy_port}")


def load_rtsp_config():
    data_path = Path(__file__).parent / "data" / "rtsp.yaml"
    if not data_path.exists():
        data_path = Path(__file__).parent.parent / "data" / "rtsp.yaml"
    if not data_path.exists():
        raise SystemExit(f"{R}[!] File not found: rtsp.yaml")
    with open(data_path, "r") as f:
        return yaml.safe_load(f)


def identify_vendor(banner, config):
    if not banner:
        return None
        
    banner_lower = banner.lower()
    for vendor in config.get("vendors", []):
        banners = vendor.get("banners", [])
        for b in banners:
            if b and b.lower() in banner_lower:
                return vendor
    return None


def rtsp_request(host, port, request_str, timeout):
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    sock.sendall(request_str.encode())

    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk

    response_str = response.decode(errors="replace")
    if "Content-Length:" in response_str:
        try:
            headers_part, _, _ = response_str.partition("\r\n\r\n")
            for line in headers_part.split("\r\n"):
                if line.lower().startswith("content-length:"):
                    content_length = int(line.split(":")[1].strip())
                    body_so_far = len(response) - len(headers_part) - 4
                    while body_so_far < content_length:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break

                        response += chunk
                        body_so_far += len(chunk)
                    break
        except (ValueError, IndexError):
            pass

    sock.close()
    return response.decode(errors="replace")


def grab_banner(host, port, timeout):
    request = (
        f"OPTIONS rtsp://{host}:{port}/ RTSP/1.0\r\n"
        f"CSeq: 1\r\n"
        f"User-Agent: RTSP-Scanner/1.0\r\n"
        f"\r\n"
    )

    try:
        response = rtsp_request(host, port, request, timeout)
        status_line = response.split("\r\n")[0]
        if "200" in status_line:
            for line in response.split("\r\n"):
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()
            return ""
        return None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def rtsp_test(args, host, conn_string, username, password, stop_event):
    if stop_event.is_set():
        return False

    if not conn_string.startswith("/"):
        conn_string = "/" + conn_string

    start = time.perf_counter()
    try:
        url = f"rtsp://{host}:{args.port}{conn_string}"
        if stop_event.is_set():
            return False

        if username or password:
            credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
            request = (
                f"DESCRIBE {url} RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"Authorization: Basic {credentials}\r\n"
                f"User-Agent: RTSP-Scanner/1.0\r\n"
                f"\r\n"
            )

            response_str = rtsp_request(host, args.port, request, args.timeout)
            status_line = response_str.split("\r\n")[0] if response_str else ""
            if "200" in status_line:
                if "m=video" in response_str:
                    latency = time.perf_counter() - start
                    stop_event.set()
                    log(f"{G}[+] {W}RTSP success: {C}{username}:{password}{W} → {Y}{url}{W}")
                    log(f"{W}    Latency: {latency:.3f}s")
                    if args.verbose:
                        for line in response_str.split("\r\n"):
                            log(f"    {W}{line}")

                    if args.save:
                        add_result("RTSP", {"type": "credentials", "data": {
                            "source": "rtsp", "host": host, "port": args.port,
                            "url": url, "username": username, "password": password,
                            "auth": "basic"
                        }})
                    return True

            elif "401" in status_line:
                if args.verbose:
                    latency = time.perf_counter() - start
                    log(f"{M}[-] {W}Auth failed: {username}:{password} → {url} ({latency:.3f}s)")
                return False

            else:
                if args.verbose:
                    latency = time.perf_counter() - start
                    log(f"{M}[-] {W}{status_line} → {url} ({latency:.3f}s)")
                return False

        # Try no-auth
        else:
            request = (
                f"DESCRIBE {url} RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"User-Agent: RTSP-Scanner/1.0\r\n"
                f"\r\n"
            )

            response_str = rtsp_request(host, args.port, request, args.timeout)
            status_line = response_str.split("\r\n")[0] if response_str else ""
            if "200" in status_line:
                if "m=video" in response_str:
                    latency = time.perf_counter() - start
                    stop_event.set()
                    log(f"{G}[+] {W}RTSP {R}no-auth: {Y}{url}{W}")
                    log(f"{W}    Latency: {latency:.3f}s")
                    if args.verbose:
                        for line in response_str.split("\r\n"):
                            log(f"    {W}{line}")

                    if args.save:
                        add_result("RTSP", {"type": "credentials", "data": {
                            "source": "rtsp", "host": host, "port": args.port,
                            "url": url, "username": "", "password": "",
                            "auth": "none"
                        }})
                    return True

            elif "401" in status_line:
                if args.verbose:
                    latency = time.perf_counter() - start
                    log(f"{Y}[!] {W}401 - auth needed but no creds ({latency:.3f}s)")
                return False

            else:
                if args.verbose:
                    latency = time.perf_counter() - start
                    log(f"{M}[-] {W}{status_line} → {url} ({latency:.3f}s)")
                return False
    except socket.timeout:
        return False
    except ConnectionRefusedError:
        return False
    except Exception as e:
        if args.verbose:
            log(f"{M}[-] RTSP error: {W}{e}")
        return False


def dortsp(args, host):
    stop_event = threading.Event()

    # --- Parser "IP:port/path" ---
    path_override = None
    if "/" in host:
        host, path_override = host.split("/", 1)
        path_override = "/" + path_override

    if ":" in host:
        parts = host.rsplit(":", 1)
        host = parts[0]
        try:
            args.port = int(parts[1])
        except ValueError:
            pass

    config = load_rtsp_config()
    setup_proxy(args) # <---- TOR

    log(f"{W}[*] Banner grab on {host}:{args.port}{W}")
    banner = grab_banner(host, args.port, args.timeout)
    if banner is None:
        raise SystemExit(f"{R}[!] RTSP not accessible on {host}:{args.port}{W}")

    log(f"{W}[*] Banner: {banner or '(vide)'}")
    vendor = identify_vendor(banner, config)
    if vendor:
        vendor_name = vendor["name"]
        log(f"{W}[*] Detected vendor:{C} {vendor_name}{W}")

    else:
        vendor_name = "common"
        log(f"{W}[*] Vendor:{C} not defined (common mode){W}")

    # --- Paths ---
    # --rtsp-path > -u/path > vendor > common
    if args.rtsp_path:
        conn_strings = parse_value(args.rtsp_path)
        for i, p in enumerate(conn_strings):
            if not p.startswith("/"):
                conn_strings[i] = "/" + p

        log(f"{W}[*] Paths:{C} {len(conn_strings)} {W}(-rtsp-path)")

    elif path_override:
        conn_strings = [path_override]
        log(f"{W}[*] Paths:{C} {path_override} {W}(-u)")

    elif vendor and vendor.get("paths", {}).get("tcp"):
        conn_strings = vendor["paths"]["tcp"]
        log(f"{W}[*] Paths:{C} {len(conn_strings)} {W}(vendor: {vendor_name})")

    else:
        conn_strings = config.get("common_paths", ["/"])
        log(f"{W}[*] Paths:{C} {len(conn_strings)} {W}(common)")

    # --- Credentials ---
    if args.user and args.password:
        usernames = parse_value(args.user)
        passwords = parse_value(args.password)
        log(f"{W}[*] Creds:{C} {len(usernames)}x{len(passwords)} {W}(-U/-P)")

    elif args.user:
        usernames = parse_value(args.user)
        passwords = [""]
        log(f"{W}[*] Creds:{C} {len(usernames)}x1 {W}(-U)")

    elif args.password:
        usernames = [""]
        passwords = parse_value(args.password)
        log(f"{W}[*] Creds:{C} 1x{len(passwords)} {W}(-P)")

    elif vendor and vendor.get("creds", {}).get("usernames"):
        usernames = vendor["creds"]["usernames"]
        passwords = vendor.get("creds", {}).get("passwords", [""])
        log(f"{W}[*] Creds:{C} {len(usernames)}x{len(passwords)} {W}(vendor: {vendor_name})")

    else:
        common_creds = config.get("common_creds", {})
        usernames = common_creds.get("usernames", [""])
        passwords = common_creds.get("passwords", [""])
        log(f"{W}[*] Creds:{C} {len(usernames)}x{len(passwords)} {W}(common)")

    total_jobs = len(usernames) * len(passwords) * len(conn_strings)
    if args.tor and args.proxy:
        raise SystemExit(f"{R}[!] Cannot use both --tor and --proxy")

    if total_jobs == 0:
        raise SystemExit(f"{R}[!] Empty combination")

    print(f"{W}[*] RTSP target:{C} rtsp://{host}:{args.port}{W}")
    print(f"{W}[*] Vendor:{C} {vendor_name} {W}| Paths:{C} {len(conn_strings)} {W}| Users:{C} {len(usernames)} {W}| Pass:{C} {len(passwords)} {W}| Tests:{C} {total_jobs}{W}")
    jobs = []
    progress = tqdm(total=total_jobs, desc="RTSP", unit="test", dynamic_ncols=True)
    try:
        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            for username in usernames:
                for password in passwords:
                    for conn_str in conn_strings:
                        jobs.append(executor.submit(rtsp_test, args, host, conn_str, username, password, stop_event))

            for job in as_completed(jobs):
                try:
                    success = job.result()
                    if success:
                        for pending in jobs:
                            pending.cancel()
                        break
                finally:
                    progress.update(1)
    finally:
        progress.close()   