import asyncio, paramiko, socket, errno, argparse, csv, urllib.request
from tqdm import tqdm
from pathlib import Path
from python_socks.async_.asyncio import Proxy
from python_socks._errors import ProxyError
from collections import Counter
from datetime import datetime, timedelta
from Dependencies.displays import M, W, R, Y, G, C, handle_error
from Dependencies.save_output import add_result


# Setup base dir for top_100 ports, IANA url and prefix name for services
BASE_DIR = Path(__file__).resolve().parent
IANA_URL = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
IANA_FILE_PREFIX = "iana_service_ports_"


# -------------------------
# IANA STUFF
# -------------------------
def get_latest_iana_file():
    files = sorted(
        BASE_DIR.glob(f"{IANA_FILE_PREFIX}*.csv"),
        reverse=True
    )

    if not files:
        return update_iana_file()

    latest = files[0]
    file_date = latest.stem.replace(IANA_FILE_PREFIX, "")

    try:
        file_date = datetime.strptime(
            file_date,
            "%Y-%m-%d"
        )
    except ValueError:
        return update_iana_file()

    if datetime.now() - file_date > timedelta(days=30):
        return update_iana_file()

    return latest

def update_iana_file():
    filename = f"{IANA_FILE_PREFIX}{datetime.now().strftime('%Y-%m-%d')}.csv"
    filepath = BASE_DIR / filename
    print(f"{Y}[!] Updating IANA services database...{W}")
    urllib.request.urlretrieve(IANA_URL, filepath)
    return filepath

def load_iana_services():
    filepath = get_latest_iana_file()
    services = {}

    with open(filepath, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["Transport Protocol"].lower() != "tcp":
                continue

            port = row["Port Number"]
            if not port.isdigit():
                continue

            service = row["Service Name"].strip()
            if service:
                port = int(port)
                if port not in services:
                    services[port] = service
    return services


# -------------------------
# GET SSH AUTH METHODS
# -------------------------
async def ssh_auth_methods(proxy, host, port=22):
    try:
        if proxy:
            sock = await proxy.connect(
                dest_host=host,
                dest_port=port,
            )
            
        else:
            sock = socket.create_connection((host, port), timeout=3)

        transport = paramiko.Transport(sock)
        transport.start_client()
        auth = paramiko.auth_handler.AuthHandler
        username = "wassup"

        try:
            transport.auth_none(username)
        except paramiko.BadAuthenticationType as e:
            return e.allowed_types

        finally:
            transport.close()

    except Exception:
        return []


# -------------------------
# GET BANNER INFOS (SERVICES)
# -------------------------
async def grab_banner(reader, writer, timeout=2):
    try:
        data = await asyncio.wait_for(reader.read(1024), timeout)
        if data:
            return data.decode(errors="ignore").strip()

    except Exception:
        pass

    return None

async def detect_service(proxy, host, port, timeout=7):
    try:
        reader, writer = await open_connection(proxy, host, port, timeout)
        banner = None
        service = "unknown"
        product = ""
        version = ""

        if port == 22:
            service = "ssh"
            banner = await grab_banner(reader, writer, timeout)
            if banner and banner.startswith("SSH-"):
                version = banner.split("-", 2)[2]
                
                if version.startswith("OpenSSH"):
                    product = ""

        elif port in (80, 81, 88, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000):
            service = "http"
            writer.write(
                b"HEAD / HTTP/1.0\r\n"
                b"Host: " + host.encode() +
                b"\r\n\r\n"
            )

            await writer.drain()
            banner = await grab_banner(reader, writer, timeout)
            if banner:
                for line in banner.splitlines():
                    if line.startswith("Server:"):
                        server = line.replace("Server:", "").strip()
                        parts = server.split("/")
                        product = parts[0]
                        if len(parts) > 1:
                            version = parts[1]

        writer.close()
        await writer.wait_closed()

        return {
            "service": service,
            "product": product,
            "version": version,
            "banner": banner,
            "auth": None
        }
    except Exception:
        return None


# -------------------------
# HELPERS
# -------------------------
def parse_ports(port_string):
    ports = set()
    for part in port_string.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def setup_proxy(args):
    if args.tor:
        return Proxy.from_url("socks5://127.0.0.1:9050")

    if args.proxy:
        return Proxy.from_url(f"socks5://{args.proxy}")

    return None


# -------------------------
# TCP SCANNER
# -------------------------
async def open_connection(proxy, host, port, timeout):
    if proxy is None:
        return await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        
    sock = await asyncio.wait_for(
        proxy.connect(
            dest_host=host,
            dest_port=port,
        ),
        timeout
    )
    return await asyncio.open_connection(sock=sock)

async def scan_port(proxy, host, port, timeout):
    try:
        reader, writer = await open_connection(proxy, host, port, timeout)
        writer.close()
        await writer.wait_closed()
        return port, "OPEN"

    except asyncio.TimeoutError:
        return port, "FILTERED (timeout)"

    except ConnectionRefusedError:
        return port, "CLOSED"

    except ProxyError:
        return port, "FILTERED (proxy error)"
        
    except OSError as e:
        if e.errno == errno.ECONNREFUSED:
            return port, "CLOSED"

        elif e.errno == errno.ETIMEDOUT:
            return port, "FILTERED (timeout)"

        elif e.errno == errno.EHOSTUNREACH:
            return port, "FILTERED (host unreachable)"

        elif e.errno == errno.ENETUNREACH:
            return port, "FILTERED (network unreachable)"

        elif e.errno == errno.ECONNRESET:
            return port, "FILTERED (connection reset)"

        elif e.errno == errno.EACCES:
            return port, "FILTERED (permission denied)"

        elif e.errno == errno.EHOSTDOWN:
            return port, "HOST DOWN"
        return None

async def worker(proxy, host, ports, timeout, concurrency):
    semaphore = asyncio.Semaphore(concurrency)
    results = []

    async def limited(port):
        async with semaphore:
            return await scan_port(proxy, host, port, timeout)
    
    tasks = [
        limited(port)
        for port in ports
    ]

    with tqdm(total=len(tasks), desc="Scanning", unit="port") as bar:
        for future in asyncio.as_completed(tasks):
            result = await future
            if result:
                results.append(result)

            bar.update(1)
    return results


def load_ports_file(path):
    ports = []
    with open(path, "r") as f:
        for line in f:
            line = line.split("#")[0].strip()
            if line:
                ports.append(int(line))
    return sorted(set(ports))

def get_scan_ports(port_arg):
    # Default top 100 custom
    if not port_arg:
        return load_ports_file(BASE_DIR / "top_100.txt")

    # --ports @file
    if port_arg.startswith("@"):
        filepath = port_arg[1:]
        return load_ports_file(filepath)

    # --ports args
    return parse_ports(port_arg)

async def services_scanner(args, target):
    timeout = args.timeout or 7
    proxy = setup_proxy(args)
    iana_services = load_iana_services()
    ports = get_scan_ports(args.ports)

    results = await worker(proxy, target, ports, timeout, args.concurrency)
    
    counter = Counter()
    rows = []
    
    for port, state in sorted(results):
        counter[state] += 1
        service = iana_services.get(port, "unknown")
        version = ""
        auth = ""

        if state == "OPEN":
            info = await detect_service(proxy, target, port)

            if info:
                if info["service"] != "unknown":
                    service = info["service"]

                if info["product"] or info["version"]:
                    version = (
                        info["product"] + " " + info["version"]
                    ).strip()

                if args.ssh_info and service == "ssh":
                    methods = await ssh_auth_methods(proxy, target, port)
                    if methods:
                        auth = ",".join(methods)
    
        if args.save:
            add_result("TCP Scan", {
                "type": "tcp",
                "data": {
                    "target": target,
                    "port": port,
                    "state": state,
                    "service": service,
                    "version": version if version else "N/A",
                    "auth": auth if auth else "N/A"
                }
            })
            
        if args.verbose:
            if state not in ("FILTERED (proxy error)", "CLOSED"):
                prefix = "[+]" if state == "OPEN" else "[-]"
                rows.append((prefix, port, state, service, version, auth))

        else:
            if state == "OPEN":
                rows.append(( "[+]", port, state, service, version, auth))

    show_auth = (args.ssh_info and any(row[3] == "ssh" for row in rows))
    headers = [
        "",
        "PORT",
        "STATE",
        "SERVICE",
        "VERSION"
    ]

    if show_auth:
        headers.append("AUTH")

    if not rows:
        print(f"\n{R}[-] No open ports found")
        return

    widths = [
        max(len(headers[i]), max(len(str(row[i])) for row in rows))
        for i in range(len(headers))
    ]

    gap = 3
    status_width = widths[0]
    port_width = widths[1]
    state_width = widths[2]
    service_width = widths[3]
    version_width = widths[4]

    if show_auth:
        auth_width = widths[5]
        
    print(
        f"\n{'':<{status_width}}{' '*gap}"
        f"{'PORT':<{port_width}}{' '*gap}"
        f"{'STATE':<{state_width}}{' '*gap}"
        f"{'SERVICE':<{service_width}}{' '*gap}"
        f"{'VERSION':<{version_width}}"
        +
        (
            f"{' '*gap}{'AUTH':<{auth_width}}"
            if show_auth else ""
        )
    )

    print(
        f"{'':<{status_width}}{' '*gap}"
        f"{'-'*port_width}{' '*gap}"
        f"{'-'*state_width}{' '*gap}"
        f"{'-'*service_width}{' '*gap}"
        f"{'-'*version_width}"
        +
        (
            f"{' '*gap}{'-'*auth_width}"
            if show_auth else ""
        )
    )

    for row in rows:
        prefix, port, state, service, version, auth = row
        
        if not show_auth:
            auth = ""

        if auth and "password" in auth.lower():
            auth = auth.replace("password", f"{R}password{W}")
                
        print(
            f"{(G + prefix + W if prefix == '[+]' else M + prefix + W)}"
            f"{' ' * (status_width - len(prefix))}"
            f"{' ' * gap}"
            f"{port:<{port_width}}{' '*gap}"
            f"{state:<{state_width}}{' '*gap}"
            f"{service:<{service_width}}{' '*gap}"
            f"{version:<{version_width}}"
            +
            (
                f"{' '*gap}{auth:<{auth_width}}"
                if show_auth else ""
            )
        )

    print(f"\n{Y}[!] {W}Summary")
    width = max(len(state) for state in counter)
    print("-" * (width + 10))
    for state, count in counter.items():
        print(f"{G}- {Y}{state:<{width}} : {W}{count:>5}")