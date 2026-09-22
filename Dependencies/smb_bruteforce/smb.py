import socket
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from impacket.smbconnection import SMBConnection, SessionError

from Dependencies.displays import M, W, R, Y, G, C
from Dependencies.save_output import add_result


# --- Proxy support ---
try:
    import socks
    HAS_PYSOCKS = True
except ImportError:
    HAS_PYSOCKS = False


def setup_proxy(args):
    """Route all outgoing TCP through a SOCKS5 proxy (Tor or custom)."""
    if args.tor:
        proxy_host, proxy_port = "127.0.0.1", 9050
    elif args.proxy:
        proxy_host, proxy_port = args.proxy.rsplit(":", 1)
        proxy_port = int(proxy_port)
    else:
        return

    if not HAS_PYSOCKS:
        raise SystemExit(f"{R}[!] PySocks is required for --tor / --proxy. Install: pip install PySocks")

    socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port)
    socket.socket = socks.socksocket
    log(f"{C}[*] SOCKS5 proxy:{W} {proxy_host}:{proxy_port}")


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


def smb_test(args, host, username, password):
    connection = None
    start = time.perf_counter()
    try:
        if args.verbose:
            if username and password:
                log(f"{W}[*] {username}:{password}{W}")
            else:
                log(f"{W}[*] anonymous{W}")

        connection = SMBConnection(remoteName=host, remoteHost=host, sess_port=args.port, timeout=args.timeout,)
        connection.login(username, password)
        latency = time.perf_counter() - start
        dialect = connection.getDialect()
        dialect_names = {
            0x0202: "SMB 2.0.2",
            0x0210: "SMB 2.1",
            0x0300: "SMB 3.0",
            0x0302: "SMB 3.0.2",
            0x0311: "SMB 3.1.1",
        }

        if isinstance(dialect, int):
            dialect_name = dialect_names.get(dialect, f"0x{dialect:04x}")
        elif isinstance(dialect, str):
            dialect_name = dialect  # ex: "3.1.1"
        else:
            dialect_name = str(dialect)
        if username and password:
            print(f"{G}[+] SMB success: {C}{username}:{password}{W}")
        else:
            print(f"{G}[+] SMB success: {C}anonymous{W}")
        print(f"{G}[+] Server:{W} {host}")
        print(f"{G}[+] Dialect:{W} {dialect_name}")
        print(f"{G}[+] Latency:{W} {latency:.3f}s")

        # Enum shares
        print(f"{G}[+] Shares:{W}")
        shares = connection.listShares()
        share_names = []
        for share in shares:
            name = str(share["shi1_netname"]).rstrip("\x00")
            remark = str(share["shi1_remark"]).rstrip("\x00")
            share_names.append(name)
            if remark:
                print(f"    {G}- {R}{name}{W} {C}({remark}){W}")
            else:
                print(f"    {G}- {R}{name}{W}")
        print()

        if args.save:
            add_result(
                "SMB",
                {
                    "type": "credentials",
                    "data": {
                        "source": "smb",
                        "host": host,
                        "port": args.port,
                        "username": username,
                        "password": password,
                        "dialect": dialect_name,
                        "shares": share_names,
                    },
                },
            )

        return True
    except SessionError as e:
        latency = time.perf_counter() - start
        if args.verbose:
            log(f"{M}[-] SMB authentication failed: {username} ({latency:.3f}s){W}")
            log(f"{M}    {e}{W}")
            
        return False
    except Exception as e:
        latency = time.perf_counter() - start
        if args.verbose:
            log(f"{M}[-] SMB error: {username} ({latency:.3f}s){W}")
            log(f"{M}    {e}{W}")

        return False
    finally:
        if connection:
            try:
                connection.logoff()
            except Exception:
                pass

def dosmb(args, host):
    if args.user and args.password:
        usernames = parse_value(args.user)
        passwords = parse_value(args.password)
    elif args.user:
        usernames = parse_value(args.user)
        passwords = [""]          # empty pass
    elif args.password:
        usernames = [""]          # empty username
        passwords = parse_value(args.password)
    else:
        # Anonymous
        usernames = [""]
        passwords = [""]

    total_jobs = len(usernames) * len(passwords)

    if args.tor and args.proxy:
        raise SystemExit(f"{R}[!] Cannot use both --tor and --proxy")

    if total_jobs == 0:
        raise SystemExit(f"{R}[!] Empty username/password list")

    setup_proxy(args)
    print(f"{C}[*] SMB target:{W} {host}:{args.port}")
    print(f"{C}[*] Users:{W} {len(usernames)} | {C}Passwords:{W} {len(passwords)} | {C}Tests:{W} {total_jobs}")
    jobs = []
    progress = tqdm(total=total_jobs, desc="SMB", unit="test", dynamic_ncols=True,)
    try:
        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            for username in usernames:
                for password in passwords:
                    jobs.append(executor.submit(smb_test, args, host, username, password,))

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
