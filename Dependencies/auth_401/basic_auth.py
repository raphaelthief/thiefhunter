import time
from pathlib import Path
from Dependencies.displays import M, W, R, Y, G, C
from Dependencies.get_request import get_request


def load(value):
    if value.startswith("@"):
        path = Path(value[1:]).expanduser()

        if not path.is_file():
            raise FileNotFoundError(f"Wordlist introuvable : {path}")

        return [
            line.strip()
            for line in path.read_text(
                encoding="utf-8",
                errors="ignore"
            ).splitlines()
            if line.strip()
        ]

    return [value]


def fuzz_auth(args):
    interrupted = False
    
    users = load(args.user)
    passwords = load(args.password)

    total = len(users) * len(passwords)
    attempt = 0
    fuzzed = False
    valid_credentials = []

    start = time.time()

    print(f"{C}[*] Users        : {W}{len(users)}")
    print(f"{C}[*] Passwords    : {W}{len(passwords)}")
    print(f"{C}[*] Combinations : {W}{total}")
    print()

    try:
        for user in users:
            for password in passwords:

                attempt += 1

                if args.verbose:
                    print(
                        f"{G}[*] [{attempt}/{total}] "
                        f"Trying {W}{user}{Y}:{W}{password}"
                    )
                else:
                    print(
                        f"\r{C}[*] Progress: {W}{attempt}/{total} "
                        f"({attempt * 100 / total:.1f}%)",
                        end="",
                        flush=True,
                    )

                r = get_request(args, args.url, auth=(user, password), timeout=10, allow_redirects=False,)

                # First 403 WAF
                if not fuzzed and r.status_code == 403:
                    fuzzed = True

                    print("\n")
                    print(f"{M}[-] Blocked by a firewall")

                    req = r.request
                    print(f"\n{G}----- REQUEST -----{W}")
                    print(f"{req.method} {req.url}")

                    for k, v in req.headers.items():
                        print(f"{k}: {v}")

                    if req.body:
                        print()
                        print(req.body)

                    print(f"\n{G}----- RESPONSE -----{W}")
                    print(f"HTTP {r.status_code}")

                    for k, v in r.headers.items():
                        print(f"{k}: {v}")

                    print()
                    print(r.text)

                    if args.batch:
                        print(f"\n{Y}[?] Do you want to continue? (y/n): {C}n")
                        break

                    answer = input(
                        f"\n{Y}[?] Do you want to continue? (y/n): {C}"
                    ).strip().lower()

                    if answer not in ("y", "yes"):
                        break

                    print()
                    
                if r.status_code not in (401, 403):
                    valid_credentials.append((user, password))
                    print(
                        f"\n{G}[+] Valid credentials: "
                        f"{R}{user}{Y}:{R}{password}"
                    )

            else:
                continue
            break

    except KeyboardInterrupt:
        interrupted = True
        print(f"\n{R}[!] Ctrl+C detected, closing...")

    except Exception as e:
        handle_error(e, "Basic auth error", args.verbose)
        return

    finally:
        elapsed = time.time() - start

        print()
        print(f"{Y}[*] {G}Fuzzing summary")
        print(f"{Y}[*] {G}Users tested        : {W}{len(users)}")
        print(f"{Y}[*] {G}Passwords tested    : {W}{len(passwords)}")
        print(f"{Y}[*] {G}Total combinations  : {W}{total}")
        print(f"{Y}[*] {G}Attempts            : {W}{attempt}")
        print(f"{Y}[*] {G}Elapsed time        : {W}{elapsed:.2f}s")

        if elapsed > 0:
            print(f"{Y}[*] {G}Speed               : {W}{attempt / elapsed:.2f} req/s")

        if valid_credentials:
            print(f"\n{G}[+] Valid credentials found:")

            for user, password in valid_credentials:
                print(f"    {R}{user}{Y}:{R}{password}")
        else:
            print(f"\n{R}[-] No valid credentials found.")
            
    if interrupted:
        raise KeyboardInterrupt