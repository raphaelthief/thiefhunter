import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from pathlib import Path
from urllib.parse import urlparse
from Dependencies.displays import M, W, R, Y, G, C, handle_error
from Dependencies.get_request import get_request
from Dependencies.save_output import add_result

def worker(args, ext, domain):
    try:
        target = f"https://{domain}.{ext.strip()}/"
        response = get_request(args, target, timeout=10)
        if response:
            if response == "timeout":
                if args.verbose:
                    tqdm.write(f"{W}[TIMEOUT] {target}")
                else:
                    pass
            elif response.status_code == 200:
                tqdm.write(f"{R}[200]{W} {target}")
                if args.save:
                    add_result("TLD_Check", {
                        "Type": "TLD_Found",
                        "data": {
                            "url": target,
                            "status": 200
                        }
                    })
            elif response.status_code == 202:
                tqdm.write(f"{R}[202]{W} {target}")
                if args.save:
                    add_result("TLD_Check", {
                        "Type": "TLD_Found",
                        "data": {
                            "url": target,
                            "status": 202
                        }
                    })
            elif response.status_code == 301:
                tqdm.write(f"{Y}[301]{W} {target}")
                if args.save:
                    add_result("TLD_Check", {
                        "Type": "TLD_Found",
                        "data": {
                            "url": target,
                            "status": 301,
                            "location": response.headers.get("Location")
                        }
                    })
            elif response.status_code == 404:
                pass
            elif args.verbose:
                tqdm.write(f"{Y}{response.status_code}{W} {target}")
    except Exception as e:
        handle_error(e, "ERROR", args.verbose)


def tld_main(args):
    try:
        print(f"\n{C}[+] Check domain TLD")
        host = urlparse(args.url if "://" in args.url else f"http://{args.url}").hostname
        domain = ".".join(host.split(".")[:-1])
        paths_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Payloads", "dns_extensions.txt")
        extensions = Path(paths_file).read_text(encoding="utf-8").splitlines()
        if args.verbose:
            print(f"{G}[*]{W} Loaded {len(extensions)} extensions")
            
        with ThreadPoolExecutor(max_workers=25) as executor:
            futures = [executor.submit(worker, args, ext, domain) for ext in extensions]
            for future in tqdm(
                as_completed(futures),
                total=len(futures),
                desc="TLD",
                unit="ext"
            ):
                future.result()
    except Exception as e:
        handle_error(e, "ERROR", args.verbose)
