import os, random, string, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from pathlib import Path
from urllib.parse import urlparse, urljoin
from Dependencies.displays import M, W, R, Y, G, C, handle_error
from Dependencies.get_request import get_request
from Dependencies.save_output import add_result

WORDLISTS = {
    "admin_logins.txt": 1,
    "indexoff.txt": 1,
    "sensitive_files.txt": 1,
    "wordpress.txt": 1,

    "api_endpoints.txt": 2,
    
    "db_backups_files.txt": 3,
    
    "swagger.txt": 4,
}


tested_listings = set()
discovered_listings = set()

def crawl_directory_listing(args, listing_url, visited=None, depth=0):
    if visited is None:
        visited = set()

    if listing_url in visited:
        return

    visited.add(listing_url)
    response = get_request(args, listing_url, timeout=30, allow_redirects=False)

    if not response or response == "timeout":
        return

    indent = "│   " * depth
    if depth == 0:
        print(f"\n{G}[LISTING]{W} {listing_url}")

    entries = re.findall(
        r'^([\-dlpscb])[rwxstST\-]{9}\s+\d+\s+\S+\s+\S+\s+\d+\s+\w+\s+\d+\s+(?:\d+:\d+|\d{4})\s+(.+)$',
        response.text,
        re.MULTILINE
    )

    base_dir = listing_url.replace("/.listing", "/")
    total_entries = [
        (t, n.strip())
        for t, n in entries
        if n.strip() not in (".", "..")
    ]

    for index, (entry_type, name) in enumerate(total_entries):
        is_last = index == len(total_entries) - 1
        branch = "└──" if is_last else "├──"
        if " -> " in name:
            name = name.split(" -> ")[0]

        # FILE
        if entry_type == "-":
            file_url = urljoin(base_dir, name)
            file_response = get_request(args, file_url, timeout=30, allow_redirects=False)

            if file_response and file_response != "timeout":
                status = f"{R}{file_response.status_code}"
            else:
                status = f"{Y}[ERR]"

            print(f"{G}{indent}{branch} {status} {W}{name}")

        # DIRECTORY
        elif entry_type == "d":
            next_listing = urljoin(base_dir, f"{name}/.listing")
            listing_response = get_request(args, next_listing, timeout=30, allow_redirects=False)
            if listing_response and listing_response != "timeout":
                status = listing_response.status_code
            else:
                status = "ERR"

            print(f"{indent}{branch} {status} {W}{name}/")
            if status == 200:
                crawl_directory_listing(args, next_listing, visited, depth + 1)

        # SYMLINK
        elif entry_type == "l":
            print(f"{indent}{branch} {Y}[LINK] {W}{name}")



def get_random_path(length=12):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length)) # Generate a random path string to test for 404 baseline


def get_baseline(args, base_url):
    random_path = get_random_path()
    target = urljoin(base_url, random_path)
    try:
        response = get_request(args, target, timeout=30, allow_redirects=False)
        if response is not None:
            return (response.status_code, len(response.text), len(response.text.split()))
    except Exception as e:
        handle_error(e, "ERROR", args.verbose)   
    return (404, 0, 0) # Default fallback if baseline request fails


def analyze_response(target, response):
    discovered_dirs = []
    content = response.text.lower()

    # Directory listing
    if (
        "index of /" in content or
        "<title>index of" in content or
        "parent directory" in content or
        "directory listing for" in content
    ):
        tqdm.write(f"      {G}- {R}[DIRLIST]{W}")

    # Apache/Nginx directory index disabled
    if (
        response.status_code == 403 and
        "directory" in content and
        "forbidden" in content
    ):
        tqdm.write(f"      {G}- {Y}[INDEX DISABLED]{W}")

    listing_entries = re.findall(
        r'^([\-dlpscb])[rwxstST\-]{9}\s+\d+\s+\S+\s+\S+\s+\d+\s+\w+\s+\d+\s+(?:\d+:\d+|\d{4})\s+(.+)$',
        response.text,
        re.MULTILINE
    )

    if len(listing_entries) >= 2:
        tqdm.write(f"      {G}- {R}[DIRECTORY LISTING]{W}")
        dirs = 0
        files = 0
        symlinks = 0
        discovered_listings.add(target)
        
        for entry_type, name in listing_entries:
            if name in (".", ".."):
                continue

            if entry_type == "d":
                dirs += 1
                discovered_dirs.append(name)

            elif entry_type == "-":
                files += 1

            elif entry_type == "l":
                symlinks += 1

        tqdm.write(f"      {G}- {C}[INFO]{W} Directories: {dirs} | Files: {files} | Symlinks: {symlinks}")
        add_result("Directory_Enumeration", {
            "Type": "Directory_Listing",
            "data": {
                "url": target,
                "status": status,
                "size": length,
                "words": words
            }
        })


    elif target.endswith("/.listing"):
        tqdm.write(f"      {G}- {R}[.LISTING FOUND]{W}")
        add_result("Directory_Enumeration", {
            "Type": "Directory_Listing",
            "data": {
                "url": target
            }
        })
        
    if target.endswith("/.git/"):
        tqdm.write(f"      {R}[GIT EXPOSED]{W}")
        add_result("Directory_Enumeration", {
            "Type": "Git_Exposed",
            "data": {
                "url": target
            }
        })

    if target.endswith("/.svn/"):
        tqdm.write(f"      {G}- {R}[SVN EXPOSED]{W}")
        add_result("Directory_Enumeration", {
            "Type": "SVN_Exposed",
            "data": {
                "url": target
            }
        })
    return discovered_dirs



def worker(args, base_url, path, baseline):
    try:
        if not path.startswith('/'):
            path = f"/{path}"
        
        target = urljoin(base_url, path)
        if target.endswith("/.listing"):
            if target in tested_listings:
                return
            tested_listings.add(target)
            
        response = get_request(args, target, timeout=30, allow_redirects=False)
        if response is None:
            return

        if response == "timeout":
            if args.verbose:
                tqdm.write(f"{W}[TIMEOUT] {target}")
            return

        status = response.status_code
        content = response.text if hasattr(response, 'text') else ""
        length = len(content)
        words = len(content.split())
        
        base_status, base_len, base_words = baseline

        # --- DETECTION LOGIC ---
        # 1. Check for Soft 404 (Status 200 but content matches baseline)
        is_soft_404 = (status == 200 and base_status == 200 and abs(length - base_len) < 10 and abs(words - base_words) < 10)
        if is_soft_404:
            return

        # 2. Check for Valid Finds
        if status == 200:
            tqdm.write(f"{R}[200]{W} {target} (Size: {length})")
            if args.save:
                add_result("Directory_Enumeration", {
                    "Type": "Path_Found",
                    "data": {
                        "url": target,
                        "status": status,
                        "size": length,
                        "words": words
                    }
                })
            analyze_response(target, response)
        elif status == 201:
            tqdm.write(f"{Y}[201]{W} {target}")
            if args.save:
                add_result("Directory_Enumeration", {
                    "Type": "Path_Found",
                    "data": {
                        "url": target,
                        "status": status,
                        "size": length,
                        "words": words
                    }
                })
        elif status == 202:
            tqdm.write(f"{Y}[202]{W} {target}")
            if args.save:
                add_result("Directory_Enumeration", {
                    "Type": "Path_Found",
                    "data": {
                        "url": target,
                        "status": status,
                        "size": length,
                        "words": words
                    }
                })
        elif status == 301 or status == 302 or status == 404:
            return
        elif status == 403:
            if args.save:
                add_result("Directory_Enumeration", {
                    "Type": "Path_Found",
                    "data": {
                        "url": target,
                        "status": status,
                        "size": length,
                        "words": words
                    }
                })
            if args.verbose:
                tqdm.write(f"{M}[403]{W} {target} (Forbidden)")
        else:
            if args.verbose:
                tqdm.write(f"{M}[{status}]{W} {target}")
            if args.save:
                add_result("Directory_Enumeration", {
                    "Type": "Path_Found",
                    "data": {
                        "url": target,
                        "status": status,
                        "size": length,
                        "words": words
                    }
                })

    except Exception as e:
        handle_error(e, "ERROR", args.verbose)



def get_robots_paths(args, base_url):
    paths = []
    try:
        robots_url = urljoin(base_url, "/robots.txt")
        response = get_request(args, robots_url, timeout=30, allow_redirects=False)
        if (response and response != "timeout" and response.status_code == 200):
            print(f"{G}[*]{W} robots.txt found")
            for line in response.text.splitlines():
                line = line.strip()
                if (not line or line.startswith("#")):
                    continue

                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if not path or path == "/":
                        continue
                    paths.append(path)
    except Exception as e:
        handle_error(e, "ERROR", args.verbose)
    return list(dict.fromkeys(paths))


def do_fuzz_paths(args):
    try:
        # 1. Parse Base URL
        raw_url = args.url if "://" in args.url else f"http://{args.url}"
        parsed = urlparse(raw_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}/"
        
        # Remove trailing slash from path if user provided one in URL, 
        # as we append paths manually. 
        # Note: urljoin handles most cases, but ensuring base is clean helps.
        if parsed.path and parsed.path != '/':
            base_url = f"{base_url}{parsed.path.lstrip('/')}"

        print(f"\n{C}[+] Fuzzing paths on: {base_url}")

        # 2. Load Wordlist
        payloads_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Payloads", "dir_enum")
        selected_files = [
            filename
            for filename, level in WORDLISTS.items()
            if level <= args.dir
        ]

        paths = []
        for filename in selected_files:
            filepath = os.path.join(payloads_dir, filename)

            if not os.path.exists(filepath):
                tqdm.write(f"{R}[ERROR]{W} Missing wordlist: {filename}")
                continue

            try:
                entries = Path(filepath).read_text(encoding="utf-8").splitlines()
                paths.extend(p.strip() for p in entries if p.strip())

                if args.verbose:
                    tqdm.write(f"{G}[*]{W} Loaded {filename}")

            except Exception as e:
                handle_error(e, "ERROR", args.verbose)

        paths = list(dict.fromkeys(paths))
        
        if args.verbose:
            print(f"{G}[*]{W} Loaded {len(paths)} unique paths from {len(selected_files)} wordlists")


        # 3. Calculate Baseline (Soft 404 Detection)
        print(f"{G}[*]{W} Calculating baseline (soft 404 detection)...")
        baseline = get_baseline(args, base_url)
        print(f"{G}[*]{W} Baseline detected -> Status: {Y}{baseline[0]}{W}, Length: {Y}{baseline[1]}{W}, Words: {Y}{baseline[2]}")
        if args.save:
            add_result("Directory_Enumeration", {
                "Type": "Baseline",
                "data": {
                    "status": baseline[0],
                    "length": baseline[1],
                    "words": baseline[2]
                }
            })

        # 4. Check robots.txt Disallow
        print(f"{G}[*]{W} Checking robots.txt...")
        robots_paths = get_robots_paths(args, base_url)
        if robots_paths:
            print(f"{G}[*]{W} Found {len(robots_paths)} paths in robots.txt")
            if args.save:
                add_result("Directory_Enumeration", {
                    "Type": "Robots_Disallow",
                    "data": {
                        "count": len(robots_paths),
                        "paths": robots_paths
                    }
                })
            skipped = 0
            for path in robots_paths:
                if "*" in path:
                    skipped += 1
                    continue
                worker(args, base_url, path, baseline)

            if skipped:
                print(f"{Y}[!]{W} Skipped {skipped} robots.txt entries containing '*'")

        
        # Special wordpress enum
        worker(args, base_url, f"wp-json/oembed/1.0/embed?url={base_url}", baseline)

        # 5. Execute Thread Pool
        with ThreadPoolExecutor(max_workers=25) as executor:
            futures = [executor.submit(worker, args, base_url, path, baseline) for path in paths]
            for future in tqdm(
                as_completed(futures),
                total=len(futures),
                desc="Fuzzing",
                unit="path",
                ncols=100
            ):
                future.result()
        
        # 6. Process .listing enum
        if discovered_listings:
            print(f"\n{R}[!]{W} {len(discovered_listings)} directory listing(s) found:")
            for listing in discovered_listings:
                print(f"    {listing}")

            if args.batch:
                print(f"\n{Y}[?] Explore discovered directory listings recursively? (y/n): {C}n")
                choice = "n"
            else:
                choice = input(f"\n{Y}[?] Explore discovered directory listings recursively? (y/n): {C}").strip().lower()

            if choice in ("y", "yes"):
                for listing in discovered_listings:
                    crawl_directory_listing(args, listing)
        if args.save:
            add_result("Directory_Enumeration", {
                "Type": "Summary",
                "data": {
                    "wordlists": selected_files,
                    "tested_paths": len(paths),
                    "directory_listings_found": list(discovered_listings)
                }
            })

    except Exception as e:
        handle_error(e, "ERROR", args.verbose)
