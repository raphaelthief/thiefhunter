import re, os
from urllib.parse import (urlparse, urlsplit, urlunsplit, parse_qs, parse_qsl, urlencode, quote, urljoin)
from collections import deque
from bs4 import BeautifulSoup
from Dependencies.get_request import get_request
from Dependencies.displays import M, W, R, Y, G, C, handle_error

# =========================================================
# INTERESTING PARAMS
# =========================================================
INTERESTING_PARAMS = {
    "redirect", "url", "next", "return", "dest",
    "destination", "continue", "callback", "redir"
}


# =========================================================
# OPEN REDIRECT PAYLOADS
# =========================================================
OPEN_REDIRECT_PAYLOADS = [
    # Classic
    "https://google.com",
    "http://google.com",
    "https://www.google.com",
    "http://www.google.com",

    # Scheme-relative
    "//google.com",
    "///google.com",

    # Path tricks
    "https://google.com/",
    "https://google.com/search",

    # Userinfo trick (important)
    "https://google.com@evil.com",
    "https://evil.com@google.com",

    # Encoding
    "https%3A%2F%2Fgoogle.com",
    "%2F%2Fgoogle.com",
    "https%253A%252F%252Fgoogle.com",

    # Weird parsing
    "https:google.com",

    # Subdomains / variations
    "https://accounts.google.com",
    "https://mail.google.com",
]


# =========================================================
# HELPERS
# =========================================================
def is_interesting_param(param: str) -> bool:
    p = param.lower()
    keywords = [
        "redirect",
        "redir",
        "url",
        "next",
        "return",
        "dest",
        "callback",
        "continue",
        "forward",
        "relay",
        "target",
        "to",
        "go"
    ]
    return any(k in p for k in keywords)


def canonicalize_url(url: str) -> str:
    parsed = urlsplit(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    query = urlencode(sorted(qs.items()), doseq=True)
    return urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path.rstrip("/") or "/",
        query,
        ""
    ))


def extract_params(url):
    return list(parse_qs(urlparse(url).query).keys())


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
            new_params.append(f"{quote(k)}={quote(v)}")

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


def is_html(response):
    if not response:
        return False
    return "text/html" in response.headers.get("Content-Type", "")


# =========================================================
# OPEN REDIRECT DETECTION
# =========================================================
def is_openredirect(response, payload_url):
    """
    Detect open redirect via Location header
    """
    if response.status_code not in (301, 302, 303, 307, 308):
        return False

    location = response.headers.get("Location", "")
    if not location:
        return False

    # External redirect heuristic
    if location.startswith("http://") or location.startswith("https://"):
        return True
    return False


# =========================================================
# CRAWLER (same logic style as traversal module)
# =========================================================
def normalize_netloc(netloc: str) -> str:
    return netloc.lower().replace("www.", "")


def is_allowed_domain(netloc: str, allowed: set) -> bool:
    netloc = normalize_netloc(netloc)
    return any(
        netloc == normalize_netloc(d)
        or netloc.endswith("." + normalize_netloc(d))
        for d in allowed
    )


def is_interesting_url(url):
    p = urlparse(url)
    return any(
        k in p.path.lower() or k in p.query.lower()
        for k in INTERESTING_PARAMS
    )


SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp",
    ".css", ".svg", ".ico",
    ".woff", ".woff2",
    ".ttf", ".eot",
    ".mp4", ".webm",
    ".pdf", ".zip"
}


def is_static_resource(url: str) -> bool:
    p = urlparse(url)
    path = p.path.lower()
    return any(path.endswith(ext) for ext in SKIP_EXTENSIONS)

def crawl_extract(args, start_url, max_depth=1):
    queue = deque([(start_url, 0)])
    seen = set()
    visited = set()
    results = {}
    allowed_domains = set()

    # =========================================================
    # INIT DOMAIN
    # =========================================================
    res = get_request(args, start_url)
    allowed_domains.add(urlparse(start_url).netloc)
    if res:
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
        is_static = is_static_resource(url)
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

        # =========================================================
        # REQUEST
        # =========================================================
        try:
            res = get_request(args, url)
        except Exception as e:
            handle_error(e, "REQUEST ERROR", args.verbose)
            continue

        if not res:
            continue

        if args.verbose:
            print(f"{Y}[HTTP] {W}{res.status_code} (DEPTH={depth}) -> {url}")

        if res.status_code >= 500:
            continue

        if not is_html(res):
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

                full = canonicalize_url(
                    urljoin(url, link.split("#")[0])
                )

                parsed_link = urlparse(full)

                # scope filtering
                if not is_allowed_domain(
                    parsed_link.netloc,
                    allowed_domains
                ):
                    continue

                # static filtering
                link_is_static = is_static_resource(full)
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


# =========================================================
# CORE TESTER
# =========================================================
def test_openredirect(args, base_url, param):
    payloads = OPEN_REDIRECT_PAYLOADS
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
        try:
            r = get_request(args, url)
        except Exception:
            continue

        if not r:
            continue

        if is_openredirect(r, payload):
            print(f"{R}[OPEN REDIRECT] {W}{url}")
            print(f"{Y} -> Location: {W}{r.headers.get('Location')}")
            return True
    return False


# =========================================================
# CLI ENTRY (same pattern as traversal)
# =========================================================
def run_openredirect(args):
    if not hasattr(args, "url"):
        return

    parsed_params = extract_params(args.url)
    if parsed_params:
        print(f"{Y}[!] {W}Params detected: {parsed_params}")
        for param in parsed_params:
            if not is_interesting_param(param):
                continue

            print(f"[*] Testing param: {param}")
            test_openredirect(args, args.url, param)
    else:
        print(f"{R}[-] {W}No params found, crawling...")
        endpoints = crawl_extract(args, args.url)
        if not endpoints:
            print(f"{R}[-] {W}No endpoints found")
            return

        for base, data in endpoints.items():
            params = data["params"]
            print(f"{G}[+] {W}Endpoint: {base} -> {list(params)}")
            for param in params:
                if not is_interesting_param(param):
                    continue

                example_url = data["examples"].get(param, base)
                print(f"[*] Testing crawled param: {param}")
                test_openredirect(args, example_url, param)