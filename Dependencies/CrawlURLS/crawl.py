import re, time
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from Dependencies.get_request import get_request
from Dependencies.displays import M, W, R, Y, G, C, handle_error

# =========================================================
# NORMALIZE URL PARAMETERS
# =========================================================
def normalize_url_params(url):
    parsed = urlparse(url)
    if not parsed.query:
        return None

    params = parse_qs(parsed.query)
    if not params:
        return None

    normalized_query = "&".join(
        f"{key}="
        for key in sorted(params.keys())
    )

    return (
        f"{parsed.scheme}://"
        f"{parsed.netloc}"
        f"{parsed.path}"
        f"?{normalized_query}"
    )


# =========================================================
# EXCLUDE EXTENSIONS
# =========================================================
def should_exclude(url, exclude_ext):
    parsed = urlparse(url)
    path = parsed.path.lower()
    for ext in exclude_ext:
        if path.endswith(ext):
            return True

    return False


# =========================================================
# CRAWLER
# =========================================================
def crawl_extractit(args, start_url, max_depth=2, exclude_ext=None, show_all=False):
    visited = set()
    results = set()
    start_time = time.time()
    stats = {
        "requests": 0,
        "parameterized": 0,
        "filtered": 0,
        "max_depth_reached": 0,
    }

    # -----------------------------------------------------
    # PROCESS LINKS
    # -----------------------------------------------------
    def process_link(args, link, current_url, depth):

        link = urljoin(current_url, link)
        link = link.split("#")[0]

        # SAME DOMAIN ONLY
        if (urlparse(link).netloc != urlparse(start_url).netloc):
            return

        # EXCLUDED EXTENSIONS
        if exclude_ext:
            if should_exclude(link, exclude_ext):
                stats["filtered"] += 1
                return

        # SHOW ALL URLS
        if show_all:
            final_url = link

        else:
            final_url = normalize_url_params(link)

            if not final_url:
                stats["filtered"] += 1
                return

        # SAVE RESULT
        if final_url not in results:
            results.add(final_url)

            if "?" in link:
                stats["parameterized"] += 1

        # CONTINUE CRAWL
        if link not in visited:
            crawl(args, link, depth + 1)

    # -----------------------------------------------------
    # CRAWL FUNCTION
    # -----------------------------------------------------
    def crawl(args, url, depth):
        if depth > max_depth:
            return

        if url in visited:
            return

        visited.add(url)

        if depth > stats["max_depth_reached"]:
            stats["max_depth_reached"] = depth

        try:
            res = get_request(args, url)
            if not res:
                return

            stats["requests"] += 1
            if args.verbose:
                print(f"{Y}[HTTP] {W}{res.status_code} (DEPTH={depth}) -> {url}")

            content_type = (res.headers.get("Content-Type", "").lower())

            if "text/html" not in content_type:
                return

            soup = BeautifulSoup(res.text, "html.parser")

            # ---------------------------------------------
            # REGEX href
            # ---------------------------------------------
            for link in re.findall(r'href=["\'](.*?)["\']', res.text):
                process_link(args, link, url, depth)

            # ---------------------------------------------
            # FULL URLS
            # ---------------------------------------------
            for link in re.findall(r'(https?://[^\s"\'<>]+)', res.text):
                process_link(args, link, url, depth)

            # ---------------------------------------------
            # HTML TAGS
            # ---------------------------------------------
            tags_attrs = [
                ("a", "href"),
                ("link", "href"),
                ("script", "src"),
                ("img", "src"),
                ("form", "action"),
            ]

            for tag, attr in tags_attrs:
                for element in soup.find_all(tag):
                    link = element.get(attr)
                    if link:
                        process_link(args, link, url, depth)

        except Exception as e:
            handle_error(e, "ERROR", args.verbose)

    # START
    crawl(args, start_url, 0)
    duration = round(time.time() - start_time, 2)

    # =====================================================
    # PRINT RESULTS
    # =====================================================
    print(f"\n{G}[+] Found {len(results)} parameterized URLs")
    for i, url in enumerate(results, 1):
        print(f"{G}[{i:04}] {W}{url}")

    # =====================================================
    # PRINT STATS
    # =====================================================
    print(f"\n{C}========== CRAWL STATS ==========")
    print(f"{G}[+] Pages crawled      : {W}{stats['requests']}")
    print(f"{G}[+] URLs visited       : {W}{len(visited)}")
    print(f"{G}[+] URLs found         : {W}{len(results)}")
    print(f"{G}[+] Param URLs found   : {W}{stats['parameterized']}")
    print(f"{G}[+] Filtered URLs      : {W}{stats['filtered']}")
    print(f"{G}[+] Max depth reached  : {W}{stats['max_depth_reached']}")
    print(f"{G}[+] Duration           : {W}{duration}s")
    print(f"{C}=================================")
