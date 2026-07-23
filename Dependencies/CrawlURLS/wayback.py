import time, requests, os
from Dependencies.displays import M, W, R, Y, G, C, handle_error
from urllib.parse import urlparse, parse_qs

def_timeout = 60
headers = {
    "User-Agent": "Mozilla/5.0"
}


def normalize_url_params(url):
    parsed = urlparse(url)

    if not parsed.query:
        return None

    params = parse_qs(parsed.query)
    if not params:
        return None

    normalized_query = "&".join(f"{key}=" for key in sorted(params.keys()))
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{normalized_query}"
    
def should_exclude(url, exclude_ext):
    parsed = urlparse(url)
    path = parsed.path.lower()

    for ext in exclude_ext:
        if path.endswith(ext):
            return True
    return False

def wayback_urls(args, domain, exclude_ext=None, show_all=False):
    start_time = time.time()
    urls = set()
    total = 0
    filtered = 0

    try:
        print(f"{M}[Info] {G}Collecting infos for {def_timeout} seconds max")
        response = requests.get(f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=txt", headers=headers, verify=False, timeout=def_timeout, stream=True)
        for line in response.iter_lines(decode_unicode=True):
            if time.time() - start_time > def_timeout:
                print(f"{Y}[*] {R}Stopping processing after {def_timeout} seconds")
                break

            if not line:
                continue

            parts = [p.strip() for p in line.split(' ') if p.strip()]
            if len(parts) <= 4:
                continue

            status_code = parts[4]
            total += 1
            raw_url = parts[2]
            if status_code != '200':
                continue

            url = raw_url.replace('%20', ' ')
            if exclude_ext and should_exclude(url, exclude_ext):
                filtered += 1
                continue

            if show_all:
                final_url = url
            else:
                final_url = normalize_url_params(url)
                if not final_url:
                    filtered += 1
                    continue

            urls.add(final_url)
        return sorted(urls), total, filtered

    except requests.exceptions.RequestException as e:
        handle_error(e, "ERROR", args.verbose)
        return []
