import requests, re
from collections import defaultdict, Counter
from urllib.parse import urlparse
from Dependencies.get_request import get_request

def tag_plugins_themes_and_versions(url):
    name = None
    tag = None

    if '/wp-content/plugins/' in url:
        tag = "plugin"
        match = re.search(r'/wp-content/plugins/([^/]+)/', url)
        if match:
            name = match.group(1)

    elif '/wp-content/themes/' in url:
        tag = "theme"
        match = re.search(r'/wp-content/themes/([^/]+)/', url)
        if match:
            name = match.group(1)

    if not name:
        return None

    version = None
    version_match = re.search(r'\?ver=([\d.]+)', url)
    if version_match:
        version = version_match.group(1)

    return tag, name, version


def aggregate_plugins_and_themes(html):
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "html.parser")

    raw_links = soup.find_all(['link', 'script'], href=True) + soup.find_all('script', src=True)

    version_data = defaultdict(list)

    for tag in raw_links:
        href = tag.get('href') or tag.get('src')
        if not href:
            continue

        result = tag_plugins_themes_and_versions(href)
        if result:
            tag_type, name, version = result
            version_data[(tag_type, name)].append(version)

    results = []

    for (tag_type, name), versions in version_data.items():
        versions = [v for v in versions if v]

        if versions:
            most_common = Counter(versions).most_common(1)[0][0]
        else:
            most_common = ""

        results.append((tag_type, name, most_common))

    return results


# -------------------------
# WORDPRESS CORE VERSION
# -------------------------

def detect_wp_meta(soup):
    meta = soup.find('meta', attrs={'name': 'generator'})
    if meta:
        content = meta.get('content', '')
        match = re.search(r'WordPress\s+(\d+\.\d+(\.\d+)?)', content)
        if match:
            return match.group(1)
    return None


def detect_wp_readme(args, url):
    try:
        r = get_request(args, f"{url.rstrip('/')}/readme.html")
        if r.status_code == 200:
            match = re.search(r'WordPress (\d+\.\d+(\.\d+)?)', r.text)
            if match:
                return match.group(1)
    except:
        pass
    return None


def detect_wp_api(args, url):
    try:
        r = get_request(args, f"{url.rstrip('/')}/wp-json/")
        if r.status_code == 200:
            data = r.json()
            if 'meta' in data and 'generator' in data['meta']:
                match = re.search(r'WordPress (\d+\.\d+(\.\d+)?)', data['meta']['generator'])
                if match:
                    return match.group(1)
    except:
        pass
    return None


def detect_wordpress_version(args, url, soup):
    """
    return best effort WP version
    """
    versions = []

    meta = detect_wp_meta(soup)
    readme = detect_wp_readme(args, url)
    api = detect_wp_api(args, url)

    for v in [meta, readme, api]:
        if v:
            versions.append(v)

    if not versions:
        return None

    return Counter(versions).most_common(1)[0][0]


def detect_wordpress(args, html, url):
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "html.parser")

    wp_version = detect_wordpress_version(args, url, soup)
    plugins_themes = aggregate_plugins_and_themes(html)

    return {
        "core": wp_version,
        "components": plugins_themes
    }