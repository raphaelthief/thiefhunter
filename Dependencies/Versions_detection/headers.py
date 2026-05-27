import requests, re
from Dependencies.get_request import get_request

interesting_headers = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-redirect-by",
    "x-drupal-cache",
    "x-varnish",
    "via",
    "cf-ray",
    "x-cache",
    "x-cache-hits",
    "x-served-by",
    "x-backend-server",
    "x-runtime",
    "x-version",
    "x-host",
    "x-amz-cf-id",
    "x-amzn-requestid"
]

def extract_tech(value):
    """
    "PHP/7.4.33" -> ("PHP", "7.4.33")
    "nginx" -> ("nginx", None)
    """
    match = re.match(r"([A-Za-z0-9\-_\.]+)(?:[/ ]([0-9\.]+))?", value)
    if match:
        name = match.group(1)
        version = match.group(2)
        return name, version
    return value, None

def header_analyze(args, url):
    response = get_request(args, url)
    results = []
    if response is None:
        return []

    responses = [response] + list(response.history)
    for resp in responses:
        for k, v in resp.headers.items():
            k_lower = k.lower()

            if k_lower in interesting_headers:
                values = [val.strip() for val in v.split(",")]
                for value in values:
                    tech, version = extract_tech(value)
                    results.append({
                        "tech": tech,
                        "version": version
                    })
    return results

def extract_headers(args, url):
    return header_analyze(args, url)

def extract_headers2(args, url):
    techs = header_analyze(args, url)
    results = {
        f"{t['tech']} {t['version']}" if t["version"] else t["tech"]
        for t in techs
    }
    return list(results)