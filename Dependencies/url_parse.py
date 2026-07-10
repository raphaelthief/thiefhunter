import tldextract
from urllib.parse import urlparse, parse_qs

def extract_domain(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    return parsed.netloc

def extract_strictdomain(url):
    extracted = tldextract.extract(url)
    return f"{extracted.domain}.{extracted.suffix}"    

def extract_params(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    return {
        "base": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
        "params": list(params.keys())
    }
    
