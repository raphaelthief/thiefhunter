import base64, mmh3
from urllib.parse import urlparse
from Dependencies.displays import M, W, R, Y, G, C, handle_error
from Dependencies.get_request import get_request
from Dependencies.save_output import add_result


def whatfavicon(args):
    try:
        print(f"{G}[+] Searching for favicon hash...")
        if not args.url.startswith(("http://", "https://")):
            args.url = "https://" + args.url
            
        parsed = urlparse(args.url)
        url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
        r = get_request(args, url, timeout=15)

        if not r.status_code == 200:
            print(f"{M}[-] favicon.icon not found")
            return
            
        favicon = base64.b64encode(r.content)
        hash_found = mmh3.hash(favicon)
        
        print(f"{G}[+] Hash          : {C}{hash_found}")
        print(f"{G}[+] Shodan filter : {C}http.favicon.hash:{hash_found}")
        print(f"{G}[+] Shodan        : {C}https://www.shodan.io/search?query=http.favicon.hash%3A{hash_found}")
        print(f"{G}[+] Censys        : {C}https://platform.censys.io/search?q=web.endpoints.http.favicons.hash_shodan%3D%22{hash_found}%22")

    except Exception as e:
        handle_error(e, "ERROR", args.verbose)
