from Dependencies.get_request import get_request_socket
from Dependencies.displays import M, W, R, Y, G, C, handle_error

HEADERS_TO_TEST = [
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Client-IP",
    "X-Original-URL",
]

PAYLOADS = [
    "\r\nX-CRLF-Test: injected",
    "%0d%0aX-CRLF-Test: injected",
    "%0D%0AX-CRLF-Test: injected",
]

def crlf_test(args):
    try:
        print(f"{C}[+] Crlf headers injections on {args.url}")
        baseline = get_request_socket(args, args.url)
        if not baseline:
            return

        baseline_headers = dict(baseline.headers)
        print(f"{G}[+] Baseline status: {baseline.status_code}")

        for header_name in HEADERS_TO_TEST:
            print(f"{W}[*] Testing header: {Y}{header_name}")
            for payload in PAYLOADS:
                injected_headers = {
                    header_name: f"test{payload}"
                }

                response = get_request_socket(args, args.url, headers=injected_headers)
                if not response:
                    continue

                interesting = False

                # 1. Header injection detection
                for k, v in response.headers.items():
                    if "X-CRLF-Test" in k or "injected" in v:
                        interesting = True
                        print(f"\n{R}[+] Possible CRLF Injection Detected")
                        print(f"{G}Header tested : {W}{header_name}")
                        print(f"{G}Payload       : {W}{repr(payload)}")
                        print(f"{G}Injected hdr  : {W}{k}: {v}")

                # 2. Status code difference
                if response.status_code != baseline.status_code:
                    interesting = True
                    print(f"\n{Y}[!] Status code changed")
                    print(f"{baseline.status_code} {G}-> {W}{response.status_code}")

                # 3. Content-Length difference
                base_len = baseline.headers.get("Content-Length")
                new_len = response.headers.get("Content-Length")
                if base_len != new_len:
                    interesting = True
                    print(f"\n{Y}[!] Content-Length changed")
                    print(f"{Y}{base_len} {G}-> {W}{new_len}")

                # 4. New headers
                new_headers = set(response.headers.keys()) - set(baseline_headers.keys())
                if new_headers:
                    interesting = True
                    print(f"\n{Y}[!] New headers detected")
                    for h in new_headers:
                        print(f"  {G}+ {h}: {W}{response.headers[h]}")

                if not interesting:
                    print(f"{G}[-] No issue detected with payload: {W}{repr(payload)}")
            print(f"{Y}-" * 60)
    except Exception as e:
        handle_error(e, "ERROR", args.verbose)