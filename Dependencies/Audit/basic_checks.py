import re, socket, hashlib, threading, os
from urllib.parse import urljoin, urlparse
from Dependencies.displays import M, W, R, Y, G, C, handle_error
from Dependencies.get_request import get_request, resolve_ip
from Dependencies.save_output import add_result
from concurrent.futures import ThreadPoolExecutor, as_completed


SECURITY_HEADERS = {
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
}

INFO_DISCLOSURE_PATTERNS = [
    r"Apache/\d+\.\d+",
    r"nginx/\d+\.\d+",
    r"PHP/\d+\.\d+",
    r"Express",
    r"Spring Boot",
    r"ASP\.NET",
    r"Traceback \(most recent call last\)",
    r"java\.lang\.",
    r"SQLException",
    r"stack trace",
]

TEST_PATHS = [
    "/doesnotexist123",
    '"<{',
    "error",
]

TEST_METHODS = [
    "OPTIONS",
    "TRACE",
    "DEBUG",
    "PUT",
    "DELETE",
    "PATCH",
]

print_lock = threading.Lock()

def check_headers(response):
    print(f"{C}[+] Checking headers")
    headers = response.headers
    for h in SECURITY_HEADERS:
        if h in headers:
            print(f"{G}[OK] {W}{h}: {headers[h]}")
            if h == "Content-Security-Policy":
                csp = headers[h]
                csp_issues = []

                if "unsafe-inline" in csp:
                    print(f"{R}    - [WEAK CSP] unsafe-inline detected")
                    csp_issues.append("unsafe-inline")

                if "unsafe-eval" in csp:
                    print(f"{R}    - [WEAK CSP] unsafe-eval detected")
                    csp_issues.append("unsafe-eval")

                if "*" in csp:
                    print(f"{R}    - [WEAK CSP] wildcard detected")
                    csp_issues.append("wildcard")
                    
                if csp_issues:
                    add_result("Audit", {
                        "Type": "csp_weakness",
                            "data": {
                                "header": "Content-Security-Policy",
                                "issues": f"{csp_issues}",
                                "value": f"{csp}"
                            }
                        })
                    
        else:
            print(f"{R}[MISSING] {h}")
            add_result("Audit", {
                "Type": "missing_header",
                    "data": {
                        "header": f"{h}"
                    }
                })
    print()
    print(f"{C}[+] Checking Sensitive headers")
    
    found_issue = False
    for h in ["Server", "X-Powered-By", "Via"]:
        if h in headers:
            print(f"{Y}[DISCLOSURE] {W}{h}: {headers[h]}")
            found_issue = True
            add_result("Audit", {
                "Type": "info_disclosure",
                    "data": {
                        "location": "header",
                        "header": f"{h}",
                        "value": f"{headers[h]}"
                    }
                })

    if not found_issue:
        print(f"{G}[OK] {W}No security issues detected in headers")
    print()

def check_body_for_disclosure(text):
    findings = []
    for pattern in INFO_DISCLOSURE_PATTERNS:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in matches:
            findings.append(match.group(0))
    return findings

def test_error_pages(args, base_url):
    print(f"{C}[+] Checking error pages")
    for path in TEST_PATHS:
        url = urljoin(base_url, path)
        try:
            r = get_request(args, url)
            print(f"{Y}[{r.status_code}] {W}{url}")
            findings = check_body_for_disclosure(r.text)

            if findings:
                print(f"{G}[+] Possible info disclosure")
                for f in findings:
                    print(f"{G}    - match: {W}{f}")
                    add_result("Audit", {
                        "Type": "info_disclosure",
                            "data": {
                                "location": "error_page",
                                "url": f"{url}",
                                "match": f"{f}",
                                "status_code": r.status_code
                            }
                        })
        except Exception as e:
            handle_error(e, "ERROR")
    print()


def analyze_response(response):
    findings = check_body_for_disclosure(response.text)
    if findings:
        print(f"{G}[+] Possible info disclosure")
        for f in findings:
            print(f"{G}    - match: {W}{f}")
            add_result("Audit", {
                "Type": "info_disclosure",
                    "data": {
                        "location": "body",
                        "match": f"{f}"
                    }
                })


def test_http_methods(args, base_url):
    print(f"{C}[+] Checking HTTP methods")
    for method in TEST_METHODS:
        try:
            r = get_request(args, base_url, method=method)
            print(f"{Y}[{method}] {W}Status={r.status_code}")
            if method == "OPTIONS":
                if "Access-Control-Allow-Methods" in r.headers:
                    print(f"{G}    - Cors methods: {W}{r.headers['Access-Control-Allow-Methods']}")
                    add_result("Audit", {
                        "Type": "Access-Control-Allow-Methods",
                            "data": {
                                "value": f"{r.headers['Access-Control-Allow-Methods']}"
                            }
                        })
                        
            if "Allow" in r.headers:
                print(f"{G}    - Allow: {W}{r.headers['Allow']}")
                add_result("Audit", {
                    "Type": "allow_header",
                        "data": {
                            "value": r.headers["Allow"]
                        }
                    })
                        
            if method in ["TRACE", "PUT", "DELETE", "DEBUG"]:
                if r.status_code not in [403, 405, 501]:
                    print(f"{G}    - {R}{method} {W}may be enabled")
                    add_result("Audit", {
                        "Type": "dangerous_method_enabled",
                            "data": {
                                "method": f"{method}",
                                "status_code": r.status_code
                            }
                        })

            analyze_response(r)
        except Exception as e:
            handle_error(e, f"ERROR {method}", args.verbose)
    print()

def check_cookies(response):
    print(f"{C}[+] Checking cookies")
    raw_cookies = response.raw.headers.get_all("Set-Cookie")

    if not raw_cookies:
        print(f"{Y}[INFO] {W}No cookies found")
        print()
        return

    for raw in raw_cookies:
        print(f"{Y}[COOKIE] {W}{raw}")
        issues = []
        lower = raw.lower()

        if "secure" not in lower:
            print(f"{R}    - Missing Secure")
            issues.append("missing_secure")

        if "httponly" not in lower:
            print(f"{R}    - Missing HttpOnly")
            issues.append("missing_httponly")

        if "samesite" not in lower:
            print(f"{R}    - Missing SameSite")
            issues.append("missing_samesite")

        if issues:
            add_result("Audit", {
                "Type": "cookie_weakness",
                    "data": {
                        "cookie": f"{raw}",
                        "issues": f"{issues}"
                    }
                })
    print()

def check_cors(response):
    print(f"{C}[+] Checking default CORS")
    acao = response.headers.get("Access-Control-Allow-Origin")
    acac = response.headers.get("Access-Control-Allow-Credentials")
    if acao == "*":
        print(f"{R}[WEAK] ACAO = *")
        add_result("Audit", {
            "Type": "wildcard_origin",
                "data": {
                    "value": f"{acao}"
                }
            })
        
    if acac == "true" and acao == "*":
        print(f"{R}[CRITICAL] wildcard + credentials")
        add_result("Audit", {
            "Type": "critical_misconfig",
                "data": {
                    "details": "wildcard + credentials"
                }
            })
        
    if acao:
        print(f"{Y}[CORS] ACAO: {W}{acao}")
        add_result("Audit", {
            "Type": "ACAO",
                "data": {
                    "value": f"{acao}"
                }
            })

    if not acao:
        print(f"{Y}[INFO] {W}No CORS headers (likely safe default)")
    print()

def check_cors_active(args):
    print(f"{C}[+] Checking active CORS")
    test_origin = "https://evil.com"
    try:
        r = get_request(args, args.url, headers={"Origin": test_origin})
        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = r.headers.get("Access-Control-Allow-Credentials")
        print(f"{Y}[TEST] {W}Origin: {test_origin}")
        if not acao:
            print(f"{Y}[INFO] {W}No ACAO returned")
            print()
            return

        print(f"{Y}[ACAO] {W}{acao}")
        if acao == test_origin:
            print(f"{R}[WEAK] Origin reflection detected")
            add_result("Audit", {
                "Type": "origin_reflection",
                    "data": {
                        "origin": f"{test_origin}"
                    }
                })
    
        # wildcard
        if acao == "*":
            print(f"{R}[WEAK] wildcard ACAO")
            add_result("Audit", {
                "Type": "wildcard ACAO",
                    "data": {
                        "origin": f"{acao}"
                    }
                })

        # credentials + reflection
        if acac == "true":
            print(f"{Y}[CREDENTIALS] enabled")
            if acao == test_origin:
                print(f"{R}[CRITICAL] CORS misconfig (reflection + credentials)")
                add_result("Audit", {
                    "Type": "critical_cors_misconfig_ACAO",
                        "data": {
                            "origin": f"{test_origin}"
                        }
                    })
                
    except Exception as e:
        handle_error(e, "CORS ERROR", args.verbose)
    print()

def check_https_redirect(args):
    print(f"{C}[+] Checking HTTPS redirect")
    try:
        parsed = urlparse(args.url)
        http_url = f"http://{parsed.netloc}"
        r = get_request(args, http_url, allow_redirects=False)

        if r.status_code in [301, 302, 307, 308]:
            location = r.headers.get("Location", "")
            print(f"{Y}[REDIRECT] {W}{location}")
            if not location.startswith("https://"):
                print(f"{R}[WEAK] Redirect does not enforce HTTPS")
                add_result("Audit", {
                    "Type": "weak_redirect",
                        "data": {
                            "location": f"{location}"
                        }
                    })

        else:
            print(f"{R}[MISSING] No HTTP -> HTTPS redirect")
            add_result("Audit", {
                "Type": "http_redirect",
                    "data": {
                        "result": "missing_https_redirect"
                    }
                })

    except Exception as e:
        handle_error(e, "HTTPS redirect check failed", args.verbose)
    print()

def check_robots(args):
    print(f"{C}[+] Checking for robots.txt configurations")
    url = urljoin(args.url, "/robots.txt")
    r = get_request(args, url)
    
    if "Disallow:" in r.text:
        print(f"{Y}[ROBOTS] {R}Sensitive paths exposed{W}")
        print("----------")
        print(r.text)
        print("----------")
        add_result("Audit", {
            "Type": "robots",
                "data": {
                    "findings": "sensitive_paths_exposed",
                    "content": f"{r.text}"
                }
            })

    else:
        if "user-agent: *" in r.text.lower():
            print(f"{Y}[ROBOTS] {G}Ok{W}")
            print("----------")
            print(r.text)
            print("----------")
            add_result("Audit", {
                "Type": "robots",
                    "data": {
                        "findings": "user-agent_*",
                        "content": f"{r.text}"
                    }
                })
        else:
            print(f"{Y}[ROBOTS] {W}Not Found ({r.status_code})")
    print()

def hash_body(r):
    return hashlib.md5(r.text.encode()).hexdigest()

def compare_responses(r_ip, r_host):
    if r_ip is None or r_host is None:
        print(f"{R}[!] Skipping comparison (null response)")
        return
    
    if r_ip.status_code != r_host.status_code:
        print(f"{G}    - {W}Status code mismatch (IP: {r_ip.status_code} | HOST: {r_host.status_code})")
        add_result("Audit", {
            "Type": "ip_access",
                "data": {
                    "findings": "status_mismatch",
                    "ip": r_ip.status_code,
                    "host": r_host.status_code
                }
            })
    
    if hash_body(r_ip) != hash_body(r_host):
        print(f"{G}    - {W}Body mismatch")
        add_result("Audit", {
            "Type": "ip_access",
                "data": {
                    "findings": "body_mismatch"
                }
            })

    
    headers_to_check = ["Server", "X-Powered-By", "Via"]
    for h in headers_to_check:
        if r_ip.headers.get(h) != r_host.headers.get(h):
            print(f"{Y}{G}    - {W}Headers mismatch: {h}")
            add_result("Audit", {
                "Type": "ip_access",
                    "data": {
                        "findings": "headers_mismatch",
                        "content": f"{h}"
                    }
                })

def test_ip_access(args):
    print(f"{C}[+] Checking IP-based access")
    parsed = urlparse(args.url)
    domain = parsed.netloc
    try:
        ip = resolve_ip(args, domain)
        print(f"{Y}[RESOLVED IP] {W}{ip}")
        ip_url = f"http://{ip}/"
        print(f"{Y}[TRYING] {R}http{W}://{ip}/ with 'Host: {domain}'")
        r_ip = get_request(args, ip_url, headers={"Host": domain}, allow_redirects=False)
        
        ip_url2 = f"https://{ip}/"
        print(f"{Y}[TRYING] {R}https{W}://{ip}/ with 'Host: {domain}'")
        
        try:
            r_ip2 = get_request(args, ip_url2, headers={"Host": domain}, allow_redirects=False)
        except:
            r_ip2 = None
            pass

        try:
            r_host = get_request(args, args.url, allow_redirects=False)
        except:
            r_host = None
            pass


        if not r_ip or not r_host:
            print(f"{R}[!] Skipping comparison (missing response)")
        else:    
            print(f"{G}[+] Comparing HTTP responses")
            compare_responses(r_ip, r_host)

            print(f"{G}[+] Comparing HTTPS responses")
            compare_responses(r_ip2, r_host)

            for label, r in [("HTTP", r_ip), ("HTTPS", r_ip2)]:
                if r.text != r_host.text:
                    print(f"{Y}[INFO] {W}{label} response differs from host (possible vhost routing issue)")
                    add_result("Audit", {
                        "Type": "ip_access",
                            "data": {
                                "target": f"{label}",
                                "findings": "response differs from host (possible vhost routing issue)"
                            }
                        })
                        
                if r.status_code == 200:
                    print(f"{R}[INFO] {label} IP access returns content (not proof of bypass)")
                    add_result("Audit", {
                        "Type": "ip_access",
                            "data": {
                                "target": f"{label}",
                                "findings": "IP access returns content (possible vhost routing issue)"
                            }
                        })
                        
                elif r.status_code in [301, 302, 303, 307, 308]:
                    print(f"{Y}[INFO] {label} redirect behavior detected")
                    add_result("Audit", {
                        "Type": "ip_access",
                            "data": {
                                "target": f"{label}",
                                "findings": "redirect behavior detected"
                            }
                        })
                        
                elif r.status_code == 403:
                    print(f"{Y}[INFO] {label} access blocked (WAF / vhost protection)")
                    add_result("Audit", {
                        "Type": "ip_access",
                            "data": {
                                "target": f"{label}",
                                "findings": "access blocked (WAF / vhost protection)"
                            }
                        })

                server = r.headers.get("Server")
                if server:
                    print(f"{Y}[Server {label}] {W}{server}")
            
            print(f'{Y}[MANUAL] {W}Try: curl -I {ip_url} -H "Host: {domain}" --insecure && curl -I {ip_url2} -H "Host: {domain}" --insecure && curl -I -L {domain} --insecure')
    except Exception as e:
        handle_error(e, "IP test failed", args.verbose)
    print()

def check_paths(args):
    print(f"{C}[+] Check sensitive paths")
    base_url = args.url.rstrip("/") + "/"
    paths_file = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..",
        "Payloads",
        "path_enum.txt"
    )

    paths_file = os.path.normpath(paths_file)
    with open(paths_file, "r", encoding="utf-8") as f:
        paths = [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]

    def worker(path):
        path = path.lstrip("/")
        url = urljoin(base_url, path)
        r = get_request(args, url, allow_redirects=False)

        if r:
            with print_lock:
                color = G if r.status_code == 200 else Y
                print(f"{color}[{r.status_code}] {W}{url} {G}(len={len(r.text)})")
                add_result("Audit", {
                    "Type": "Sensitive_paths",
                        "data": {
                            "url": f"{url}",
                            "status_code": r.status_code,
                            "length": len(r.text)
                        }
                    })

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(worker, path) for path in paths]

        for future in as_completed(futures):
            future.result()

def auditor(args):
    try:
        # --- MAIN REQUEST ---
        r = get_request(args, args.url)
        if r is None:
            print(f"{R}[ERROR] Failed to get a valid response from target")
            print(f"{R}[*] {W}Skipping Headers check")
            print(f"{R}[*] {W}Skipping Cookies check")
            print(f"{R}[*] {W}Skipping Cors passive check")
            
            
        # --- BASIC CHECKS ---
        print(f"\n{C}[!] Basic checks")
        if r is not None:
            check_headers(r)
            findings = check_body_for_disclosure(r.text)
            if findings:
                print(f"{C}[+] Info disclosure on the main page")
                for f in findings:
                    print(f"{G}    - {W}{f}")
                    
                    if args.save:
                        add_result("Auditor", {
                            "type": "info_disclosure",
                            "data": {
                                "source": "main page",
                                "findings": f"{f}"
                            }
                        })
                print()

        # --- ERROR PAGES ---    
        test_error_pages(args, args.url)
        
        # --- HTTP METHODS ---
        test_http_methods(args, args.url)
        
        # --- COOKIES ---
        if r is not None:
            check_cookies(r)
        
        # --- CORS ---
        if r is not None:
            check_cors(r)
        check_cors_active(args)
        
        # --- HTTPS REDIRECT ---
        check_https_redirect(args)
        
        # --- IP ACCESS ---
        test_ip_access(args)
        
        # --- ROBOTS ---
        check_robots(args)

        # --- BASIC PATH ---
        results = check_paths(args)
    except Exception as e:
        handle_error(e, "ERROR", args.verbose)
