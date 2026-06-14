import os, time
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed
from Dependencies.displays import M, W, R, Y, G, C, handle_error
from Dependencies.get_request import get_request
from Dependencies.save_output import add_result

load_dotenv()
API_KEY = os.getenv("DNSDUMPSTER_API_KEY")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

REVERSE_PROXIES = [
    # CDN / Reverse proxy
    "CLOUDFLARE",
    "CLOUDFLARENET",
    "FASTLY",
    "AKAMAI",
    "CLOUDFRONT",
    "AMAZON CLOUDFRONT",
    "EDGECAST",
    "STACKPATH",
    "CDN77",
    "BUNNY",
    "CACHEFLY",
    "KEYCDN",

    # WAF / Protection / Proxy
    "INCAPSULA",
    "SUCURI",
    "DATADOME",
    "PERIMETERX",
    "HUMAN SECURITY",
    "F5",
    "AZURE FRONT DOOR",
    "AZUREEDGE",
    "NETSCALER",
    "CITRIX",
    "RADWARE",
    "REBLAZE",
    "DDOS-GUARD",

    # Edge platforms / serverless frontends
    "VERCEL",
    "NETLIFY"
]

SENSITIVE_SUBDOMAINS = [
    # Administration / interne
    "admin",
    "administrator",
    "adm",
    "panel",
    "cpanel",
    "dashboard",
    "portal",
    "internal",
    "intranet",
    "backoffice",
    "backend",
    "manage",
    "management",

    # Authentification / comptes
    "auth",
    "sso",
    "login",
    "signin",
    "accounts",
    "account",
    "id",
    "identity",
    "oauth",
    "saml",
    "secure",

    # Dev / staging / test
    "dev",
    "development",
    "test",
    "testing",
    "staging",
    "preprod",
    "uat",
    "sandbox",
    "beta",
    "demo",
    "qa",

    # APIs / services internes
    "api",
    "api-dev",
    "api-staging",
    "graphql",
    "rest",
    "services",
    "service",
    "microservice",
    "rpc",
    "ws",
    "webhook",

    # Monitoring / logs / debug
    "monitor",
    "metrics",
    "grafana",
    "prometheus",
    "logs",
    "log",
    "kibana",
    "elk",
    "status",
    "health",
    "debug",
    "trace",

    # Admin tools / infra exposée
    "jenkins",
    "gitlab",
    "github",
    "ci",
    "cd",
    "jenkins-ci",
    "build",
    "artifactory",
    "nexus",
    "registry",

    # Cloud / storage / buckets
    "s3",
    "storage",
    "files",
    "cdn",
    "assets",
    "media",
    "uploads",
    "download",
    "static",

    # Mail / messaging
    "mail",
    "smtp",
    "imap",
    "pop",
    "webmail",
    "mx",
    "relay",
    "exchange",

    # Divers
    "vpn",
    "remote",
    "rdp",
    "citrix",
    "ssh",
    "gateway",
    "proxy",
    "old",
    "legacy",
    "archive",
    "backup",
    "experts"
]


def is_reverse_proxy(asn_name: str) -> bool:
    return any(proxy in asn_name.upper() for proxy in REVERSE_PROXIES)

def fetch_crtsh(args, domain: str, retries: int = 10): # 10 retry for crt.sh
    url = f"https://crt.sh/json?q={domain}"
    headers = {
        "User-Agent": "Mozilla/5.0"
    }
    for attempt in range(retries):
        try:
            if args.verbose:
                print(f"{Y}[INFO] {W}Attempt {attempt + 1}/{retries} for crt.sh")

            response = get_request(args, url, timeout=60)
            
            # retry error code 502
            if response.status_code == 502:
                if args.verbose:
                    print(f"{R}[Error] 502 error code")
                    
                time.sleep(1)
                continue

            response.raise_for_status()
            return response.json()
        except:               
            time.sleep(0.5)
            
    return []

def probe_subdomains(args, subdomains: list, max_threads: int = 25, hide_suspicious: bool = True):
    results = {}
    if args.verbose:
        print(f"{Y}[INFO] {W}Starting 25 Threads")
        
    def probe_one(args, sub):
        for scheme in ["https", "http"]:
            url = f"{scheme}://{sub}"
            try:
                r = get_request(args, url)

                if r is None:
                    continue

                redirect_chain = [resp.status_code for resp in r.history]
                suspicious = (
                    any(code in [301, 302, 307, 308] for code in redirect_chain)
                    and len(r.history) > 3
                    and r.status_code in [200, 403]
                )

                return sub, {
                    "status_code": r.status_code,
                    "final_url": r.url,
                    "suspicious": suspicious
                }
            except Exception as e:
                handle_error(e, "ERROR", args.verbose)
                continue

        return sub, {
            "status_code": "unreachable",
            "final_url": None,
            "suspicious": False
        }

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(probe_one, args, s) for s in subdomains]
        for future in as_completed(futures):
            sub, result = future.result()
            results[sub] = result

    if hide_suspicious:
        results = {
            k: v for k, v in results.items()
            if not v.get("suspicious", False)
        }
    return results

def get_subdomains(args, domain: str) -> list:
    results = {}

    # -------------------------
    # 1. DNSDumpster
    # -------------------------
    if API_KEY:
        print(f"{G}[+] Searching on DNSDumpster ...")
        try:
            url = f"https://api.dnsdumpster.com/domain/{domain}"
            headers = {
                "X-API-Key": API_KEY,
                "Accept": "application/json"
            }

            response = get_request(args, url, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
            for record in data.get("a", []):
                host = record.get("host")

                if not host or host == domain:
                    continue

                for ip_info in record.get("ips", []):
                    results[host] = {
                        "subdomain": host,
                        "ip": ip_info.get("ip", "N/A"),
                        "asn_name": ip_info.get("asn_name", "N/A")
                    }
                    if args.save:
                        add_result("Subdomains", {
                            "type": "dnsdumpster",
                            "data": {
                                "source": "dnsdumpster",
                                "subdomain": host,
                                "ip": ip_info.get("ip", "N/A"),
                                "asn": ip_info.get("asn_name", "N/A")
                            }
                        })
        except Exception as e:
            handle_error(e, "ERROR", args.verbose)
            pass
    else:
        print(f"{G}[-] No API KEY, skipping DNSDumpster ...")

    # -------------------------
    # 2. CRT.SH
    # -------------------------
    try:
        print(f"{G}[+] Searching on crt.sh ...")
        crt_data = fetch_crtsh(args, domain)
        for entry in crt_data:
            name_value = entry.get("name_value", "")
            for sub in name_value.split("\n"):
                sub = sub.strip()
                if not sub or "*" in sub:
                    continue

                if sub not in results:
                    results[sub] = {
                        "subdomain": sub,
                        "ip": "N/A",
                        "asn_name": "(CRT.sh)"
                    }
                    if args.save:
                        add_result("Subdomains", {
                            "type": "crt.sh",
                            "data": {
                                "source": "crtsh",
                                "subdomain": sub,
                                "ip": "N/A"
                            }
                        })
    except Exception as e:
        handle_error(e, "ERROR", args.verbose)
        pass

    # -------------------------
    # 3. VirusTotal
    # -------------------------
    if VT_API_KEY:
        print(f"{G}[+] Searching on VirusTotal ...")
        try:
            vt_url = "https://www.virustotal.com/vtapi/v2/domain/report"
            params = {
                "apikey": VT_API_KEY,
                "domain": domain
            }

            response = get_request(args, vt_url, params=params, timeout=30)
            data = response.json()
            for sub in data.get("subdomains", []):
                if sub not in results:
                    results[sub] = {
                        "subdomain": sub,
                        "ip": "N/A",
                        "asn_name": "(VirusTotal)"
                    }
                    if args.save:
                        add_result("Subdomains", {
                            "type": "VirusTotal",
                            "data": {
                                "source": "virustotal",
                                "subdomain": sub
                            }    
                        })
        except Exception as e:
            handle_error(e, "ERROR", args.verbose)
            pass
    else:
        print(f"{G}[-] No API KEY, skipping VirusTotal ...")

    # -------------------------
    # 4. Active enumeration
    # -------------------------   
    print(f"{G}[+] Probing missing sensitive subdomains ...")
    to_probe = []
    for word in SENSITIVE_SUBDOMAINS:
        test_sub = f"{word}.{domain}"
        if test_sub in results:
            continue
        to_probe.append(test_sub)
        
    probe_results = probe_subdomains(args, to_probe)
    for sub, result in probe_results.items():
        results[sub] = {
            "subdomain": sub,
            "ip": "N/A",
            "asn_name": "(PROBE)",
            "status": result["status_code"],
            "final_url": result["final_url"],
            "suspicious": result.get("suspicious", False)
        }
        if args.save:
            add_result("Subdomains", {
                "type": "Probes",
                "data": {
                    "source": "probe",
                    "subdomain": sub,
                    "status": result["status_code"],
                    "final_url": result["final_url"],
                    "suspicious": result.get("suspicious", False)
                    }
            })

    # -------------------------
    # Print results
    # -------------------------   
    print()
    subs = list(results.values())
    longest = max(len(item['subdomain']) for item in subs)
    displayed_subdomains = []
    for item in subs:
        if item.get("status") == "unreachable":
            continue
        
        displayed_subdomains.append(item)
        asn_name = item["asn_name"].upper()
        is_proxy = (
            is_reverse_proxy(item["asn_name"]) or
            asn_name in ["(VIRUSTOTAL)", "(CRT.SH)", "(PROBE)"]
        )
        
        color = W if is_proxy else R
        warn = ""
        if item.get("status") == "ssl_error":
            warn = f"{Y} [SSL FAIL]"
        elif item.get("suspicious"):
            warn = f"{Y} [REDIRECT CHAIN]"

        print(f"{G}[*] {Y}{item['subdomain']:<{longest}} → {color}{item.get('status', item['ip'])} {W}{item['asn_name']}{warn}")


    # -------------------------
    # Ask user if they want HTTP access checks
    # -------------------------
    if args.batch:
        print(f"\n{Y}[?] Do you want to test access to discovered subdomains? (y/n): {C}y")
        check_access = "yes"
    else:
        check_access = input(f"\n{Y}[?] Do you want to test access to discovered subdomains? (y/n): {C}").strip().lower()
        
    if check_access in ["y", "yes"]:
        print(f"{G}[+] Testing HTTP access on discovered subdomains ...")
        for entry in displayed_subdomains:
            if entry.get("status") == 404:
                continue
                
            sub = entry["subdomain"]

            # -------------------------
            # Try HTTPS first
            # -------------------------
            https_url = f"https://{sub}"
            response = get_request(args, https_url, timeout=10)
            url = https_url

            # -------------------------
            # Fallback HTTP
            # -------------------------
            if response is None:
                http_url = f"http://{sub}"
                response = get_request(args, http_url, timeout=10)

                url = http_url

            # No response at all
            if response is None:
                print(f"{W}[NO RESPONSE] {url}")
                continue

            if response == "timeout":
                print(f"{W}[TIMEOUT] {url}")
                continue


            suspicious = False
            title = response.text.lower()
            headers = response.headers
            status = response.status_code
            www_auth = str(headers.get("WWW-Authenticate", "")).lower()
            login_keywords = [
                "login",
                "signin",
                "sign-in",
                "auth",
                "authentication",
                "admin",
                "dashboard",
                "portal"
            ]

            # -------------------------
            # Classic HTML login page
            # -------------------------
            if status in [200, 401, 403]:
                if any(keyword in title for keyword in login_keywords):
                    suspicious = True

            # -------------------------
            # HTTP Basic/Digest popup
            # -------------------------
            if "basic" in www_auth or "digest" in www_auth:
                suspicious = True

            # -------------------------
            # Status colors
            # -------------------------
            if status in [200, 401]:
                status_color = R
            elif status == 404:
                status_color = W
            else:
                status_color = Y

            # -------------------------
            # Auth type display
            # -------------------------
            auth_type = ""
            if "basic" in www_auth:
                auth_type = " [HTTP BASIC AUTH]"
            elif "digest" in www_auth:
                auth_type = " [HTTP DIGEST AUTH]"

            print(f"{status_color}[{status}] {W}{url} {G}{'(LOGIN PAGE?)' if suspicious else ''}{C}{auth_type}")
            
            if args.save:
                add_result("Subdomains", {
                    "Type": "http_check",
                        "data": {
                            "subdomain": sub,
                            "url": url,
                            "status": status,
                            "auth": auth_type.strip(),
                            "suspicious": suspicious
                        }
                })
