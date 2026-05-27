import requests, os, time
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed
from Dependencies.displays import M, W, R, Y, G, C, handle_error
from Dependencies.get_request import get_request

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

            response = get_request(args, url, timeout=30)
            
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
    if not API_KEY:
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

    print()
    # -------------------------
    # RETURN DEDUPED LIST (BY ORDER)
    # -------------------------
    return list(results.values())