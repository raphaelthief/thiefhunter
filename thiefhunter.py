import argparse, sys, json, re, signal, base64, io
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import redirect_stdout
from Dependencies.displays import isargsok, clear_screen, print_banner, help_menu, no_clean, M, W, R, Y, G, C, highlight, handle_error, init_env_file
from Dependencies.url_parse import extract_domain, extract_strictdomain, extract_params
from Dependencies.JWT.jwt_parser import analyze_jwt, print_jwt_analysis, is_jwt
from Dependencies.JWT.jwt_payload import JWTPlayground
from Dependencies.CrawlURLS.wayback import wayback_urls
from Dependencies.CrawlURLS.crawl import crawl_extractit
from Dependencies.CrawlURLS.wtf_scan import wtf_scan, is_personal_email, is_sensitive_url
from Dependencies.Versions_detection.headers import extract_headers
from Dependencies.Versions_detection.source import extract_assets_tech
from Dependencies.Versions_detection.wordpress_vuln_displayer import extract_wordpress
from Dependencies.Versions_detection.CVE_vuln_displayer import is_there_a_vuln, scan_all_versions
from Dependencies.Subdomains.subdomains import get_subdomains, is_reverse_proxy
from Dependencies.Traversal.traversal import detect_os_from_headers, crawl_extract, test_traversal
from Dependencies.Open_redirect.openredirect import run_openredirect
from Dependencies.get_request import ensure_tor_or_exit, resolve_ip
from Dependencies.Audit.basic_checks import auditor
from Dependencies.Audit.ssl_checks import ssl_that
from Dependencies.crlf.crlf_headers import crlf_test
from Dependencies.waf_detection.waf_detect import whatwaf
from Dependencies.github_commits.commits import repos
from Dependencies.TLD.tld_enum import tld_main
from Dependencies.dir_enum.dir_files_scan import do_fuzz_paths
from Dependencies.do403_bypass.fuzzer_403 import do_403


def handle_exit(sig, frame):
    print(f"\n{R}[!] Ctrl+C detected, closing...")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_exit)


def process_target(args, target_url):
    local_args = argparse.Namespace(**vars(args))
    local_args.url = target_url
    
    if local_args.file:
        print(f"\n{Y}{'='*60}")
        print(f"{G}[TARGET] {W}{local_args.url}")
        print(f"{Y}{'='*60}\n")


    # -------------------------
    # JWT Tokens
    # -------------------------
    if args.jwt:
        if not is_jwt(args.jwt):
            handle_error("Invalid JWT format", "ERROR")
            return
        analyze_jwt(args.jwt)
        pg = JWTPlayground(args.jwt)
        
        try:
            pg = JWTPlayground(args.jwt)
        except ValueError as e:
            handle_error(e, "ERROR", args.verbose)
            return
        
        tests = pg.generate()
        for t in tests:
            print(f"{G}[*] {t.name}{W}")
            print(
                f"{Y}[signature] "
                f"{t.signature_status}{W}"
            )

            print(t.token)
            print()

    # -------------------------
    # GITHUB COMMITS
    # -------------------------
    if local_args.commits:
        repos(args, local_args.commits)


    # -------------------------
    # Wayback URLs
    # -------------------------
    if local_args.exclude:
        isargsok(local_args, "need_wayback_or_extract")

    if local_args.show_all:
        isargsok(local_args, "need_wayback_or_extract")

    if local_args.wayback:
        if isargsok(local_args, "need_url"):
            extracted_domain = extract_domain(local_args.url)
            exclude_ext = None
            if local_args.exclude:
                exclude_ext = [
                    f".{ext.strip().lower().lstrip('.')}"
                    for ext in local_args.exclude.split(",")
                ]

            wayback_output, total, filtered = wayback_urls(extracted_domain, exclude_ext=exclude_ext, show_all=local_args.show_all)
            for i, url in enumerate(wayback_output, 1):
                print(f"{G}[{i:04}] {W}{url}")

            print(f"\n{G}[+] Found {len(wayback_output)} URLs")
            print(f"{G}[*] {filtered} URLs filtered (assets / no params / excluded)")


    # -------------------------
    # Crawl URLs with parameters
    # -------------------------
    if local_args.extract:
        if isargsok(local_args, "need_url"):
            exclude_ext = None
            if local_args.exclude:
                exclude_ext = [
                    f".{ext.strip().lower().lstrip('.')}"
                    for ext in local_args.exclude.split(",")
                ]
                
            print(f"{C}[!] {G}Crawling with depth {local_args.extract}")
            crawl_extractit(local_args, local_args.url, max_depth=local_args.extract, exclude_ext=exclude_ext, show_all=local_args.show_all)




    # -------------------------
    # Search for URLs, API, emails, phones, conf files
    # -------------------------
    if local_args.wtf:
        if isargsok(local_args, "need_url"):
            print(f"{C}[!] {G}Running WTF scan (depth={local_args.wtf})")
            data = wtf_scan(local_args.url, local_args, max_depth=local_args.wtf)

            if data["emails"]:
                print(f"{G}[+] Emails")
                extracted_domain = extract_strictdomain(local_args.url)
                for e in data["emails"]:
                    if is_personal_email(e, extracted_domain):
                        print(f"{G}    - {highlight(e, R)}")
                    else:
                        print(f"{G}    - {W}{e}")
                print()

            if data["phones"]:
                print(f"{G}[+] Phones (FR - 06 / 07)")
                for p in data["phones"]:
                    print(f"{G}    - {W}{p}")
                print()

            if data["secrets"]:
                print(f"{G}[+] Secrets")
                for s in data["secrets"]:
                    print(f"{G}    - {W}{s}")
                print()

            if data["robots"]:
                print(f"{G}[+] robots.txt - Disallowed")
                for r in data["robots"]:
                    if is_sensitive_url(r):
                        print(f"{G}    - {highlight(r, R)}")
                    else:
                        print(f"{G}    - {W}{r}")
                print()

            if data["subdomains"]:
                print(f"{G}[+] Detected subdomains")
                for r in data["subdomains"]:
                    print(f"{G}    - {W}{r}")
                print()

            if data["apis"]:
                print(f"{G}[+] APIs")
                for r in data["apis"]:
                    if is_sensitive_url(r):
                        print(f"{G}    - {highlight(r, R)}")
                    else:
                        print(f"{G}    - {W}{r}")
                print()
                
            if data["sensitive_keywords"]:
                print(f"{G}[+] Sensitive keywords")

                for key, values in data["sensitive_keywords"].items():
                    for v in values:
                        print(f"{G}    -{W} ...{v}...")
                print()

            if data["sensitive_urls"]:
                print(f"{G}[+] Sensitive urls")
                for r in data["sensitive_urls"]:
                    if is_sensitive_url(r):
                        print(f"{G}    - {highlight(r, R)}")
                    else:
                        print(f"{G}    - {W}{r}")
                print()

            if not any(data.values()):
                print(f"{R}[-] Nothing found")


    # -------------------------
    # Search for versions and associated CVE and exploits
    # -------------------------
    if local_args.vuln:
        if isargsok(local_args, "need_url"):
            seen_headers = set()
            seen_all = set()
            versions_list = []
            def normalize(name):
                return re.sub(r"[^a-z0-9]", "", name.lower())

            def is_valid_version(version): # allow: 1.2 - 1.2.3 - 4.9.7.2
                return bool(re.fullmatch(r"\d+(?:\.\d+){1,4}", version))

            print(f"\n{C}[+] Versions and vulnerabilities detection")
            techs = extract_headers(local_args, local_args.url)
            if techs:
                print(f"{G}[+] Headers detection")
                for t in techs:
                    tech_name = t["tech"]
                    version = t["version"]
                    full = f"{tech_name} {version}" if version else tech_name
                    key = normalize(full)
                    if key not in seen_all:
                        seen_all.add(key)
                        seen_headers.add(key)
                        print(f"    {G}- {highlight(full, Y)}")

                    if version and is_valid_version(version):
                        versions_list.append({
                            "name": tech_name,
                            "version": version
                        })
                print()
                
            tech = extract_assets_tech(local_args, local_args.url)
            if tech:
                print(f"{G}[+] Assets detection")
                for name, version in tech:
                    full = f"{name} {version}".strip() if version else name
                    key = normalize(full)
                    if key in seen_headers:
                        continue

                    if key not in seen_all:
                        seen_all.add(key)
                        print(f"    {G}- {highlight(full, Y)}")
                        versions_list.append({
                            "name": name,
                            "version": version
                        })
        filtered = [
            item for item in versions_list
            if item.get("version") and item["version"].strip()
        ]
        extract_wordpress(filtered, local_args)
        versions_dict = {
            local_args.url: {
                item["name"]: {"version": item["version"]}
                for item in filtered
            }
        }
        is_there_a_vuln(versions_dict, local_args)


    # -------------------------
    # Search specific vuln
    # -------------------------
    if local_args.exploit_search:
        print(f"\n{C}[+] Search-vulns scan")
        scan_all_versions(local_args.exploit_search, local_args)

    # -------------------------
    # Audit (basic checks)
    # -------------------------
    if local_args.audit:
        if isargsok(local_args, "need_url"):
            auditor(local_args)
            extracted_domain = extract_strictdomain(local_args.url)
            ssl_that(extracted_domain, local_args)
            ip = resolve_ip(local_args, extracted_domain)
            if ip:
                ip_b64 = base64.b64encode(ip.encode("utf-8"))
                print(f"{Y}\n[!] {G}Interesting urls to visit")
                print(f" {G}- {W}https://www.shodan.io/host/{ip}")
                print(f' {G}- {W}https://platform.censys.io/search?q=host.ip%3D"{ip}"')
                print(f" {G}- {W}https://en.fofa.info/result?qbase64={ip_b64}%3D")
                print(f" {G}- {W}https://www.virustotal.com/gui/ip-address/{ip}/details")


    # -------------------------
    # Subdomains
    # -------------------------
    if local_args.subdomains:
        if isargsok(local_args, "need_url"):
            extracted_domain = extract_strictdomain(local_args.url)
            get_subdomains(local_args, extracted_domain)


    # -------------------------
    # Directory and files enum
    # -------------------------
    if local_args.dir:
        if isargsok(local_args, "need_url"):
            do_fuzz_paths(local_args)


    # -------------------------
    # 403 bypass
    # -------------------------
    if local_args.bypass_403:
        if isargsok(local_args, "need_url"):
            do_403(local_args)

    # -------------------------
    # Path traversal
    # -------------------------
    if local_args.traversal:
        if isargsok(local_args, "need_url"):
            OS_type = detect_os_from_headers(local_args, local_args.url)
            parsed = extract_params(local_args.url)
            if parsed["params"]:
                print(f"{Y}[!] {W}Endpoint detected: {parsed['params']}")
                for param in parsed["params"]:
                    print(f"{Y}[*] {W}Testing param: {param}")
                    test_traversal(local_args, parsed["base"], param, OS_type)
            else:
                print(f"{R}[-] {W}No endpoint found in URL, starting crawl...")
                endpoints = crawl_extract(local_args, local_args.url, max_depth=2)
                if not endpoints:
                    print(f"{R}[-] {W}No endpoints discovered during crawl")
                for ep_base, data in endpoints.items():
                    params = data["params"]
                    print(f"{G}[+] {W}Endpoint: {ep_base} -> params: {params}")
                    examples = data.get("examples", {})
                    for param in params:
                        example_url = examples.get(param, ep_base)
                        print(f"{G}[*] {W}Testing crawled param: {param} -> {example_url}")
                        test_traversal(
                            local_args,
                            example_url,
                            param,
                            OS_type
                        )


    # -------------------------
    # Open redirect
    # -------------------------
    if local_args.open_redirect:
        if isargsok(local_args, "need_url"):
            run_openredirect(local_args)


    # -------------------------
    # CRLF
    # -------------------------
    if local_args.crlf:
        if isargsok(local_args, "need_url"):
            crlf_test(local_args)


    # -------------------------
    # WAF
    # -------------------------
    if local_args.waf:
        if isargsok(local_args, "need_url"):
            whatwaf(local_args)


    # -------------------------
    # TLD enum
    # -------------------------
    if local_args.tld:
        if isargsok(local_args, "need_url"):
            tld_main(local_args)




def main():
    parser = argparse.ArgumentParser(description="Automated Bug Hunting and Pentesting Tool")
    parser.add_argument("-hh", action="store_true", help="Show full help menu")
    parser.add_argument("-nc", "--no-clean", action="store_true", help="Do not clean the CLI")
    parser.add_argument("--jwt", help="Check JWT Bearer Token (--jwt JWT_TOKEN)")
    parser.add_argument("-u", "--url", help="Target URL to scan")
    parser.add_argument("-f", "--file", help="Targets URL to scan from file")
    parser.add_argument("--random-headers", action="store_true", help="Use random User-Agent for each requests from the header file (paylaods) instead of default one")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable Verbose mode")
    parser.add_argument("-p", "--proxy", help="Custom proxy (--proxy http://user:pass@host:port)")
    parser.add_argument("--tor", action="store_true", help="Force use of Tor SOCKSH proxy (127.0.0.1:9050)")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    parser.add_argument("--headers", help='Custom headers as JSON string (--headers "Accept=application/json,Authorization=Bearer TOKEN")')
    parser.add_argument("-c", "--cookies", help='Cookies as JSON string (--cookies "session=abc123; token=xyz789")')
    parser.add_argument("-X", "--method", default="GET", choices=["GET", "POST", "PUT", "DELETE"], help="HTTP method (default: GET)")
    parser.add_argument("-e", "--extract", type=int, help="Crawl and extract URLs with parameters (--extract 2)")
    parser.add_argument("-w", "--wayback", action="store_true", help="Extract Wayback Machine URLs")
    parser.add_argument("--exclude", help="Exclude extensions from --wayback (comma separated, e.g: png,jpg,css,js)")
    parser.add_argument("--show-all", action="store_true", help="Show all URLs from --wayback (default = only URLs with parameters)")
    parser.add_argument("--wtf", type=int, help="Deep scan: extract emails, phones, secrets + robots.txt (--wtf 3)")
    parser.add_argument("--vln", "--vuln", dest="vuln", action="store_true", help="Detect vulnerable versions and associated CVE and exploits")
    parser.add_argument("--dir", type=int, choices=[1, 2, 3, 4], default=None, help="Directory fuzzing level (1=Low 2=Moderate 3=Medium 4=High)")
    parser.add_argument("--exp", "--exploit-search", dest="exploit_search", help='Search exploit from technologie and version (--exploit-search "PHP 8.1" or --exploit-search CVE-2026-8838 or --exploit-search cpe:2.3:a:sudo_project:sudo:1.8.2:*:*:*:*:*:*:*)')
    parser.add_argument("--audit", action="store_true", help="Perform basic checks on missing headers and configurations")
    parser.add_argument("--sub", "--subdomains", dest="subdomains", action="store_true", help="Detect target subdomains (DNSDumpster, VirusTotal API key needed)")
    parser.add_argument("--tld", action="store_true", help="Detect new dns extension target (target.to becoming target.cz for exemple")
    parser.add_argument("--trav", "--traversal", dest="traversal", action="store_true", help="Try path traversal on specific endpoint (https://site.com/?endpoint=exemple) or find one by auto crawling (depth set to 2)")
    parser.add_argument("--ord", "--open-redirect", dest="open_redirect", action="store_true", help="Try open redirect on specific endpoint (https://site.com/?endpoint=exemple) or find one by auto crawling (depth set to 2)")
    parser.add_argument("--crlf", action="store_true", help="Try to detect crlf injections")
    parser.add_argument("--waf", action="store_true", help="Try to detect WAF application")
    parser.add_argument("--bypass-403", action="store_true", help="Attempt 403 bypass techniques")
    parser.add_argument("--batch", action="store_true", help="Never ask for user input, use the default behavior")
    parser.add_argument("--commits", help="Found related emails from Github commits (--commits <GITHUB_USERNAME>")
    
    args = parser.parse_args()
    
    
    # -------------------------
    # Forms & params
    # -------------------------
    if len(sys.argv) == 1:
        clear_screen()
        print_banner()
        parser.print_usage()
        sys.exit()

    no_clean(args)
    print(f"{Y}[!] {C}Command: {G}{' '.join(sys.argv)}")

    init_env_file(args)

    # -------------------------
    # Full help menu
    # -------------------------
    if args.hh:
        print(help_menu)
        exit(0)


    # -------------------------
    # Tor check
    # -------------------------
    if args.tor:
       ensure_tor_or_exit()

    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                targets = [
                    line.strip()
                    for line in f
                    if line.strip()
                ]
        except Exception as e:
            print(f"{R}[-] Cannot read file: {e}")
            sys.exit(1)

        # -------------------------
        # Sequential mode
        # -------------------------
        for target in targets:
            if not target.startswith(("http://", "https://")):
                print(f"{R}[-] Invalid URL: {target}")
                continue

            try:
                process_target(args, target)
            except KeyboardInterrupt:
                raise
                
            except Exception as e:
                print(f"{R}[-] Error with {target}: {e}")

        print(f"\n{Y}[!] {W}End of multi-target scan")
        
    else:
        
        # -------------------------
        # Single mode
        # -------------------------
        process_target(args, args.url)
        print(f"\n{Y}[!] {W}End of search")


if __name__ == "__main__":
    main()
