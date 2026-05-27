import requests, time, os
from Dependencies.displays import M, W, R, Y, G, C, handle_error
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("SEARCH_VULNS_API_KEY")
URL = "https://search-vulns.com/api/search-vulns"
delay=2.5 # Cooldown


def is_there_a_vuln(versions_data, args):
    print(f"\n{C}[+] Search-vulns scan")
    if isinstance(versions_data, dict):
        # {url: {tech: {version}}}
        flat_list = []
        for _, techs in versions_data.items():
            for name, data in techs.items():
                if isinstance(data, dict):
                    flat_list.append({
                        "name": name,
                        "version": data.get("version")
                    })
        versions_list = flat_list

    elif isinstance(versions_data, list):
        versions_list = versions_data
    else:
        print(f"{Y}[!] invalid input format")
        return
    
    
    seen = set()
    for item in versions_list:
        if not isinstance(item, dict):
            continue

        name = item.get("name")
        version = item.get("version")
        if not name or not version:
            continue
            
        if not version:
            return

        key = f"{name}:{version}"
        if key in seen:
            continue

        seen.add(key)
        try:
            query = f"{name} {version}"
            scan_all_versions(query, args)
        except Exception as e:
            print(f"{Y}[!] {G}error scanning {key}: {e}")
        time.sleep(delay)


def scan_all_versions(query, args):
    params = {
        "query": query,
        "ignore-general-product-vulns": "true",
        "include-single-version-vulns": "true",
        "is-good-product-id": "true",
        "include-patched": "false",
        "use-created-product-ids": "false"
    }

    headers = {
        "accept": "application/json",
        "API-Key": API_KEY
    }

    response = requests.get(
        URL,
        params=params,
        headers=headers,
        timeout=15
    )

    print(f"{G}[+] {C}{query}")
    print(f"{Y}-" * 40)

    data = response.json()
    vulns = data.get("vulns", {})

    # -----------------------------
    # PRODUCT IDS / CPE
    # -----------------------------
    product_ids = data.get("product_ids", {})
    cpes = product_ids.get("cpe", [])

    if cpes:
        print(f" {Y}| {G}CPE  : {W}{cpes[0]}")
    else:
        print(f" {Y}| {G}CPE  : {W}N/A")

    # -----------------------------
    # VERSION STATUS / EOL
    # -----------------------------
    version_status = data.get("version_status", {})

    latest = version_status.get("latest", "unknown")
    status = version_status.get("status", "unknown")
    reference = version_status.get("reference", "")

    status_color = (
        R if status.upper() == "EOL"
        else Y if status.upper() in ["OUTDATED", "DEPRECATED"]
        else G
    )

    print(
        f" {Y}| {G}STATUS : {W}{status_color}{status}\n"
        f" {Y}| {G}LATEST : {W}{latest}"
    )

    if reference:
        print(f" {Y}| {G}EOL URL: {W}{reference}")

    print(f"{Y}-" * 40)

    if not vulns:
        print(f" {Y}| {M}[-] {W}No vulnerabilities found\n")
        return

    sorted_vulns = sorted(
        vulns.items(),
        key=lambda x: float(
            x[1].get("severity", {})
            .get("CVSS", {})
            .get("score", 0)
        ),
        reverse=True
    )

    for cve_id, v in sorted_vulns:

        cvss = v.get("severity", {}).get("CVSS", {})
        epss = v.get("severity", {}).get("EPSS", {})

        score = cvss.get("score")

        try:
            score = float(score)
        except (TypeError, ValueError):
            score = None

        color = (
            R if score is not None and score >= 8 else
            Y if score is not None and score >= 5 else
            G
        )

        print(
            f" {Y}| [!] {R}{cve_id}\n"
            f" {Y}|   {G}CVSS : {W}{color}{score if score is not None else 'N/A'}\n"
            f" {Y}|   {G}EPSS : {W}{epss.get('score', 'N/A')}\n"
            f" {Y}|   {G}KEV  : {W}{f'{R}YES' if v.get('cisa_kev') else 'no'}\n"
            f" {Y}|   {G}MATCH: {W}{v.get('match_reason', 'unknown')}\n"
            f" {Y}|   {G}INFO : {W}{v.get('description', '')[:300]}..."
        )

        exploits = v.get("exploits", [])
        if exploits:
            print(f" {Y}| [!] {R}Exploits")

            for e in exploits:
                print(f" {Y}|     {G}- {W}{e}")
        print()
    print(f"{Y}-" * 40)