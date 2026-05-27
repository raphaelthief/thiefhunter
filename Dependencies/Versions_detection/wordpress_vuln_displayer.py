import os, time, json, requests
from pathlib import Path
from packaging.version import Version, InvalidVersion
from Dependencies.displays import M, W, R, Y, G, C, handle_error
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("WORDFENCE_API_KEY")

BASE_DIR = Path(__file__).resolve().parent
VULN_DB_PATH = BASE_DIR / "wp_vulns.json"

VULN_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"
CACHE_TTL = 86400  # 24h


def load_vuln_db():
    def download_db(token):
        headers = {"Authorization": f"Bearer {token}"}
        r = requests.get(
            VULN_URL,
            headers=headers,
            timeout=60,
            verify=False
        )
        r.raise_for_status()
        VULN_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(VULN_DB_PATH, "wb") as f:
            f.write(r.content)

    # =====================================================
    # CASE 1 — NO TOKEN
    # =====================================================
    if not API_KEY:
        handle_error("No Wordfence token found → using local DB only", "WARNING")
        if not VULN_DB_PATH.exists():
            handle_error("No local DB found → skipping WordPress vulnerability checks", "WARNING")
            return None

        with open(VULN_DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)

    # =====================================================
    # CASE 2 — UPDATE DB
    # =====================================================
    try:
        if (
            not VULN_DB_PATH.exists()
            or (time.time() - VULN_DB_PATH.stat().st_mtime) > CACHE_TTL
        ):
            print(f"\n{Y}[!] {W}Updating Wordfence DB...")
            download_db(API_KEY)
    except Exception as e:
        handle_error(e, "ERROR")

    # =====================================================
    # LOAD LOCAL DB
    # =====================================================
    if not VULN_DB_PATH.exists():
        handle_error("No DB available → skipping WordPress checks", "WARNING")
        return None

    with open(VULN_DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)
    

def is_version_affected(version, affected_versions):
    try:
        current = Version(str(version))
    except InvalidVersion:
        return False

    for _, rule in affected_versions.items():
        from_v_raw = rule.get("from_version")
        to_v_raw = rule.get("to_version")
        from_inclusive = rule.get("from_inclusive", True)
        to_inclusive = rule.get("to_inclusive", True)

        # =====================================================
        # HANDLE *
        # =====================================================

        from_v = None
        to_v = None
        try:
            if from_v_raw and from_v_raw != "*":
                from_v = Version(str(from_v_raw))

            if to_v_raw and to_v_raw != "*":
                to_v = Version(str(to_v_raw))
        except InvalidVersion:
            continue

        # =====================================================
        # CHECK LOWER BOUND
        # =====================================================

        if from_v:
            if from_inclusive:
                if current < from_v:
                    continue
            else:
                if current <= from_v:
                    continue

        # =====================================================
        # CHECK UPPER BOUND
        # =====================================================

        if to_v:
            if to_inclusive:
                if current > to_v:
                    continue
            else:
                if current >= to_v:
                    continue
        return True
    return False
    
def scan_versions(versions_list, vulns_data, args):
    # versions_list = [{"name": "...", "version": "..."}]
    found = False
    print(f"\n{C}[+] Wordpress vulnerability scan (Wordfense DB)")

    # filter valid versions only
    items = [
        v for v in versions_list
        if v.get("version") and v["version"].strip()
    ]

    if not items:
        print(f"{M}[-] {W}No valid versions found")
        return

    for item in items:
        name = item["name"]
        version = item["version"]
        print(f"{G}[+] {name} {R}{version}")
        vuln_found = False
        for vuln in vulns_data.values():
            for software in vuln.get("software", []):
                if software.get("slug", "").lower() != name.lower():
                    continue

                affected = software.get("affected_versions", {})
                if is_version_affected(version, affected):
                    found = True
                    vuln_found = True
                    print(
                        f" {Y}| [!] {G}{vuln['title']}\n"
                        f" {Y}|   {G}Description : {W}{vuln['description'][:100]}...\n"
                        f" {Y}|   {G}CVSS        : {W}{vuln['cvss']['score']} ({vuln['cvss']['rating']})\n"
                        f" {Y}|   {G}Reference   : {W}{vuln['references'][0]}\n"
                    )
        
        if not vuln_found:
            print(f" {Y}| {M}[-] {W}No vulnerabilities found\n")

    if not found:
        print(f"{Y}[!] {W}No wordpress vulnerabilities detected in target")

def extract_wordpress(versions_list, args):
    vulns_data = load_vuln_db()
    if not vulns_data:
        print(f"{Y}[!] {W}WordPress vulnerability checks skipped (no DB available)")
        return

    try:
        scan_versions(versions_list, vulns_data, args)
    except Exception as e:
        handle_error(e, "ERROR")
