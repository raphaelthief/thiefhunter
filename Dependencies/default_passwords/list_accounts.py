import csv, yaml, re, html
from pathlib import Path
from tabulate import tabulate
from Dependencies.displays import M, W, R, Y, G, C, handle_error

BASE_DIR = Path(__file__).resolve().parent

TEMPLATES_DIR = BASE_DIR / "data" / "nuclei_templates"
CSV_DIR = BASE_DIR / "data" / "CSV"
EYEWITNESS_FILE = BASE_DIR / "data" / "EyeWitness" / "signatures.txt"

CSV_FILES = [
    CSV_DIR / "defaultcredentials.csv",
    CSV_DIR / "DefaultCreds-Cheat-Sheet.csv",
    CSV_DIR / "many-passwords.csv",
]

BLANK_VALUES = {
    "",
    "<blank>",
    "(blank)",
    "(none)",
    "none",
    "null",
    "no password"
}

CRED_PATTERN = re.compile(r'\b([A-Za-z0-9._-]+):([A-Za-z0-9._-]+)\b')


def highlight_keyword(text, keyword="", color=None):
    text = str(text)
    if not keyword or keyword.casefold() == "all":
        return text

    pattern = re.compile(re.escape(keyword), re.IGNORECASE)
    return pattern.sub(lambda match: f"{R}{match.group(0)}{W}", text)


def clean_signature(value):
    """Convert an EyeWitness signature into readable text."""
    value = html.unescape(value)
    value = re.sub(r"<[^>]+>", " ", value)
    return " ".join(value.split()).strip()


def list_eyewitness_signatures(keyword="All"):
    """Search and display EyeWitness descriptions after the last pipe."""
    if not EYEWITNESS_FILE.is_file():
        print(f"{R}[!] EyeWitness file not found: {W}{EYEWITNESS_FILE}")
        return

    keyword = str(keyword or "All").strip()
    rows = []
    try:
        with EYEWITNESS_FILE.open("r", encoding="utf-8-sig") as stream:
            for raw_line in stream:
                line = raw_line.strip()
                if (not line or line.startswith("#") or "|" not in line):
                    continue

                # Keep only the text after the LAST pipe.
                description = line.rsplit("|", 1)[1].strip()
                if not description:
                    continue

                # Filter results by keyword, case-insensitively.
                if (keyword.casefold() not in ("", "all") and keyword.casefold() not in description.casefold()):
                    continue

                rows.append([
                    highlight_keyword(description, keyword, R)
                    if keyword.casefold() not in ("", "all")
                    else description
                ])

        if not rows:
            print(f"{M}[-] {W}No EyeWitness results found for: {R}{keyword}{W}")
            return

        print(tabulate(rows, headers=[f"{G}EyeWitness — Application / Product & Credentials{W}"], tablefmt="rounded_grid", maxcolwidths=[100]))
        print(f"\n{G}[+] {W}EyeWitness results: {Y}{len(rows)}{W}")

    except OSError as exc:
        print(f"{R}[!] Error reading EyeWitness signatures: {exc}{W}")


def normalize_value(value):
    """Normalize missing credential values without losing original data."""
    if value is None:
        return ""

    value = str(value).strip()
    if value.casefold() in BLANK_VALUES:
        return ""

    return value


def as_list(value):
    """Normalize a YAML payload into a list of strings."""
    if value is None:
        return []

    if isinstance(value, list):
        return [str(item) for item in value]

    return [str(value)]


def extract_payloads(data):
    """Extract username/password payloads from HTTP templates."""
    results = []
    if not isinstance(data, dict):
        return results

    http_blocks = data.get("http", [])
    if isinstance(http_blocks, dict):
        http_blocks = [http_blocks]

    if not isinstance(http_blocks, list):
        return results

    for block in http_blocks:
        if not isinstance(block, dict):
            continue

        payloads = block.get("payloads", {})
        if not isinstance(payloads, dict):
            continue

        usernames = as_list(payloads.get("username"))
        passwords = as_list(payloads.get("password"))
        if usernames or passwords:
            results.append({
                "attack": block.get("attack", "N/A"),
                "usernames": usernames,
                "passwords": passwords,
            })

    return results


def iter_yaml_credentials():
    """Yield credentials extracted from Nuclei YAML templates."""
    if not TEMPLATES_DIR.exists():
        print(f"{M}[-] {W}Directory not found: {TEMPLATES_DIR}")
        return

    files = sorted(path for path in TEMPLATES_DIR.rglob("*") if path.is_file() and path.suffix.lower() in (".yaml", ".yml"))
    print(f"[*] Scanning {len(files)} YAML templates...")
    for file in files:
        try:
            with file.open("r", encoding="utf-8") as stream:
                for data in yaml.safe_load_all(stream):
                    if not isinstance(data, dict):
                        continue

                    info = data.get("info", {})
                    if not isinstance(info, dict):
                        info = {}

                    template_id = str(data.get("id", file.stem))
                    application = str(info.get("name", template_id))
                    for payload in extract_payloads(data):
                        usernames = payload["usernames"] or [""]
                        passwords = payload["passwords"] or [""]
                        for username in usernames:
                            for password in passwords:
                                yield {
                                    "vendor": "",
                                    "product": application,
                                    "category": "nuclei",
                                    "model": "",
                                    "username": normalize_value(username),
                                    "password": normalize_value(password),
                                    "access": str(payload["attack"]),
                                    "source": file.name,
                                    "template_id": template_id,
                                }

        except (OSError, yaml.YAMLError) as exc:
            print(f"{R}[!] Error reading {file.name}: {exc}")


def filter_matching_sources(source, keyword):
    """Return matching source filenames when possible."""
    sources = [
        item.strip()
        for item in source.split(" | ")
        if item.strip()
    ]

    if not keyword or keyword.casefold() == "all":
        return " | ".join(sources) or "-"

    # If the keyword matches a filename, show only those files.
    matches = [
        item for item in sources
        if keyword.casefold() in item.casefold()
    ]

    # If no filename matches, preserve the original sources.
    return " | ".join(matches or sources) or "-"


def get_field(row, *names):
    """Find a CSV column without depending on capitalization."""
    normalized = {
        str(key).strip().casefold(): value
        for key, value in row.items()
        if key is not None
    }

    for name in names:
        value = normalized.get(name.casefold())
        if value is not None:
            return normalize_value(value)

    return ""


def iter_csv_credentials():
    """Read credentials from the supported CSV formats."""
    for file in CSV_FILES:
        if not file.exists():
            print(f"{R}[!] CSV not found: {W}{file}")
            continue

        count = 0
        try:
            with file.open(
                "r",
                encoding="utf-8-sig",
                newline="",
            ) as stream:
                reader = csv.DictReader(stream)

                for row in reader:
                    if not row:
                        continue

                    # defaultcredentials.csv
                    # DefaultCreds-Cheat-Sheet.csv
                    # many-passwords.csv
                    vendor = get_field(row, "vendor", "productvendor")
                    product = get_field(row, "product", "productvendor", "model/software name", "model")
                    model = get_field(row, "model/software name", "model")
                    username = get_field(row, "username")
                    password = get_field(row, "password")

                    # Skip records that do not contain credentials.
                    if not username and not password:
                        continue

                    yield {
                        "vendor": vendor,
                        "product": product or vendor or file.stem,
                        "category": get_field(row, "category"),
                        "model": model,
                        "username": username,
                        "password": password,
                        "access": get_field(
                            row, "access", "access type"
                        ),
                        "source": f"{file.name}",
                        "template_id": "",
                    }
                    count += 1

            print(f"{W}[*] Read {file.name}: {count} credential rows")

        except (OSError, csv.Error) as exc:
            print(f"{R}[!] Error reading {file.name}: {exc}{W}")


def credential_key(record):
    """
    Deduplicate actual credential pairs globally.

    Entries without credentials must remain distinct per product.
    """
    username = record["username"].casefold()
    password = record["password"].casefold()
    if not username and not password:
        return (record["category"].casefold(), record["product"].casefold(), username, password)

    return (username, password)




def load_all_credentials():
    """Merge YAML, CSV and EyeWitness credentials."""
    unique = {}
    duplicates = 0

    sources = (iter_yaml_credentials, iter_csv_credentials)
    for source_iterator in sources:
        for record in source_iterator():
            key = credential_key(record)
            if key in unique:
                duplicates += 1

                # Preserve additional source information.
                existing = unique[key]
                existing_sources = existing["source"].split(" | ")
                if record["source"] not in existing_sources:
                    existing["source"] += " | " + record["source"]

                continue

            unique[key] = record

    print(f"{W}[*] Unique credential pairs: {len(unique)}")
    print(f"{W}[*] Duplicate rows skipped: {duplicates}")
    return list(unique.values())


def display_value(value):
    """Display an empty credential explicitly."""
    return value if value else "<blank>"


def list_default_credentials():
    """List all unique credentials from every source."""
    records = load_all_credentials()

    if not records:
        print(f"{W}[*] No credentials found.")
        return

    rows = [
        [
            record["vendor"] or "-",
            record["product"],
            record["username"] and display_value(record["username"])
            or "<blank>",
            display_value(record["password"]),
            record["access"] or "-",
            record["source"],
        ]
        for record in records
    ]

    print(tabulate(
        rows,
        headers=[
            "Vendor",
            "Application / Product",
            "Username",
            "Password",
            "Access",
            "Source",
        ],
        tablefmt="rounded_grid",
        maxcolwidths=[22, 32, 25, 40, 15, 35]
    ))
    
    print(f"\n{G}[+] {W}Unique credential pairs: {len(records)}")


def _eyewitness_credentials(keyword=""):
    """Yield (username, password) pairs from EyeWitness matching the keyword."""
    if not EYEWITNESS_FILE.is_file():
        return

    keyword = keyword.strip().casefold()
    with EYEWITNESS_FILE.open("r", encoding="utf-8-sig") as stream:
        for raw_line in stream:
            line = raw_line.strip()
            if not line or line.startswith("#") or "|" not in line:
                continue

            description = line.rsplit("|", 1)[1].strip()
            if not description:
                continue

            if keyword and keyword not in ("all",) and keyword not in description.casefold():
                continue

            clean = clean_signature(description)
            for match in CRED_PATTERN.finditer(clean):
                user = normalize_value(match.group(1))
                pwd = normalize_value(match.group(2))
                if user or pwd:
                    yield user, pwd


def save_credentials_wordlist(records, keyword, args):
    if args.batch:
        print(f"\n{W}[*] Batch mode, skip saving wordlist mode")
        return
        
    answer = input(f"\n{Y}[?] {W}Do you want to save the wordlist in username:password format? (y/n): ").strip().casefold()
    if answer not in ("y", "yes"):
        print(f"{M}[-] {W}Wordlist not saved.")
        return

    filename = keyword + "_wordlist.txt"
    try:
        output_path = Path(filename)
        written = set()
        count = 0
        with output_path.open("w", encoding="utf-8", newline="\n") as stream:
            for record in records:
                username = record["username"]
                password = record["password"]
                if not username and not password:
                    continue
                pair = f"{username}:{password}"
                if pair in written:
                    continue
                written.add(pair)
                stream.write(pair + "\n")
                count += 1

            for username, password in _eyewitness_credentials(keyword):
                pair = f"{username}:{password}"
                if pair in written:
                    continue
                written.add(pair)
                stream.write(pair + "\n")
                count += 1

        print(f"{G}[+] {W}Wordlist saved to: {Y}{output_path.resolve()}{W}")
        print(f"{G}[+] {W}Credentials written: {Y}{count}{W}")
    except OSError as exc:
        print(f"{R}[!] Error saving wordlist: {exc}{W}")


def search_default_credentials(args, keyword="All"):
    """Search merged credentials by product, source or credential."""
    records = load_all_credentials()
    keyword = keyword.strip().casefold()

    if keyword in ("", "all"):
        matches = records
    else:
        matches = [
            record
            for record in records
            if keyword in " ".join([
                record["vendor"],
                record["product"],
                record["category"],
                record["model"],
                record["username"],
                record["password"],
                record["access"],
                record["source"],
                record["template_id"],
            ]).casefold()
        ]

    if not matches:
        print(f"{M}[-] {W}No results found for: {R}{keyword}{W}")
        return

    rows = [
        [
            highlight_keyword(record["vendor"] or "-", keyword),
            highlight_keyword(record["product"], keyword),
            highlight_keyword(
                display_value(record["username"]), keyword, Y
            ),
            highlight_keyword(
                display_value(record["password"]), keyword, Y
            ),
            highlight_keyword(record["access"] or "-", keyword),
            highlight_keyword(filter_matching_sources(record["source"], keyword), keyword),
        ]
        for record in matches
    ]

    print(tabulate(
        rows,
        headers=[
            f"{G}Vendor{W}",
            f"{G}Application / Product{W}",
            f"{G}Username{W}",
            f"{G}Password{W}",
            f"{G}Access{W}",
            f"{G}Source{W}",
        ],
        tablefmt="rounded_grid",
        maxcolwidths=[22, 32, 25, 40, 15, 35],
        disable_numparse=True
    ))

    list_eyewitness_signatures(keyword)
    print(f"{G}[+] {W}Other: {Y}{len(matches)}{W}")
    save_credentials_wordlist(matches, keyword, args)