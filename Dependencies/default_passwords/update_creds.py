import time
import hashlib
import requests
from pathlib import Path
from tqdm import tqdm
from Dependencies.displays import M, W, R, Y, G, C, handle_error

BASE_DIR = Path(__file__).resolve().parent

TEMPLATES_DIR = BASE_DIR / "data" / "nuclei_templates"
DATASETS_DIR_CSV = BASE_DIR / "data" / "CSV"

EYEWITNESS_DIR = BASE_DIR / "data" / "EyeWitness"
EYEWITNESS_URL = (
    "https://raw.githubusercontent.com/"
    "RedSiege/EyeWitness/master/Python/signatures.txt"
)

CHECKSUM_URL = (
    "https://raw.githubusercontent.com/"
    "projectdiscovery/nuclei-templates/main/templates-checksum.txt"
)
RAW_BASE = (
    "https://raw.githubusercontent.com/"
    "projectdiscovery/nuclei-templates/main/http/default-logins/"
)
TARGET_PREFIX = "http/default-logins/"

CSV_SOURCES = {
    "many-passwords.csv": (
        "https://raw.githubusercontent.com/"
        "many-passwords/many-passwords/main/passwords.csv"
    ),
    "DefaultCreds-Cheat-Sheet.csv": (
        "https://raw.githubusercontent.com/"
        "ihebski/DefaultCreds-cheat-sheet/main/"
        "DefaultCreds-Cheat-Sheet.csv"
    ),
    "defaultcredentials.csv": (
        "https://www.defaultcredentials.org/"
        "api/export?format=csv"
    ),
}

session = requests.Session()
session.headers.update({"User-Agent": "ThiefHunter"})


# UTILITIES
def sha256_content(content):
    return hashlib.sha256(content).hexdigest()


def sha1_file(path):
    digest = hashlib.sha1()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


# CSV DATASETS
def update_csv_datasets():
    DATASETS_DIR_CSV.mkdir(parents=True, exist_ok=True)
    stats = {
        "downloaded": 0,
        "updated": 0,
        "unchanged": 0,
        "failed": [],
    }

    print(f"\n{Y}[1/3] {W}UPDATING CSV DATASETS")
    for filename, url in CSV_SOURCES.items():
        destination = DATASETS_DIR_CSV / filename
        temp_path = destination.with_suffix(destination.suffix + ".tmp")
        try:
            response = session.get(url, timeout=60)
            response.raise_for_status()
            content = response.content
            if not content:
                raise ValueError("Empty response")

            if destination.exists():
                local_hash = sha256_content(destination.read_bytes())
                remote_hash = sha256_content(content)
                if local_hash == remote_hash:
                    stats["unchanged"] += 1
                    print(f"{W}[*] Unchanged: {filename}")
                    continue

                status = "updated"
            else:
                status = "downloaded"

            try:
                temp_path.write_bytes(content)
                temp_path.replace(destination)
            finally:
                if temp_path.exists():
                    temp_path.unlink()

            stats[status] += 1
            print(f"{G}[+] {W}{status.capitalize()}: {filename}")

        except (requests.RequestException, OSError, ValueError) as exc:
            stats["failed"].append((filename, str(exc)))
            print(f"{R}[-] Failed: {filename}: {exc}{W}")

    return stats


# EYEWITNESS DATASETS
def update_eyewitness_signatures():
    EYEWITNESS_DIR.mkdir(parents=True, exist_ok=True)

    filename = "signatures.txt"
    destination = EYEWITNESS_DIR / filename
    temp_path = destination.with_suffix(".txt.tmp")

    stats = {
        "downloaded": 0,
        "updated": 0,
        "unchanged": 0,
        "failed": [],
    }

    print(f"\n{Y}[2/3] {W}UPDATING EYEWITNESS SIGNATURES")

    try:
        response = session.get(EYEWITNESS_URL, timeout=60)
        response.raise_for_status()
        content = response.content

        if not content:
            raise ValueError("Empty response")

        if destination.exists():
            local_hash = sha256_content(destination.read_bytes())
            remote_hash = sha256_content(content)

            if local_hash == remote_hash:
                stats["unchanged"] += 1
                print(f"{W}[*] Unchanged: {filename}")
                return stats

            status = "updated"
        else:
            status = "downloaded"

        try:
            temp_path.write_bytes(content)
            temp_path.replace(destination)
        finally:
            if temp_path.exists():
                temp_path.unlink()

        stats[status] += 1
        print(f"{G}[+] {W}{status.capitalize()}: {filename}")

    except (requests.RequestException, OSError, ValueError) as exc:
        stats["failed"].append((filename, str(exc)))
        print(f"{R}[-] Failed: {filename}: {exc}{W}")

    return stats


# NUCLEI TEMPLATES
def get_remote_checksums():
    response = session.get(CHECKSUM_URL, timeout=60)
    response.raise_for_status()
    checksums = {}
    for line in response.text.splitlines():
        if ":" not in line:
            continue

        path, checksum = line.rsplit(":", 1)
        if path.startswith(TARGET_PREFIX):
            relative_path = path[len(TARGET_PREFIX):]
            checksums[relative_path] = checksum.strip()

    return checksums


def update_templates():
    stats = {
        "new": 0,
        "updated": 0,
        "failed": [],
        "obsolete": 0,
        "skipped": False,
        "duration": 0.0,
    }

    start = time.time()

    try:
        print(f"\n{Y}[3/3] {W}UPDATING NUCLEI TEMPLATES")
        print(f"{W}[*] Fetching remote checksums...")
        remote = get_remote_checksums()
        if not remote:
            print(f"{R}[-] No remote checksums found. Aborting{W}")
            stats["failed"].append(("checksums", "No remote checksums found"))
            return stats

        # Index existing local templates by their relative path.
        existing = {}

        if TEMPLATES_DIR.is_dir():
            for path in TEMPLATES_DIR.rglob("*"):
                if path.is_file() and path.suffix.lower() in (".yaml", ".yml"):
                    relative_path = path.relative_to(TEMPLATES_DIR).as_posix()
                    existing[relative_path] = path

        to_download = []
        for relative_path, remote_sha1 in remote.items():
            local_path = existing.get(relative_path)

            if local_path is None:
                to_download.append((relative_path, "new"))

            elif sha1_file(local_path) != remote_sha1:
                to_download.append((relative_path, "updated"))

        obsolete = set(existing) - set(remote)

        print(f"{G}[+] {W}Remote templates : {len(remote)}")
        print(f"{G}[+] {W}New templates    : {sum(s == 'new' for _, s in to_download)}")
        print(f"{G}[+] {W}Updated templates: {sum(s == 'updated' for _, s in to_download)}")
        print(f"{G}[+] {W}Obsolete locally : {len(obsolete)}")

        if not to_download and not obsolete:
            print(f"{G}[+] {W}All templates are up to date.")
            return stats

        successful = set()
        with tqdm(total=len(to_download), desc="Updating templates", unit="file", dynamic_ncols=True,) as progress:
            for relative_path, status in to_download:
                destination = TEMPLATES_DIR / relative_path
                destination.parent.mkdir(parents=True, exist_ok=True)

                temp_path = destination.with_suffix(destination.suffix + ".tmp")

                try:
                    response = session.get(RAW_BASE + relative_path, timeout=30)
                    response.raise_for_status()
                    content = response.content
                    expected_sha1 = remote[relative_path]
                    actual_sha1 = hashlib.sha1(content).hexdigest()
                    if actual_sha1 != expected_sha1:
                        raise ValueError("SHA-1 checksum mismatch")

                    try:
                        temp_path.write_bytes(content)
                        temp_path.replace(destination)
                    finally:
                        if temp_path.exists():
                            temp_path.unlink()

                    successful.add(relative_path)

                except (requests.RequestException, OSError, ValueError) as exc:
                    stats["failed"].append((relative_path, str(exc)))

                progress.update(1)
                progress.set_postfix(failed=len(stats["failed"]))

        # Compter les téléchargements réussis.
        for relative_path, status in to_download:
            if relative_path in successful:
                stats[status] += 1

        # Ne supprimer les anciens fichiers que si tous les
        # téléchargements nécessaires ont réussi.
        if not stats["failed"]:
            for relative_path in obsolete:
                existing[relative_path].unlink()
                stats["obsolete"] += 1
                print(f"{M}[-] {W}Removed obsolete template: {relative_path}")

            # Nettoyer les dossiers devenus vides.
            directories = sorted((path for path in TEMPLATES_DIR.rglob("*") if path.is_dir()), key=lambda path: len(path.parts), reverse=True)
            for directory in directories:
                if not any(directory.iterdir()):
                    directory.rmdir()

    except requests.RequestException as exc:
        stats["failed"].append(("checksums", str(exc)))
        print(f"{R}[-] Failed to retrieve checksums: {exc}{W}")

    finally:
        stats["duration"] = time.time() - start

    return stats


# GLOBAL SUMMARY
def print_global_summary(csv_stats, template_stats, duration, eyewitness_stats=None):
    csv_failed = csv_stats["failed"]
    template_failed = template_stats["failed"]
    eyewitness_failed = (eyewitness_stats["failed"] if eyewitness_stats is not None else [])
    total_failed = (len(csv_failed) + len(template_failed) + len(eyewitness_failed))

    print("")
    print(f"{W}=" * 60)
    print(f"             {G}GLOBAL UPDATE SUMMARY")
    print(f"{W}=" * 60)

    print(f"\n{Y}[CSV DATASETS]{W}")
    print(f"Downloaded          : {csv_stats['downloaded']}")
    print(f"Updated             : {csv_stats['updated']}")
    print(f"Unchanged           : {csv_stats['unchanged']}")
    print(f"Failed              : {len(csv_failed)}")
    print(f"Directory           : {DATASETS_DIR_CSV}")

    if eyewitness_stats is not None:
        print(f"\n{Y}[EYEWITNESS SIGNATURES]{W}")
        print(f"Downloaded          : {eyewitness_stats['downloaded']}")
        print(f"Updated             : {eyewitness_stats['updated']}")
        print(f"Unchanged           : {eyewitness_stats['unchanged']}")
        print(f"Failed              : {len(eyewitness_stats['failed'])}")
        print(f"Directory           : {EYEWITNESS_DIR}")

    print(f"\n{Y}[NUCLEI TEMPLATES]{W}")
    if template_stats["skipped"]:
        print("Status              : Skipped by user")
    else:
        print(f"New templates       : {template_stats['new']}")
        print(f"Updated templates   : {template_stats['updated']}")
        print(f"Obsolete removed    : {template_stats['obsolete']}")
        print(f"Failed              : {len(template_failed)}")
        print(f"Duration            : {template_stats['duration']:.1f}s")

    print(f"Directory           : {TEMPLATES_DIR}")

    print(f"\n{Y}[OVERALL]{W}")
    print(f"Total failures      : {total_failed}")
    print(f"Total duration      : {duration:.1f}s")

    if total_failed:
        print(f"\n{R}[!] Errors encountered{W}")

        for filename, error in csv_failed:
            print(f"  {Y}[CSV]{W} {filename}: {error}")

        for filename, error in eyewitness_failed:
            print(f"  {Y}[EYEWITNESS]{W} {filename}: {error}")

        for filename, error in template_failed:
            print(f"  {Y}[NUCLEI]{W} {filename}: {error}")

        print(f"\n{R}[!] {W}Update completed with errors")
    else:
        print(f"\n{G}[+] {W}Update completed successfully{W}")

    print("=" * 60)
    print()


def update_defaults(args):
    csv_files = [
        path for path in DATASETS_DIR_CSV.rglob("*")
        if path.is_file() and path.suffix.lower() == ".csv"
    ] if DATASETS_DIR_CSV.is_dir() else []

    yaml_files = [
        path for path in TEMPLATES_DIR.rglob("*")
        if path.is_file() and path.suffix.lower() in (".yaml", ".yml")
    ] if TEMPLATES_DIR.is_dir() else []

    if csv_files or yaml_files:
        if not args.batch:
            answer = input(f"{Y}[?] {W}Found {len(csv_files)} CSV file(s) and {len(yaml_files)} YAML template(s). Check for updates? [y/N]:{C} ").strip().lower()
            if answer not in ("y", "yes"):
                print(f"{W}[*] Update skipped\n")
                return
        else:
            print(f"{W}[*] Batch mode, update skipped\n")
            return

    start = time.time()

    csv_stats = update_csv_datasets()
    eyewitness_stats = update_eyewitness_signatures()
    template_stats = update_templates()

    duration = time.time() - start
    print_global_summary(csv_stats, template_stats, duration, eyewitness_stats)
