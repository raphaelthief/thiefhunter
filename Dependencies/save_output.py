import json
from pathlib import Path
from urllib.parse import urlparse


REPORT = {
    "target": None,
    "modules": {}
}


def init_report(args: str):
    if args.url:
        if not args.url.startswith(("http://", "https://")):
            args.url = f"https://{args.url}"
        REPORT["target"] = args.url
    else:
        REPORT["target"] = args.commit

def add_result(module, result):
    REPORT["modules"].setdefault(module, [])
    REPORT["modules"][module].append(result)


def save_report(args):
    if args.url:
        if not args.url.startswith(("http://", "https://")):
            args.url = f"https://{args.url}"

        domain = urlparse(args.url).hostname
        filename = f"{domain}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(REPORT, f, indent=4, ensure_ascii=False)
        return filename
    else:
        filename = f"{args.commit}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(REPORT, f, indent=4, ensure_ascii=False)
        return filename