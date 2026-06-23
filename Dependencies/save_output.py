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
    def normalize_url(url):
        if url and not url.startswith(("http://", "https://")):
            return f"https://{url}"
        return url

    def default_filename():
        if args.url:
            url = normalize_url(args.url)
            domain = urlparse(url).hostname or "output"
            return f"{domain}.json"
        return f"{args.commit}.json"

    if getattr(args, "save", None):
        if args.save is True:
            filename = default_filename()
        else:
            filename = args.save
    else:
        filename = default_filename()

    url = normalize_url(args.url) if args.url else None
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(REPORT, f, indent=4, ensure_ascii=False)
    return filename
