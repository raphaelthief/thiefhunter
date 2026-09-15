import json
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime


REPORTS = {
    "tool": {
        "name": "thiefhunter",
        "version": "v2",
        "author": "raphaelthief"
    },
    "targets": []
}
CURRENT_REPORT = None


def normalize_url(url):
    if url and not url.startswith(("http://", "https://")):
        return f"https://{url}"
    return url


def init_report(args, target=None):
    global CURRENT_REPORT

    CURRENT_REPORT = {
        "target": normalize_url(target) if target else None,
        "modules": {}
    }

    if not target and args.commits:
        CURRENT_REPORT["commits"] = args.commits

    REPORTS["targets"].append(CURRENT_REPORT)


def add_result(module, result):
    if CURRENT_REPORT is None:
        return

    CURRENT_REPORT["modules"].setdefault(module, [])
    CURRENT_REPORT["modules"][module].append(result)


def save_report(args):
    if args.file:
        filename = "scan-report.json"

    elif args.url:
        url = normalize_url(args.url)
        domain = urlparse(url).hostname or "output"
        filename = f"{domain}.json"

    elif args.commits:
        filename = f"{args.commits}.json"

    else:
        filename = "scan-report.json"

    data = {
        "targets": REPORTS
    }

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(
            data,
            f,
            indent=4,
            ensure_ascii=False
        )

    return filename



class HARRecorder:
    def __init__(self, filename=datetime.now().strftime("%d-%m-%y-%H-%M.har")):
        self.filename = filename
        self.entries = []

    def add(self, method, url, headers, body, response):
        if response is None:
            return

        try:
            parsed = urlparse(url)
            request_headers = [
                {
                    "name": k,
                    "value": v
                }
                for k, v in headers.items()
            ]

            response_headers = [
                {
                    "name": k,
                    "value": v
                }
                for k, v in response.headers.items()
            ]

            entry = {
                "startedDateTime": datetime.utcnow().isoformat() + "Z",
                "time": 0,

                "request": {
                    "method": method,
                    "url": url,
                    "httpVersion": "HTTP/1.1",
                    "headers": request_headers,
                    "queryString": [],
                    "cookies": [],
                    "headersSize": -1,
                    "bodySize": len(body or "")
                },

                "response": {
                    "status": response.status_code,
                    "statusText": "",
                    "httpVersion": "HTTP/1.1",
                    "redirectURL": response.headers.get("Location", ""),
                    "headers": response_headers,
                    "cookies": [],
                    "content": {
                        "size": len(response.text),
                        "mimeType": response.headers.get(
                            "Content-Type",
                            ""
                        ),
                        "text": response.text
                    }
                },

                "cache": {},
                "timings": {
                    "send": 0,
                    "wait": 0,
                    "receive": 0
                }
            }
            self.entries.append(entry)
        except Exception:
            pass

    def save(self):
        data = {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "ThiefHunter",
                    "version": "2.0"
                },
                "entries": self.entries
            }
        }
        Path(self.filename).write_text(
            json.dumps(data, indent=4),
            encoding="utf-8"
        )
