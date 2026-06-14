import json, re, os
from bs4 import BeautifulSoup
from collections import Counter
from urllib.parse import urljoin, urlparse
from webtech import WebTech
from webtech.utils import WrongContentTypeException
from wappalyzer import Wappalyzer
from packaging import version
from Dependencies.Versions_detection.wordpress import detect_wordpress
from Dependencies.get_request import get_request
from Dependencies.displays import handle_error



with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "patterns.json"), "r", encoding="utf-8") as f:
    SIGNATURES = json.load(f)

def webtech_scan(url):
    wt = WebTech()
    wt.timeout = 30
    wt.auto_fallback = False
    try:
        return wt.start_from_url(url)
    except WrongContentTypeException:
        return ""
    except Exception:
        return ""


def wappalyze_that(url, cookies=None):
    try:
        with Wappalyzer(workers=1, timeout=30) as scanner:
            return scanner.analyze(url)
    except Exception:
        return {}


def format_webtech(result):
    lines = result.split("\n")
    techs = []
    for line in lines:
        line = line.strip()

        if line.startswith("-"):
            line = line.replace("-", "").strip()
            if " " in line:
                name, version = line.split(" ", 1)
            else:
                name, version = line, ""
                
            techs.append((name.strip(), version.strip()))
    return techs

def format_wappalyzer(result):
    techs = []

    if not result:
        return techs

    # case analyze_many()
    if isinstance(result, dict) and any(isinstance(v, dict) for v in result.values()):
        for url, data in result.items():
            for tech, info in data.items():
                version = str(info.get("version") or "").strip()
                techs.append((tech.strip(), version.strip()))

    # case analyze() single URL
    else:
        for tech, info in result.items():
            version = str(info.get("version") or "").strip()
            techs.append((tech.strip(), version.strip()))

    return techs

def normalize_name(name):
    name = name.lower().strip()

    if name.startswith("plugin:"):
        return name
    if name.startswith("theme:"):
        return name

    return name

def pick_highest_version(existing, new):
    def clean(v):
        if not v:
            return None
        if re.match(r"^\d+(\.\d+){0,3}$", v):
            return v
        return None

    existing = clean(existing)
    new = clean(new)

    if not existing:
        return new or ""
    if not new:
        return existing

    try:
        return str(max(version.parse(existing), version.parse(new)))
    except:
        return existing

def is_relevant_asset(url):
    return any(x in url for x in [".js", ".css", "/_next/", "static", "assets"])

def is_valid_version(v):
    return bool(v) and v != "." and re.match(r"^\d+(\.\d+){0,3}$", v)

def detect(content, signatures):
    found = []

    for tech, data in signatures.items():

        # 1. simple detection (signal)
        detected = False

        for regex in data.get("detect", []):
            if re.search(regex, content, re.I | re.S):
                detected = True
                break

        if not detected:
            continue

        version = ""

        # 2. version extraction
        for vregex in data.get("version", []):
            match = re.search(vregex, content, re.I | re.S)
            if match:
                for g in match.groups():
                    if g and re.match(r"^\d+(\.\d+){0,3}$", g):
                        version = g
                        break
                if version:
                    break

        found.append((tech, version))
    return found


def extract_assets(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    assets = []
    for tag in soup.find_all(["script", "link"]):
        src = tag.get("src")
        href = tag.get("href")
        asset = src or href
        if asset:
            assets.append(urljoin(base_url, asset))
    return assets

def manual_detection(args, url):
    found = []
    try:
        r = get_request(args, url)
        if not r:
            return []
            
        html = r.text
        final_url = r.url
    except:
        return []
        
    found += detect(html, SIGNATURES)
    assets = extract_assets(html, final_url)
    for asset in assets:
        if not is_relevant_asset(asset):
            continue
    
        found += detect(asset, SIGNATURES)
        try:
            r = get_request(args, asset)
            if not r:
                return []
                
            text = r.text                
            found += detect(r.text, SIGNATURES)
        except Exception as e:
            handle_error(e, f"ERROR FETCHING: {asset}", args.verbose)
            pass
    return found


def extract_assets_tech(args, url):
    wt_result = webtech_scan(url)
    wp_raw = wappalyze_that(url)
    wt_techs = format_webtech(wt_result)
    wp_techs = format_wappalyzer(wp_raw)
    manual_techs = manual_detection(args, url)

    try:
        r = get_request(args, url)
        html = r.text
    except:
        html = ""

    wp = detect_wordpress(args, html, url)

    merged = {}

    # -------------------
    # WordPress core
    # -------------------
    if wp and wp.get("core"):
        merged["WordPress"] = wp["core"]

    # -------------------
    # WordPress plugins/themes (NORMALIZED)
    # -------------------
    if wp and wp.get("components"):
        for t, name, ver in wp["components"]:
            key = name.strip().lower()

            merged[key] = pick_highest_version(
                merged.get(key, ""),
                ver
            )

    # -------------------
    # WebTech + Wappalyzer + manual
    # -------------------
    for name, ver in wt_techs + wp_techs + manual_techs:
        key = normalize_name(name)

        merged[key] = pick_highest_version(
            merged.get(key, ""),
            ver
        )

    # -------------------
    # OUTPUT FLAT
    # -------------------
    result = []
    for name, ver in merged.items():
        if ver:
            result.append((name, ver))
        else:
            result.append((name, ""))

    return result
