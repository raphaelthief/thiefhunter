import json
import re
from pathlib import Path
from Dependencies.get_request import get_request
from Dependencies.displays import M, W, R, Y, G, C, handle_error

WAF_STRONG_CODES = {406, 419, 429, 525, 1020}

BASE_DIR = Path(__file__).resolve().parent
WAF_FILE = BASE_DIR / "wafsignatures.json"

with open(WAF_FILE, "r", encoding="utf-8") as f:
    WAF_SIGS = json.load(f)

# ----------------------------
# ACTIVE PROBE HELPERS
# ----------------------------
def active_probe(args, url):
    payloads = [
        "'\"><script>",
        "../../../etc/passwd",
        "%0d%0aX-Test: injected",
        "test%00",
    ]

    responses = []
    for p in payloads:
        try:
            r = get_request(args, url + p)
            responses.append(r)
        except:
            continue
    return responses


def analyze_probe_response(resp):
    text = resp.text.lower() if resp.text else ""
    status = resp.status_code
    waf_keywords = [
        "blocked",
        "firewall",
        "access denied",
        "request rejected",
        "forbidden",
        "malicious",
        "not acceptable"
    ]

    if status in (403, 406, 429):
        return {"blocked": True}

    if any(k in text for k in waf_keywords):
        return {"blocked": True}
    return {"blocked": False}


# ----------------------------
# CORE ENGINE
# ----------------------------
def detect_waf(response, args, verbose=False):
    results = []
    baseline_response = response
    baseline_status = str(baseline_response.status_code)
    headers = {k.lower(): v for k, v in response.headers.items()}
    body = response.text or ""
    status = str(response.status_code)

    if verbose:
        print(f"{C}[DEBUG] Response Analysis{W}")
        print(f"{Y}Status:{W} {status}")
        print(f"{Y}Headers count:{W} {len(headers)}")
        print(f"{Y}Body size:{W} {len(body)} chars\n")

    for waf_name, rules in WAF_SIGS.items():
        score = 0
        max_score = 0
        evidence = {}
        breakdown = {
            "code": False,
            "headers": False,
            "cookie": False,
            "page": False
        }

        # --------------------
        # STATUS CODE
        # --------------------
        if rules.get("code") is not None:
            max_score += 1
            if status == str(rules["code"]):
                score += 1  # pas 1
                evidence["code"] = {"status": status}
 
        # --------------------
        # HEADERS
        # --------------------
        if rules.get("headers"):
            max_score += 1
            pattern = re.compile(rules["headers"], re.I)

            # fusion key + value in one blob
            for k, v in headers.items():
                if pattern.search(k.lower()) or pattern.search(v.lower()):
                    score += 1
                    breakdown["headers"] = True
                    break

        # --------------------
        # COOKIE
        # --------------------
        if rules.get("cookie"):
            max_score += 1
            cookie_str = headers.get("set-cookie", "")
            if re.search(rules["cookie"], cookie_str, re.I):
                score += 1
                breakdown["cookie"] = True

        # --------------------
        # BODY
        # --------------------
        if rules.get("page"):
            max_score += 1
            patterns = rules["page"].split("|")
            if any(p and p in body for p in patterns):
                score += 1
                breakdown["page"] = True

        confidence = (score / max_score) if max_score else 0
        if confidence >= 0.5:
            results.append({
                "waf": waf_name,
                "sources": ["passive"],
                "confidence": round(confidence, 2),
                "score": score,
                "max_score": max_score,
                "breakdown": breakdown,
                "evidence": evidence
            })

    # ----------------------------
    # ACTIVE PROBING (DEFAULT)
    # ----------------------------
    try:
        probe_responses = active_probe(args, args.url)
        waf_votes = {}
        total = len(probe_responses)
        for r in probe_responses:
            signals = analyze_probe_response(r)
            if not signals["blocked"]:
                continue

            matches = match_waf_signatures(r, WAF_SIGS, baseline_response)
            for name, data in matches.items():
                conf = data.get("confidence", 0)
                if name not in waf_votes:
                    waf_votes[name] = data
                else:
                    if conf > waf_votes[name].get("confidence", 0):
                        waf_votes[name] = data

        for name, data in waf_votes.items():
            conf = data.get("confidence", 0)
            evidence = data.get("evidence", {})
            results.append({
                "waf": name,
                "sources": ["active"],
                "confidence": round(conf, 2),
                "evidence": evidence,
                "score": int(conf * total),
                "max_score": total,
                "breakdown": {
                    "code": False,
                    "headers": False,
                    "cookie": False,
                    "page": True
                }
            })
    except Exception as e:
        handle_error(e, "Active probe error", args.verbose)
    results = merge_results(results)
    results.sort(key=lambda x: x["confidence"], reverse=True)
    return results


def highlight(v):
    if v is None:
        return None
    return f"{R}{v}{W}"


def match_waf_signatures(response, waf_sigs, baseline_response=None):
    headers = {k.lower(): v for k, v in response.headers.items()}
    body = response.text or ""
    status = str(response.status_code)
    baseline_status = str(baseline_response.status_code) if baseline_response else None
    matches = {}
    for waf_name, rules in waf_sigs.items():
        score = 0
        max_score = 0
        evidence = {}

        # --------------------
        # CODE
        # --------------------
        if rules.get("code"):
            max_score += 1

            probe_status = str(status)
            if probe_status == str(rules["code"]):
                if baseline_status and probe_status != baseline_status:
                    score += 1
                    evidence["code"] = {
                        "probe": probe_status,
                        "baseline": baseline_status,
                        "delta": True
                    }
        # --------------------
        # HEADERS
        # --------------------
        if rules.get("headers"):
            max_score += 1
            pattern = re.compile(rules["headers"], re.I)
            for k, v in headers.items():
                if pattern.search(k):
                    score += 1
                    evidence["headers"] = {"match": k, "type": "key"}
                    break

                match = pattern.search(v)
                if match:
                    score += 1
                    evidence["headers"] = {
                        "header": k,
                        "match": match.group(0),
                        "type": "value"
                    }
                    break

        # --------------------
        # COOKIE
        # --------------------
        if rules.get("cookie"):
            max_score += 1
            cookie_str = headers.get("set-cookie", "")
            match = re.search(rules["cookie"], cookie_str, re.I)
            if match:
                score += 1
                evidence["cookie"] = match.group(0)

        # --------------------
        # PAGE
        # --------------------
        if rules.get("page"):
            max_score += 1
            patterns = rules["page"].split("|")
            for p in patterns:
                if p and p in body:
                    score += 1
                    idx = body.find(p)
                    snippet = body[max(0, idx-40): idx+40]
                    evidence["page"] = {
                        "match": p,
                        "snippet": snippet
                    }
                    break

        confidence = (score / max_score) if max_score else 0
        if confidence >= 0.5:
            matches[waf_name] = {
                "confidence": confidence,
                "evidence": evidence
            }
    return matches


def merge_results(results):
    merged = {}
    for r in results:
        key = r["waf"]

        if key not in merged:
            merged[key] = r
            continue

        existing = merged[key]

        # 1. merge sources
        existing_sources = set(existing.get("sources", []))
        new_sources = set(r.get("sources", []))
        existing["sources"] = list(existing_sources | new_sources)

        # 2. garde meilleure confidence SANS écraser l'objet
        if r.get("confidence", 0) > existing.get("confidence", 0):
            existing["confidence"] = r["confidence"]
            existing["evidence"] = {
                **existing.get("evidence", {}),
                **r.get("evidence", {})
            }
            existing["breakdown"] = r.get("breakdown", existing.get("breakdown", {}))
            existing["score"] = r.get("score", existing.get("score", 0))
            existing["max_score"] = r.get("max_score", existing.get("max_score", 0))

        merged[key] = existing
    return list(merged.values())


# ----------------------------
# WRAPPER
# ----------------------------
def format_breakdown(breakdown):
    formatted = []
    for k, v in breakdown.items():
        if v is True:
            formatted.append(f"{k}: {Y}{v}{W}")
        else:
            formatted.append(f"{k}: {v}")
    return "{" + ", ".join(formatted) + "}"

def whatwaf(args):
    try:
        print(f"\n{C}[+] WAF detection")
        response = get_request(args, args.url)
        wafs = detect_waf(
            response,
            args,
            verbose=getattr(args, "verbose", False)
        )

        if not wafs:
            print(f"{R}[-] No WAF detected")
            return

        print(f"{G}[+] {W}Detected WAF(s):")
        for w in wafs:
            sources = "+".join(w.get("sources", []))
            print(f"{G}  - {Y}{w['waf']} {W}({w['confidence']*100:.0f}%) [{sources}]")
            if getattr(args, "verbose", False):
                evidence = w.get("evidence", {})
                print(f"     {G}↳ {W}score: {w['score']}/{w['max_score']}")
                print(f"     {G}↳ {W}matches: {format_breakdown(w['breakdown'])}")
                print(f"     {G}↳ {W}evidence:")
                for k, v in evidence.items():
                    print(f"        {G}- {Y}{k}{W}: {highlight(v)}")
    except Exception as e:
        handle_error(e, "Error during WAF detection", args.verbose)
