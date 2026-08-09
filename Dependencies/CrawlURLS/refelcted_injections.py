import uuid, re
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from Dependencies.get_request import get_request
from Dependencies.displays import M, W, R, Y, G, handle_error


visited = set()
REFLECTION_CHARS = '<>"\'&'


# ============================================================
# SQL ERROR DETECTION
# ============================================================
SQL_ERROR_PROBES = {
    "single_quote": "'",
    "double_quote": '"',
    "parenthesis": ")",
}

SQL_ERROR_PATTERNS = {
    "MYSQL": [
        r"you have an error in your sql syntax",
        r"warning.*mysql",
        r"mysql_fetch",
        r"mysqli_",
        r"pdo_mysql",
        r"unknown column .* in .*",
        r"check the manual that corresponds to your mysql",
    ],

    "POSTGRESQL": [
        r"postgresql.*error",
        r"pg_query\(",
        r"pg_exec\(",
        r"psql:",
        r"syntax error at or near",
        r"unterminated quoted string",
    ],

    "MSSQL": [
        r"microsoft sql server",
        r"\[microsoft\]\[odbc sql server driver\]",
        r"odbc sql server driver",
        r"unclosed quotation mark after the character string",
        r"incorrect syntax near",
        r"sqlexception",
    ],

    "ORACLE": [
        r"ora-\d{5}",
        r"oracle error",
        r"oracle database",
        r"quoted string not properly terminated",
    ],

    "SQLITE": [
        r"sqlite error",
        r"sqlite3",
        r"near .*: syntax error",
        r"unrecognized token",
        r"unterminated string",
    ],
}

def detect_sql_errors(response_text):
    findings = []
    for database, patterns in SQL_ERROR_PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                findings.append({
                    "database": database,
                    "pattern": pattern,
                    "match": match.group(0),
                })
    return findings


def get_sql_baseline(args, url):
    try:
        response = get_request(args, url, timeout=10)
        if response is None:
            return None, []

        return response, detect_sql_errors(response.text)
    except KeyboardInterrupt:
        raise
    except Exception:
        return None, []


def test_sql_errors(args, url, parameter):
    print(f"{Y}[*] {W}Testing SQL error disclosure for parameter '{parameter}'")
    baseline_response, baseline_errors = get_sql_baseline(args, url)
    baseline_databases = {
        finding["database"]
        for finding in baseline_errors
    }

    if baseline_errors:
        print(f"{Y}[!] SQL error already present in baseline response{W}")

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    for probe_name, probe in SQL_ERROR_PROBES.items():
        print(f"    {G}- {W}Testing probe: {probe_name}")
        test_params = params.copy()
        test_params[parameter] = [probe]
        query = urlencode(test_params, doseq=True)
        injected_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))

        try:
            response = get_request(args, injected_url, timeout=10)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            handle_error(e, "ERROR", args.verbose)
            continue

        if response is None:
            continue

        findings = detect_sql_errors(response.text)
        new_findings = [
            finding
            for finding in findings
            if finding["database"]
            not in baseline_databases
        ]

        if new_findings:
            print(f"        {G}[+] SQL ERROR DISCLOSURE DETECTED{W}")
            for finding in new_findings:
                print(f"            {G}✓{W} {finding['database']}")
                if args.verbose:
                    print(f"              Match: {finding['match']}")

        elif findings:
            print(f"        {Y}[!] {W}SQL error signature present, but also present in baseline")

        else:
            print(f"        {M}[-] {W}No SQL error detected")
        print()


# ============================================================
# URL / PARAMETERS
# ============================================================
def same_domain(url, base):
    return urlparse(url).netloc == urlparse(base).netloc


def extract_links(url, html):
    links = set()
    soup = BeautifulSoup(html, "html5lib")
    for tag in soup.find_all("a", href=True):
        absolute = urljoin(url, tag["href"])
        if absolute.startswith(("http://", "https://")):
            links.add(absolute)
    return links


def extract_query_parameters(url):
    parsed = urlparse(url)
    return list(parse_qs(parsed.query, keep_blank_values=True).keys())


# ============================================================
# BUILD REFLECTION REQUEST
# ============================================================
def build_reflection_request(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    markers = {}
    for parameter in params:
        marker = "REFLECT_" + uuid.uuid4().hex[:8]
        markers[parameter] = marker
        
        params[parameter] = [
            marker + REFLECTION_CHARS
        ]

    query = urlencode(params, doseq=True)
    injected_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment,))
    return injected_url, markers


# ============================================================
# CHARACTER ENCODING ANALYSIS
# ============================================================
def analyze_characters(response_text, marker, position):
    value_start = position + len(marker)
    encodings = {
        "<": {
            "RAW": "<",
            "HTML_ENCODED": "&lt;",
            "URL_ENCODED": "%3C",
        },
        ">": {
            "RAW": ">",
            "HTML_ENCODED": "&gt;",
            "URL_ENCODED": "%3E",
        },
        '"': {
            "RAW": '"',
            "HTML_ENCODED": "&quot;",
            "URL_ENCODED": "%22",
        },
        "'": {
            "RAW": "'",
            "HTML_ENCODED": "&#39;",
            "URL_ENCODED": "%27",
        },
        "&": {
            "RAW": "&",
            "HTML_ENCODED": "&amp;",
            "URL_ENCODED": "%26",
        },
    }

    results = []
    cursor = value_start
    for character in REFLECTION_CHARS:
        found = False

        for encoding_type, representation in encodings[character].items():
            if response_text[
                cursor:cursor + len(representation)
            ].lower() == representation.lower():

                results.append({
                    "character": character,
                    "encoding": encoding_type,
                    "representation": representation,
                })

                cursor += len(representation)
                found = True
                break

        if not found:
            results.append({
                "character": character,
                "encoding": "NOT_OBSERVED",
                "representation": None,
            })
            break

    return results


# ============================================================
# CONTEXT
# ============================================================

def detect_context(html, position):
    if position < 0:
        return "UNKNOWN"

    before = html[:position]
    last_open = before.rfind("<")
    last_close = before.rfind(">")
    if last_open > last_close:
        tag_start = before.rfind("<")
        tag = html[tag_start:position].lower()
        if tag.startswith("<script"):
            return "JAVASCRIPT"

        return "HTML_ATTRIBUTE"

    script_open = before.lower().rfind("<script")
    script_close = before.lower().rfind("</script>")
    if script_open > script_close:
        return "JAVASCRIPT"
        
    return "HTML_TEXT"


# ============================================================
# FIND REFLECTIONS
# ============================================================
def find_reflections(response_text, marker, max_occurrences=10):
    occurrences = []
    start = 0
    while len(occurrences) < max_occurrences:
        position = response_text.find(marker, start)
        if position == -1:
            break

        context = detect_context(response_text, position)
        character_analysis = analyze_characters(response_text, marker, position)
        occurrences.append({
            "position": position,
            "context": context,
            "characters": character_analysis,
        })

        start = position + len(marker)
    return occurrences


# ============================================================
# TAG ESCAPE TEST
# ============================================================
def test_tag_escape(args, url, parameter, marker, occurrences):
    has_raw_characters = False
    raw_occurrences = []
    
    for occ in occurrences:
        if occ["characters"]:
            for char_result in occ["characters"]:
                if char_result["encoding"] == "RAW":
                    has_raw_characters = True
                    raw_occurrences.append(occ)
                    break
    
    if not has_raw_characters:
        print(f"{M}[-] {W}No RAW characters found, skipping tag escape test")
        return
    
    print(f"{Y}[*] {W}Testing HTML context breakout")
    context = raw_occurrences[0]["context"]
    print(f"{Y}[*] {W}Context detected:{W} {context}")
    
    payloads = build_escape_payloads(context, marker)
    for payload_name, payload in payloads.items():
        test_payload(args, url, parameter, marker, payload_name, payload)




def build_escape_payloads(context, marker):
    payloads = {}
    if context == "HTML_TEXT":
        payloads["html_element_escape"] = (f'<div data-reflect-poc="{marker}">POC</div>')
        payloads["html_tag_escape"] = (f'<span data-reflect-poc="{marker}">POC</span>')

    elif context == "HTML_ATTRIBUTE":
        payloads["attribute_double_quote"] = (f'"><div data-reflect-poc="{marker}">POC</div>')
        payloads["attribute_single_quote"] = (f"'><div data-reflect-poc='{marker}'>POC</div>")

    elif context == "JAVASCRIPT":
        print(f"{Y}[*] {W}JavaScript context detected - HTML breakout test skipped")

    else:
        payloads["generic_html_element"] = (f'<div data-reflect-poc="{marker}">POC</div>')
    return payloads



def test_payload(args, url, parameter, marker, payload_name, payload):
    print(f"{Y}[*] {W}Testing payload:{Y} {payload_name}")
    print(f"    {G}-> {W}Payload:{Y} {payload}")
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[parameter] = [payload]
    
    query = urlencode(params, doseq=True)
    injected_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))
    
    try:
        response = get_request(args, injected_url, timeout=10)
        if response is None:
            return
        
        html = response.text
        evidence = []

        if marker in html:
            evidence.append("MARKER_REFLECTED")
        else:
            print(f"        {M}[-] Marker not reflected{W}")
            return

        soup = BeautifulSoup(html, "html5lib")
        poc_elements = soup.find_all(attrs={"data-reflect-poc": marker})
        if poc_elements:
            evidence.append("HTML_ELEMENT_INJECTED")

        if evidence:
            print(f"        {G}[+] POC RESULT{W}")
            for indicator in evidence:
                print(f"            {G}✓{W} {indicator}")

            if poc_elements:
                print()
                print(f"        {G}[+] New HTML element detected:{W}")
                for element in poc_elements:
                    print(f'            <{element.name} data-reflect-poc="{marker}">')
            print()

            if args.verbose:
                position = html.find(marker)
                if position != -1:
                    start = max(0, position - 100)
                    end = min(len(html), position + len(marker) + 200)
                    print(f"{Y}[*] {W}Context around marker:")
                    print(f"{Y}-" * 60)
                    print(f"{W}{html[start:end]}")
                    print(f"{Y}-" * 60)
                    print()

        else:
            print(f"        {M}[-] {W}Payload reflected but no HTML element detected")

    except Exception as e:
        handle_error(e, "ERROR", args.verbose)


# ============================================================
# TEST PARAMETER WITH ESCAPE
# ============================================================
def test_parameter_with_escape(args, url, parameter, marker, occurrences):
    raw_found = False
    for occ in occurrences:
        if occ["characters"]:
            for char_result in occ["characters"]:
                if char_result["encoding"] == "RAW":
                    raw_found = True
                    break
            if raw_found:
                break
    
    if raw_found:
        print(f"{G}[+] RAW characters detected for parameter '{parameter}', testing escape{W}")
        test_tag_escape(args, url, parameter, marker, occurrences)
    else:
        print(f"{Y}[*] {W}No RAW characters found for '{parameter}', skipping escape test")


# ============================================================
# QUERY PARAMETER TEST
# ============================================================

def test_query_parameters(args, url):
    parameters = extract_query_parameters(url)
    if not parameters:
        return

    injected_url, markers = build_reflection_request(url)
    print(f"{Y}[*] Reflection test:{W} {injected_url}")

    try:
        response = get_request(args, injected_url, timeout=10)
    except KeyboardInterrupt:
        raise
    except Exception:
        return

    if response is None:
        return

    response_text = response.text
    for parameter, marker in markers.items():
        occurrences = find_reflections(response_text, marker)
        if not occurrences:
            print(f"{M}[-] {W}{parameter}: NOT REFLECTED")
            continue

        print(f"{G}[+] REFLECTION FOUND{W}")
        print(f"    {Y}Parameter   :{W} {parameter}")
        print(f"    {Y}Marker      :{W} {marker}")
        print(f"    {Y}Occurrences :{W} {len(occurrences)}")

        for index, occurrence in enumerate(occurrences, start=1):
            print(f"    {G}- {Y}Occurrence #{index}{W} -> {G}{occurrence['context']}{W}")
            for result in occurrence["characters"]:
                character = result["character"]
                encoding = result["encoding"]
                representation = result["representation"]
                
                if encoding == "RAW":
                    status = f"{R}RAW{W}"

                elif encoding == "HTML_ENCODED":
                    status = f"{G}HTML_ENCODED{W}"

                elif encoding == "URL_ENCODED":
                    status = f"{G}URL_ENCODED{W}"

                else:
                    status = f"{Y}NOT_OBSERVED{W}"

                if representation is not None:
                    print(f"        {character!r} -> {status} ({representation})")
                else:
                    print(f"        {character!r} -> {status}")
            print()

        if args.verbose:
            position = response_text.find(marker)
            start = max(0, position - 100)
            end = min(len(response_text), position + len(marker) + 150)
            print(f"{Y}[*] {W}Raw response context:")
            print(f"{Y}-" * 60)
            print(f"{W}{response_text[start:end]}")
            print(f"{Y}-" * 60)
            print()
            
        test_parameter_with_escape(args, url, parameter, marker, occurrences)
        test_sql_errors(args, url, parameter)
        
    if not occurrences:   
        for parameter in parameters:
            test_sql_errors(args, url, parameter)        



# ============================================================
# PAGE ANALYSIS
# ============================================================
def analyze_page(args, url, html):
    parameters = extract_query_parameters(url)
    if not parameters:
        return
    test_query_parameters(args,url)


# ============================================================
# CRAWLER
# ============================================================
def crawl(args, url, depth, max_depth, base):
    if depth > max_depth:
        return

    if url in visited:
        return

    visited.add(url)
    print(f"{W}[*] Crawling {url} (depth={depth})")

    try:
        response = get_request(args, url, timeout=10)
    except KeyboardInterrupt:
        raise
    except Exception:
        return

    if response is None:
        return

    content_type = response.headers.get("Content-Type", "").lower()
    if "text/html" not in content_type:
        return

    html = response.text
    analyze_page(args, url, html)
    if depth == max_depth:
        return

    for link in extract_links(url, html):
        if same_domain(link, base):
            crawl(args, link, depth + 1, max_depth, base)


# ============================================================
# ENTRY POINT
# ============================================================
def reflector(args):
    crawl(args, args.url, 0, args.reflect, args.url)
