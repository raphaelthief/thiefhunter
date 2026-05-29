import base64, json, re
from datetime import datetime, timezone
from colorama import init, Fore, Style
from Dependencies.displays import M, W, R, Y, G, C


def b64url_decode(data: str):
    padding = '=' * (-len(data) % 4)
    decoded = base64.urlsafe_b64decode(data + padding)
    try:
        return json.loads(decoded)
    except Exception as e:
        handle_error(e, "ERROR", args.verbose)
        return decoded.decode(errors="ignore")


def is_jwt(token: str) -> bool:
    parts = token.split('.')
    return len(parts) == 3 and all(parts)


def ts_to_datetime(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc)

def format_dt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def analyze_jwt(token: str):
    header_b64, payload_b64, signature = token.split('.')

    header = b64url_decode(header_b64)
    payload = b64url_decode(payload_b64)

    alg = header.get("alg", "inconnu")
    typ = header.get("typ", "inconnu")

    now = datetime.now(timezone.utc)

    exp = payload.get("exp")
    iat = payload.get("iat")
    nbf = payload.get("nbf")

    result = {
        "header": header,
        "payload": payload,
        "algorithme": alg,
        "type": typ,
    }

    if iat:
        iat_dt = ts_to_datetime(iat)
        result["issued_at"] = format_dt(iat_dt)

    if exp:
        exp_dt = ts_to_datetime(exp)
        result["expires_at"] = format_dt(exp_dt)

        if iat:
            duration = exp - iat
            result["validity_duration_seconds"] = duration

        remaining = exp_dt - now
        result["time_remaining"] = str(remaining)

        result["is_expired"] = now > exp_dt

    if nbf:
        nbf_dt = ts_to_datetime(nbf)
        result["not_before"] = format_dt(nbf_dt)
        result["not_valid_yet"] = now < nbf_dt

    print_jwt_analysis(result)
    
def print_jwt_analysis(data):
    if "error" in data:
        print(f"{R}[!] ERROR: {data['error']}")
        return

    print(f"\n{C}[!] JWT ANALYSIS{Style.RESET_ALL}")
    print(f"{G}    [*] Algorithm : {W}{data.get('algorithme')}")
    print(f"{G}    [*] Type      : {W}{data.get('type')}")

    # Expiration
    if "is_expired" in data:
        status = f"{R}EXPIRED" if data["is_expired"] else f"{G}VALID"
        print(f"{Y}    [+] Status    : {status}")

    # Headers
    print(f"{C}\n[!] Header claims{Style.RESET_ALL}")

    for k, v in data.get("header", {}).items():
        print(f"{G}    [*] {k} = {W}{v}")
        
    # Payload
    email_regex = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    print(f"{C}\n[!] Payload claims{Style.RESET_ALL}")
    for k, v in data.get("payload", {}).items():
        is_email = isinstance(v, str) and re.match(email_regex, v)
        if is_email:
            print(f"{G}    [*] {k} = {Y}{v}")
        else:
            print(f"{G}    [*] {k} = {W}{v}")
    
    # Token validity
    print(f"{C}\n[!] Token validity{Style.RESET_ALL}")
    if "issued_at" in data:
        print(f"{G}    [*] Issued At : {W}{data['issued_at']}")
    if "expires_at" in data:
        print(f"{G}    [*] Expires   : {W}{data['expires_at']}")
    if "time_remaining" in data:
        print(f"{G}    [*] Remaining : {W}{data['time_remaining']}")

    def audit(level, title, detail, impact=None):
        colors = {
            "info": G,
            "low": G,
            "medium": Y,
            "high": R,
            "critical": R
        }
        print(f"    {G}[*] {W}{title} {colors.get(level, W)}[{level.upper()}]{Style.RESET_ALL}")
        print(f"        {Y}→ {detail}")

        if impact:
            print(f"        {Y}→ Impact: {W}{impact}")

    def format_duration(seconds: int) -> str:
        seconds = int(seconds)
        days, seconds = divmod(seconds, 86400)
        hours, seconds = divmod(seconds, 3600)
        minutes, seconds = divmod(seconds, 60)
        parts = []
        
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        if seconds > 0 or not parts:
            parts.append(f"{seconds}s")
        return " ".join(parts)

    if "validity_duration_seconds" in data:
        seconds = data["validity_duration_seconds"]
        readable = format_duration(seconds)

        # classification pentest (sources : me and my ass)
        if seconds < 900:  # < 15 min
            audit(
                "low",
                "Very short token lifetime",
                f"{Y}{readable} {W}lifetime detected",
                "May indicate high-frequency re-authentication system"
            )
        elif seconds < 86400:  # < 1 day
            audit(
                "info",
                "Standard token lifetime",
                f"{readable} lifetime detected",
                "Normal session behavior for web applications"
            )
        elif seconds < 604800:  # < 7 days
            audit(
                "medium",
                "Extended token lifetime",
                f"{readable} lifetime detected",
                "Increases impact of token theft (replay risk)"
            )
        else:
            audit(
                "high",
                "Long-lived token detected",
                f"{readable} lifetime detected",
                "High risk if token is compromised (persistent access)"
            )
