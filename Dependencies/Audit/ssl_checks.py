import ssl, warnings, socket, socks
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
from collections import defaultdict
from Dependencies.displays import M, W, R, Y, G, C, handle_error

warnings.filterwarnings("ignore", category=DeprecationWarning)
PORT = 443

SOCKS_PROXY = {
    "host": "127.0.0.1",
    "port": 9050,
    "type": socks.SOCKS5,
    "rdns": True  # enables remote DNS (SOCKS5H behavior)
}

def create_socket(host, port, args=None, timeout=10):
    # -------------------------
    # TOR / SOCKS5
    # -------------------------
    if args and getattr(args, "tor", False):
        s = socks.socksocket()
        s.set_proxy(
            SOCKS_PROXY["type"],
            SOCKS_PROXY["host"],
            SOCKS_PROXY["port"],
            rdns=SOCKS_PROXY["rdns"]
        )
        s.settimeout(timeout)
        s.connect((host, port))
        return s

    # -------------------------
    # DIRECT
    # -------------------------
    return socket.create_connection(
        (host, port),
        timeout=timeout
    )


# ----------------------------
# TLS protocol detection
# ----------------------------
def test_protocol(host, port, args=None):
    results = {}
    protocols = {
        "SSLv3": ssl.TLSVersion.SSLv3,
        "TLSv1": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }
    for name, ver in protocols.items():
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            with create_socket(host, port, args=args, timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    results[name] = True
        except:
            results[name] = False
    return results


# ----------------------------
# FULL Cipher Enumeration
# OpenSSL driven
# ----------------------------
def test_ciphers(host, port, args=None):
    results = defaultdict(list)
    versions = {
        "TLSv1": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }

    # -------------------------
    # GET ALL OPENSSL CIPHERS
    # -------------------------
    base_ctx = ssl.create_default_context()
    openssl_ciphers = base_ctx.get_ciphers()

    # TLS <=1.2 / TLS1.3
    legacy_ciphers = []
    tls13_ciphers = []
    for c in openssl_ciphers:
        name = c["name"]
        proto = c.get("protocol", "")

        if proto == "TLSv1.3":
            if name not in tls13_ciphers:
                tls13_ciphers.append(name)
        else:
            if name not in legacy_ciphers:
                legacy_ciphers.append(name)

    # -------------------------
    # OPTIONAL EXTRA LEGACY
    # (OpenSSL may hide them)
    # -------------------------
    extra_legacy = [
        "DES-CBC3-SHA",
        "RC4-SHA",
        "NULL-MD5",
        "EXP-RC4-MD5",
    ]
    for c in extra_legacy:
        if c not in legacy_ciphers:
            legacy_ciphers.append(c)


    # -------------------------
    # PROBE FUNCTION
    # -------------------------
    def probe(cipher, version_name, version_obj):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # force TLS version
            ctx.minimum_version = version_obj
            ctx.maximum_version = version_obj

            # lower OpenSSL security level
            # needed for weak/legacy suites
            cipher_string = f"{cipher}:@SECLEVEL=0"

            # TLS <= 1.2
            if version_obj != ssl.TLSVersion.TLSv1_3:
                ctx.set_ciphers(cipher_string)

            # TLS 1.3
            else:
                if hasattr(ctx, "set_ciphersuites"):
                    ctx.set_ciphersuites(cipher)
            with create_socket(
                host,
                port,
                args=args,
                timeout=10
            ) as sock:
                with ctx.wrap_socket(
                    sock,
                    server_hostname=host
                ) as ssock:
                    negotiated = ssock.cipher()

                    if negotiated:
                        cipher_name = negotiated[0]

                        if cipher_name.lower() == cipher.lower():
                            analysis = analyze_cipher(cipher_name, version_name)
                            security, reasons = classify_cipher(cipher_name, version_name)
                            results[version_name].append({
                                "cipher": cipher_name,
                                "bits": negotiated[2],
                                "security": security,
                                "reasons": reasons
                            })
        except ssl.SSLError:
            pass
        except Exception:
            pass


    # -------------------------
    # TEST TLS <=1.2
    # -------------------------
    tasks = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        for version_name, version_obj in versions.items():
            if version_obj == ssl.TLSVersion.TLSv1_3:
                continue

            for cipher in legacy_ciphers:
                tasks.append(
                    executor.submit(
                        probe,
                        cipher,
                        version_name,
                        version_obj
                    )
                )
        for future in as_completed(tasks):
            pass


    # -------------------------
    # TEST TLS1.3
    # -------------------------
    tasks = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        for cipher in tls13_ciphers:
            tasks.append(
                executor.submit(
                    probe,
                    cipher,
                    "TLSv1.3",
                    ssl.TLSVersion.TLSv1_3
                )
            )
        for future in as_completed(tasks):
            pass


    # -------------------------
    # REMOVE DUPLICATES
    # -------------------------
    cleaned = defaultdict(list)
    for version, entries in results.items():
        seen = set()
        for e in entries:
            if e["cipher"] not in seen:
                cleaned[version].append(e)
                seen.add(e["cipher"])
    return cleaned


def classify_cipher(cipher: str, version: str):
    reasons = []

    if version in ["TLSv1", "TLSv1.1"]:
        return "BAD", ["tls_obsolete"]

    if any(x in cipher for x in ["NULL", "EXPORT", "RC4"]):
        return "BAD", ["broken_cipher"]

    fs = ("ECDHE" in cipher or "DHE" in cipher)
    aead = any(x in cipher for x in ["GCM", "CHACHA20", "CCM"])

    if fs:
        reasons.append("pfs")

    if "CBC" in cipher:
        reasons.append("cbc_mode")
        return ("WEAK", reasons)

    if cipher.endswith("-SHA") and "GCM" not in cipher:
        reasons.append("sha1_hmac")
        return ("WEAK", reasons)

    if "CCM8" in cipher:
        reasons.append("weak_auth_tag")
        return ("WEAK", reasons)

    if aead:
        reasons.append("aead")
        return ("GOOD", reasons)
    return "WEAK", ["legacy_cipher"]



def analyze_cipher(cipher: str, version: str):
    result = {
        "cipher": cipher,
        "security": "UNKNOWN",
        "fs": False,
        "aead": False
    }

    # -------------------------
    # TLS legacy = BAD direct
    # -------------------------
    if version in ["TLSv1", "TLSv1.1"]:
        result["security"] = "BAD"
        return result

    # -------------------------
    # Forward secrecy detection
    # -------------------------
    if "ECDHE" in cipher or "DHE" in cipher:
        result["fs"] = True

    # -------------------------
    # AEAD detection (GOOD)
    # -------------------------
    if "GCM" in cipher or "CHACHA20" in cipher or "CCM" in cipher:
        result["aead"] = True

    # -------------------------
    # Weak patterns
    # -------------------------
    if "NULL" in cipher or "EXPORT" in cipher or "RC4" in cipher:
        result["security"] = "BAD"
    elif "CBC" in cipher:
        result["security"] = "WEAK"
    elif result["aead"]:
        result["security"] = "GOOD"
    else:
        result["security"] = "WEAK"
    return result


# ----------------------------
# ALPN
# ----------------------------
def test_alpn(host, port, args=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    try:
        with create_socket(host, port, args=args, timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.selected_alpn_protocol()
    except:
        return None


# ----------------------------
# Certificate info (SAFE)
# ----------------------------
def get_cert(host, port, args=None):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with create_socket(host, port, args=args, timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                if not der:
                    return {"error": "no certificate"}

                cert = x509.load_der_x509_certificate(
                    der,
                    default_backend()
                )

                public_key = cert.public_key()
                result = {
                    "version": ssock.version(),
                    "cipher": ssock.cipher(),
                    "subject": ssock.getpeercert().get("subject", []),
                    "issuer": ssock.getpeercert().get("issuer", []),
                    "san": ssock.getpeercert().get("subjectAltName", []),
                    "signature_algorithm":
                        cert.signature_hash_algorithm.name
                        if cert.signature_hash_algorithm else None,
                    "public_key_type":
                        public_key.__class__.__name__,
                    "key_size":
                        getattr(public_key, "key_size", None),
                    "rsa_exponent": None,
                }

                try:
                    result["rsa_exponent"] = (
                        public_key.public_numbers().e
                    )
                except Exception:
                    pass

                if result["public_key_type"] == "RSAPublicKey":
                    result["key_type"] = "RSA"
                else:
                    result["key_type"] = result["public_key_type"]
                return result
    except Exception as e:
        handle_error(e, "ERROR")
        return {"error": str(e)}


def get_cert_extended(host, port, args=None):
    """
    Extended certificate info (RSA size, exponent, signature algo)
    WITHOUT modifying existing get_cert()
    """

    ctx = ssl.create_default_context()
    with create_socket(host, port, args=args, timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(der, default_backend())
            public_key = cert.public_key()
            result = {
                # TLS session
                "version": ssock.version(),
                "cipher": ssock.cipher(),

                # Cert identity (kept simple like your style)
                "subject": ssock.getpeercert().get("subject", []),
                "issuer": ssock.getpeercert().get("issuer", []),
                "san": ssock.getpeercert().get("subjectAltName", []),

                # cryptographic info
                "signature_algorithm": cert.signature_hash_algorithm.name
                if cert.signature_hash_algorithm else None,

                "public_key_type": public_key.__class__.__name__,
                "key_size": getattr(public_key, "key_size", None),

                # RSA-only fields (safe fallback)
                "rsa_exponent": None,
            }

            # RSA specific extraction
            try:
                result["rsa_exponent"] = public_key.public_numbers().e
            except Exception:
                pass

            # Format like OpenSSL style (optional helper fields)
            if result["public_key_type"] == "RSAPublicKey":
                result["key_type"] = "RSA"
            else:
                result["key_type"] = result["public_key_type"]
            return result


def evaluate_cert_security(ext):
    score = 100
    issues = []
    sig = (ext.get("signature_algorithm") or "").lower()
    key_size = ext.get("key_size") or 0

    # -------------------------
    # Signature algorithm
    # -------------------------
    if "md5" in sig:
        score -= 60
        issues.append("MD5 signature (broken)")
    elif "sha1" in sig:
        score -= 30
        issues.append("SHA1 deprecated")
    elif "sha256" in sig or "sha384" in sig or "sha512" in sig:
        pass
    else:
        issues.append("unknown signature algorithm")

    # -------------------------
    # Key size
    # -------------------------
    if key_size < 1024:
        score -= 80
        issues.append("key too small (broken)")
    elif key_size < 2048:
        score -= 50
        issues.append("weak key size")
    elif key_size < 3072:
        score -= 15
        issues.append("acceptable but not strong")
    elif key_size >= 4096:
        score += 5

    # -------------------------
    # Final rating
    # -------------------------
    score = max(0, min(100, score))
    if score >= 90:
        rating = "EXCELLENT"
    elif score >= 75:
        rating = "OK"
    elif score >= 50:
        rating = "WEAK"
    else:
        rating = "CRITICAL"
    return rating, score, issues


# ----------------------------
# OUTPUT
# ----------------------------
def print_protocols(results):
    print(f"{G}[+] SSL/TLS support:{W}")
    for k, v in results.items():
        if k in ["SSLv3", "TLSv1", "TLSv1.1"]:
            if v:
                print(f" {k:<8} {Y}offered (deprecated){W}")
            else:
                print(f" {k:<8} {G}not offered (OK){W}")

        # TLS 1.2
        elif k == "TLSv1.2":
            if v:
                print(f" {k:<8} {G}offered (OK){W}")
            else:
                print(f" {k:<8} {R}not offered (weak server){W}")

        # TLS 1.3
        elif k == "TLSv1.3":
            if v:
                print(f" {k:<8} {G}offered (modern){W}")
            else:
                print(f" {k:<8} {R}not offered (missing modern TLS){W}")


def print_ciphers(ciphers):
    print(f"\n{G}[+] Cipher suites:{W}")
    for version in ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]:
        print(f"{M}{version}{W}")
        items = ciphers.get(version, [])
        if not items:
            print(f"  {R}-")
            print()
            continue

        for item in items:
            cipher = item["cipher"]
            bits = item["bits"]
            sec = item.get("security", "WEAK")
            reasons = item.get("reasons", [])

            if sec == "GOOD":
                color = G
            elif sec == "WEAK":
                color = Y
            else:
                color = R
            reason_str = f" [{', '.join(reasons)}]" if reasons else ""
            print(f"  {color}- {cipher} ({bits} bits){W}{reason_str}")        


def print_cert(cert):
    print(f"\n{G}[+] Certificate{W}")
    
    # -------------------------
    # CN
    # -------------------------
    cn = cert.get("subject") or cert.get("cn")
    print(f"{Y}CN:{W} {G}{cn or 'N/A'}{W}")

    # -------------------------
    # SAN
    # -------------------------
    san_data = cert.get("san", [])

    if san_data:
        # old ssl format
        if isinstance(san_data[0], tuple):
            san = ", ".join(x[1] for x in san_data)

        # cryptography format
        else:
            san = ", ".join(str(x) for x in san_data)
    else:
        san = "N/A"
    print(f"{Y}SAN:{W} {san}")

    # -------------------------
    # Issuer
    # -------------------------
    issuer = cert.get("issuer")

    if not issuer:
        print("  N/A")

    # old ssl.getpeercert() format
    elif isinstance(issuer, (list, tuple)):
        for part in issuer:
            for item in part:
                print(f"  - {item[0]}: {item[1]}")

    # cryptography string format
    elif isinstance(issuer, str):
        print(f"  {issuer}")

    else:
        print(f"  {issuer}")

    # -------------------------
    # TLS / Cipher
    # -------------------------
    print(f"{Y}TLS Version:{W} {G}{cert.get('version') or 'N/A'}{W}")
    cipher = cert.get("cipher")
    if cipher:
        print(f"{Y}Cipher:{W} {G}{cipher[0]}{W} ({cipher[2]} bits)")
    else:
        print(f"{Y}Cipher:{W} N/A")

    fmt = "%b %d %H:%M:%S %Y %Z"
    try:
        not_before = cert.get("not_before")
        not_after = cert.get("not_after")

        print(f"{Y}Validity:{W}")
        print(f"  Not Before: {not_before}")
        print(f"  Not After : {not_after}")

        # -------------------------
        # Convert if old OpenSSL string
        # -------------------------
        if isinstance(not_after, str):
            fmt = "%b %d %H:%M:%S %Y %Z"

            expiry = datetime.strptime(
                not_after,
                fmt
            ).replace(tzinfo=timezone.utc)

            start = datetime.strptime(
                not_before,
                fmt
            ).replace(tzinfo=timezone.utc)

        else:
            # already datetime objects
            expiry = not_after
            start = not_before

        if not expiry or not start:
            print(f"{Y}Validity: unavailable{W}")
            return

        now = datetime.now(timezone.utc)
        total_days = (expiry - start).days
        remaining_days = (expiry - now).days

        # -------------------------
        # STATUS
        # -------------------------
        if remaining_days < 0:
            status = f"{R}EXPIRED{W}"
        elif total_days > 825:
            status = f"{Y}too long lifetime ({total_days} days){W}"
        elif remaining_days < 30:
            status = f"{Y}expiring soon ({remaining_days} days){W}"
        else:
            status = (
                f"{G}OK "
                f"({remaining_days} days left, "
                f"{total_days} days total){W}"
            )
        print(f"  Lifetime  : {total_days} days")
        print(f"  Remaining : {remaining_days} days")
        print(f"  Status    : {status}")
    except Exception as e:
        print(f"{Y}Validity: N/A{W}")
        print(f"  DEBUG: {e}")


def print_cert_extended(ext):
    print(f"\n{G}[+] Extended Certificate Info{W}")
    sig = ext.get("signature_algorithm", "N/A")
    key_type = ext.get("key_type", "N/A")
    key_size = ext.get("key_size", "N/A")
    exp = ext.get("rsa_exponent")

    # -------------------------
    # Signature Algorithm
    # -------------------------
    print(f"{Y}Signature Algorithm{W:<5} {W}{sig.upper()}{W}")

    # -------------------------
    # Key line (OpenSSL style)
    # -------------------------
    if key_type == "RSA" and exp:
        print(f"{Y}Server key size{W:<9} {W}RSA {key_size} bits (exponent is {exp}){W}")
    else:
        print(f"{Y}Server key size{W:<9} {W}{key_type} {key_size} bits{W}")

def print_cert_rating(ext):
    rating, score, issues = evaluate_cert_security(ext)
    print(f"Score : {score}/100")
    if rating == "EXCELLENT":
        color = G
    elif rating == "OK":
        color = C
    elif rating == "WEAK":
        color = Y
    else:
        color = R

    print(f"Rating: {color}{rating}{W}")
    if issues:
        print(f"{Y}Issues:{W}")
        for i in issues:
            print(f" - {i}")


# ----------------------------
# MAIN
# ----------------------------
def ssl_that(HOST, args):
    print(f"\n{C}[+] SSL Scanning {HOST}:{PORT}{W}")

    proto = test_protocol(HOST, PORT, args=args)
    print_protocols(proto)

    ciphers = test_ciphers(HOST, PORT, args=args)
    print_ciphers(ciphers)
    print(f"\n{M}Double Check at: {W}")
    print(f"https://www.ssllabs.com/ssltest/analyze.html?d={HOST}")
    print(f"testssl --color 3 {HOST}")
    
    alpn = test_alpn(HOST, PORT, args=args)
    print(f"\n{G}[+] ALPN:{W}")
    if alpn == "h2":
        print(f"  {G}OK - HTTP/2 supported ({alpn}){W}")
    elif alpn == "http/1.1":
        print(f"  {Y}OK - only HTTP/1.1 ({alpn}){W}")
    elif alpn is None:
        print(f"  {R}NOT SUPPORTED - no ALPN{W}")
    else:
        print(f"  {C}UNKNOWN - {alpn}{W}")

    cert = get_cert(HOST, PORT, args=args)
    if cert.get("error"):
        print(f"{R}[!] Certificate retrieval failed:{W} {cert['error']}")
        return

    print_cert(cert)
    ext = get_cert_extended(HOST, PORT, args=args)
    if ext.get("error"):
        print(f"{R}[!] Extended certificate retrieval failed:{W} {ext['error']}")
        return

    print_cert_extended(ext)
    print_cert_rating(ext)