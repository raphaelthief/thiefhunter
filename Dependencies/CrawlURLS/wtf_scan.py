import re, tldextract, base64
from urllib.parse import urljoin, urlparse
from Dependencies.displays import M, W, R, Y, G, C
from Dependencies.get_request import get_request

EMAIL_REGEX = r'\b[a-zA-Z0-9][a-zA-Z0-9._%+-]{1,63}@[a-zA-Z0-9.-]{2,}\.[a-zA-Z]{2,}\b'
PHONE_REGEX = r'\b(?:\+33|0)[67][0-9]{8}\b' # French only 06 / 07

SECRET_REGEX = [
    r'api[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']',
    r'secret["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']',
    r'token["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']',
    r'Bearer\s+[A-Za-z0-9\-_\.]+',
]

SENSITIVE_EXTENSIONS = [
    ".env",
    ".env.local",
    ".env.production",
    ".env.dev",
    ".ini",
    ".conf",
    ".config",
    ".yaml",
    ".yml",

    ".sql",
    ".sqlite",
    ".db",
    ".bak",
    ".backup",
    ".old",
    ".dump",
    ".tar",
    ".gz",
    ".zip",
    ".7z",

    ".htaccess",
    ".htpasswd",
    "web.config",
    "server.xml",

    ".git",
    ".git/config",
    ".svn",
    ".DS_Store",

    ".log",
    ".logs",

    ".pem",
    ".key",
    ".crt",
    ".p12",
    ".pfx",

    ".swp",
    ".swo",
    ".DS_Store",
]

STATIC_FILE_REGEX = re.compile(
    r"\.(jpg|jpeg|png|gif|svg|webp|bmp|ico|mp4|webm|mp3|wav|woff2?|ttf|eot|css|scss|sass|less|map)(\?|$)",
    re.IGNORECASE
)

SENSITIVE_URL = [
    "/admin",
    "/administrator",
    "/admin/login",
    "/admin.php",
    "/admin.html",
    "/admin.asp",
    "/admin.aspx",
    "/admin.jsp",
    "/admin-panel",
    "/adminpanel",
    "/controlpanel",
    "/cp",
    "/cpanel",
    "/dashboard",
    "/manage",
    "/manager",
    "/backend",
    "/backoffice",
    "/console",
    "/system",
    "/sys",
    "/root",
    "/superadmin",
    "/staff",
    "/internal",
    "/private",
    "/secure",
    "/secret",
    "/hidden",
    "/dev",
    "/development",
    "/test",
    "/testing",
    "/staging",
    "/preprod",
    "/beta",
    "/debug",
    "/debug/",
    "/trace",
    "/logs",
    "/log",
    "/errors",
    "/error",
    "/status",
    "/health",
    "/healthz",
    "/metrics",
    "/actuator",
    "/monitoring",
    "/prometheus",
    "/grafana",
    "/kibana",

    "/api",
    "/api/v1",
    "/api/v2",
    "/rest",
    "/graphql",
    "/graphiql",
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/openapi.json",
    "/api-docs",
    "/docs",
    "/redoc",
    "/ws",
    "/socket.io",
    "/websocket",

    "/auth",
    "/login",
    "/signin",
    "/logout",
    "/register",
    "/signup",
    "/oauth",
    "/oauth2",
    "/sso",
    "/session",
    "/token",
    "/jwt",
    "/authentication",
    "/authorize",

    "/user",
    "/users",
    "/account",
    "/accounts",
    "/profile",
    "/me",
    "/settings",

    "/config",
    "/config.php",
    "/config.json",
    "/config.yml",
    "/config.yaml",
    "/settings.php",
    "/env",
    "/.env",
    "/.env.local",
    "/.git",
    "/.git/config",
    "/.svn",
    "/.hg",
    "/.DS_Store",
    "/web.config",
    "/phpinfo.php",
    "/info.php",

    "/backup",
    "/backups",
    "/backup.zip",
    "/backup.tar.gz",
    "/site.zip",
    "/www.zip",
    "/db.sql",
    "/dump.sql",
    "/database.sql",
    "/backup.sql",
    "/old",
    "/archive",
    "/archives",
    "/bak",
    "/tmp",
    "/temp",

    "/uploads",
    "/files",
    "/download",
    "/export",
    "/import",

    "/jenkins",
    "/gitlab",
    "/gitea",
    "/sonarqube",
    "/nexus",
    "/artifactory",
    "/phpmyadmin",
    "/pma",
    "/adminer",
    "/mysql",
    "/redis",
    "/mongo-express",
    "/elasticsearch",
    "/rabbitmq",
    "/portainer",
    "/k8s",
    "/kubernetes",
    "/docker",
    "/containers",

    "/server-status",
    "/nginx_status",
    "/server-info",

    "/vault",
    "/secrets",
    "/keys",
    "/certs",
    "/certificate",
    "/credentials",

    "/payment",
    "/payments",
    "/billing",
    "/invoice",
    "/invoices",

    "/hr",
    "/finance",
    "/crm",
    "/erp",

    "/mobile",
    "/app",
    "/apps",

    "/v1",
    "/v2",
    "/v3",

    "/graphql/playground",
    "/playground",
    "/console/login",

    "/sitemap.xml",
    "/robots.txt",
    "/crossdomain.xml",
    "/security.txt"
]

SENSITIVE_PATTERNS = {
    # AWS
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(r"(?i)aws(.{0,20})?(secret|access)?.{0,20}['\"][0-9a-zA-Z\/+=]{40}['\"]"),

    # Google
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),

    # Stripe
    "stripe_live_secret": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "stripe_test_secret": re.compile(r"sk_test_[0-9a-zA-Z]{24,}"),

    # GitHub
    "github_token": re.compile(r"github_pat_[0-9a-zA-Z_]{20,}|ghp_[0-9A-Za-z]{36}|gho_[0-9A-Za-z]{36}"),

    # Slack
    "slack_token": re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,}"),

    # Discord
    "discord_token": re.compile(r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}"),

    # JWT
    "jwt_token": re.compile(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+"),

    # Generic API keys
    "generic_api_key": re.compile(
        r"(?i)(api[_-]?key|secret|token|access[_-]?token)"
        r"\s*[:=]\s*['\"]?[0-9a-zA-Z\-_]{16,}['\"]?"
    ),

    # Bearer tokens
    "bearer_token": re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"),

    # Basic auth
    "basic_auth": re.compile(r"Basic\s+[A-Za-z0-9+/=]{10,}"),

    # Private keys
    "private_key": re.compile(
        r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP)? ?PRIVATE KEY-----"
    ),

    # SSH keys
    "ssh_public_key": re.compile(r"ssh-rsa\s+[A-Za-z0-9+/]+[=]{0,3}"),

    # Firebase
    "firebase_url": re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"),

    # MongoDB URI
    "mongodb_uri": re.compile(
        r"mongodb(\+srv)?:\/\/[^:\s]+:[^@\s]+@[^\/\s]+"
    ),

    # PostgreSQL URI
    "postgres_uri": re.compile(
        r"postgres(ql)?:\/\/[^:\s]+:[^@\s]+@[^\/\s]+"
    ),

    # MySQL URI
    "mysql_uri": re.compile(
        r"mysql:\/\/[^:\s]+:[^@\s]+@[^\/\s]+"
    ),

    # Password in config
    "password_assignment": re.compile(
        r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"].{4,}['\"]"
    ),

    # .env style
    "dotenv_secret": re.compile(
        r"(?i)^[A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD)[A-Z0-9_]*=.*$",
        re.MULTILINE
    ),

    # Twilio
    "twilio_api_key": re.compile(r"SK[0-9a-fA-F]{32}"),

    # SendGrid
    "sendgrid_api_key": re.compile(r"SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"),

    # RSA PEM blocks
    "pem_file": re.compile(
        r"-----BEGIN CERTIFICATE-----"
    ),

    # Heroku
    "heroku_api_key": re.compile(
        r"(?i)heroku(.{0,20})?[0-9a-f]{32}"
    ),

    # Generic secrets
    "generic_secret": re.compile(
        r"(?i)(secret|client_secret|app_secret)"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9\/+=\-_]{12,}['\"]?"
    ),
}

SENSITIVE_KEYWORDS = [
    # --- AUTH / LOGIN ---
    "admin", "administrator", "root", "superuser",
    "login", "signin", "sign-in", "register",
    "auth", "authentication", "authorization",
    "oauth", "sso", "session", "jwt", "bearer",

    # --- KEYS / SECRETS ---
    "password", "passwd", "pwd",
    "secret", "token", "api_key", "apikey",
    "access_token", "refresh_token",
    "client_secret", "client_id",
    "private_key", "public_key", "ssh_key",
    "encryption_key", "crypt_key", "master_key",
    "hmac_key", "keystore",

    # --- CLOUD / PROVIDERS ---
    "aws_access_key", "aws_secret_key",
    "google_api_key", "firebase_api_key",
    "stripe_api_key", "github_token",
    "gitlab_token", "slack_token", "discord_token",

    # --- INFRA / SERVICES ---
    "webhook", "credentials",
    "database_url", "db_password", "db_user",
    "smtp_password", "smtp_user",
    "ftp_password", "ftp_user",
    "proxy_password", "proxy_user",

    # --- ENVIRONMENTS ---
    "dev", "development", "test", "testing",
    "staging", "preprod", "pre-prod",
    "sandbox", "debug", "beta",

    # --- DATA / FILES ---
    "backup", "backups", "dump",
    "export", "restore", "archive",
    "internal", "private", "intranet",
    "confidential", "restricted",

    # --- API / DOCS ---
    "api", "graphql", "swagger", "openapi",
    "docs", "documentation",

    # --- SYSTEM ---
    "config", "settings", "system",
    "monitor", "metrics", "health", "status",

    # --- FILE OPS ---
    "upload", "uploads",
    "download", "file", "files",
]


def is_probably_base64(s):
    if len(s) < 15:
        return False
    if len(s) % 4 != 0:
        return False
    return re.fullmatch(r'[A-Za-z0-9+/=]+', s) is not None


def try_decode_base64(s):
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        return None


def extract_base64(text):
    results = []
    chunks = re.split(r'[^A-Za-z0-9+/=]+', text)
    for chunk in chunks:
        if not is_probably_base64(chunk):
            continue

        decoded = try_decode_base64(chunk)
        if not decoded:
            continue

        if len(decoded) < 15:
            continue

        try:
            results.append(decoded.decode("utf-8"))
        except UnicodeDecodeError:
            pass
    return results


def is_valid_email(email):
    local, domain = email.rsplit("@", 1)

    if len(local) < 2:
        return False

    if len(domain.split(".")) < 2:
        return False

    tld = domain.split(".")[-1]

    if len(tld) < 2 or not tld.isalpha():
        return False

    if any(c.isdigit() for c in tld):
        return False
    return True

def is_sensitive_url(url):
    lower = url.lower()
    path = urlparse(url).path.lower()

    if any(path.endswith(ext) for ext in SENSITIVE_EXTENSIONS):
        return True

    if any(k in lower for k in SENSITIVE_KEYWORDS):
        return True

    return False

def is_personal_email(email, domain):
    return domain not in email

def extract_api_endpoints(html):
    return re.findall(r'https?://[a-zA-Z0-9.-]+/(?:api|graphql|v\d+)/[^\s"\'<>]*', html)

def extract_js(html):
    return re.findall(r'<script.*?>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)

def is_valid_url(url):
    bad_ext = (".png", ".jpg", ".jpeg", ".gif", ".css", ".svg", ".woff", ".ttf")
    return not url.lower().endswith(bad_ext)

def extract_from_text(text):
    emails = [
    e for e in re.findall(EMAIL_REGEX, text)
    if is_valid_email(e)
    ]
    phones = set(re.findall(PHONE_REGEX, text))
    secrets = set()
    for pattern in SECRET_REGEX:
        matches = re.findall(pattern, text, re.IGNORECASE)
        secrets.update(matches)

    return emails, phones, secrets

def parse_robots(start_url):
    parsed = urlparse(start_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    disallowed = set()

    try:
        res = get_request(args, robots_url)
        for line in res.text.splitlines():
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    full_url = urljoin(start_url, path)
                    disallowed.add(full_url)
    except:
        pass
    return disallowed

def scan_sensitive_content(text, patterns, seen):
    findings = {}
    CONTEXT_BEFORE = 30
    CONTEXT_AFTER = 30
    
    for name, pattern in patterns.items():
        for match in pattern.finditer(text):
            start, end = match.span()
            matched_text = match.group(0)
            if matched_text in seen:
                continue
            seen.add(matched_text)

            line_start = text.rfind("\n", 0, start) + 1
            line_end = text.find("\n", end)
            if line_end == -1:
                line_end = len(text)

            context_start = max(line_start, start - CONTEXT_BEFORE)
            context_end = min(line_end, end + CONTEXT_AFTER)
            snippet = text[context_start:context_end]
            local_start = start - context_start
            local_end = local_start + (end - start)
            highlighted = (
                snippet[:local_start]
                + f"{R}{snippet[local_start:local_end]}{W}"
                + snippet[local_end:]
            )
            findings.setdefault(name, []).append(highlighted)
    return findings

def scan_sensitive_urls(urls):
    found = set()
    for url in urls:
        if STATIC_FILE_REGEX.search(url):
            continue
            
        if "data:image" in url.lower():
            continue

        lower = url.lower()
        if any(ext in lower for ext in SENSITIVE_EXTENSIONS):
            found.add(url)
            continue

        if any(k in lower for k in SENSITIVE_URL):
            found.add(url)
    return found


def wtf_scan(start_url, args, max_depth=2):
    found_seen = set()
    visited = set()
    found_emails = set()
    found_phones = set()
    found_secrets = set()
    found_apis = set()
    found_sensitive_keywords = {}
    found_sensitive_urls = set()
    found_subdomains = set()
    found_base64 = set()
    
    ext = tldextract.extract(args.url)
    base_domain = f"{ext.domain}.{ext.suffix}"
    
    def crawl(url, depth):
        if depth > max_depth or url in visited:
            return

        visited.add(url)
        try:
            res = get_request(args, url)
            if args.verbose:
                print(f"{Y}[HTTP] {W}{res.status_code} (DEPTH={depth}) -> {url}")
                
            text = res.text
            current_domain = urlparse(url).netloc
            if current_domain.endswith(base_domain):
                found_subdomains.add(current_domain)
            
            # 0. headers b64 scan
            for k, v in res.headers.items():
                if isinstance(v, str):
                    for decoded in extract_base64(v):
                        found_base64.add(decoded)

            # 1. HTML scan
            emails, phones, secrets = extract_from_text(text)
            found_emails.update(emails)
            found_phones.update(phones)
            found_secrets.update(secrets)
            b64_decoded = extract_base64(text)
            for item in b64_decoded:
                found_base64.add(item)


            # 2. JS scan
            for script in extract_js(text):
                e, p, s = extract_from_text(script)
                found_emails.update(e)
                found_phones.update(p)
                found_secrets.update(s)
                for item in extract_base64(script):
                    found_base64.add(item)


            # 3. API scan
            apis = extract_api_endpoints(text)
            found_apis.update(apis)

            # 4. Sensitive keyword scan in source code
            results = scan_sensitive_content(
                text,
                SENSITIVE_PATTERNS,
                found_seen
            )

            for key, values in results.items():
                found_sensitive_keywords.setdefault(key, [])
                found_sensitive_keywords[key].extend(values)

            links = re.findall(r'(?:href|src)=["\'](.*?)["\']', text)
            found_sensitive_urls.update(scan_sensitive_urls(links))

            # 5 Detect subdomain in discovered links
            domain_matches = re.findall(
                r'https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
                text
            )

            for domain in domain_matches:
                if domain.endswith(base_domain):
                    found_subdomains.add(domain)

            for link in links:
                link = urljoin(url, link)
                parsed = urlparse(link)
                domain = parsed.netloc

                if domain.endswith(base_domain):
                    found_subdomains.add(domain)

                if domain != base_domain and not domain.endswith("." + base_domain):
                    continue

                if not is_valid_url(link):
                    continue

                if link not in visited:
                    crawl(link, depth + 1)

        except:
            pass

    crawl(start_url, 0)
    robots_urls = parse_robots(start_url)

    return {
        "emails": sorted(found_emails),
        "phones": sorted(found_phones),
        "secrets": sorted(found_secrets),
        "robots": sorted(robots_urls),
        "apis": sorted(found_apis),
        "sensitive_keywords": found_sensitive_keywords,
        "sensitive_urls": sorted(found_sensitive_urls),
        "subdomains": sorted(found_subdomains),
        "base64": sorted(found_base64),
    }
