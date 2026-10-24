import re
from urllib.parse import urlparse, urljoin
from Dependencies.displays import M, W, R, Y, G, C, handle_error
from Dependencies.get_request import get_request
from Dependencies.default_passwords.list_accounts import search_default_credentials


TECH_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Drupal-Cache",
    "X-Generator",
    "X-Frame-Options",
    "Set-Cookie",
    "X-Rendered-By",
    "Via",
]


TECH_PATTERNS = [
    (r'zabbix', "Zabbix"),
    (r'truenas|middlewared', "TrueNAS"),
    (r'synology|diskstation', "Synology DSM"),
    (r'fortigate|fortiweb|fortianalyzer', "Fortinet"),
    (r'juniper|junos', "Juniper"),
    (r'cisco|ios_xe|ios_xr', "Cisco"),
    (r'pfsense|pfSense', "pfSense"),
    (r'sonicwall', "SonicWall"),
    (r'watchguard', "WatchGuard"),
    (r'opnsense', "OPNsense"),
    (r'proxmox', "Proxmox"),
    (r'vmware|vcenter|vsphere', "VMware vCenter"),
    (r'apache tomcat', "Apache Tomcat"),
    (r'weblogic|wls', "Oracle WebLogic"),
    (r'webshpere|was', "IBM WebSphere"),
    (r'glassfish', "Oracle GlassFish"),
    (r'nginx', "Nginx"),
    (r'apache/', "Apache"),
    (r'iis/', "Microsoft IIS"),
    (r'haproxy', "HAProxy"),
    (r'nextcloud', "Nextcloud"),
    (r'owncloud', "OwnCloud"),
    (r'wordpress', "WordPress"),
    (r'joomla', "Joomla"),
    (r'drupal', "Drupal"),
    (r'kibana', "Kibana"),
    (r'elasticsearch', "Elasticsearch"),
    (r'jenkins', "Jenkins"),
    (r'gitlab', "GitLab"),
    (r'gitea', "Gitea"),
    (r'portainer', "Portainer"),
    (r'docker', "Docker"),
    (r'keycloak', "Keycloak"),
    (r'apache ofbiz', "Apache OFBiz"),
    (r'netapp|ontap', "NetApp ONTAP"),
    (r'dell|unity|powerstore', "Dell EMC"),
    (r'hpe|hpe oneview', "HPE"),
    (r'lenovo|thinkserver', "Lenovo"),
    (r'hp color laserjet|hp laserjet', "HP Printer"),
    (r'raritan|dominion', "Raritan"),
    (r'ipmi|ipmi2', "IPMI"),
    (r'kerbynet|zeroshell', "ZeroShell"),
    (r'peoplesoft|pslogin', "Oracle PeopleSoft"),
    (r'loitec|loytec', "Loytec"),
    (r'thecus', "Thecus"),
    (r'iomega|my book', "Iomega"),
    (r'laCie', "LaCie"),
    (r'prometheus', "Prometheus"),
    (r'zabbix', "Zabbix"),
    (r'checkmk', "Checkmk"),
    (r'icinga', "Icinga"),
    (r'nagios', "Nagios"),
    (r'prtg', "PRTG"),
    (r'librenms', "LibreNMS"),
    (r'netdata', "Netdata"),
    (r'graylog', "Graylog"),
    (r'opensearch', "OpenSearch"),

    # Virtualisation & infrastructure
    (r'proxmox', "Proxmox"),
    (r'vmware|vsphere|vcenter', "VMware vCenter"),
    (r'xenserver|xcp-ng', "XenServer / XCP-ng"),
    (r'xen orchestra', "Xen Orchestra"),
    (r'openstack', "OpenStack"),
    (r'nutanix', "Nutanix"),
    (r'cockpit', "Cockpit"),
    (r'webmin', "Webmin"),
    (r'virtualmin', "Virtualmin"),
    (r'ispconfig', "ISPConfig"),
    (r'plesk', "Plesk"),
    (r'cpanel', "cPanel"),
    (r'vesta|hestia', "HestiaCP / VestaCP"),

    # Network & security appliances
    (r'palo alto|pan-os', "Palo Alto Networks"),
    (r'checkpoint|check point', "Check Point"),
    (r'f5 big-ip|bigip', "F5 BIG-IP"),
    (r'citrix netscaler|netscaler', "Citrix NetScaler"),
    (r'aruba|arubaos', "HPE Aruba"),
    (r'ubiquiti|unifi', "Ubiquiti UniFi"),
    (r'mikrotik|routeros', "MikroTik RouterOS"),
    (r'meraki', "Cisco Meraki"),
    (r'openvpn', "OpenVPN"),
    (r'wireguard', "WireGuard"),
    (r'clearpass', "Aruba ClearPass"),
    (r'ise.*login|cisco ise', "Cisco ISE"),
    (r'vpn.*login|login.*vpn', "VPN Portal"),

    # Identity & access management
    (r'keycloak', "Keycloak"),
    (r'authentik', "Authentik"),
    (r'authelia', "Authelia"),
    (r'openam|forgerock', "ForgeRock"),
    (r'auth0', "Auth0"),
    (r'casdoor', "Casdoor"),
    (r'kanidm', "Kanidm"),
    (r'privacyidea', "privacyIDEA"),
    (r'wallix', "WALLIX"),
    (r'beyondtrust', "BeyondTrust"),
    (r'cyberark', "CyberArk"),
    (r'duo.*login', "Cisco Duo"),

    # CI/CD, DevOps & container platforms
    (r'jenkins', "Jenkins"),
    (r'gitlab', "GitLab"),
    (r'gitea', "Gitea"),
    (r'forgejo', "Forgejo"),
    (r'grafana', "Grafana"),
    (r'argocd|argo cd', "Argo CD"),
    (r'harbor', "Harbor Registry"),
    (r'rancher', "Rancher"),
    (r'portainer', "Portainer"),
    (r'kubernetes|k8s dashboard', "Kubernetes Dashboard"),
    (r'traefik', "Traefik"),
    (r'consul', "HashiCorp Consul"),
    (r'vault', "HashiCorp Vault"),
    (r'nexus repository', "Sonatype Nexus"),
    (r'artifactory', "JFrog Artifactory"),
    (r'azure devops', "Azure DevOps"),

    # Databases & administration
    (r'phpmyadmin', "phpMyAdmin"),
    (r'phppgadmin', "phpPgAdmin"),
    (r'pgadmin', "pgAdmin"),
    (r'adminer', "Adminer"),
    (r'cloudbeaver', "CloudBeaver"),
    (r'clickhouse', "ClickHouse"),
    (r'couchdb', "Apache CouchDB"),
    (r'mongodb.*(express|login)|mongo-express', "mongo-express"),
    (r'redis commander|redis-commander', "Redis Commander"),
    (r'orientdb', "OrientDB"),
    (r'neo4j', "Neo4j"),
    (r'cockroachdb', "CockroachDB"),

    # Web applications & collaboration
    (r'roundcube', "Roundcube"),
    (r'zimbra', "Zimbra"),
    (r'iredmail|iredadmin', "iRedMail"),
    (r'keyhelp', "KeyHelp"),
    (r'collabora', "Collabora Online"),
    (r'onlyoffice', "ONLYOFFICE"),
    (r'mattermost', "Mattermost"),
    (r'rocketchat|rocket.chat', "Rocket.Chat"),
    (r'element.*login|matrix', "Matrix"),
    (r'bookstack', "BookStack"),
    (r'wiki\.js|wikijs', "Wiki.js"),
    (r'vaultwarden', "Vaultwarden"),
    (r'bitwarden', "Bitwarden"),
    (r'paperless-ngx', "Paperless-ngx"),

    # Backup & storage
    (r'veeam', "Veeam"),
    (r'commvault', "Commvault"),
    (r'vel ero|velero', "Velero"),
    (r'bareos', "Bareos"),
    (r'urbackup', "UrBackup"),
    (r'openmediavault', "OpenMediaVault"),
    (r'unraid', "Unraid"),
    (r'qnap|qts', "QNAP"),
    (r'synology|diskstation', "Synology DSM"),
    (r'ceph', "Ceph Dashboard"),
    (r'minio', "MinIO"),

    # Security monitoring & management
    (r'wazuh', "Wazuh"),
    (r'security onion', "Security Onion"),
    (r'tenable|nessus', "Tenable Nessus"),
    (r'qualys', "Qualys"),
    (r'rapid7|insightvm', "Rapid7 InsightVM"),
    (r'greenbone|openvas', "Greenbone / OpenVAS"),
    (r'elastic.*security', "Elastic Security"),
    (r'fortisoar', "FortiSOAR"),
    (r'splunk', "Splunk"),
    (r'sentinel.*login', "Microsoft Sentinel"),

    # Remote access & support
    (r'guacamole', "Apache Guacamole"),
    (r'rdweb|remote desktop web', "Microsoft RD Web"),
    (r'parsec', "Parsec"),
    (r'anydesk', "AnyDesk"),
    (r'teamviewer', "TeamViewer"),
    (r'rustdesk', "RustDesk"),
    (r'meshcentral', "MeshCentral"),
    (r'kasm', "Kasm Workspaces"),
    (r'noVNC|novnc', "noVNC"),
    (r'freerdp.*web', "FreeRDP Web"),
    
    # HP
    (r'hp.*(?:laserjet|officejet|deskjet|pagewide|designjet)',
     "HP Printer"),
    (r'\bhp\s+(?:jetdirect|web\s+jetadmin)\b',
     "HP JetDirect / Web Jetadmin"),

    # Brother
    (r'brother.*(?:printer|mfc|hl-|dcp-|ql-|pt-)',
     "Brother Printer"),
    (r'\bbradmin\b', "Brother BRAdmin"),

    # Canon
    (r'canon.*(?:printer|imagerunner|imageclass|pixma|maxify)',
     "Canon Printer"),

    # Epson
    (r'epson.*(?:printer|workforce|ecotank|surecolor|expression)',
     "Epson Printer"),

    # Lexmark
    (r'lexmark', "Lexmark Printer"),

    # Xerox
    (r'xerox|workcentre|versalink|altalink',
     "Xerox Printer"),

    # Kyocera
    (r'kyocera|ecosys|taskalfa',
     "Kyocera Printer"),

    # Ricoh
    (r'ricoh|im\s*c\d{3,4}|aficio',
     "Ricoh Printer"),

    # Konica Minolta
    (r'konica\s*minolta|bizhub',
     "Konica Minolta Printer"),

    # Sharp
    (r'sharp.*(?:printer|copier)|mx-\d{3,4}',
     "Sharp Printer"),

    # Toshiba
    (r'toshiba.*(?:printer|e-studio)|e-studio',
     "Toshiba Printer"),

    # Zebra label printers
    (r'zebra.*(?:printer|technologies)|zebra\s*(?:zt|zd|gx|zm)\d+',
     "Zebra Printer"),

    # OKI
    (r'\boki\b|oki\s+data|microline',
     "OKI Printer"),

    # Fujifilm / Fujitsu
    (r'fujifilm.*(?:printer|apeos)|apeos',
     "Fujifilm Apeos"),

    # Samsung printers
    (r'samsung.*(?:printer|xpress|clp-|ml-|scx-)',
     "Samsung Printer"),

    # Print management / print servers
    (r'papercut', "PaperCut"),
    (r'printix', "Printix"),
    (r'cups', "CUPS Print Server"),
    (r'printeron', "PrinterOn"),
    (r'pharos', "Pharos Print Management"),
    (r'printerlogic|stampli.*printer',
     "PrinterLogic")
]


LOGIN_PATTERNS = [
    r'<input[^>]+type=["\']password["\']',
    r'<input[^>]+name=["\'](?:password|passwd|pwd)["\']',
    r'<form[^>]+(?:login|signin|sign-in|authenticate|auth)',
    r'(?:login|signin|sign-in)[^"\']{0,80}(?:password|username)',
    r'(?:password|username)[^"\']{0,80}(?:login|signin|sign-in)'
]


JS_REDIRECT_PATTERNS = [
    r'document\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
    r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
    r'location\.href\s*=\s*["\']([^"\']+)["\']',
    r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+url=([^"\'>\s]+)',
    r'redirect_suffix\s*=\s*["\']([^"\']+)["\']'
]


def is_login_page(html: str) -> bool:
    return any(re.search(pattern, html, re.I | re.S) for pattern in LOGIN_PATTERNS)


def find_login_url(html: str, base_url: str) -> str | None:
    from urllib.parse import urljoin
    login_url_patterns = [
        r'(?:href|action|src|url)\s*=\s*["\']([^"\']*login[^"\']*)["\']',
        r'(?:href|action|src|url)\s*=\s*["\']([^"\']*log\s*-?\s*in[^"\']*)["\']',
        r'(?:href|action|src|url)\s*=\s*["\']([^"\']*signin[^"\']*)["\']',
        r'(?:href|action|src|url)\s*=\s*["\']([^"\']*sign\s*-?\s*in[^"\']*)["\']',
        r'(?:href|action|src|url)\s*=\s*["\']([^"\']*auth[^"\']*)["\']',
        r'(?:href|action|src|url)\s*=\s*["\']([^"\']*session[^"\']*)["\']',
        r'(?:href|action|src|url)\s*=\s*["\']([^"\']*sso[^"\']*)["\']',
        r'(?:href|action|src|url)\s*=\s*["\']([^"\']*cgi-bin[^"\']*)["\']'
    ]

    candidates = []
    for pattern in login_url_patterns:
        for m in re.finditer(pattern, html, re.I):
            url = m.group(1).strip()
            if not url or url.startswith(('javascript:', 'data:', '#', 'mailto:')):
                continue

            if re.search(r'logout|signout|sign-out|log-?out|deconnect', url, re.I):
                continue
            candidates.append(urljoin(base_url, url))

    seen = set()
    for url in candidates:
        if url not in seen:
            seen.add(url)
            return url
    return None


def follow_js_redirects(resp, args, max_hops=5):
    visited = {resp.url}
    for _ in range(max_hops):
        html = resp.text
        for pattern in JS_REDIRECT_PATTERNS:
            m = re.search(pattern, html, re.I)
            if m:
                target_url = urljoin(resp.url, m.group(1).strip())
                if target_url in visited:
                    break
                visited.add(target_url)
                print(f"    {G}- {W}JS redirect → {target_url}")
                resp = get_request(args, target_url, timeout=30, allow_redirects=True)
                break
        else:
            break
    return resp


def detect_tech(args, url: str = None) -> dict:
    target_url = url or args.url
    resp = get_request(args, target_url, timeout=30, allow_redirects=True)
    html = resp.text
    result = {
        "url": target_url,
        "status": resp.status_code,
        "title": "",
        "headers": {},
        "tech": set(),
        "generator": "",
        "is_login": False,
    }

    # 1. Title
    m = re.search(r'<title[^>]*>(.*?)</title>', html, re.I | re.S)
    if m:
        result["title"] = m.group(1).strip()

    # 2. Look in the title (fast path)
    for pattern, name in TECH_PATTERNS:
        if re.search(pattern, result["title"], re.I):
            result["tech"].add(name)

    if result["tech"]:
        result["is_login"] = is_login_page(html)  # ← AJOUTE CHERE
        result["tech"] = sorted(result["tech"])
        return result


    # 3. Not found in the title
    # Check if this is a login page
    result["is_login"] = is_login_page(html)

    if not result["is_login"]:
        result["tech"] = []
        return result

    # 4. This is a login page
    # Get usefull headers.
    for h in TECH_HEADERS:
        if h in resp.headers:
            result["headers"][h] = resp.headers[h]

    # 5. Search in all html front end
    for pattern, name in TECH_PATTERNS:
        if re.search(pattern, html, re.I):
            result["tech"].add(name)

    # 6. Search in the headers
    for value in result["headers"].values():
        for pattern, name in TECH_PATTERNS:
            if re.search(pattern, value, re.I):
                result["tech"].add(name)

    # 7. Meta generator
    m = re.search(
        r'<meta\b(?=[^>]*\bname=["\']generator["\'])'
        r'[^>]*\bcontent=["\']([^"\']*)["\'][^>]*>',
        html,
        re.I | re.S,
    )

    if m:
        result["generator"] = m.group(1).strip()
        result["tech"].add(result["generator"])

    result["tech"] = sorted(result["tech"])
    return result


def login_detection(args):
    print(f"{G}[+] {W}Detecting login page technology")

    info = detect_tech(args)

    # If not a login page, search for it
    if not info["is_login"]:
        print(f"{W}[*] Searching login page")
        resp = get_request(args, args.url, timeout=30, allow_redirects=True)
        resp = follow_js_redirects(resp, args)
        html = resp.text
        if is_login_page(html):
            print(f"{G}[+] {W}Login page found via redirect: {resp.url}")
            info = detect_tech(args, url=resp.url)
        else:
            login_url = find_login_url(html, resp.url)
            if login_url:
                print(f"    Login page found in source: {login_url}")
                info = detect_tech(args, url=login_url)

    loginpagetech = ', '.join(info["tech"]) or "Unknown"
    items = [
        f"URL   : {info['url']}",
        f"Title : {info['title'] or 'Unknown'}",
        f"Login : {'Yes' if info['is_login'] else 'No'}",
        f"Tech  : {R}{loginpagetech}{W}",
    ]
    
    if info["generator"]:
        items.append(f"Gen   : {info['generator']}")

    total = len(items) + (len(info["headers"]) if info["headers"] else 0)
    idx = 0
    for text in items:
        idx += 1
        is_last = (idx == total)
        print(f" {G}{'└── ' if is_last else '├── '}{W}{text}")

    if info["headers"]:
        for k, v in info["headers"].items():
            idx += 1
            is_last = (idx == total)
            print(f" {G}{'└── ' if is_last else '├── '}{W}{k}: {v}")

    print()

    if loginpagetech == "Unknown":
        return

    search_default_credentials(args, loginpagetech)