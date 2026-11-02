import itertools, sys, gc
from collections.abc import Generator
from tqdm import tqdm
from datetime import date
from prompt_toolkit import Application
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout, HSplit, VSplit, Window
from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl
from prompt_toolkit.styles import Style
from prompt_toolkit.application import get_app

from Dependencies.displays import W, R, Y, G, C


# ═══════════════════════════════════════════════════════════
# FIELDS
# ═══════════════════════════════════════════════════════════
FIELDS: list[str] = [
    "Company name",
    "City",

    "First name",
    "Last name",
    "Birth year (ex: 1990)",
    "Birth month (1-12)",    
    
    "Wife / husband",
    "Marriage year (ex: 2015)",
    
    "Child name",
    "Child birth date (ex: 15032018)",

    "Pet name",
    "Car brand",

    "Years from (ex: 1990)",

    "Leetspeak? (y/n)",
    "Soft swap? (y/n)",
    "Special chars? (y/n)",
    "Today's date? (y/n)",
    
    "Digit combos (1=0-9, 2=00-99, ...)",
    "Add shitty wordlist (1234, admin, ...) (y/n)",
    "Extra words (comma-sep)"
]


# ═══════════════════════════════════════════════════════════
# SHIT WORDLIST
# ═══════════════════════════════════════════════════════════
SHIT_WORDS = [
    "123", "1234", "12345", "123456", "1234567", "12345678", "123456789",
    "password", "admin", "root", "test", "user", "login", "pass",
    "letmein", "welcome", "qwerty", "abc123", "iloveyou", "monkey",
    "dragon", "master", "shadow", "sunshine", "princess", "football",
    "starwars", "hello", "freedom", "whatever", "trustno1", "654321",
    "666666", "000000", "111111", "222222", "333333", "444444",
    "555555", "777777", "888888", "999999", "121212", "131313",
    "159753", "qwerty123", "admin123", "root123", "pass123",
    "changeme", "default", "guest", "demo", "temp", "temp123",
    "secret", "secret123", "passw0rd", "p@ssw0rd", "p@ssword",
    "admin@123", "root@123", "user@123", "test@123",
    "password1", "password123", "admin1", "admin1234",
    "qwertyuiop", "azerty", "azerty123",
    "p@ss", "p4ss", "p4ssw0rd", "adm1n", "r00t"
]


# ═══════════════════════════════════════════════════════════
# DATES COMBOS
# ═══════════════════════════════════════════════════════════
def gen_date_combos():
    today = date.today()
    d, m, y = today.day, today.month, today.year
    y2 = y % 100
    return {
        # ── DD.MM.YYYY ──
        f"{d:02d}.{m:02d}.{y}",
        f"{d:02d}{m:02d}{y}",
        f"{d:02d}-{m:02d}-{y}",
        f"{d:02d}_{m:02d}_{y}",
        f"{d:02d}/{m:02d}/{y}",

        # ── DD.MM.YY ──
        f"{d:02d}.{m:02d}.{y2:02d}",
        f"{d:02d}{m:02d}{y2:02d}",
        f"{d:02d}-{m:02d}-{y2:02d}",
        f"{d:02d}_{m:02d}_{y2:02d}",
        f"{d:02d}/{m:02d}/{y2:02d}",

        # ── MM.DD.YYYY ──
        f"{m:02d}.{d:02d}.{y}",
        f"{m:02d}{d:02d}{y}",
        f"{m:02d}-{d:02d}-{y}",
        f"{m:02d}_{d:02d}_{y}",
        f"{m:02d}/{d:02d}/{y}",

        # ── MM.DD.YY ──
        f"{m:02d}.{d:02d}.{y2:02d}",
        f"{m:02d}{d:02d}{y2:02d}",
        f"{m:02d}-{d:02d}-{y2:02d}",
        f"{m:02d}_{d:02d}_{y2:02d}",
        f"{m:02d}/{d:02d}/{y2:02d}",

        # ── YYYY.MM.DD ──
        f"{y}{m:02d}{d:02d}",
        f"{y}.{m:02d}.{d:02d}",
        f"{y}-{m:02d}-{d:02d}",
        f"{y}_{m:02d}_{d:02d}",
        f"{y}/{m:02d}/{d:02d}",

        # ── No leading zeros: D.M.Y ──
        f"{d}.{m}.{y}",
        f"{d}{m}{y}",
        f"{d}-{m}-{y}",
        f"{d}_{m}_{y}",
        f"{d}/{m}/{y}",

        # ── No leading zeros: M.D.Y ──
        f"{m}.{d}.{y}",
        f"{m}{d}{y}",
        f"{m}-{d}-{y}",
        f"{m}_{d}_{y}",
        f"{m}/{d}/{y}",

        # ── No leading zeros: D.M.YY ──
        f"{d}.{m}.{y2}",
        f"{d}{m}{y2}",
        f"{d}-{m}-{y2}",
        f"{d}_{m}_{y2}",
        f"{d}/{m}/{y2}",

        # ── No leading zeros: M.D.YY ──
        f"{m}.{d}.{y2}",
        f"{m}{d}{y2}",
        f"{m}-{d}-{y2}",
        f"{m}_{d}_{y2}",
        f"{m}/{d}/{y2}",
    }


def _year_range(start_year):
    """Generate all years from start_year to current"""
    try:
        start = int(start_year)
        current = date.today().year
        return [str(y) for y in range(start, current + 1)]
    except (ValueError, TypeError):
        return []


# ═══════════════════════════════════════════════════════════
# LEETS COMBOS
# ═══════════════════════════════════════════════════════════
def _leet(s):
    table = str.maketrans({
        'a': '4', 'e': '3', 'i': '1', 'o': '0',
        't': '7', 'l': '1', 's': '5', 'g': '9',
        '@': 'a', '3': 'e', '0': 'o', '1': 'i',
    })
    return s.translate(table)


def _leet_soft(s):
    table = str.maketrans({
        'a': '@', 'e': '3', 'i': '!', 'o': '0', 'l': '1',
    })
    return s.translate(table)


# ═══════════════════════════════════════════════════════════
# DOMAIN NAME COMBOS
# ═══════════════════════════════════════════════════════════
def _domain_variants(name: str) -> list[str]:
    """Generate all variants (case, separators, connectors) of a company name"""
    CONNECTORS = {"et", "and"}
    words = name.lower().split()
    if len(words) == 1:
        w = words[0]
        return [w.capitalize(), w.lower()]

    connector_idx = [i for i, w in enumerate(words) if w in CONNECTORS]
    if connector_idx:
        real_words = [w for i, w in enumerate(words) if i not in connector_idx]
        connector = words[connector_idx[0]]

        # Possible separators: " and " or " et ": (preserved) & + . _
        separators = [f" {connector} ", "&", "+", ".", "_"]
        results = []
        for sep in separators:
            for combo in itertools.product(*[(w.capitalize(), w.lower()) for w in real_words]):
                if sep.startswith(" "):
                    results.append(sep.join(combo).strip())
                else:
                    results.append(sep.join(combo))
        return list(dict.fromkeys(results))

    # --- No connector case (ex: "evil corp") ---
    results = []
    for combo in itertools.product(*[(w.capitalize(), w.lower()) for w in words]):
        results.append(" ".join(combo))
        results.append(".".join(combo))
        results.append("_".join(combo))
    return list(dict.fromkeys(results))


# ═══════════════════════════════════════════════════════════
# NAMES COMBOS
# ═══════════════════════════════════════════════════════════
def _name_wordlist(prenom: str, nom: str) -> list[str]:
    """Generate a wordlist from a first name and a last name"""
    p = prenom.capitalize()
    n = nom.capitalize()
    pl, nl = p.lower(), n.lower()
    pi, ni = p[0], n[0]  # initiales
    pil, nil = pi.lower(), ni.lower()  # initiales minuscules

    wordlist = [
        # FirstName only
        p, pl,
        # LastName only
        n, nl,
        # Concaténation
        p + n, p + nl, pl + n, pl + nl,
        # FirstName.LastName
        f"{p}.{n}", f"{p}.{nl}", f"{pl}.{n}", f"{pl}.{nl}",
        # LastName.FirstName
        f"{n}.{p}", f"{n}.{pl}", f"{nl}.{p}", f"{nl}.{pl}",
        # F.LastName
        f"{pi}{n}", f"{pi}{nl}", f"{pil}{n}", f"{pil}{nl}",
        f"{pi}.{n}", f"{pi}.{nl}", f"{pil}.{n}", f"{pil}.{nl}",
        # LastName.F
        f"{n}{pi}", f"{n}{pil}", f"{nl}{pi}", f"{nl}{pil}",
        f"{n}.{pi}", f"{n}.{pil}", f"{nl}.{pi}", f"{nl}.{pil}",
    ]
    return list(dict.fromkeys(wordlist))  # deduplication while preserving order


# ═══════════════════════════════════════════════════════════
# SPECIAL CHAR COMBOS
# ═══════════════════════════════════════════════════════════
def add_special(s: str, chars: str = "!@#$%&*+") -> list[str]:
    results = [s]
    for c in chars:
        results.append(c + s)
        results.append(s + c)
    return results


# ═══════════════════════════════════════════════════════════
# ADD DIGIT
# ═══════════════════════════════════════════════════════════
def digit_combos(n: int) -> list[str]:
    if n <= 0:
        return [""]
    return [str(i).zfill(n) for i in range(10 ** n)]


# ═══════════════════════════════════════════════════════════
# UI
# ═══════════════════════════════════════════════════════════
def ask_fields(mode: str) -> list[str] | None:
    style = Style.from_dict({
        "title": "bold #ff5f5f",
        "subtitle": "#888888",
        "field-label": "#bbbbbb",
        "field-label-active": "bold #5fd7ff",
        "field": "bg:#20252b #ffd75f",
        "field-focused": "bg:#153b30 #ffffff",
        "toolbar": "bg:#30363d #ffffff",
    })

    buffers = [Buffer() for _ in FIELDS]
    controls = [BufferControl(buffer=b) for b in buffers]
    kb = KeyBindings()
    state = {"generate": False, "cancel": False}
    @kb.add("c-s")
    def _generate(event):
        state["generate"] = True
        event.app.exit()

    @kb.add("c-c")
    @kb.add("escape")
    def _cancel(event):
        state["cancel"] = True
        event.app.exit()

    @kb.add("tab")
    def _next(event):
        event.app.layout.focus_next()

    @kb.add("s-tab")
    def _prev(event):
        event.app.layout.focus_previous()

    @kb.add("down")
    def _down(event):
        event.app.layout.focus_next()

    @kb.add("up")
    def _up(event):
        event.app.layout.focus_previous()

    rows = []
    for i, label in enumerate(FIELDS):
        def make_label(idx=i, lbl=label):
            def render():
                focused = get_app().layout.has_focus(controls[idx])
                cls = "class:field-label-active" if focused else "class:field-label"
                return [(cls, f" {idx+1:02d}. {lbl}")]
            return render

        rows.append(VSplit([
            Window(FormattedTextControl(make_label()), width=50, dont_extend_width=True),
            Window(controls[i], height=1, style="class:field")
        ], height=1))

    body = HSplit([
        Window(FormattedTextControl([
            ("class:title", f"  THIEFHUNTER — {mode.upper()}"),
            ("", "\n"),
            ("class:subtitle", "  Password Wordlist Generator")
        ]), height=3),
        Window(char="─", height=1),
        *rows,
        Window(char="─", height=1),
        Window(FormattedTextControl(
            "  ↑/↓ or Tab : Navigate   Ctrl+S : Generate   Ctrl+C : Exit"
        ), height=1, style="class:toolbar")
    ], padding=0)

    app = Application(layout=Layout(body, focused_element=controls[0]), key_bindings=kb, style=style, full_screen=True, mouse_support=True)

    try:
        app.run()
    except (KeyboardInterrupt, EOFError):
        return None

    if state["cancel"] or not state["generate"]:
        return None
    return [b.text.strip() for b in buffers]


def section(num, total, name):
    bar = "█" * num + "░" * (total - num)
    print(f"\n  [{bar}] {num}/{total} ── {name}")



def dopass(args) -> None:
    answers = ask_fields(args.pass_maker)
    if answers is None:
        print(f"\n{R}[!] Canceled{W}")
        return

    wordlist: list[str] = []

    company       = answers[0]
    city          = answers[1]

    prenom        = answers[2]
    nom           = answers[3]
    annee_naiss   = answers[4]
    mois_naiss    = answers[5]

    conjoint      = answers[6]
    annee_mariage = answers[7]

    enfant_nom    = answers[8]
    enfant_date   = answers[9]

    animal        = answers[10]
    voiture       = answers[11]

    years_from    = answers[12]
    leet          = answers[13].lower() in ("y", "yes", "1", "true")
    soft_swap     = answers[14].lower() in ("y", "yes", "1", "true")
    special_chars = answers[15].lower() in ("y", "yes", "1", "true")
    today_date    = answers[16].lower() in ("y", "yes", "1", "true")

    try:
        digits = int(answers[17]) if answers[17] else 0
    except ValueError:
        digits = 0

    shit_words    = answers[18].lower() in ("y", "yes", "1", "true")
    extra_words   = [w.strip() for w in answers[19].split(",") if w.strip()] if answers[18] else []

    print(f"\n{G}[+] Réponses:{W}")
    for label, val in zip(FIELDS, answers):
        print(f"  {label:<35} {C}{val}{W}" if val else f"  {label:<35} {Y}(vide){W}")

    TOTAL = 11
    count = 0
    filename = f"wordlist_{args.pass_maker}.txt"
    f = open(filename, "w+", encoding="utf-8")

    def add(*words):
        nonlocal count
        for w in words:
            f.write(w + "\n")
            count += 1

    def read_back() -> list[str]:
        f.flush()
        f.seek(0)
        return f.read().splitlines()

    # ═══════════════════════════════════════════
    section(1, TOTAL, "Single Words")
    if city:
        add(*_domain_variants(city))
    if company:
        add(*_domain_variants(company))
    if nom:
        add(nom.lower(), nom.capitalize(), nom.upper())
    if prenom:
        add(prenom.lower(), prenom.capitalize(), prenom.upper())
    if conjoint:
        add(conjoint.lower(), conjoint.capitalize(), conjoint.upper())
    if enfant_nom:
        add(enfant_nom.lower(), enfant_nom.capitalize(), enfant_nom.upper())
    if animal:
        add(animal.lower(), animal.capitalize(), animal.upper())
    if voiture:
        add(voiture.lower(), voiture.capitalize(), voiture.upper())

    # ── Leet / Soft Swap (limited) ──
    section(2, TOTAL, "Limited Swap")
    if args.pass_maker == "limited":
        if leet or soft_swap:
            base = read_back()
            for w in base:
                if leet:
                    add(_leet(w))
                if soft_swap:
                    add(_leet_soft(w))

    section(3, TOTAL, "Basic Combos")
    if company and city:
        for c in _domain_variants(company):
            for v in _domain_variants(city):
                add(c + v, c + "." + v, c + "_" + v,
                    v + c, v + "." + c, v + "_" + c)

    if prenom and nom:
        add(*_name_wordlist(prenom, nom))

    if prenom and city:
        p, pl = prenom.capitalize(), prenom.lower()
        c, cl = city.capitalize(), city.lower()
        for a in (p, pl):
            for b in (c, cl):
                add(a + b, a + "." + b, a + "_" + b,
                    b + a, b + "." + a, b + "_" + a)

    if nom and city:
        n, nl = nom.capitalize(), nom.lower()
        c, cl = city.capitalize(), city.lower()
        for a in (n, nl):
            for b in (c, cl):
                add(a + b, a + "." + b, a + "_" + b,
                    b + a, b + "." + a, b + "_" + a)

    if args.pass_maker == "insane":
        if prenom and nom and city:
            words = [prenom, nom, city]
            for perm in itertools.permutations(words):
                for combo in itertools.product(*[(w.capitalize(), w.lower()) for w in perm]):
                    add("".join(combo), ".".join(combo), "_".join(combo))

    if prenom and annee_naiss:
        p, pl = prenom.capitalize(), prenom.lower()
        a = annee_naiss
        add(p + a, pl + a, a + p, a + pl,
            p + "." + a, pl + "." + a, a + "." + p, a + "." + pl,
            p + "_" + a, pl + "_" + a, a + "_" + p, a + "_" + pl)

    if nom and annee_naiss:
        n, nl = nom.capitalize(), nom.lower()
        a = annee_naiss
        add(n + a, nl + a, a + n, a + nl,
            n + "." + a, nl + "." + a, a + "." + n, a + "." + nl,
            n + "_" + a, nl + "_" + a, a + "_" + n, a + "_" + nl)

    if prenom and mois_naiss:
        p, pl = prenom.capitalize(), prenom.lower()
        m, m1 = mois_naiss.zfill(2), mois_naiss
        for mv in (m, m1):
            add(p + mv, pl + mv, mv + p, mv + pl,
                p + "." + mv, pl + "." + mv, mv + "." + p, mv + "." + pl,
                p + "_" + mv, pl + "_" + mv, mv + "_" + p, mv + "_" + pl)

    if nom and mois_naiss:
        n, nl = nom.capitalize(), nom.lower()
        m, m1 = mois_naiss.zfill(2), mois_naiss
        for mv in (m, m1):
            add(n + mv, nl + mv, mv + n, mv + nl,
                n + "." + mv, nl + "." + mv, mv + "." + n, mv + "." + nl,
                n + "_" + mv, nl + "_" + mv, mv + "_" + n, mv + "_" + nl)

    if args.pass_maker == "insane":
        if prenom and nom and annee_naiss:
            words = [prenom, nom, annee_naiss]
            for perm in itertools.permutations(words):
                for combo in itertools.product(*[(w.capitalize(), w.lower()) for w in perm]):
                    add("".join(combo), ".".join(combo), "_".join(combo))

        if prenom and nom and mois_naiss:
            words = [prenom, nom, mois_naiss.zfill(2)]
            for perm in itertools.permutations(words):
                for combo in itertools.product(*[(w.capitalize(), w.lower()) for w in perm]):
                    add("".join(combo), ".".join(combo), "_".join(combo))

    if conjoint and annee_mariage:
        c, cl = conjoint.capitalize(), conjoint.lower()
        a = annee_mariage
        add(c + a, cl + a, a + c, a + cl,
            c + "." + a, cl + "." + a, a + "." + c, a + "." + cl,
            c + "_" + a, cl + "_" + a, a + "_" + c, a + "_" + cl)

    # ── Years from (Combinations with each word) ──
    section(3, TOTAL, "Years combos")
    if args.pass_maker != "limited" and years_from:
        years = _year_range(years_from)
        base = read_back()
        for w in base:
            for y in years:
                add(w + y, y + w)
                if args.pass_maker == "insane":
                    add(w + "_" + y, y + "_" + w, w + "." + y, y + "." + w)

    section(4, TOTAL, "Childs Spec")
    if enfant_nom and enfant_date:
        e_lower, e_cap, e_upper = enfant_nom.lower(), enfant_nom.capitalize(), enfant_nom.upper()
        d = enfant_date
        for e in (e_lower, e_cap, e_upper):
            add(e + d, d + e, e + "." + d, d + "." + e, e + "_" + d, d + "_" + e)

    section(5, TOTAL, "Extra Leet")
    if args.pass_maker == "basic":
        if leet or soft_swap:
            base = read_back()
            for w in tqdm(base, desc="  leet", leave=False):
                if leet:
                    add(_leet(w))
                if soft_swap:
                    add(_leet_soft(w))

    def digit_combos(level):
        """level 1 → ['0'..'9'], level 2 → ['00'..'99'], etc."""
        return [f"{i:0{level}d}" for i in range(10 ** level)]

    section(6, TOTAL, "Digits")
    if digits > 0:
        base = read_back()
        digit_list = digit_combos(digits)
        for w in tqdm(base, desc=f"  digits={digits}", leave=False):
            for d in digit_list:
                add(w + d)
                
                if args.pass_maker == "basic":
                    add(w + " " + d)
                    
                if args.pass_maker == "insane":
                    add(d + w)
                    add(w + " " + d)
                    add(w + "." + d)
                    add(w + "_" + d)

    section(7, TOTAL, "Shitty words")
    if shit_words:
        # ── Standalone ──
        for w in SHIT_WORDS:
            add(w, w.capitalize(), w.upper())

        # ── Combos with the existing wordlist ──
        if not args.pass_maker == "limited":
            base = read_back()
            for s in tqdm(SHIT_WORDS, desc="  shit_words", leave=False):
                for w in base:
                    add(w + s)
                    add(w + "." + s)
                    add(w + "_" + s)
                    add(w + " " + s)
                    add(w + s.capitalize())

                    if args.pass_maker == "insane":
                        add(s + w)
                        add(s + "." + w)
                        add(s + "_" + w)
                        add(s + " " + w)
                        add(s.capitalize() + w)

    section(8, TOTAL, "Special chars")
    if special_chars:
        base = read_back()
        for w in tqdm(base, desc="  special", leave=False):
            add(*add_special(w))

    section(9, TOTAL, "Years from (standalone)")
    if years_from:
        add(*_year_range(years_from))

    section(10, TOTAL, "Today date (standalone)")
    if today_date:
        add(*gen_date_combos())

    section(11, TOTAL, "Leet / Soft Swap")
    if args.pass_maker == "insane":
        if leet or soft_swap:
            base = read_back()
            for w in tqdm(base, desc="  leet", leave=False):
                if leet:
                    add(_leet(w))
                if soft_swap:
                    add(_leet_soft(w))

    if not args.pass_maker == "limited": 
        add("") # empty password

    f.close()
    print(f"\n{G}[+] Wordlist written to {C}{filename}{W} ({count} words)\n")