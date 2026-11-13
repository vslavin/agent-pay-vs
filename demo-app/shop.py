"""Public merchant storefronts at /shop/<username> (Python stdlib only).

Every merchant gets a demo catalog branded with their business name. There are two store profiles:
  sneakers (default): mid-priced; accepts autonomous purchases by an agent within the user's mandate.
  atelier:            high-priced watches; human-present, so the user must approve each exact cart with a passkey.
The profile of a store is set in data/stores.json ({"<merchant username>": "atelier"}). Prices are test OUSD on
Tempo's testnet. Checkout verifies the agent's signed request and mandates; it quotes a price, it does not pay.
"""

import html
import json
import pathlib
import urllib.parse

STORES_FILE = pathlib.Path(__file__).parent / "data" / "stores.json"

TEMPLATE = pathlib.Path(__file__).parent / "templates" / "shop.html"
EXPLORER = "https://explore.testnet.tempo.xyz"
SIZES = ["US 7", "US 8", "US 9", "US 10", "US 11", "US 12"]

# (slug, name, colorway, tag, price in OUSD, upper, accent, sole)
PRODUCTS = [
    ("aero-runner",    "Aero Runner",    "Hot Pink / Sun",      "NEW",     "89",  "#ff3d71", "#ffe14d", "#f4f4f8"),
    ("midnight-court", "Midnight Court", "Midnight / Cyan",     "",        "120", "#1b1f3b", "#00e5ff", "#e8e8f0"),
    ("neon-drift",     "Neon Drift",     "Volt / Black",        "LIMITED", "145", "#b6ff00", "#111111", "#ffffff"),
    ("cloud-trainer",  "Cloud Trainer",  "Cloud / Periwinkle",  "",        "95",  "#e9edf5", "#7c8cff", "#cfd6ea"),
    ("sunset-glide",   "Sunset Glide",   "Sunset / Crimson",    "",        "110", "#ff7a18", "#af002d", "#fff1e6"),
    ("arctic-pulse",   "Arctic Pulse",   "Ice / Ocean",         "NEW",     "130", "#bde0fe", "#0077b6", "#ffffff"),
    ("brick-hi-top",   "Brick Hi-Top",   "Brick / Sand",        "",        "160", "#c2410c", "#fde68a", "#fff7ed"),
    ("forest-trail",   "Forest Trail",   "Forest / Mint",       "",        "105", "#2d6a4f", "#d8f3dc", "#f1f1e6"),
    ("royal-flash",    "Royal Flash",    "Royal / Lilac",       "",        "150", "#5a189a", "#e0aaff", "#f8f0ff"),
    ("chrome-racer",   "Chrome Racer",   "Chrome / Hot Pink",   "LIMITED", "185", "#c9ced6", "#ff3d71", "#3a3a46"),
    ("sand-low",       "Sand Low",       "Sand / Cocoa",        "",        "75",  "#e5d3b3", "#7f5539", "#fffaf0"),
    ("vault-one",      "Vault 1",        "Black / Gold",        "LIMITED", "210", "#14141c", "#ffd700", "#2b2b36"),
]


# (slug, name, colorway, tag, price in OUSD, case, dial, strap)
WATCHES = [
    ("meridian-38",  "Meridian 38",   "Steel / Ivory",        "NEW",     "420",  "#c9ced6", "#f3ecd8", "#3b2a1e"),
    ("nocturne",     "Nocturne",      "Black / Gold",         "",        "560",  "#d4af37", "#111111", "#1a1a1a"),
    ("aviator-gmt",  "Aviator GMT",   "Steel / Slate",        "",        "680",  "#b7bcc6", "#2f3b4c", "#5b4636"),
    ("regent",       "Regent",        "Rose gold / Cream",    "",        "790",  "#e2a98d", "#f7efe2", "#6b3f2a"),
    ("abyss-diver",  "Abyss Diver",   "Steel / Deep blue",    "LIMITED", "940",  "#aab1bd", "#0b2a4a", "#14202e"),
    ("heritage-ii",  "Heritage II",   "Gold / Champagne",     "",        "1250", "#d4af37", "#efe0b8", "#2a1d14"),
    ("tourbillon-x", "Tourbillon X",  "Titanium / Skeleton",  "LIMITED", "1800", "#8a8f98", "#1b1f27", "#222222"),
    ("sovereign",    "Sovereign",     "Platinum / Onyx",      "LIMITED", "2400", "#e5e4e2", "#0a0a0a", "#0d0d0d"),
]

PROFILES = {
    "sneakers": {"mode": "autonomous", "noun": "sneakers", "products": PRODUCTS, "sizes": SIZES, "theme": "sneakers",
                 "tagline": "Fresh kicks. Agent-ready checkout.", "colorways": "new colorways",
                 "ticker": ["PAY IN OUSD", "AGENTS WELCOME", "NEW DROPS WEEKLY", "TEST TOKENS · NO REAL MONEY", "READY FOR THE FUTURE"],
                 "note": "This store accepts purchases made autonomously by your agent, within the mandate you signed."},
    "atelier":  {"mode": "human_present", "noun": "timepieces", "products": WATCHES, "sizes": ["38 mm", "41 mm", "44 mm"], "theme": "atelier",
                 "tagline": "Fine timepieces. You approve every purchase.", "colorways": "references",
                 "ticker": ["PAY IN OUSD", "HUMAN APPROVAL REQUIRED", "HANDCRAFTED", "TEST TOKENS · NO REAL MONEY", "AGENTS MAY ASK, YOU DECIDE"],
                 "note": "High-value store: your agent can ask, but you must approve each exact cart with your passkey before it is quoted."},
}


def profile_name(username):
    try:
        name = json.loads(STORES_FILE.read_text()).get(str(username).lower(), "sneakers")
    except Exception:
        name = "sneakers"
    return name if name in PROFILES else "sneakers"


def profile(username):
    return PROFILES[profile_name(username)]


def policy(m):
    """What this store demands of a purchase: autonomous within a mandate, or the user present to approve."""
    return {"mode": profile(m["username"])["mode"]}


def watch_svg(case, dial, strap):
    ticks = "".join(f'<line x1="160" y1="38" x2="160" y2="{46 if i % 3 == 0 else 42}" stroke="{case}" stroke-width="{3 if i % 3 == 0 else 1.5}" transform="rotate({i * 30} 160 95)"/>' for i in range(12))
    return f"""<svg viewBox="0 0 320 190" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Watch">
<ellipse cx="160" cy="176" rx="90" ry="7" fill="rgba(0,0,0,.5)"/>
<rect x="136" y="2" width="48" height="58" rx="8" fill="{strap}"/><rect x="136" y="130" width="48" height="58" rx="8" fill="{strap}"/>
<circle cx="160" cy="95" r="62" fill="{case}"/><circle cx="160" cy="95" r="54" fill="{dial}" stroke="rgba(0,0,0,.35)" stroke-width="2"/>
{ticks}
<line x1="160" y1="95" x2="160" y2="58" stroke="{case}" stroke-width="3.5" stroke-linecap="round"/>
<line x1="160" y1="95" x2="184" y2="108" stroke="{case}" stroke-width="3" stroke-linecap="round"/>
<circle cx="160" cy="95" r="4" fill="{case}"/><rect x="222" y="88" width="9" height="14" rx="2" fill="{case}"/>
</svg>"""


def sneaker_svg(upper, accent, sole):
    return f"""<svg viewBox="0 0 320 190" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Sneaker">
<ellipse cx="160" cy="168" rx="120" ry="9" fill="rgba(0,0,0,.5)"/>
<path d="M26 132 Q26 158 58 158 L262 158 Q296 158 298 132 L298 120 L26 120 Z" fill="{sole}"/>
<path d="M30 141 L294 141" stroke="{accent}" stroke-width="5" opacity=".9"/>
<path d="M32 120 C28 96 40 78 68 74 L112 70 C122 50 146 34 174 34 C198 34 212 50 228 64 C252 84 290 92 298 110 L298 120 Z" fill="{upper}"/>
<path d="M228 64 C252 84 290 92 298 110 L298 120 L240 120 C246 98 240 78 228 64 Z" fill="{accent}" opacity=".92"/>
<path d="M32 120 C28 96 40 78 68 74 L76 120 Z" fill="{accent}" opacity=".92"/>
<path d="M112 70 C122 50 146 34 174 34 L172 52 C150 54 134 62 128 80 Z" fill="#0b0b14"/>
<path d="M92 116 C132 104 176 86 214 62" stroke="{accent}" stroke-width="9" stroke-linecap="round" fill="none"/>
<path d="M44 108 C48 94 58 86 72 83" stroke="#fff" stroke-width="3" stroke-linecap="round" fill="none" opacity=".28"/>
<g stroke="#fff" stroke-width="3.2" stroke-linecap="round" opacity=".95"><path d="M134 66 L150 80"/><path d="M148 56 L164 70"/><path d="M162 49 L178 63"/><path d="M176 45 L191 58"/></g>
</svg>"""


def _sku(username, i):
    return f"{(username[:3] or 'SHP').upper()}-{i:03d}"


def art(username, upper, accent, sole):
    return (watch_svg if profile_name(username) == "atelier" else sneaker_svg)(upper, accent, sole)


def products(username, store_url):
    out = []
    prof = profile(username)
    for i, (slug, name, colorway, tag, price, upper, accent, sole) in enumerate(prof["products"], start=1):
        out.append({"sku": _sku(username, i), "slug": slug, "name": name, "colorway": colorway, "tag": tag,
                    "price": price, "upper": upper, "accent": accent, "sole": sole, "sizes": prof["sizes"],
                    "url": f"{store_url}#{slug}"})
    return out


def catalog(m, store_url):
    """Machine-readable catalog for AI shoppers."""
    return {
        "merchant": {
            "name": m["businessName"] or m["username"], "url": store_url,
            "description": m.get("businessDescription") or "",
            "visaTapSandbox": bool(m.get("visa") and m["visa"].get("status") == "registered"),
            "receiptKey": m.get("receiptKey"),
        },
        "payment": {"currency": "OUSD", "network": "Tempo testnet (test tokens, no real value)",
                    "payTo": m["address"],
                    "checkout": {
                        "url": store_url + "/checkout", "method": "POST",
                        "body": {"sku": "<sku>", "mandates": {"open": "<open mandate JWS>", "closed": "<closed mandate JWS>"}},
                        "requires": ["TAP-style signed request: Signature-Input and Signature headers, tag agent-payer-auth, covering @authority and @path",
                                     "an open mandate signed by the user for this agent, allowing this store and amount",
                                     "a closed mandate signed by the agent for exactly this order"],
                        "orderHash": "base64url SHA-256 of the canonical JSON of {amount, currency, merchant, quantity, sku}: keys sorted, no spaces",
                        "mandateFormat": "open mandate: compact JWS (EdDSA), vct mandate.payment.open.1, constraints array (payment.allowed_payees, payment.amount_range, payment.budget; amounts are integer micro-OUSD), cnf = the agent's key. "
                                         "closed mandate: vct mandate.payment.1, transaction_id = the orderHash below, payee {id, address}, payment_amount {amount in micro-OUSD, currency}, open = base64url SHA-256 of the open mandate JWS",
                        "paying": {"how": "From the wallet that holds the mandate, send the quoted amount of OUSD to payTo with transferWithMemo, memo = payment.reference (the order id). Then confirm.",
                                   "confirmUrl": store_url + "/orders/<orderId>/confirm", "confirmBody": {"txHash": "0x..."},
                                   "statusUrl": store_url + "/orders/<orderId>",
                                   "quoteValidity": "5 minutes; an unpaid quote stops counting against the mandate's budget when it expires"},
                        "receipts": "responses carry signed receipts (JWS, EdDSA) under `receipts`: `mandate` (result success or error, reference = hash of the closed mandate) on every checkout decision, and `payment` (status Success or Error, payment_id, network_confirmation_id) once payment is confirmed. They verify against merchant.receiptKey.",
                        "purchaseMode": profile(m["username"])["mode"],
                        "purchaseModeNote": ("autonomous: a valid mandate is enough" if profile(m["username"])["mode"] == "autonomous" else
                                             "human_present: the first valid checkout opens an approval request (response field approval.id, status pending). "
                                             "The user must approve that exact cart in the Agent Pay app with a fresh passkey sign-in. "
                                             "Then repeat the checkout with a fresh signature; it returns 402. Approvals are single-use and expire after 15 minutes."),
                        "responses": {"402": "authorized: pay the amount to payTo, quoting the reference", "401": "agent identity rejected",
                                      "403": "mandate rejected, or (human_present stores) waiting for the user's approval: see code purchase_mode and approval"},
                    }},
        "products": [{"sku": p["sku"], "name": p["name"], "colorway": p["colorway"], "price": p["price"],
                      "currency": "OUSD", "sizes" if profile_name(m["username"]) == "sneakers" else "options": p["sizes"], "url": p["url"]} for p in products(m["username"], store_url)],
    }


def render(m, store_url):
    e = html.escape
    brand = m["businessName"] or m["username"]
    prof = profile(m["username"])
    tagline = (m.get("businessDescription") or "").strip() or prof["tagline"]
    items = products(m["username"], store_url)
    registered = bool(m.get("visa") and m["visa"].get("status") == "registered")
    addr = m["address"]

    cards = []
    for p in items:
        instruction = f"Buy the {p['name']} ({p['sku']}) from {brand} at {store_url} for {p['price']} OUSD."
        tag = f'<span class="badge">{e(p["tag"])}</span>' if p["tag"] else ""
        chips = "".join(f"<span>{e(s)}</span>" for s in p["sizes"])
        cards.append(
            f'<article class="card" id="{e(p["slug"], quote=True)}" style="--c:{p["upper"]};--a:{p["accent"]}">'
            f'{tag}<div class="shoe">{art(m["username"], p["upper"], p["accent"], p["sole"])}</div>'
            f'<div class="meta"><div class="sku">{e(p["sku"])}</div><h3>{e(p["name"])}</h3>'
            f'<div class="colorway">{e(p["colorway"])}</div><div class="sizes">{chips}</div>'
            f'<div class="buy"><div class="price">{e(p["price"])} <small>OUSD</small></div>'
            f'<button type="button" class="copy" data-copy="{e(instruction, quote=True)}">Copy agent instruction</button></div></div>'
            "</article>")

    rack = "".join(
        f'<a class="mini" href="#{e(p["slug"], quote=True)}" style="--c:{p["upper"]};--a:{p["accent"]}" title="{e(p["name"], quote=True)}">'
        f'<div class="mini-shoe">{art(m["username"], p["upper"], p["accent"], p["sole"])}</div>'
        f'<span>{e(p["name"])}</span><b>{e(p["price"])} OUSD</b></a>' for p in items)

    hero = items[0]
    ticker = " ★ ".join(prof["ticker"])
    visa_badge = (f'<span class="pill visa" title="Registered in Visa’s sandbox merchant registry">✔ Visa sandbox merchant</span>'
                  if registered else "")
    words = brand.upper().split()
    big = "<br>".join(e(w) for w in words) if len(words) <= 4 else e(brand.upper())
    ld = json.dumps({"@context": "https://schema.org", "@type": "Store", "name": brand, "url": store_url,
                     "description": tagline, "paymentAccepted": "OUSD (Tempo testnet)"}).replace("</", "<\\/")

    text = TEMPLATE.read_text()
    for key, value in {
        "TITLE": e(f"{brand} — {prof['noun']}"), "NOUN": e(prof["noun"]), "THEME": prof["theme"], "COLORWAYS": e(prof["colorways"]),
        "POLICY_NOTE": e(prof["note"]), "MODE_PILL": ("Autonomous purchases" if prof["mode"] == "autonomous" else "Human approval required"), "BRAND": e(brand), "TAGLINE": e(tagline), "BIG": big,
        "VISA_BADGE": visa_badge, "HERO_SHOE": art(m["username"], hero["upper"], hero["accent"], hero["sole"]),
        "TICKER": e(ticker), "RACK": rack, "PRODUCTS": "".join(cards), "COUNT": str(len(items)),
        "CATALOG_URL": e(store_url + "/catalog.json", quote=True), "STORE_URL": e(store_url),
        "ADDRESS_LINK": f'<a href="{EXPLORER}/address/{e(addr, quote=True)}" target="_blank" rel="noopener">{e(addr[:10])}…{e(addr[-8:])}</a>',
        "JSONLD": ld,
    }.items():
        text = text.replace(f"<!-- {key} -->", value)
    return text


def not_found(username):
    e = html.escape
    return (f'<!doctype html><meta charset="utf-8"><title>No such store</title>'
            f'<body style="background:#0a0a12;color:#eee;font-family:system-ui;display:grid;place-items:center;min-height:100vh">'
            f'<div style="text-align:center"><h1>No store called “{e(username)}”</h1><p>Only merchants have storefronts.</p>'
            f'<p><a style="color:#ff3d71" href="/">Back to Agent Pay</a></p></div>')
