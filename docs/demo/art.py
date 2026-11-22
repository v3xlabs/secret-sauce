"""Render the pixel-art pieces of the advancement demo with headless chromium: the scenes with the terminal
window, the two drawn panels, the toasts, the chat lines and the end card.

Usage: python3 art.py EXAMPLE_DIR   (writes ./art; build.sh runs it)

Everything is drawn here with CSS: no game textures.
The numbers and lines in the panels are read from the real files at build time: the declaration from
the example flake, the sops lines from secrets.sops.yaml next to this script and the lengths from the
.sauce.yaml files that the recording left in the example copy.
"""
import pathlib
import random
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
OUT = pathlib.Path("art").resolve()
SOPS_FILE = HERE / "secrets.sops.yaml"

W, H = 1100, 660
WIN = (50, 124, 1000, 396)         # outer window box
SCREEN = (61, 161, 978, 348)       # terminal video lands here; the panels use the same area
TOAST_W, TOAST_H = 612, 108
CHAT_W, CHAT_H = 780, 26
GROUND = 536                       # top of the grass

# Minecraft chat colours
GOLD, YELLOW, GREEN, AQUA = "#FFAA00", "#FFFF55", "#55FF55", "#55FFFF"
RED, PURPLE, WHITE = "#FF5555", "#FF55FF", "#FFFFFF"
GRAY = "#AAAAAA"

BASE = """<!doctype html><html><head><meta charset="utf-8"><style>
html,body{margin:0;padding:0;background:transparent}
body{width:%(w)dpx;height:%(h)dpx;overflow:hidden;position:relative;font-family:Minecraftia,monospace}
div,span.b{position:absolute;box-sizing:border-box}
.mc{font-family:Monocraft,monospace;white-space:pre}
%(css)s
</style></head><body>%(body)s</body></html>"""


def shot(name, w, h, css, body, opaque=False):
    html = OUT / f"{name}.html"
    html.write_text(BASE % {"w": w, "h": h, "css": css, "body": body})
    bg = "ffffffff" if opaque else "00000000"
    subprocess.run(
        ["chromium", "--headless", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
         f"--default-background-color={bg}", f"--window-size={w},{h}",
         f"--screenshot={OUT / (name + '.png')}", f"file://{html}"],
        check=True, capture_output=True,
    )


def rect(x, y, w, h, color, extra=""):
    return f'<div style="left:{x}px;top:{y}px;width:{w}px;height:{h}px;background:{color};{extra}"></div>'


def text(x, y, s, size, color, line=None, extra=""):
    """Monocraft text. x, y is the top left of the line box."""
    line = line or size + 6
    return (f'<div class="mc" style="left:{x}px;top:{y}px;font-size:{size}px;line-height:{line}px;'
            f'color:{color};{extra}">{s}</div>')


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def pixel_art(rows, palette, scale, x, y):
    """One div whose box-shadow list paints the art; '.' is empty."""
    shadows = []
    for j, row in enumerate(rows):
        for i, ch in enumerate(row):
            if ch != ".":
                shadows.append(f"{(i + 1) * scale}px {(j + 1) * scale}px 0 0 {palette[ch]}")
    return (f'<div style="left:{x - scale}px;top:{y - scale}px;width:{scale}px;height:{scale}px;'
            f'box-shadow:{",".join(shadows)}"></div>')


# ---- icons: my own pixel art -------------------------------------------------------------------

OUTLINE = "#14101c"


def sprite(fills, size=12):
    """fills: {(x, y): colour}. Adds a one pixel outline and returns rows and palette for pixel_art."""
    cells = dict(fills)
    for (x, y) in list(fills):
        for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            cells.setdefault((x + dx, y + dy), OUTLINE)
    colours = sorted(set(cells.values()))
    keys = {c: chr(ord("a") + i) for i, c in enumerate(colours)}
    rows = []
    for y in range(size):
        rows.append("".join(keys[cells[(x, y)]] if (x, y) in cells else "." for x in range(size)))
    return rows, {v: k for k, v in keys.items()}


def line(points, colour):
    return {p: colour for p in points}


def fill_rect(x0, y0, x1, y1, colour):
    return {(x, y): colour for x in range(x0, x1 + 1) for y in range(y0, y1 + 1)}


def merge(*parts):
    out = {}
    for p in parts:
        out.update(p)
    return out


def make_pickaxe():
    stone, light, wood, dark = "#8c8c8c", "#c4c4c4", "#9b6a34", "#5d3d1b"
    head = merge(
        line([(2, 4), (3, 3), (4, 2), (5, 2), (6, 2), (7, 2), (8, 3), (9, 4), (9, 5), (9, 6)], stone),
        line([(3, 4), (4, 3), (5, 3), (6, 3), (7, 3), (8, 4), (8, 5)], light),
    )
    handle = merge(line([(1, 10), (2, 9), (3, 8), (4, 7), (5, 6), (6, 5), (7, 4)], wood),
                   line([(2, 10), (3, 9), (4, 8), (5, 7), (6, 6), (7, 5)], dark))
    return sprite(merge(handle, head))


def make_brewing_stand():
    glass, potion = "#cfe9ff", "#e83b2e"
    return sprite(merge(
        fill_rect(5, 1, 6, 2, "#b8803a"), fill_rect(5, 3, 6, 4, glass),
        fill_rect(2, 5, 9, 8, glass), fill_rect(3, 6, 8, 8, potion), {(3, 6): "#ff8f85", (4, 6): "#ff8f85"},
        fill_rect(1, 9, 10, 10, "#8c8c8c"), fill_rect(1, 9, 10, 9, "#c4c4c4"),
    ))


def make_eye():
    cells = {}
    for y in range(12):
        for x in range(12):
            r = ((x - 5.5) ** 2 + (y - 5.5) ** 2) ** 0.5
            if r < 1.7:
                cells[(x, y)] = "#0a0a0a"
            elif r < 2.8:
                cells[(x, y)] = "#2fd07a"
            elif r < 4.6:
                cells[(x, y)] = "#1f8f55"
    cells[(4, 4)] = "#b8ffd8"
    return sprite(cells)


def make_egg():
    widths = {1: 4, 2: 6, 3: 8, 4: 8, 5: 10, 6: 10, 7: 10, 8: 10, 9: 8, 10: 6}
    cells = {}
    for y, w in widths.items():
        x0 = 6 - w // 2
        for x in range(x0, x0 + w):
            cells[(x, y)] = "#1a1026"
    for p in [(4, 3), (7, 4), (3, 6), (6, 6), (8, 8), (5, 9), (4, 8), (7, 2)]:
        if p in cells:
            cells[p] = "#a64dff"
    for p in [(5, 2), (4, 3)]:
        cells[p] = "#7a3dc4"
    return sprite(cells)


def make_sculk():
    block, edge, glow = "#12303c", "#1c4a5a", "#3df0e6"
    return sprite(merge(
        fill_rect(1, 6, 10, 10, block), fill_rect(1, 6, 10, 6, edge),
        line([(2, 7), (5, 8), (8, 7), (3, 9), (7, 9)], glow),
        line([(2, 2), (2, 3), (2, 4), (2, 5), (5, 1), (5, 2), (5, 3), (5, 4), (5, 5), (8, 2), (8, 3), (8, 4), (8, 5)], glow),
        line([(1, 3), (3, 3), (4, 2), (6, 2), (7, 3), (9, 3)], "#1fb8b0"),
    ))


def make_bed():
    return sprite(merge(
        fill_rect(1, 4, 3, 6, "#f4f4f4"), fill_rect(4, 4, 10, 6, "#d83a3a"), fill_rect(4, 4, 10, 4, "#f06a6a"),
        fill_rect(1, 7, 10, 8, "#9b6a34"), fill_rect(1, 9, 2, 10, "#5d3d1b"), fill_rect(9, 9, 10, 10, "#5d3d1b"),
        fill_rect(1, 3, 1, 3, "#9b6a34"),
    ))


def make_lock():
    return sprite(merge(
        line([(3, 2), (4, 1), (5, 1), (6, 1), (7, 2), (3, 3), (7, 3), (3, 4), (7, 4)], "#d8d8d8"),
        fill_rect(2, 5, 8, 9, "#ffaa00"), fill_rect(2, 5, 8, 5, "#ffd23f"),
        fill_rect(5, 6, 5, 8, "#3a2200"),
    ))


def make_book():
    return sprite(merge(
        fill_rect(1, 2, 8, 10, "#7a4a22"), fill_rect(2, 3, 7, 9, "#f2e8c9"), fill_rect(1, 2, 1, 10, "#4e2c12"),
        line([(3, 4), (4, 4), (5, 4), (6, 4), (3, 6), (4, 6), (5, 6)], "#8a7a58"),
        line([(10, 1), (9, 2), (8, 3), (7, 4), (6, 5)], "#ffffff"),
        line([(10, 2), (9, 3), (8, 4)], "#d0d0d0"), {(5, 6): "#55ffff"},
    ))


ICONS = {
    "pickaxe": (*make_pickaxe(), 4),
    "brewing": (*make_brewing_stand(), 4),
    "eye": (*make_eye(), 4),
    "egg": (*make_egg(), 4),
    "sculk": (*make_sculk(), 4),
    "bed": (*make_bed(), 4),
    "book": (*make_book(), 3),
    "lock": (*make_lock(), 3),
    "spark": (
        [
            "..Y..",
            "..Y..",
            "YYWYY",
            "..Y..",
            "..Y..",
        ],
        {"Y": YELLOW, "W": WHITE},
        4,
    ),
    "bottle": (
        [
            "....cccc....",
            "....cccc....",
            "....gGGg....",
            "....gGGg....",
            "...gRRRRg...",
            "..gRRRRRRg..",
            "..gRWWWWRg..",
            "..gRWkkWRg..",
            "..gRWWWWRg..",
            "..gRRRRRRg..",
            "..gRRRRRRg..",
            "...gggggg...",
        ],
        {"c": GOLD, "g": "#9fd8ff", "G": "#dff2ff", "R": "#e83b2e", "W": "#fff4d6", "k": "#7a1d14"},
        10,
    ),
}


def icon_centered(name, cx, cy):
    rows, palette, scale = ICONS[name]
    width = max(len(r) for r in rows)
    return pixel_art(rows, palette, scale, cx - width * scale // 2, cy - len(rows) * scale // 2)


# ---- scene ---------------------------------------------------------------------------------------

def sky():
    bands = ["#5b90ee", "#6da0f4", "#80b1f9", "#94c1fc"]
    return "".join(rect(0, i * 140, W, 140 if i < 3 else H, c) for i, c in enumerate(bands))


def sun():
    return rect(36, 26, 72, 72, "#ffb62e") + rect(44, 34, 56, 56, "#ffd84a") + rect(56, 46, 32, 32, "#fff3a3")


def cloud(x, y, cells):
    """cells: one (dx, width) row per 12 px of height."""
    out = [rect(x + dx * 12, y + i * 12, w * 12, 12, "#ffffff") for i, (dx, w) in enumerate(cells)]
    dx, w = cells[-1]
    out.append(rect(x + dx * 12, y + len(cells) * 12, w * 12, 6, "#dbe8ff"))
    return "".join(out)


def hills():
    rng = random.Random(11)
    out = []
    h = 3
    for i in range(W // 24 + 1):
        h = max(2, min(5, h + rng.choice([-1, 0, 0, 1])))
        out.append(rect(i * 24, GROUND - 30 - h * 12, 24, 600, "#82c95c"))
    h = 2
    for i in range(W // 24 + 1):
        h = max(0, min(3, h + rng.choice([-1, 0, 1])))
        out.append(rect(i * 24, GROUND - 8 - h * 12, 24, 600, "#63b23f"))
    return "".join(out)


def ground():
    rng = random.Random(5)
    out = [rect(0, GROUND + 24, W, H, "#8a5f3a"), rect(0, GROUND, W, 8, "#3e8f2a"),
           rect(0, GROUND + 8, W, 16, "#58b335")]
    for i in range(W // 12 + 1):  # blocky grass fringe hanging into the dirt
        if rng.random() < 0.45:
            out.append(rect(i * 12, GROUND + 24, 12, 12, "#58b335"))
    for _ in range(190):
        x = rng.randrange(0, W // 12) * 12
        y = rng.randrange(0, (H - GROUND - 40) // 12) * 12 + GROUND + 40
        out.append(rect(x, y, 12, 12, rng.choice(["#74502f", "#9a6e45", "#6a4727"])))
    for _ in range(14):
        x = rng.randrange(0, W // 12) * 12
        out.append(rect(x, GROUND - 12, 12, 12, rng.choice([RED, YELLOW, "#ffffff", PURPLE])))
    return "".join(out)


def tree(x):
    base = GROUND + 2
    trunk = rect(x + 26, base - 84, 16, 84, "#7a5230") + rect(x + 26, base - 84, 6, 84, "#6a4524")
    top = base - 130
    leaves = (rect(x + 6, top + 12, 56, 24, "#2f8a2b") + rect(x - 6, top + 36, 80, 28, "#379a31")
              + rect(x + 6, top + 64, 56, 12, "#2f8a2b") + rect(x + 18, top, 32, 12, "#44aa3a")
              + rect(x - 6, top + 36, 12, 28, "#2f8a2b") + rect(x + 36, top + 48, 12, 12, "#44aa3a"))
    return trunk + leaves


def window_box(title=None, icon=None, buttons=True):
    """A gray GUI panel with bevels and an inset around the screen. The terminal has three square
    buttons in the title bar; a panel has an icon and a title in the dark gray of Minecraft containers."""
    x, y, w, h = WIN
    sx, sy, sw, sh = SCREEN
    bevel = "border:4px solid;border-color:#ffffff #555555 #555555 #ffffff"
    inset = "border:3px solid;border-color:#373737 #ffffff #ffffff #373737"
    parts = [
        rect(x + 12, y + 12, w, h, "rgba(0,0,0,.3)"),                                # hard shadow
        rect(x - 3, y - 3, w + 6, h + 6, "#111111"),                                 # black outline
        rect(x, y, w, h, "#c6c6c6", bevel),
        rect(sx - 3, sy - 3, sw + 6, sh + 6, "#8b8b8b", inset),
        rect(sx, sy, sw, sh, "#1b1b24"),                                             # screen
    ]
    if buttons:
        for i, c in enumerate([RED, YELLOW, GREEN]):
            bx = x + 18 + i * 26
            parts.append(rect(bx, y + 12, 18, 18, c, "border:3px solid #111111"))
    if icon:
        parts.append(icon_centered(icon, x + 34, y + 21))
    if title:
        parts.append(text(x + 62, y + 7, title, 18, "#404040", line=24))
    return "".join(parts)


def scene(window=None):
    body = sky() + sun()
    body += cloud(160, 34, [(1, 3), (0, 6), (0, 5)])
    body += cloud(430, 70, [(1, 2), (0, 4)])
    body += cloud(560, 18, [(1, 2), (0, 3)])
    body += hills() + ground() + tree(-14) + tree(1054)
    if window is not None:
        body += window
    return body


# ---- panel A: the declaration ----------------------------------------------------------------------

def read_declaration(example):
    """Lines 6 to 11, then 16 to 21 of the real file, as (number, text)."""
    lines = (example / "services" / "hedgedoc.nix").read_text().split("\n")
    assert lines[5].startswith('  sauce.secrets."hedgedoc/db-password" = {'), lines[5]
    assert lines[17].startswith('  sauce.secrets."hedgedoc/session-secret".generator = {'), lines[17]
    assert lines[15] == "  };" and lines[16] == "" and lines[20] == "  };", lines[15:21]
    return [(n, lines[n - 1]) for n in (6, 7, 8, 9, 10, 11)], [(n, lines[n - 1]) for n in range(16, 22)]


TOKEN = re.compile(r'(?P<str>"[^"]*")|(?P<num>\b\d+\b)|(?P<path>\bsauce\.secrets\b)|(?P<attr>[A-Za-z_][\w-]*)')


def highlight(src):
    """Colour a nix line with the Minecraft chat palette: path green, names aqua, strings gold, numbers purple."""
    out, pos = [], 0
    for m in TOKEN.finditer(src):
        out.append(f'<span style="color:{GRAY}">{esc(src[pos:m.start()])}</span>')
        kind = m.lastgroup
        colour = {"str": GOLD, "num": PURPLE, "path": GREEN, "attr": AQUA}[kind]
        out.append(f'<span style="color:{colour}">{esc(m.group())}</span>')
        pos = m.end()
    out.append(f'<span style="color:{GRAY}">{esc(src[pos:])}</span>')
    return "".join(out)


def panel_a(example):
    sx, sy, sw, sh = SCREEN
    first, second = read_declaration(example)
    body = window_box(title="services/hedgedoc.nix", icon="book", buttons=False)
    gutter = 62
    body += rect(sx, sy, gutter, sh, "#232331")
    body += rect(sx + gutter, sy, 2, sh, "#33334a")
    body += rect(sx + sw - 20, sy, 20, sh, "#101018") + rect(sx + sw - 16, sy + 14, 12, 118, "#8b8b8b")
    body += rect(sx + sw - 16, sy + 14, 12, 4, "#c6c6c6") + rect(sx + sw - 16, sy + 128, 12, 4, "#555555")
    y = sy + 24
    for n, src in first:
        body += text(sx, y, f'<span style="color:#6d6d85">{n}</span>', 18, GRAY, line=24, extra=f"width:{gutter - 14}px;text-align:right")
        body += text(sx + gutter + 18, y, highlight(src), 18, GRAY, line=24)
        y += 24
    body += rect(sx + gutter + 18, y + 4, sw - gutter - 18 - 44, 4, "transparent",
                 "border-top:4px dotted #4a4a62")
    y += 12
    for n, src in second:
        body += text(sx, y, f'<span style="color:#6d6d85">{n}</span>', 18, GRAY, line=24, extra=f"width:{gutter - 14}px;text-align:right")
        body += text(sx + gutter + 18, y, highlight(src), 18, GRAY, line=24)
        y += 24
    return scene(body)


# ---- panel B: the padding comparison --------------------------------------------------------------------

def read_sops():
    """The three lines of the sops fixture, cut right after the data field, with the data length."""
    rows = []
    for raw in SOPS_FILE.read_text().split("\n"):
        m = re.match(r"^(\w+): (ENC\[AES256_GCM,data:)([^,]+)(,iv:.*)$", raw)
        if m:
            rows.append((m.group(1), m.group(2), m.group(3)))
    assert len(rows) == 3, rows
    return rows


def read_sauce(example, names):
    """Name, the start of the value field and its length, for the named secrets of the example copy."""
    rows = []
    for name in names:
        path = example / "secrets" / f"{name}.sauce.yaml"
        values = [l for l in path.read_text().split("\n") if l.startswith("value: ")]
        assert len(values) == 1, path
        rows.append((name, values[0][len("value: "):]))
    return rows


COLS = 94                  # characters of a sops line that fit the panel at 15 px
BAR_X = 262                # bars start here; ten characters are one block of 16 px on both sides
UNIT = 16


def bar_width(n):
    full, rest = divmod(n, 10)
    return full * UNIT + (max(2, round((UNIT - 2) * rest / 10)) if rest else 0)


def bar(x, y, n, colour):
    """A row of blocks: ten characters a block, the last block partial."""
    full, rest = divmod(n, 10)
    out = [rect(x + i * UNIT, y, UNIT - 2, 14, colour) for i in range(full)]
    if rest:
        out.append(rect(x + full * UNIT, y, bar_width(n) - full * UNIT, 14, colour))
    return "".join(out)


def panel_b(example):
    sx, sy, sw, sh = SCREEN
    sops = read_sops()
    sauce = read_sauce(example, ["ddclient/api-token", "hedgedoc/db-password", "hedgedoc/session-secret"])
    body = window_box(title="Length of the encrypted value", icon="lock", buttons=False)
    body += text(WIN[0] + WIN[2] - 24 - 300, WIN[1] + 8, "one block is 10 characters", 15, "#5a5a5a", line=24,
                 extra="width:300px;text-align:right")
    pad = 16
    lens_left = [len(d) for _, _, d in sops]
    lens_right = [len(v) for _, v in sauce]
    assert len(set(lens_left)) == 3 and len(set(lens_right)) == 1, (lens_left, lens_right)

    def section(y, header, lines, labels, lengths, colour):
        out = text(sx + pad, y, header, 18, WHITE, line=24)
        y += 26
        for src in lines:
            out += text(sx + pad, y, src, 15, GRAY, line=17)
            y += 17
        y += 5
        for label, n in zip(labels, lengths):
            out += text(sx + pad, y + 4, label, 15, "#c8c8d8", line=17)
            out += bar(sx + BAR_X, y + 5, n, colour)
            bx = sx + BAR_X + bar_width(n) + 12
            out += text(bx, y - 1, str(n), 27, colour, line=27)
            out += text(bx + 18 * len(str(n)) + 8, y + 4, "chars", 15, GRAY, line=17)
            y += 25
        return out

    left_lines = []
    for key, prefix, data in sops:
        left_lines.append(f'<span style="color:{AQUA}">{key}:</span> <span style="color:#8a8aa6">{prefix}</span>'
                          f'<span style="color:{YELLOW}">{esc(data)}</span><span style="color:{GRAY}">…</span>')
    right_lines = []
    for _, value in sauce:
        shown = value[:COLS - len("value: ") - 1]
        right_lines.append(f'<span style="color:{AQUA}">value:</span> '
                           f'<span style="color:{YELLOW}">{esc(shown)}</span><span style="color:{GRAY}">…</span>')
    body += section(sy + 8, "secrets.sops.yaml", left_lines, [k for k, _, _ in sops], lens_left, RED)
    body += rect(sx + pad, sy + 169, sw - 2 * pad, 2, "#33334a")
    body += section(sy + 173, "*.sauce.yaml", right_lines, [n for n, _ in sauce], lens_right, GREEN)
    return scene(body), lens_left, lens_right


# ---- toasts and chat -----------------------------------------------------------------------------

TOAST_CSS = f"""
.t{{left:0;top:0;width:{TOAST_W}px;height:{TOAST_H}px;background:#d6d6d6;
  clip-path:polygon(0 3px,3px 3px,3px 0,calc(100% - 3px) 0,calc(100% - 3px) 3px,100% 3px,100% calc(100% - 3px),
  calc(100% - 3px) calc(100% - 3px),calc(100% - 3px) 100%,3px 100%,3px calc(100% - 3px),0 calc(100% - 3px))}}
.t2{{left:3px;top:3px;right:3px;bottom:3px;background:#4d4d4d}}
.t3{{left:6px;top:6px;right:6px;bottom:6px;background:#212121}}
.slot{{left:18px;top:24px;width:60px;height:60px;background:#8b8b8b}}
.slot2{{left:21px;top:27px;width:54px;height:54px;background:#3c3c3c}}
.h{{left:96px;top:13px;font-size:24px;line-height:24px;color:{YELLOW};white-space:nowrap;text-shadow:3px 3px 0 #3f3f15}}
.n{{left:96px;top:42px;font-size:24px;line-height:24px;color:{WHITE};white-space:nowrap;text-shadow:3px 3px 0 #3f3f3f}}
.d{{left:96px;top:73px;font-size:20px;line-height:20px;color:{GRAY};white-space:nowrap;text-shadow:2px 2px 0 #2a2a2a}}
"""

TOASTS = [
    ("Getting an Upgrade", "Take sops-nix and add a lifecycle", "pickaxe"),
    ("Local Brewery", "Brew every secret with one command", "brewing"),
    ("The End?", "Give a token its expiry date", "eye"),
    ("The Next Generation", "Rotate a secret to version 2", "egg"),
    ("Sneak 100", "Pad every secret to the same length", "sculk"),
    ("Sweet Dreams", "Keep every secret safe in your repo", "bed"),
]


def toast(name, title, desc, ic):
    body = ('<div class="t"></div><div class="t2"></div><div class="t3"></div>'
            '<div class="slot"></div><div class="slot2"></div>' + icon_centered(ic, 48, 54) +
            f'<div class="h">Advancement Made!</div><div class="n">{title}</div><div class="d">{desc}</div>')
    shot(name, TOAST_W, TOAST_H, TOAST_CSS, body)


CHAT_CSS = f"""
.c{{left:0;top:0;height:{CHAT_H}px;padding:3px 8px 0 8px;font-size:20px;line-height:20px;white-space:nowrap;
  background:rgba(0,0,0,.5);color:{WHITE};text-shadow:2px 2px 0 #3f3f3f}}
.nm{{color:{AQUA};text-shadow:2px 2px 0 #153f3f}}
.ad{{color:{GREEN};text-shadow:2px 2px 0 #153f15}}
"""


def chat(name, title):
    body = (f'<div class="c"><span class="nm">Luc</span> has made the advancement '
            f'<span class="ad">[{title}]</span></div>')
    shot(name, CHAT_W, CHAT_H, CHAT_CSS, body)


# ---- end card -------------------------------------------------------------------------------------

def endcard():
    css = f"""
.logo{{left:290px;top:262px;font-size:80px;line-height:80px;color:{GOLD};white-space:nowrap;
  text-shadow:6px 6px 0 #5a3700,-3px 0 0 #5a3700,3px 0 0 #5a3700,0 -3px 0 #5a3700,0 3px 0 #5a3700}}
"""
    return css, '<div class="logo">secret-sauce</div>'


def main(example):
    OUT.mkdir(exist_ok=True)
    shot("scene", W, H, "", scene(window_box()), opaque=True)
    shot("scene-a", W, H, "", panel_a(example), opaque=True)
    body, lens_left, lens_right = panel_b(example)
    shot("scene-b", W, H, "", body, opaque=True)
    print("panel B lengths: sops", lens_left, "sauce", lens_right)
    css, body = endcard()
    shot("scene-end", W, H, css, scene() + body, opaque=True)
    shot("bottle", 120, 120, "", icon_centered("bottle", 60, 60))
    shot("spark", 20, 20, "", icon_centered("spark", 10, 10))
    for i, (title, desc, ic) in enumerate(TOASTS, start=1):
        toast(f"t{i}", title, desc, ic)
        chat(f"c{i}", title)


if __name__ == "__main__":
    main(pathlib.Path(sys.argv[1]))
