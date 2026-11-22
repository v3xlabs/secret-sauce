#!/usr/bin/env python3
"""Write the SECRET-SAUCE block lettermark as an SVG.

Usage: python3 lettermark.py OUT.svg

The letters are 5x7 bitmaps, thickened to 6x8 cells. Every cell is a stone, redstone or gold block with
a dark frame, a bevel, a depth strip and a hard shadow. The art is painted on a grid of one art pixel
(a block is C pixels wide), then the pixels are merged into plain rects with crisp edges.
The random block texture uses random.Random(SEED).
"""
import pathlib
import random
import sys

C = 8              # block size in art pixels
SEED = 3
SCALE = 2          # SVG pixels per art pixel (a whole number: crisp)
PAD = 4            # art pixels of even padding around the art, shadow included
OUTLINE = 2        # dark frame around every block
BEVEL = 2
SHADOW = "#0A143C"
SHADOW_ALPHA = 0.38
SHADOW_DX = SHADOW_DY = 7
FRAME = "#121212"
# One art pixel of outline outside the dark frame, so the letter edge also reads on a dark page
# (#0d1117 swallows the #121212 frame). #818181 is one of the stone face colours.
RING = "#818181"

GLYPHS = {
    "S": [".####", "#....", "#....", ".###.", "....#", "....#", "####."],
    "E": ["#####", "#....", "#....", "####.", "#....", "#....", "#####"],
    "C": [".####", "#....", "#....", "#....", "#....", "#....", ".####"],
    "R": ["####.", "#...#", "#...#", "####.", "#.#..", "#..#.", "#...#"],
    "T": ["#####", "..#..", "..#..", "..#..", "..#..", "..#..", "..#.."],
    "-": ["", "", "", "###"],
    "A": [".###.", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"],
    "U": ["#...#", "#...#", "#...#", "#...#", "#...#", "#...#", ".###."],
}
WORD = "SECRET-SAUCE"

# group -> (face colours, light edge, dark edge)
FACE = {
    "stone": (["#8C8C8C", "#979797", "#818181"], "#CFCFCF", "#585858"),
    "dash": (["#E83A3A"], "#FF8A8A", "#9A1515"),
    "gold": (["#FFB800", "#FFC21A", "#F7AA00"], "#FFE766", "#C47400"),
}
DEPTH = {"stone": "#454545", "dash": "#6E1010", "gold": "#8A5200"}


def bold(glyph):
    """The cells of a glyph, each mark grown to 2x2."""
    cells = set()
    for r, line in enumerate(glyph):
        for k, mark in enumerate(line):
            if mark == "#":
                cells |= {(k, r), (k + 1, r), (k, r + 1), (k + 1, r + 1)}
    return cells


def logo_cells():
    """Cells of the lettermark as {(col, row): group}: stone SECRET, redstone hyphen, gold SAUCE."""
    cells = {}
    col = 0
    for idx, ch in enumerate(WORD):
        group = "stone" if idx < 6 else "dash" if ch == "-" else "gold"
        shape = bold(GLYPHS[ch])
        for cx, cy in shape:
            cells[(col + cx, cy)] = group
        col += max(cx for cx, _ in shape) + 2
    return cells


def rgb(hexcolor):
    return tuple(int(hexcolor[i:i + 2], 16) for i in (1, 3, 5))


class Grid:
    """RGBA art pixels."""

    def __init__(self, w, h):
        self.w, self.h = w, h
        self.px = [[None] * w for _ in range(h)]    # None = transparent, else (r, g, b, a)

    def fill(self, x, y, w, h, colour, alpha=255):
        value = rgb(colour) + (alpha,)
        for yy in range(y, y + h):
            row = self.px[yy]
            for xx in range(x, x + w):
                row[xx] = value


def paint():
    """Return the painted grid, cropped to the art and padded evenly."""
    cells = logo_cells()
    rng = random.Random(SEED)
    ext = C // 2
    m = 40                                         # scratch margin, cropped away below
    ox = oy = m
    cols = 1 + max(cx for cx, _ in cells)
    rows = 1 + max(cy for _, cy in cells)
    g = Grid(cols * C + 2 * m, rows * C + ext + 2 * m)
    # hard shadow: the union of the shifted frames at one alpha
    mask = Grid(g.w, g.h)
    for cx, cy in cells:
        mask.fill(ox + cx * C - OUTLINE + SHADOW_DX, oy + cy * C - OUTLINE + ext + SHADOW_DY,
                  C + 2 * OUTLINE, C + 2 * OUTLINE + ext, "#000000")
    for y in range(g.h):
        for x in range(g.w):
            if mask.px[y][x]:
                g.px[y][x] = rgb(SHADOW) + (round(SHADOW_ALPHA * 255),)
    for cx, cy in cells:
        g.fill(ox + cx * C - OUTLINE - 1, oy + cy * C - OUTLINE - 1, C + 2 * OUTLINE + 2,
               C + 2 * OUTLINE + 2 + ext, RING)
    for cx, cy in cells:
        g.fill(ox + cx * C - OUTLINE, oy + cy * C - OUTLINE, C + 2 * OUTLINE, C + 2 * OUTLINE + ext, FRAME)
    for (cx, cy), grp in cells.items():
        g.fill(ox + cx * C, oy + cy * C + ext, C, C, DEPTH[grp])
    for (cx, cy), grp in cells.items():
        base, hi, lo = FACE[grp]
        x, y = ox + cx * C, oy + cy * C
        g.fill(x, y, C, C, rng.choice(base))
        # bevel: top and left light, bottom and right dark; top wins a corner
        if (cx + 1, cy) not in cells:
            g.fill(x + C - BEVEL, y, BEVEL, C, lo)
        if (cx, cy + 1) not in cells:
            g.fill(x, y + C - BEVEL, C, BEVEL, lo)
        if (cx - 1, cy) not in cells:
            g.fill(x, y, BEVEL, C, hi)
        if (cx, cy - 1) not in cells:
            g.fill(x, y, C, BEVEL, hi)
    ys = [y for y in range(g.h) if any(g.px[y])]
    xs = [x for x in range(g.w) if any(g.px[y][x] for y in range(g.h))]
    x0, x1, y0, y1 = min(xs), max(xs) + 1, min(ys), max(ys) + 1
    out = Grid(x1 - x0 + 2 * PAD, y1 - y0 + 2 * PAD)
    for y in range(y1 - y0):
        out.px[y + PAD][PAD:PAD + x1 - x0] = g.px[y0 + y][x0:x1]
    return out


def merge(g, transpose):
    """Greedy rects of equal colour: runs along rows, then runs stacked over equal neighbours."""
    w, h = (g.h, g.w) if transpose else (g.w, g.h)
    at = (lambda a, b: g.px[a][b]) if transpose else (lambda a, b: g.px[b][a])   # a along the run
    open_runs = {}       # (start, length, value) -> first line
    rects = []
    for line in range(h + 1):
        runs = set()
        if line < h:
            a = 0
            while a < w:
                v = at(a, line)
                b = a
                while b < w and at(b, line) == v:
                    b += 1
                if v:
                    runs.add((a, b - a, v))
                a = b
        for key in [k for k in open_runs if k not in runs]:
            first = open_runs.pop(key)
            rects.append((key[0], first, key[1], line - first, key[2]))
        for key in runs:
            open_runs.setdefault(key, line)
    if transpose:
        rects = [(y, x, hh, ww, v) for x, y, ww, hh, v in rects]
    return rects


def svg_text(g):
    rects = min((merge(g, False), merge(g, True)), key=len)
    by_colour = {}
    for x, y, w, h, v in sorted(rects, key=lambda r: (r[4], r[1], r[0])):
        by_colour.setdefault(v, []).append((x, y, w, h))
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{g.w * SCALE}" height="{g.h * SCALE}" '
           f'viewBox="0 0 {g.w} {g.h}" shape-rendering="crispEdges">',
           "<title>SECRET-SAUCE</title>"]
    for v, rs in sorted(by_colour.items(), key=lambda kv: (kv[0][3] != 255, kv[0])):
        colour = "#%02X%02X%02X" % v[:3]
        opacity = "" if v[3] == 255 else f' fill-opacity="{v[3] / 255:.2f}"'
        out.append(f'<g fill="{colour}"{opacity}>')
        for x, y, w, h in rs:
            out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}"/>')
        out.append("</g>")
    out.append("</svg>")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    pathlib.Path(sys.argv[1]).write_text(svg_text(paint()))
