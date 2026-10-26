#!/usr/bin/env python3
"""Compose the php-scanner GitHub social preview (1280x640, Pliny purple godmode theme)."""
from PIL import Image, ImageDraw, ImageFilter, ImageFont
import random

W, H = 1280, 640
img = Image.new("RGB", (W, H), (7, 5, 14))

# --- radial purple-magenta glow, bottom-left and top-right ---
glow = Image.new("RGB", (W, H), (0, 0, 0))
gd = ImageDraw.Draw(glow)
def radial(cx, cy, r, color, steps=60):
    for i in range(steps, 0, -1):
        a = max(0, int(i / steps * 255))
        c = tuple(int(v * (i / steps) ** 1.6) for v in color)
        gd.ellipse([cx - r * i / steps, cy - r * i / steps, cx + r * i / steps, cy + r * i / steps], fill=c)
radial(140, 560, 700, (120, 20, 160))     # violet, bottom-left
radial(1180, 90, 620, (180, 20, 120))     # hot magenta, top-right
img = Image.blend(img, glow, 0.85)
img = img.filter(ImageFilter.GaussianBlur(60))

d = ImageDraw.Draw(img, "RGBA")

# --- faint grid, terminal vibe ---
for x in range(0, W, 40):
    d.line([(x, 0), (x, H)], fill=(120, 80, 160, 14), width=1)
for y in range(0, H, 40):
    d.line([(0, y), (W, y)], fill=(120, 80, 160, 14), width=1)

# --- right half: floating code panel with PHP lines, vuln rows flaring magenta ---
panel_w, panel_h = 560, 420
panel = Image.new("RGBA", (panel_w, panel_h), (0, 0, 0, 0))
pd = ImageDraw.Draw(panel)
pd.rounded_rectangle([0, 0, panel_w - 1, panel_h - 1], radius=14, fill=(10, 8, 20, 216),
                     outline=(150, 90, 200, 90), width=2)
pd.rounded_rectangle([0, 0, panel_w - 1, 34], radius=14, fill=(22, 14, 40, 255))
pd.rectangle([0, 20, panel_w - 1, 34], fill=(22, 14, 40, 255))
for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
    pd.ellipse([16 + i * 22, 11, 30 + i * 22, 25], fill=c)

mono = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 22)
lines = [
    ("<?php session_start();", False),
    ("$id = $_GET['id'];", False),
    ("$q = \"SELECT * FROM p WHERE id=$id\";", True),
    ("echo shell_exec('ping ' . $_POST['h']);", True),
    ("include $_GET['page'];", True),
    ("unserialize($_COOKIE['cart']);", True),
    ("header('Location: ' . $_GET['go']);", True),
    ("?>", False),
]
random.seed(7)
for i, (text, vuln) in enumerate(lines):
    y = 52 + i * 44
    if vuln:  # magenta flare row — dark fill, bright text for thumbnail contrast
        pd.rounded_rectangle([10, y - 6, panel_w - 10, y + 26], radius=5, fill=(120, 0, 70, 235),
                             outline=(255, 60, 170, 255), width=3)
        pd.text((22, y), text, font=mono, fill=(255, 235, 248, 255))
    else:
        pd.text((22, y), text, font=mono, fill=(150, 140, 190, 190))

panel = panel.rotate(-4, expand=True, resample=Image.BICUBIC)
panel = panel.resize((int(panel.width * 0.85), int(panel.height * 0.85)), Image.LANCZOS)
img.paste(panel, (710, 100), panel)
d = ImageDraw.Draw(img, "RGBA")

# --- scanner beam: from top-right eye down-left over the panel ---
beam = Image.new("RGBA", (W, H), (0, 0, 0, 0))
bd = ImageDraw.Draw(beam)
bd.polygon([(1180, 70), (700, 160), (760, 520), (1235, 250)], fill=(200, 40, 200, 46))
beam = beam.filter(ImageFilter.GaussianBlur(14))
img = Image.alpha_composite(img.convert("RGBA"), beam).convert("RGB")
d = ImageDraw.Draw(img, "RGBA")
# scanner eye at beam origin
ex, ey = 1185, 85
d.ellipse([ex - 46, ey - 46, ex + 46, ey + 46], fill=(12, 8, 22), outline=(170, 90, 220, 255), width=3)
d.ellipse([ex - 26, ey - 26, ex + 26, ey + 26], fill=(255, 30, 150), outline=(255, 150, 220, 255), width=3)
d.ellipse([ex - 9, ey - 9, ex + 9, ey + 9], fill=(255, 220, 240))

# --- left half: title ---
bold = ImageFont.truetype("/System/Library/Fonts/HelveticaNeue.ttc", 84)
title = "php-scanner"
tw = d.textlength(title, font=bold)
tx = 64
while tx + tw > 600:  # keep clear of the code panel
    bold = ImageFont.truetype("/System/Library/Fonts/HelveticaNeue.ttc", bold.size - 4)
    tw = d.textlength(title, font=bold)
d.text((tx, 190), title, font=bold, fill=(238, 226, 255))
# luminous rule under title
rule = Image.new("RGBA", (W, H), (0, 0, 0, 0))
rd = ImageDraw.Draw(rule)
rd.rounded_rectangle([tx, 310, tx + tw, 317], radius=4, fill=(200, 40, 210, 255))
rule = rule.filter(ImageFilter.GaussianBlur(6))
img = Image.alpha_composite(img.convert("RGBA"), rule)
rd2 = ImageDraw.Draw(img)
rd2.rounded_rectangle([tx, 310, tx + tw, 317], radius=4, fill=(255, 120, 230, 255))

sub = ImageFont.truetype("/System/Library/Fonts/HelveticaNeue.ttc", 28)
subB = ImageFont.truetype("/System/Library/Fonts/HelveticaNeue.ttc", 28)
vx = tx + 4
for part, font, col in [
    ("scan", subB, (255, 190, 240, 255)), (" · ", sub, (140, 120, 170, 255)),
    ("triage", subB, (255, 190, 240, 255)), (" · ", sub, (140, 120, 170, 255)),
    ("pentest", subB, (255, 190, 240, 255)), ("  —  small PHP sites", sub, (196, 170, 226, 235)),
]:
    rd2.text((vx, 337), part, font=font, fill=col)
    vx += rd2.textlength(part, font=font)

img.save("gh_og_share_image.png", optimize=True)
print("saved", img.size)
