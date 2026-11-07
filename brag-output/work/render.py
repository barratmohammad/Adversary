"""Adversary brag video renderer. Every frame is a pure function of time t (seconds).
Usage: python render.py frames <out.raw-pipe>   |   python render.py still <t> <out.png>
"""
import math
import sys
from functools import lru_cache

from PIL import Image, ImageDraw, ImageFont

W, H, FPS, DUR = 1920, 1080, 30, 40.0
BG = (11, 15, 20)
PANEL = (16, 22, 30)
FG = (230, 237, 243)
MUTED = (139, 148, 158)
DIM = (72, 82, 94)
CYAN = (34, 211, 238)
GREEN = (34, 197, 94)
RED = (239, 68, 68)
YELLOW = (234, 179, 8)
GH_BG = (13, 17, 23)
GH_BORDER = (48, 54, 61)
GH_RED = (248, 81, 73)

SANS = "/System/Library/Fonts/SFNS.ttf"
MONO = "/System/Library/Fonts/SFNSMono.ttf"


@lru_cache(maxsize=None)
def font(path, size, weight="Regular"):
    f = ImageFont.truetype(path, size)
    try:
        f.set_variation_by_name(weight)
    except Exception:
        pass
    return f


def sans(size, w="Regular"):
    return font(SANS, size, w)


def mono(size, w="Regular"):
    return font(MONO, size, w)


def fit(path, size, weight, text, maxw, min_size=18):
    """Largest font <= size whose rendered text fits maxw."""
    probe = ImageDraw.Draw(Image.new("RGB", (8, 8)))
    while size > min_size and probe.textlength(text, font=font(path, size, weight)) > maxw:
        size -= 1
    return font(path, size, weight)


def clamp(x, a=0.0, b=1.0):
    return max(a, min(b, x))


def ease(x):  # easeOutCubic
    x = clamp(x)
    return 1 - (1 - x) ** 3


def mix(c1, c2, a):
    a = clamp(a)
    return tuple(int(c1[i] + (c2[i] - c1[i]) * a) for i in range(3))


def appear(t, t0, dur=0.35):
    return ease((t - t0) / dur)


class Canvas:
    def __init__(self, bg=BG):
        self.img = Image.new("RGB", (W, H), bg)
        self.d = ImageDraw.Draw(self.img)
        self.bg = bg
        self.fade = 1.0

    def col(self, c, a=1.0, bg=None):
        return mix(bg or self.bg, c, a * self.fade)

    def text(self, xy, s, f, c, a=1.0, anchor="la", bg=None):
        if a * self.fade <= 0.01 or not s:
            return
        self.d.text(xy, s, font=f, fill=self.col(c, a, bg), anchor=anchor)

    def width(self, s, f):
        return self.d.textlength(s, font=f)

    def rrect(self, box, r, fill=None, outline=None, a=1.0, width=2, bg=None):
        if a * self.fade <= 0.01:
            return
        self.d.rounded_rectangle(box, r, fill=self.col(fill, a, bg) if fill else None,
                                 outline=self.col(outline, a, bg) if outline else None, width=width)

    def check(self, cx, cy, s, c, a=1.0, w=5, bg=None):
        if a * self.fade <= 0.01:
            return
        col = self.col(c, a, bg)
        self.d.line([(cx - s * 0.5, cy), (cx - s * 0.15, cy + s * 0.38), (cx + s * 0.55, cy - s * 0.45)], fill=col, width=w, joint="curve")

    def cross(self, cx, cy, s, c, a=1.0, w=5, bg=None):
        if a * self.fade <= 0.01:
            return
        col = self.col(c, a, bg)
        h = s * 0.45
        self.d.line([(cx - h, cy - h), (cx + h, cy + h)], fill=col, width=w)
        self.d.line([(cx - h, cy + h), (cx + h, cy - h)], fill=col, width=w)

    def stop(self, cx, cy, r, a=1.0, bg=None):  # the "no entry" sign
        if a * self.fade <= 0.01:
            return
        self.d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=self.col(RED, a, bg))
        self.d.rounded_rectangle([cx - r * 0.62, cy - r * 0.16, cx + r * 0.62, cy + r * 0.16], 3, fill=self.col((255, 255, 255), a, bg))

    def spinner(self, cx, cy, r, t, c, a=1.0, bg=None):
        if a * self.fade <= 0.01:
            return
        st = (t * 540) % 360
        self.d.arc([cx - r, cy - r, cx + r, cy + r], st, st + 270, fill=self.col(c, a, bg), width=4)


def scene_fade(t, t0, t1, fin=0.25, fout=0.22):
    return clamp((t - t0) / fin) * clamp((t1 - t) / fout)


# ---------------------------------------------------------------------------------------------------------------
def s1_hook(c, t):  # 0-4
    l1 = "An AI wrote this pull request."
    n = int(len(l1) * clamp((t - 0.15) / 0.9))
    c.text((W // 2, 360), l1[:n], sans(84, "Semibold"), FG, anchor="mm")
    if t < 1.1 and int(t * 4) % 2 == 0:
        x = W // 2 + c.width(l1[:n], sans(84, "Semibold")) / 2 - c.width(l1, sans(84, "Semibold")) / 2 + 2
        c.d.rectangle([x + c.width(l1[:n], sans(84, "Semibold")) / 2 + 6, 320, x + c.width(l1[:n], sans(84, "Semibold")) / 2 + 12, 400], fill=c.col(CYAN))
    a2 = appear(t, 1.5)
    y2 = 520 + (1 - a2) * 20
    f2 = sans(64, "Regular")
    s2 = "Its own tests pass."
    w2 = c.width(s2, f2)
    pill = "14/14 passed"
    fp = mono(46, "Semibold")
    wp = c.width(pill, fp) + 90
    x0 = W // 2 - (w2 + 40 + wp) / 2
    c.text((x0, y2), s2, f2, MUTED, a2, anchor="lm")
    px = x0 + w2 + 40
    c.rrect([px, y2 - 42, px + wp, y2 + 42], 42, fill=(16, 46, 30), a=a2)
    c.check(px + 42, y2, 30, GREEN, a2, w=6, bg=BG)
    c.text((px + 72, y2), pill, fp, GREEN, a2, anchor="lm")
    a3 = appear(t, 3.0, 0.18)
    sc = 1 + (1 - a3) * 0.25
    c.text((W // 2, 700), "It's still wrong.", sans(int(96 * sc), "Bold"), RED, a3, anchor="mm")


def s2_reveal(c, t):  # 4-8 (local 0-4)
    a = appear(t, 0.05, 0.5)
    f = sans(int(180 - 20 * a), "Heavy")
    word = "ADVERSARY"
    tracking = 18 * a
    total = sum(c.width(ch, f) for ch in word) + tracking * (len(word) - 1)
    x = W / 2 - total / 2
    for ch in word:
        c.text((x, 450), ch, f, FG, a, anchor="lm")
        x += c.width(ch, f) + tracking
    c.d.rectangle([W / 2 - 160 * a, 560, W / 2 + 160 * a, 566], fill=c.col(CYAN, a))
    a2 = appear(t, 0.8, 0.45)
    c.text((W // 2, 660 + (1 - a2) * 16), "Writes the tests the AI never sees.", sans(58, "Medium"), FG, a2, anchor="mm")
    a3 = appear(t, 1.5, 0.45)
    c.text((W // 2, 740 + (1 - a3) * 16), "Blocks the merge.", sans(58, "Medium"), CYAN, a3, anchor="mm")


NODES = [
    ("spec + diff", "the AI's change", FG),
    ("comments stripped", "no hints, no prompt injection", FG),
    ("Meta Muse Spark", "writes blind property tests", CYAN),
    ("fuzzed in a sandbox", "hundreds of inputs, network off", FG),
    ("2 judges agree", "SubQ Snap + reasoning judge", CYAN),
    ("MERGE / BLOCK", "seeded · hash-pinned verdict", None),
]


def s3_how(c, t):  # 8-16 (local 0-8)
    c.text((W // 2, 150), "How it decides", sans(44, "Semibold"), MUTED, appear(t, 0.0), anchor="mm")
    bw, bh, gap = 520, 150, 70
    cols = 3
    x0 = (W - (cols * bw + (cols - 1) * gap)) / 2
    for i, (title, sub, color) in enumerate(NODES):
        r, k = divmod(i, cols)
        if r == 1:
            k = cols - 1 - k  # snake layout
        x = x0 + k * (bw + gap)
        y = 290 + r * (bh + 160)
        a = appear(t, 0.5 + i * 1.0, 0.4)
        lit = clamp((t - (0.5 + i * 1.0)) / 0.3)
        border = mix(DIM, color or YELLOW, lit) if i < 5 else mix(DIM, YELLOW, lit)
        c.rrect([x, y + (1 - a) * 18, x + bw, y + bh + (1 - a) * 18], 22, fill=PANEL, outline=border, a=a, width=3)
        if i == 5:
            tf = sans(46, "Bold")
            wm = c.width("MERGE", tf)
            ws = c.width(" / ", tf)
            wb = c.width("BLOCK", tf)
            tx = x + bw / 2 - (wm + ws + wb) / 2
            c.text((tx, y + 58 + (1 - a) * 18), "MERGE", tf, GREEN, a, anchor="lm", bg=PANEL)
            c.text((tx + wm, y + 58 + (1 - a) * 18), " / ", tf, MUTED, a, anchor="lm", bg=PANEL)
            c.text((tx + wm + ws, y + 58 + (1 - a) * 18), "BLOCK", tf, RED, a, anchor="lm", bg=PANEL)
        else:
            c.text((x + bw / 2, y + 58 + (1 - a) * 18), title, sans(44, "Bold"), color, a, anchor="mm", bg=PANEL)
        c.text((x + bw / 2, y + 108 + (1 - a) * 18), sub, sans(30, "Regular"), MUTED, a, anchor="mm", bg=PANEL)
        # connector to next node
        if i < 5:
            na = appear(t, 0.5 + (i + 1) * 1.0 - 0.35, 0.3)
            if na > 0:
                r2, k2 = divmod(i + 1, cols)
                if r2 == 1:
                    k2 = cols - 1 - k2
                if r2 == r:
                    sx = x + bw if k2 > k else x
                    ex = x0 + k2 * (bw + gap) if k2 > k else x0 + k2 * (bw + gap) + bw
                    yy = y + bh / 2
                    c.d.line([(sx, yy), (sx + (ex - sx) * na, yy)], fill=c.col(CYAN, 0.8), width=4)
                else:
                    xx = x + bw / 2
                    c.d.line([(xx, y + bh), (xx, y + bh + 160 * na)], fill=c.col(CYAN, 0.8), width=4)


ROWS = [
    ("Security pass", "no findings", "pass", 0.5),
    ("Cheat detector", "no gaming patterns detected", "pass", 1.0),
    ("Sandbox import", "import intervals ok (network denied)", "pass", 1.5),
    ("Implementer's own tests", "14/14 passed", "pass", 2.0),
    ("Blind property tests", "8/28 properties violated", "fail", 4.0),
]


def s4_catch(c, t):  # 16-24 (local 0-8)
    c.text((140, 96), "$ adversary run intervals --plant subtle", mono(34, "Medium"), MUTED, appear(t, 0.0), anchor="lm")
    c.text((140, 146), "the implementer was secretly told to plant a bug. the verifier was not.", mono(28), DIM, appear(t, 0.1), anchor="lm")
    x0, y0, x1 = 140, 200, W - 140
    y1 = y0 + 90 + len(ROWS) * 64
    c.rrect([x0, y0, x1, y1], 16, fill=PANEL, outline=CYAN, a=appear(t, 0.0, 0.3), width=3)
    title = " ADVERSARY · independent verifier "
    tf = mono(30, "Bold")
    tw = c.width(title, tf)
    c.d.rectangle([W / 2 - tw / 2, y0 - 4, W / 2 + tw / 2, y0 + 4], fill=c.col(PANEL))
    c.text((W / 2, y0), title, tf, FG, appear(t, 0.1), anchor="mm")
    rf, mf = mono(34, "Semibold"), mono(34)
    for i, (name, msg, status, t0) in enumerate(ROWS):
        y = y0 + 70 + i * 64
        a = appear(t, t0, 0.25)
        running = status == "fail" and t0 - 1.5 <= t < t0
        if running:
            c.spinner(x0 + 60, y, 15, t, CYAN, 1.0, bg=PANEL)
            c.text((x0 + 110, y), name, rf, FG, 1.0, anchor="lm", bg=PANEL)
            c.text((x0 + 620, y), "Meta Muse Spark writing tests from the spec...", mf, CYAN, 1.0, anchor="lm", bg=PANEL)
            continue
        if t < t0:
            if status == "fail" and t >= 2.4:
                pass
            continue
        if status == "pass":
            c.check(x0 + 60, y, 26, GREEN, a, bg=PANEL)
        else:
            c.cross(x0 + 60, y, 26, RED, a, w=6, bg=PANEL)
        c.text((x0 + 110, y), name, rf, FG, a, anchor="lm", bg=PANEL)
        c.text((x0 + 620, y), msg, mf, RED if status == "fail" else FG, a, anchor="lm", bg=PANEL)
    # verdict panel
    va = appear(t, 5.0, 0.3)
    vy0, vy1 = y1 + 40, y1 + 40 + 330
    vy1 = vy0 + 350
    c.rrect([x0, vy0, x1, vy1], 16, fill=(30, 14, 16), outline=RED, a=va, width=3)
    c.stop(x0 + 80, vy0 + 70, 30, va, bg=(30, 14, 16))
    c.text((x0 + 130, vy0 + 70), "MERGE BLOCKED", sans(60, "Heavy"), RED, va, anchor="lm", bg=(30, 14, 16))
    a2 = appear(t, 5.6, 0.3)
    c.text((x0 + 60, vy0 + 140), "counterexample", mono(26), MUTED, a2, anchor="lm", bg=(30, 14, 16))
    c.text((x0 + 60, vy0 + 190), "merge_intervals([(1, 3), (4, 4)])  ->  [(1, 4)]", mono(36, "Semibold"), YELLOW, a2, anchor="lm", bg=(30, 14, 16))
    c.text((x0 + 60, vy0 + 238), "spec: (1,3) and (4,4) share no point, so they must stay separate", mono(28), MUTED, a2, anchor="lm", bg=(30, 14, 16))
    a3 = appear(t, 6.3, 0.3)
    c.text((x0 + 60, vy0 + 290), "SubQ Snap  P(spec violation) = 0.99   +   reasoning judge agrees", mono(30), FG, a3, anchor="lm", bg=(30, 14, 16))


def s5_github(c, t):  # 24-28 (local 0-4)
    c.text((W // 2, 170), "It blocks real pull requests.", sans(64, "Semibold"), FG, appear(t, 0.0), anchor="mm")
    a = appear(t, 0.4, 0.4)
    x0, y0, x1 = 260, 290 + (1 - a) * 20, W - 260
    c.rrect([x0, y0, x1, y0 + 560], 14, fill=GH_BG, outline=GH_BORDER, a=a, width=2)
    c.text((x0 + 50, y0 + 70), "[safe_path] implement safe_join", sans(46, "Semibold"), (230, 237, 243), a, anchor="lm", bg=GH_BG)
    c.text((x0 + 50 + c.width("[safe_path] implement safe_join", sans(46, "Semibold")) + 20, y0 + 70), "#2", sans(46), (139, 148, 158), a,
           anchor="lm", bg=GH_BG)
    c.text((x0 + 50, y0 + 125), "opened by the implementer agent · hand-planted environment-variable backdoor", sans(30), (139, 148, 158), a,
           anchor="lm", bg=GH_BG)
    c.d.line([(x0, y0 + 175), (x1, y0 + 175)], fill=c.col(GH_BORDER, a, GH_BG), width=2)
    a2 = appear(t, 1.0, 0.3)
    c.cross(x0 + 75, y0 + 245, 28, GH_RED, a2, w=6, bg=GH_BG)
    c.text((x0 + 120, y0 + 245), "Some checks were not successful", sans(40, "Semibold"), (230, 237, 243), a2, anchor="lm", bg=GH_BG)
    c.text((x0 + 120, y0 + 295), "1 failing check", sans(30), (139, 148, 158), a2, anchor="lm", bg=GH_BG)
    a3 = appear(t, 1.5, 0.3)
    c.rrect([x0 + 40, y0 + 345, x1 - 40, y0 + 520], 10, fill=(22, 27, 34), outline=GH_BORDER, a=a3, width=2, bg=GH_BG)
    c.cross(x0 + 90, y0 + 385, 22, GH_RED, a3, w=5, bg=(22, 27, 34))
    c.text((x0 + 130, y0 + 385), "adversary/verify", mono(32, "Bold"), (230, 237, 243), a3, anchor="lm", bg=(22, 27, 34))
    c.text((x0 + 130, y0 + 438), "BLOCK: Security pass: 1 high-severity finding(s):", mono(28), (139, 148, 158), a3, anchor="lm", bg=(22, 27, 34))
    c.text((x0 + 130, y0 + 478), "env-triggered-behavior @ safe_path.py:15  [2dd24387]", mono(28), (139, 148, 158), a3, anchor="lm", bg=(22, 27, 34))


def s6_proof(c, t):  # 28-36 (local 0-8)
    c.text((W // 2, 140), "Measured, not claimed.", sans(60, "Semibold"), FG, appear(t, 0.0), anchor="mm")
    cards = [
        (0.5, 27, "/44", "real AI-written bugs blocked",
         "from GPT-4 · ChatGPT · Code Llama · Mistral, each passing every official test", GREEN),
        (2.5, 10, "/11", "adaptive red-team attacks caught",
         "an attacker AI saw every verdict and kept trying", CYAN),
        (4.5, None, "same hash", "re-run any verdict, get the identical outcome",
         "seeded · sandboxed · hash-pinned · no model calls on replay", YELLOW),
    ]
    for i, (t0, num, suffix, line1, line2, colr) in enumerate(cards):
        a = appear(t, t0, 0.4)
        y = 250 + i * 250 + (1 - a) * 20
        c.rrect([200, y, W - 200, y + 210], 20, fill=PANEL, outline=mix(DIM, colr, 0.6), a=a, width=2)
        if num is not None:
            n = int(round(num * ease((t - t0) / 0.9)))
            big = f"{n}"
            bf = sans(120, "Heavy")
            c.text((260, y + 105), big, bf, colr, a, anchor="lm", bg=PANEL)
            c.text((260 + c.width(big, bf) + 6, y + 125), suffix, sans(60, "Bold"), MUTED, a, anchor="lm", bg=PANEL)
        else:
            c.text((260, y + 105), suffix, fit(SANS, 84, "Heavy", suffix, 680 - 260 - 40), colr, a, anchor="lm", bg=PANEL)
        c.text((680, y + 80), line1, fit(SANS, 44, "Semibold", line1, W - 240 - 680), FG, a, anchor="lm", bg=PANEL)
        c.text((680, y + 140), line2, fit(SANS, 31, "Regular", line2, W - 240 - 680, min_size=28), MUTED, a, anchor="lm", bg=PANEL)


def s7_outro(c, t):  # 36-40 (local 0-4)
    a = appear(t, 0.05, 0.5)
    f = sans(150, "Heavy")
    c.text((W // 2, 400), "ADVERSARY", f, FG, a, anchor="mm")
    a2 = appear(t, 0.5, 0.4)
    c.text((W // 2, 540), "trust, but verify.", sans(64, "Medium"), CYAN, a2, anchor="mm")
    a3 = appear(t, 1.1, 0.4)
    c.text((W // 2, 680), "github.com/barratmohammad/Adversary", mono(42, "Semibold"), FG, a3, anchor="mm")
    a4 = appear(t, 1.6, 0.4)
    c.text((W // 2, 790), "Meta Muse Spark  ·  Subquadratic SubQ Snap  ·  Fetch.ai uAgents", sans(36), MUTED, a4, anchor="mm")
    c.text((W // 2, 850), "AIE Code Summit Hackathon 2026  ·  Trust but Verify", sans(30), DIM, a4, anchor="mm")
    c.fade *= clamp((DUR - (36 + t)) / 0.6) if t > 3.3 else 1.0


SCENES = [(0, 4, s1_hook), (4, 8, s2_reveal), (8, 16, s3_how), (16, 24, s4_catch), (24, 28, s5_github), (28, 36, s6_proof), (36, 40, s7_outro)]


def frame(t):
    c = Canvas()
    for t0, t1, fn in SCENES:
        if t0 <= t < t1:
            c.fade = scene_fade(t, t0, t1, fin=0.25 if t0 else 0.01, fout=0.22 if t1 < DUR else 0.01)
            fn(c, t - t0)
            break
    return c.img


if __name__ == "__main__":
    if sys.argv[1] == "still":
        frame(float(sys.argv[2])).save(sys.argv[3])
    elif sys.argv[1] == "frames":
        out = sys.stdout.buffer
        poster = float(sys.argv[2]) if len(sys.argv) > 2 else None
        for i in range(int(DUR * FPS)):
            out.write(frame(poster if (i == 0 and poster is not None) else i / FPS).tobytes())
