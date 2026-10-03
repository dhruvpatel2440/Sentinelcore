"""Contrast audit for the token pairs the site actually uses. Run: python scripts/contrast.py"""
import sys


def hex2rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def lum(c):
    def f(v):
        v /= 255
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = c
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def ratio(a, b):
    la, lb = sorted((lum(a), lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def over(fg, bg, a):
    return tuple(round(fg[i] * a + bg[i] * (1 - a)) for i in range(3))


H = hex2rgb
VIOLET, MINT, INK, NIGHT, LILAC, WHITE = H("a855f7"), H("3dffc5"), H("0b0b14"), H("16162a"), H("f0ebff"), H("ffffff")

# Worst-case backgrounds under body text: gradient end colours plus the glow overlay.
dark_bgs = [INK, NIGHT, H("2a1553"), over(VIOLET, H("2a1553"), 0.38), over(VIOLET, INK, 0.38)]
light_bgs = [LILAC, H("e4dcff"), H("d6c9ff"), over(VIOLET, H("d6c9ff"), 0.28)]
# Glass panels: base at 55% / 24% over the same backgrounds.
dark_glass = [over(NIGHT, b, 0.55) for b in dark_bgs] + [over(NIGHT, b, 0.24) for b in dark_bgs]
light_glass = [over(WHITE, b, 0.55) for b in light_bgs] + [over(WHITE, b, 0.24) for b in light_bgs]

checks = []


def add(name, fg, bgs, need=4.5):
    worst = min(ratio(fg, b) for b in bgs)
    checks.append((name, worst, need))


add("dark: text on page", H("f6f4ff"), dark_bgs)
add("dark: text on glass", H("f6f4ff"), dark_glass)
add("dark: muted text on page", H("c9c5e6"), dark_bgs)
add("dark: muted text on glass", H("c9c5e6"), dark_glass)
add("dark: link (mint) on page", MINT, dark_bgs)
add("dark: link (mint) on glass", MINT, dark_glass)
add("light: text on page", INK, light_bgs)
add("light: text on glass", INK, light_glass)
add("light: muted text on page", H("433f63"), light_bgs)
add("light: muted text on glass", H("433f63"), light_glass)
add("light: link on page", H("4c1d95"), light_bgs)
add("light: link on glass", H("4c1d95"), light_glass)
for label, bg in [("mint button", MINT), ("violet button/badge", VIOLET), ("critical badge", H("ff4b6e")),
                  ("high badge", H("ff9a3c")), ("medium badge", H("ffd93d")), ("low badge", H("3db8ff")),
                  ("info badge", H("9a98b0"))]:
    add(f"ink on {label}", INK, [bg])
add("terminal text", H("e8fff7"), [INK])
add("terminal dim text", H("a9a5c9"), [INK, H("1d1d38")])
add("terminal muted title", H("c9c5e6"), [H("1d1d38")])

bad = 0
for name, got, need in checks:
    ok = got >= need
    bad += not ok
    print(f"{'ok  ' if ok else 'FAIL'} {got:5.2f}:1 (need {need})  {name}")
sys.exit(1 if bad else 0)
