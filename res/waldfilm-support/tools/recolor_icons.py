# Recolor the original RustDesk icons (blue gradient #0071ff -> #00bfe1) to Waldfilm green.
# usage: recolor.py <orig_root> <out_root> <remote|support>
import sys, os, re, colorsys
from PIL import Image
orig, out, variant = sys.argv[1], sys.argv[2], sys.argv[3]
H, S = 117/360, 0.46
L0, L1 = (0.41, 0.49) if variant == "remote" else (0.35, 0.43)   # remote: centre L=45% = #43A83E
def green(g):
    r, gg, b = colorsys.hls_to_rgb(H, L0 + (L1-L0)*g, S)
    return (r*255, gg*255, b*255)
def hexcol(g):
    return '#%02x%02x%02x' % tuple(round(c) for c in green(g))
def recolor(im):
    im = im.convert("RGBA"); px = im.load()
    for y in range(im.height):
        for x in range(im.width):
            r, g, b, a = px[x, y]
            if b - r <= 12:
                continue
            t = 1 - r/255.0
            if t < 0.02:
                continue
            base = [(c - (1-t)*255)/t for c in (r, g, b)]
            bb = max(base[2], 1)
            gpos = min(max((base[1]/bb - 0.443)/(0.849-0.443), 0), 1)
            refb = 255 + (225-255)*gpos
            k = min(bb/refb, 1.0)
            gr = green(gpos)
            px[x, y] = tuple(int(round((1-t)*255 + t*k*c)) for c in gr) + (a,)
    return im
def p(*a): return os.path.join(*a)
def ensure(f): os.makedirs(os.path.dirname(f), exist_ok=True)
# PNGs
for f in ["res/icon.png","res/mac-icon.png","res/32x32.png","res/64x64.png","res/128x128.png","res/128x128@2x.png"]:
    o = p(out,f); ensure(o); recolor(Image.open(p(orig,f))).save(o)
# ICOs: recolor every contained size
for f in ["res/icon.ico","res/tray-icon.ico","flutter/windows/runner/resources/app_icon.ico"]:
    src = Image.open(p(orig,f)); sizes = sorted(src.info["sizes"])
    frames = {}
    for s in sizes:
        src.size = s
        frames[s] = recolor(src.copy() if False else Image.open(p(orig,f)).ico.getimage(s))
    big = frames[sizes[-1]]
    o = p(out,f); ensure(o)
    big.save(o, sizes=sizes, append_images=[frames[s] for s in sizes[:-1]], bitmap_format="bmp")
# flutter/assets/icon.ico (used by Windows shortcuts of custom clients): same as res/icon.ico
o = p(out,"flutter/assets/icon.ico"); ensure(o)
Image.open(p(out,"res/icon.ico")).save(o, sizes=sorted(Image.open(p(orig,"res/icon.ico")).info["sizes"]), bitmap_format="bmp") if False else open(o,"wb").write(open(p(out,"res/icon.ico"),"rb").read())
# ICNS: recolor every contained size
import subprocess, tempfile, glob
tmp = tempfile.mkdtemp(); iset = os.path.join(tmp, "AppIcon.iconset")
subprocess.check_call(["iconutil", "-c", "iconset", p(orig,"flutter/macos/Runner/AppIcon.icns"), "-o", iset])
for f in glob.glob(os.path.join(iset, "*.png")):
    recolor(Image.open(f)).save(f)
print("icns frames:", sorted(os.path.basename(f) for f in glob.glob(os.path.join(iset, "*.png"))))
o = p(out,"flutter/macos/Runner/AppIcon.icns"); ensure(o)
subprocess.check_call(["iconutil", "-c", "icns", iset, "-o", o])
# SVGs with the gradient
for f in ["flutter/assets/icon.svg","res/scalable.svg","res/logo.svg","res/icon.svg","res/design.svg","res/logo-header.svg"]:
    if not os.path.exists(p(orig,f)): continue
    s = open(p(orig,f)).read()
    s2 = re.sub("#0071ff", hexcol(0), s, flags=re.I); s2 = re.sub("#00bfe1", hexcol(1), s2, flags=re.I)
    if s2 != s:
        o = p(out,f); ensure(o); open(o,"w").write(s2)
print(variant, "centre", hexcol(0.5), "ends", hexcol(0), hexcol(1))
