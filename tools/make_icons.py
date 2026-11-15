#!/usr/bin/env python3
"""Generate res/netguard.ico (active, green shield) and res/netguard-paused.ico (grey, pause bars). No dependencies."""
import struct, zlib, pathlib, math
root = pathlib.Path(__file__).resolve().parent.parent
SHIELD = [(.50,.04),(.86,.16),(.88,.46),(.80,.68),(.50,.96),(.20,.68),(.12,.46),(.14,.16)]

def inside(poly, x, y):
    c = False; n = len(poly)
    for i in range(n):
        x1, y1 = poly[i]; x2, y2 = poly[(i + 1) % n]
        if (y1 > y) != (y2 > y) and x < (x2 - x1) * (y - y1) / (y2 - y1) + x1: c = not c
    return c

def seg_dist(px, py, a, b):
    (x1, y1), (x2, y2) = a, b
    dx, dy = x2 - x1, y2 - y1
    t = max(0, min(1, ((px - x1) * dx + (py - y1) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - (x1 + t * dx), py - (y1 + t * dy))

def edge_dist(poly, x, y):
    return min(seg_dist(x, y, poly[i], poly[(i + 1) % len(poly)]) for i in range(len(poly)))

def render(size, active):
    fill, border = ((46, 160, 90), (24, 104, 58)) if active else ((124, 130, 142), (78, 83, 94))
    ss = 4; px = []
    for yy in range(size):
        row = []
        for xx in range(size):
            r = g = b = a = 0
            for sy in range(ss):
                for sx in range(ss):
                    x = (xx + (sx + .5) / ss) / size; y = (yy + (sy + .5) / ss) / size
                    if not inside(SHIELD, x, y): continue
                    col = border if edge_dist(SHIELD, x, y) < 0.075 else fill
                    mark = False
                    if active:   # check mark
                        mark = min(seg_dist(x, y, (.31, .52), (.45, .68)), seg_dist(x, y, (.45, .68), (.71, .33))) < 0.065
                    else:        # pause bars
                        mark = (.35 < x < .46 or .54 < x < .65) and .30 < y < .70
                    if mark: col = (255, 255, 255)
                    r += col[0]; g += col[1]; b += col[2]; a += 1
            n = ss * ss
            row.append((r // a, g // a, b // a, 255 * a // n) if a else (0, 0, 0, 0))
        px.append(row)
    return px

def ico(path, active, sizes=(16, 20, 24, 32, 48, 64)):
    imgs = []
    for s in sizes:
        px = render(s, active)
        pix = b"".join(struct.pack("<BBBB", b, g, r, a) for row in reversed(px) for (r, g, b, a) in row)   # BGRA, bottom-up
        mask = b"\x00" * (((s + 31) // 32) * 4 * s)
        hdr = struct.pack("<IiiHHIIiiII", 40, s, s * 2, 1, 32, 0, len(pix) + len(mask), 0, 0, 0, 0)
        imgs.append(hdr + pix + mask)
    out = struct.pack("<HHH", 0, 1, len(sizes)); off = 6 + 16 * len(sizes)
    for s, d in zip(sizes, imgs):
        out += struct.pack("<BBBBHHII", s, s, 0, 0, 1, 32, len(d), off); off += len(d)
    pathlib.Path(path).write_bytes(out + b"".join(imgs))

def png(path, px):
    h, w = len(px), len(px[0])
    raw = b"".join(b"\x00" + b"".join(struct.pack("BBBB", *p) for p in row) for row in px)
    def ch(t, d): return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    pathlib.Path(path).write_bytes(b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)) + ch(b"IDAT", zlib.compress(raw)) + ch(b"IEND", b""))

if __name__ == "__main__":
    ico(root / "res" / "netguard.ico", True)
    ico(root / "res" / "netguard-paused.ico", False)
    print("wrote res/netguard.ico and res/netguard-paused.ico")
