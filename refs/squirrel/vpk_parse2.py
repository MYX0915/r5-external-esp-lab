import io, os, re, struct
BASE = r"E:\Users\MYX\Desktop\test-game\refs\squirrel\vpk\CheatsFolder"
DIR_VPK = os.path.join(BASE, "englishclient_frontend.bsp.pak000_dir.vpk")
raw = io.open(DIR_VPK, "rb").read()

def rc(buf, pos):
    e = buf.find(b"\x00", pos)
    if e < 0: return None, pos
    return buf[pos:e].decode("latin1"), e+1

pos = 16
entries = []
while pos < len(raw):
    ext, pos2 = rc(raw, pos)
    if not ext: break
    pos = pos2
    while pos < len(raw):
        path, pos2 = rc(raw, pos)
        if path is None: break
        pos = pos2
        if not path: break
        while pos < len(raw):
            name, pos2 = rc(raw, pos)
            if name is None: break
            pos = pos2
            if not name: break
            if pos + 18 > len(raw): break
            crc, pre, arch, off, ln, term = struct.unpack_from("<IHHIIH", raw, pos)
            pos += 18
            full = ("%s/%s.%s" % (path, name, ext)) if path else ("%s.%s" % (name, ext))
            entries.append((full, off, ln))
        if pos >= len(raw): break

out = os.path.join(os.path.dirname(BASE), "vpk_listing.txt")
io.open(out, "w", encoding="utf-8").write("\n".join("%s\t0x%08X\t%d" % e for e in entries))
print("entries:", len(entries), "->", out)
valid = re.compile(r"^[A-Za-z0-9_./-]+$")
good = [e for e in entries if valid.match(e[0])]
print("valid-looking:", len(good))
print()
for p, off, ln in good:
    print("%-72s off=0x%08X len=%d" % (p, off, ln))
