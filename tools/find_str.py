import struct, os, sys

def sections(path):
    d = open(path, 'rb').read()
    e = struct.unpack_from('<I', d, 0x3C)[0]
    coff = e + 4
    nsec = struct.unpack_from('<H', d, coff + 2)[0]
    optsize = struct.unpack_from('<H', d, coff + 16)[0]
    opt = coff + 20
    pe64 = struct.unpack_from('<H', d, opt)[0] == 0x20b
    base = struct.unpack_from('<Q', d, opt + 24)[0] if pe64 else struct.unpack_from('<I', d, opt + 28)[0]
    so = opt + optsize
    secs = []
    for i in range(nsec):
        s = so + i * 40
        name = d[s:s+8].rstrip(b'\0').decode('latin1')
        vs, va, rs, rp = struct.unpack_from('<IIII', d, s + 8)
        secs.append((name, va, vs, rp, rs))
    return d, base, secs

def off2rva(secs, off):
    for name, va, vs, rp, rs in secs:
        if rp <= off < rp + rs:
            return va + (off - rp), name
    return None, None

path = sys.argv[1]
needles = [n.encode() for n in sys.argv[2:]]
d, base, secs = sections(path)
print(f'{os.path.basename(path)} size=0x{len(d):X}')
for nd in needles:
    hits = []
    start = 0
    while len(hits) < 6:
        i = d.find(nd, start)
        if i < 0: break
        rva, sec = off2rva(secs, i)
        hits.append((rva, sec, i))
        start = i + 1
    print(f'  "{nd.decode(errors="replace")}" -> ' + (', '.join(f'RVA 0x{r:X}[{s}]' for r, s, o in hits) if hits else 'NOT FOUND'))
