import struct, os, sys

def load(path):
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
    def rva2off(rva):
        for name, va, vs, rp, rs in secs:
            if va <= rva < va + max(vs, rs):
                return rp + (rva - va), name
        return None, None
    return d, base, secs, rva2off

path = sys.argv[1]
d, base, secs, rva2off = load(path)
print(f'{os.path.basename(path)}  size=0x{len(d):X}  imagebase=0x{base:X}')
print('sections:', ', '.join(f'{n}@0x{va:X}(0x{vs:X})' for n, va, vs, rp, rs in secs))

targets = [(0x2CEF5E2, 48), (0x1AC86F9, 48), (0x1AC8721, 32), (0x1AC8734, 32), (0x2FF51E0, 24)]
for rva, n in targets:
    off, sec = rva2off(rva)
    if off is None:
        print(f'  RVA 0x{rva:X}: not mapped'); continue
    b = d[off:off+n]
    txt = ''.join(chr(c) if 32 <= c < 127 else '.' for c in b)
    print(f'  RVA 0x{rva:X} [{sec}] off=0x{off:X}: {b.hex(" ")}  |{txt}|')
