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
        secs.append({'name': name, 'va': va, 'vs': vs, 'rp': rp, 'rs': rs})
    dd = opt + (112 if pe64 else 96)
    nexp = struct.unpack_from('<I', d, dd + 108)[0]  # exception dir entry (index 3)
    exc_rva, exc_size = struct.unpack_from('<II', d, dd + 4 * 3)
    return d, base, secs, exc_rva, exc_size

def rva2off(secs, rva):
    for s in secs:
        if s['va'] <= rva < s['va'] + max(s['vs'], s['rs']):
            return s['rp'] + (rva - s['va'])
    return None

def sec_by_name(secs, name):
    for s in secs:
        if s['name'] == name:
            return s
    return None

def parse_pdata(d, secs, exc_rva, exc_size):
    # prefer the real .pdata section, fall back to the exception directory RVA
    s = sec_by_name(secs, '.pdata')
    if s is not None:
        off = s['rp']
        n = min(s['rs'], s['vs']) // 12
    else:
        off = rva2off(secs, exc_rva)
        if off is None:
            return []
        n = exc_size // 12
    funcs = []
    for i in range(n):
        b, e, u = struct.unpack_from('<III', d, off + i * 12)
        if b:
            funcs.append((b, e))
    funcs.sort()
    return funcs

def enclosing(funcs, rva):
    import bisect
    starts = [f[0] for f in funcs]
    i = bisect.bisect_right(starts, rva) - 1
    if i >= 0 and funcs[i][0] <= rva < funcs[i][1]:
        return funcs[i]
    return None

path = sys.argv[1]
str_rvas = [int(x, 16) for x in sys.argv[2:]]
d, base, secs, exc_rva, exc_size = load(path)
funcs = parse_pdata(d, secs, exc_rva, exc_size)
text = sec_by_name(secs, '.text')
print(f'{os.path.basename(path)} size=0x{len(d):X} funcs={len(funcs)} text=0x{text["va"]:X}..0x{text["va"]+text["vs"]:X}')

lo = rva2off(secs, text['va'])
buf = d[lo:lo + text['vs']]
tv = text['va']

def report(kind, at, target):
    fn = enclosing(funcs, at)
    info = f'func 0x{fn[0]:X}-0x{fn[1]:X} (size 0x{fn[1]-fn[0]:X})' if fn else 'no pdata entry'
    print(f'  {kind:<22} at RVA 0x{at:X}  -> target 0x{target:X}  [{info}]')

print('--- lea xrefs (48/4C 8D xx disp32) ---')
for i in range(len(buf) - 7):
    b0, b1, b2 = buf[i], buf[i+1], buf[i+2]
    if b0 in (0x48, 0x4C) and b1 == 0x8D and (b2 & 0xC7) == 0x05:
        disp = struct.unpack_from('<i', buf, i + 3)[0]
        tgt = tv + i + 7 + disp
        for s in str_rvas:
            if s - 32 <= tgt <= s + 64:
                report('lea', tv + i, tgt)
print('--- rip-rel cmp/mov byte refs (38 15 / 8A 05 / 0F B6 05) ---')
for i in range(len(buf) - 7):
    if buf[i] == 0x38 and buf[i+1] == 0x15:
        disp = struct.unpack_from('<i', buf, i + 2)[0]
        tgt = tv + i + 6 + disp
        for s in str_rvas:
            if s - 32 <= tgt <= s + 64:
                report('cmp-byte', tv + i, tgt)
    if buf[i] == 0x0F and buf[i+1] == 0xB6 and buf[i+2] == 0x05:
        disp = struct.unpack_from('<i', buf, i + 3)[0]
        tgt = tv + i + 7 + disp
        for s in str_rvas:
            if s - 32 <= tgt <= s + 64:
                report('movzx-byte', tv + i, tgt)
