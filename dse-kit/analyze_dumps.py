"""analyze_dumps.py -- 分析 dumper2 产出的内核镜像 dump

对每个文件输出：时间戳、SizeOfImage、节表（重点看 Themida 的 .grfn*/.themida）、
导入的 DLL 及关键 API、以及命中的特征字符串。
"""
import glob, os, struct, sys

MARKS = [b'eaac', b'javelin', b'electronic arts', b'eaanticheat', b'eac', b'anticheat',
         b'themida', b'.grfn', b'winio', b'\\device\\', b'driverentry']


def rva2off(secs, rva):
    for name, va, vs, rp, rs in secs:
        if va <= rva < va + max(vs, rs):
            return rp + (rva - va)
    return None


def cstr(d, off, maxlen=256):
    if off is None or off >= len(d):
        return None
    end = d.find(b'\0', off, min(len(d), off + maxlen))
    if end < 0:
        return None
    try:
        return d[off:end].decode('ascii')
    except UnicodeDecodeError:
        return None


def analyze(path):
    d = open(path, 'rb').read()
    if len(d) < 0x200 or d[:2] != b'MZ':
        return None
    e = struct.unpack_from('<I', d, 0x3C)[0]
    if e + 0x100 > len(d) or d[e:e+4] != b'PE\0\0':
        return None
    coff = e + 4
    machine, nsec = struct.unpack_from('<HH', d, coff)
    ts = struct.unpack_from('<I', d, coff + 4)[0]
    optsz = struct.unpack_from('<H', d, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from('<H', d, opt)[0]
    pe64 = magic == 0x20b
    size_img = struct.unpack_from('<I', d, opt + 56)[0]
    dd = opt + (112 if pe64 else 96)
    secs = []
    so = opt + optsz
    for i in range(nsec):
        s = so + i * 40
        nm = d[s:s+8].rstrip(b'\0').decode('latin1', 'ignore')
        vs, va, rs, rp = struct.unpack_from('<IIII', d, s + 8)
        secs.append((nm, va, vs, rp, rs))
    # imports
    imp = []
    if dd + 8 <= len(d):
        imp_rva, imp_sz = struct.unpack_from('<II', d, dd + 8)
        off = rva2off(secs, imp_rva) if imp_rva else None
        while off and off + 20 <= len(d):
            name_rva, _, _, first_thunk, orig_thunk = struct.unpack_from('<IIIII', d, off)[:5]
            if name_rva == 0 and first_thunk == 0:
                break
            dll = cstr(d, rva2off(secs, name_rva))
            fns = []
            t_rva = orig_thunk or first_thunk
            t_off = rva2off(secs, t_rva)
            while t_off and t_off + (8 if pe64 else 4) <= len(d):
                val = struct.unpack_from('<Q' if pe64 else '<I', d, t_off)[0]
                if val == 0:
                    break
                if not (val & (1 << 63)) and not (val & 0x80000000):
                    fn = cstr(d, rva2off(secs, val & 0x7FFFFFFF), 128)
                    if fn:
                        fns.append(fn)
                t_off += 8 if pe64 else 4
                if len(fns) > 12:
                    break
            imp.append((dll, fns))
            off += 20
    # markers
    low = d.lower()
    hits = sorted({m.decode() for m in MARKS if m in low})
    return dict(path=path, size=len(d), ts=ts, size_img=size_img, secs=secs,
                imports=imp, hits=hits, machine=machine)


def main():
    rows = []
    for f in sorted(glob.glob(r'C:\ProgramData\kmod_*.bin')):
        r = analyze(f)
        if r:
            rows.append(r)
    rows.sort(key=lambda x: -len(x['hits']))
    for r in rows:
        print(f"\n=== {os.path.basename(r['path'])}  {r['size']}B  SizeOfImage=0x{r['size_img']:X}  ts=0x{r['ts']:08X} ===")
        print("  sections:", ', '.join(f"{n}(0x{vs:X})" for n, va, vs, rp, rs in r['secs']))
        if r['hits']:
            print("  markers :", ', '.join(r['hits']))
        for dll, fns in r['imports'][:4]:
            print(f"  import  : {dll}  ->  {', '.join(fns[:8])}")


if __name__ == '__main__':
    main()
