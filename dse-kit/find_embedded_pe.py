"""find_embedded_pe.py -- 在超大文件里找内嵌 PE 镜像（尤其 NATIVE 子系统的驱动）

用法: python find_embedded_pe.py <file> [min_size]
"""
import struct, sys, os

SUBSYS = {1: 'NATIVE', 2: 'GUI', 3: 'CUI', 9: 'WINCE', 10: 'EFI'}


def scan(path, min_size=0x1000):
    d = open(path, 'rb').read()
    n = len(d)
    print(f"{os.path.basename(path)}  size={n:#x}  ({n/1024/1024:.1f} MB)")
    i = 0
    found = 0
    while True:
        i = d.find(b'MZ', i)
        if i < 0 or i + 0x40 > n:
            break
        try:
            e = struct.unpack_from('<I', d, i + 0x3C)[0]
        except struct.error:
            break
        if not (0x40 <= e < 0x1000) or i + e + 0x100 > n:
            i += 2
            continue
        if d[i + e:i + e + 4] != b'PE\0\0':
            i += 2
            continue
        coff = i + e + 4
        try:
            machine, nsec = struct.unpack_from('<HH', d, coff)
            ts = struct.unpack_from('<I', d, coff + 4)[0]
            optsz = struct.unpack_from('<H', d, coff + 16)[0]
            opt = coff + 20
            magic = struct.unpack_from('<H', d, opt)[0]
        except struct.error:
            i += 2
            continue
        if magic not in (0x10b, 0x20b) or nsec == 0 or nsec > 96:
            i += 2
            continue
        pe64 = magic == 0x20b
        try:
            subsys = struct.unpack_from('<H', d, opt + (68 if pe64 else 68))[0]
            size_img = struct.unpack_from('<I', d, opt + 56)[0]
            ep = struct.unpack_from('<I', d, opt + 16)[0]
        except struct.error:
            i += 2
            continue
        if size_img < min_size or size_img > 0x8000000:
            i += 2
            continue
        # 节名
        nsec_real = nsec
        so = opt + optsz
        names = []
        ok = True
        for k in range(min(nsec_real, 8)):
            s = so + k * 40
            if s + 40 > n:
                ok = False
                break
            nm = d[s:s + 8].rstrip(b'\0').decode('latin1', 'ignore')
            names.append(nm)
        if not ok:
            i += 2
            continue
        print(f"  @0x{i:08X}  {SUBSYS.get(subsys, subsys):<6} img=0x{size_img:<8X} ep=0x{ep:<6X} "
              f"ts=0x{ts:08X} nsec={nsec_real}  [{', '.join(names)}]")
        found += 1
        i += size_img if size_img else 2
    print(f"  -> {found} 个内嵌 PE")


if __name__ == '__main__':
    scan(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 0x1000)
