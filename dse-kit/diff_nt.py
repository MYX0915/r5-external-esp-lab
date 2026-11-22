"""diff_nt.py -- 运行中 ntoskrnl 内存 vs 磁盘文件，找被 patch 的字节（排除重定位点）

输出：所有差异区间，标注 RVA 与差异字节。命中 `E9 rel32` / `48 B8 imm64 FF E0`
      且目标在 ntoskrnl 之外的，基本就是 AС 的 inline hook。
"""
import sys, struct, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kva

KRNL = r"C:\Windows\System32\ntoskrnl.exe"


def parse_pe(d):
    e = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, e + 6)[0]
    optsz = struct.unpack_from('<H', d, e + 20)[0]
    opt = e + 24
    base = struct.unpack_from('<Q', d, opt + 24)[0]
    secs = []
    so = opt + optsz
    for i in range(nsec):
        s = so + i * 40
        name = d[s:s + 8].rstrip(b'\0').decode('latin1')
        vs, va, rs, rp = struct.unpack_from('<IIII', d, s + 8)
        secs.append((name, va, vs, rp, rs))
    rel_rva, rel_sz = struct.unpack_from('<II', d, opt + 0x70 + 5 * 8)
    return e, base, secs, rel_rva, rel_sz


def reloc_offsets(d, secs, rel_rva, rel_sz, rva2off):
    out = set()
    off = rva2off(rel_rva)
    if off is None:
        return out
    end = off + rel_sz
    p = off
    while p < end:
        page, blocksize = struct.unpack_from('<II', d, p)
        if blocksize < 8:
            break
        n = (blocksize - 8) // 2
        for i in range(n):
            e = struct.unpack_from('<H', d, p + 8 + i * 2)[0]
            t = e >> 12
            o = e & 0xFFF
            if t in (3, 10):                 # HIGHLOW / DIR64
                out.add(page + o)
        p += blocksize
    return out


def main():
    d = open(KRNL, 'rb').read()
    e, pref, secs, rel_rva, rel_sz = parse_pe(d)

    def rva2off(rva):
        for name, va, vs, rp, rs in secs:
            if va <= rva < va + max(vs, rs):
                return rp + (rva - va)
        return None

    relocs = reloc_offsets(d, secs, rel_rva, rel_sz, rva2off)
    print(f"重定位点数量: {len(relocs)}")

    k = kva.KVA()
    base, size = kva.nt_base()
    print(f"运行 ntoskrnl = 0x{base:X} size=0x{size:X}")
    mem = k.read(base, size)
    if not mem:
        print("读取失败"); return

    diffs = []
    for name, va, vs, rp, rs in secs:
        if name not in ('.text', 'PAGE', 'INIT'):
            continue
        chunk = d[rp:rp + rs]
        n = min(len(chunk), max(0, size - va))
        for i in range(n):
            rva = va + i
            if rva in relocs:
                continue
            if chunk[i] != mem[rva]:
                diffs.append(rva)
    # 合并成连续区间
    ranges = []
    for r in diffs:
        if ranges and r == ranges[-1][1] + 1:
            ranges[-1][1] = r
        else:
            ranges.append([r, r])
    print(f"差异区间数: {len(ranges)}  差异字节数: {len(diffs)}")
    for a, b in ranges[:40]:
        m = mem[a:b + 1]
        s = d[rva2off(a):rva2off(a) + (b - a + 1)]
        tag = ''
        if len(m) >= 5 and m[0] == 0xE9:
            t = base + a + 5 + struct.unpack_from('<i', m, 1)[0]
            tag = f'  E9->0x{t:X}'
        elif len(m) >= 12 and m[0] == 0x48 and m[1] == 0xB8 and m[10] == 0xFF and m[11] == 0xE0:
            t = struct.unpack_from('<Q', m, 2)[0]
            tag = f'  MOVJMP->0x{t:X}'
        print(f"  rva=0x{a:X}-0x{b:X} ({b - a + 1}B) mem={m.hex(' ')} file={s.hex(' ')}{tag}")


if __name__ == '__main__':
    main()
