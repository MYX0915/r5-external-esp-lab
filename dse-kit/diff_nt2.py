"""diff_nt2.py -- 精确比对：运行中 ntoskrnl 内存 vs 磁盘文件，排除重定位影响

重定位处理：解析 .reloc 全部块，把 DIR64/HIGHLOW 覆盖的字节位置收集起来，
比对时跳过这些位置（它们因 KASLR 基址不同必然不同）。

输出：剩余差异（即真正的 patch），带 RVA、原始/新字节，并识别跳转目标。
"""
import struct, sys

KRNL = r"C:\Windows\System32\ntoskrnl.exe"
MEM = r"C:\ProgramData\ntoskrnl_mem.bin"


def parse(d):
    e = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, e + 6)[0]
    optsz = struct.unpack_from('<H', d, e + 20)[0]
    opt = e + 24
    secs = []
    so = opt + optsz
    for i in range(nsec):
        s = so + i * 40
        nm = d[s:s + 8].rstrip(b'\0').decode('latin1', 'ignore')
        vs, va, rs, rp = struct.unpack_from('<IIII', d, s + 8)
        secs.append((nm, va, vs, rp, rs))
    rel_rva, rel_sz = struct.unpack_from('<II', d, opt + 0x70 + 5 * 8)
    return e, secs, rel_rva, rel_sz


def rva2off(secs, rva):
    for nm, va, vs, rp, rs in secs:
        if va <= rva < va + max(vs, rs):
            return rp + (rva - va)
    return None


def reloc_set(d, secs, rel_rva, rel_sz):
    out = set()
    off = rva2off(secs, rel_rva)
    if off is None:
        return out
    end = off + rel_sz
    p = off
    blocks = 0
    while p + 8 <= end:
        page, size = struct.unpack_from('<II', d, p)
        if size < 8:
            break
        n = (size - 8) // 2
        for i in range(n):
            if p + 8 + i * 2 + 2 > len(d):
                break
            e = struct.unpack_from('<H', d, p + 8 + i * 2)[0]
            t = e >> 12
            o = e & 0xFFF
            if t in (3, 10):
                width = 4 if t == 3 else 8
                for k in range(width):
                    out.add(page + o + k)
        p += size
        blocks += 1
    print(f"重定位块数={blocks}  受影响的字节位置={len(out)}")
    return out


def main():
    d = open(KRNL, 'rb').read()
    m = open(MEM, 'rb').read()
    e, secs, rel_rva, rel_sz = parse(d)
    print(f"磁盘 ntoskrnl = {len(d):#x}   内存镜像 = {len(m):#x}")
    rel = reloc_set(d, secs, rel_rva, rel_sz)

    diffs = []
    for nm, va, vs, rp, rs in secs:
        if nm not in ('.text', 'PAGE', 'INIT'):
            continue
        chunk = d[rp:rp + rs]
        n = min(len(chunk), max(0, len(m) - va))
        for i in range(n):
            rva = va + i
            if rva in rel:
                continue
            if chunk[i] != m[rva]:
                diffs.append(rva)

    ranges = []
    for r in diffs:
        if ranges and r == ranges[-1][1] + 1:
            ranges[-1][1] = r
        else:
            ranges.append([r, r])

    print(f"\n差异字节={len(diffs)}  差异区间={len(ranges)}")
    for a, b in ranges[:40]:
        o = rva2off(secs, a)
        mm = m[a:b + 1]
        ff = d[o:o + (b - a + 1)]
        tag = ''
        if len(mm) >= 5 and mm[0] == 0xE9:
            rel32 = struct.unpack_from('<i', mm, 1)[0]
            tag = f'  E9 -> rva 0x{(a + 5 + rel32) & 0xFFFFFFFF:X}'
        elif len(mm) >= 12 and mm[0] == 0x48 and mm[1] == 0xB8 and mm[10] == 0xFF and mm[11] == 0xE0:
            tag = '  MOV RAX,IMM64;JMP RAX'
        print(f"  rva=0x{a:X}-0x{b:X} ({b - a + 1}B)  mem={mm.hex(' ')}  file={ff.hex(' ')}{tag}")


if __name__ == '__main__':
    main()
