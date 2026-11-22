"""cluster_scan.py -- 扫 16 个 ts=0 镜像里所有指向 ntoskrnl 地址范围的指针
（不限于导出函数），并用 .pdata 反查目标函数。

修正上一版的缺口：之前只匹配导出函数，会漏掉指向 ntoskrnl 内部函数的指针。
"""
import glob, os, struct

NT_BASE = 0xFFFFF80790400000
NT_SIZE = 0x1450000
m = open(r'C:\ProgramData\ntoskrnl_mem.bin', 'rb').read()

# ntoskrnl .pdata 函数表
PD_RVA, PD_SIZE = 0xE2000, 0x6F8F4
funcs = []
for i in range(PD_SIZE // 12):
    b, e2, u = struct.unpack_from('<III', m, PD_RVA + i * 12)
    if 0 < b < len(m):
        funcs.append((b, e2))
funcs.sort()

def containing(rva):
    lo, hi, best = 0, len(funcs) - 1, None
    while lo <= hi:
        mid = (lo + hi) // 2
        if funcs[mid][0] <= rva:
            best = funcs[mid]; lo = mid + 1
        else:
            hi = mid - 1
    if best and best[0] <= rva < best[1]:
        return best
    return None

# 导出
hdr = struct.unpack_from('<I', m, 0x3C)[0]
opt = hdr + 24
exp_rva, _ = struct.unpack_from('<II', m, opt + 0x70)
nn = struct.unpack_from('<I', m, exp_rva + 0x18)[0]
af, an, ao = struct.unpack_from('<III', m, exp_rva + 0x1C)
exp = {}
for i in range(nn):
    nr = struct.unpack_from('<I', m, an + i * 4)[0]
    nm = m[nr:m.find(b'\0', nr)].decode('latin1', 'ignore')
    oi = struct.unpack_from('<H', m, ao + i * 2)[0]
    fr = struct.unpack_from('<I', m, af + oi * 4)[0]
    exp[fr] = nm

# 只看 16 个 ts=0 镜像
files = []
for f in sorted(glob.glob(r'C:\ProgramData\kmod_*.bin')):
    d = open(f, 'rb').read()
    if d[:2] != b'MZ':
        continue
    e = struct.unpack_from('<I', d, 0x3C)[0]
    if d[e:e+4] != b'PE\0\0':
        continue
    ts = struct.unpack_from('<I', d, e + 8)[0]
    if ts != 0:
        continue
    files.append((f, d))

print(f"ts=0 镜像 {len(files)} 个\n")

total = 0
for f, d in files:
    base = int(os.path.basename(f)[5:-4], 16)
    e = struct.unpack_from('<I', d, 0x3C)[0]
    optsz = struct.unpack_from('<H', d, e + 20)[0]
    opt2 = e + 24
    size_img = struct.unpack_from('<I', d, opt2 + 56)[0]
    hits = {}
    n = min(size_img, len(d))
    for i in range(0, n - 8):
        v = struct.unpack_from('<Q', d, i)[0]
        if not (NT_BASE <= v < NT_BASE + NT_SIZE):
            continue
        rva = v - NT_BASE
        hits.setdefault(rva, []).append(i)
    if not hits:
        continue
    total += len(hits)
    print(f"=== {os.path.basename(f)} (0x{base:X}, 0x{size_img:X}) 命中 {len(hits)} 个不同目标 ===")
    for rva in sorted(hits)[:14]:
        fn = containing(rva)
        nm = exp.get(fn[0], '') if fn else ''
        at_entry = (fn and fn[0] == rva)
        fs = f"fun 0x{fn[0]:X}" if fn else "非函数"
        tag = " [导出]" if nm else (" [函数入口]" if at_entry else "")
        print(f"   -> nt_rva=0x{rva:<9X} {fs}{(' '+nm) if nm else ''}{tag}   出现在镜像 +0x{hits[rva][0]:X}")

print(f"\n合计 {total} 个不同目标")
