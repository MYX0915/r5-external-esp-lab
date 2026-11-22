"""xref_boot.py -- 离线重建 ntoskrnl 内存镜像（施加 KASLR 重定位），
                   再扫描其中指向"本次启动的隐藏镜像"的指针

隐藏镜像基址从当前 C:\\ProgramData\\kmod_*.bin 的文件名解析（同一启动）。
ntoskrnl 运行基址从 dumper2 日志里取（PE base=... size=0x1450000 ts=0x6674BB5E）。
"""
import glob, os, re, struct

KRNL = r"C:\Windows\System32\ntoskrnl.exe"

# 1) 从日志找本次启动的 ntoskrnl 基址
base_rt = None
for line in open(r"C:\ProgramData\kmaplog.txt", errors='ignore'):
    m = re.search(r'\[dumper2\] PE base=0x([0-9A-F]+) size=0x1450000 ts=0x6674BB5E', line)
    if m:
        base_rt = int(m.group(1), 16)
if base_rt is None:
    print("未在日志中找到 ntoskrnl 基址"); raise SystemExit
print(f"ntoskrnl 运行基址 = 0x{base_rt:X}")

# 2) 隐藏镜像范围
HID = []
for f in glob.glob(r'C:\ProgramData\kmod_*.bin'):
    d = open(f, 'rb').read()
    if d[:2] != b'MZ':
        continue
    e = struct.unpack_from('<I', d, 0x3C)[0]
    if d[e:e+4] != b'PE\0\0':
        continue
    optsz = struct.unpack_from('<H', d, e + 20)[0]
    size_img = struct.unpack_from('<I', d, e + 24 + 56)[0]
    base = int(os.path.basename(f)[5:-4], 16)
    HID.append((base, min(size_img, len(d)), os.path.basename(f)))
HID.sort()
print(f"隐藏镜像 {len(HID)} 个，范围 0x{HID[0][0]:X} ~ 0x{HID[-1][0]+HID[-1][1]:X}")

# 3) 读文件、解析节与重定位
d = bytearray(open(KRNL, 'rb').read())
e = struct.unpack_from('<I', d, 0x3C)[0]
nsec = struct.unpack_from('<H', d, e + 6)[0]
optsz = struct.unpack_from('<H', d, e + 20)[0]
opt = e + 24
pref = struct.unpack_from('<Q', d, opt + 24)[0]
size_img = struct.unpack_from('<I', d, opt + 56)[0]
secs = []
so = opt + optsz
for i in range(nsec):
    s = so + i * 40
    nm = d[s:s + 8].rstrip(b'\0').decode('latin1', 'ignore')
    vs, va, rs, rp = struct.unpack_from('<IIII', d, s + 8)
    secs.append((nm, va, vs, rp, rs))
rel_rva, rel_sz = struct.unpack_from('<II', d, opt + 0x70 + 5 * 8)


def r2o(rva):
    for nm, va, vs, rp, rs in secs:
        if va <= rva < va + max(vs, rs):
            return rp + (rva - va)
    return None


delta = (base_rt - pref) & 0xFFFFFFFFFFFFFFFF
print(f"preferred=0x{pref:X}  delta=0x{delta:X}")

# 施加重定位（就地改文件缓冲区）
off = r2o(rel_rva)
cnt64 = cnt32 = 0
if off:
    p = off
    end = off + rel_sz
    while p + 8 <= end:
        page, bsz = struct.unpack_from('<II', d, p)
        if bsz < 8:
            break
        n = (bsz - 8) // 2
        for i in range(n):
            ee = struct.unpack_from('<H', d, p + 8 + i * 2)[0]
            t, o = ee >> 12, ee & 0xFFF
            fo = r2o(page + o)
            if fo is None:
                continue
            if t == 10 and fo + 8 <= len(d):
                v = struct.unpack_from('<Q', d, fo)[0]
                struct.pack_into('<Q', d, fo, (v + delta) & 0xFFFFFFFFFFFFFFFF)
                cnt64 += 1
            elif t == 3 and fo + 4 <= len(d):
                v = struct.unpack_from('<I', d, fo)[0]
                struct.pack_into('<I', d, fo, (v + delta) & 0xFFFFFFFF)
                cnt32 += 1
        p += bsz
print(f"应用重定位: DIR64={cnt64} HIGHLOW={cnt32}")

# 重建 RVA 视图
img = bytearray(size_img)
for nm, va, vs, rp, rs in secs:
    n = min(vs, rs, size_img - va)
    if n > 0:
        img[va:va + n] = d[rp:rp + n]

# 4) 扫描指向隐藏镜像的指针
ranges = [(b, b + s, n) for b, s, n in HID]
hits = {}
for i in range(0, size_img - 8):
    v = struct.unpack_from('<Q', img, i)[0]
    for b, e2, name in ranges:
        if b <= v < e2:
            hits.setdefault(name, []).append((i, v - b))
            break

print(f"\n命中 {sum(len(v) for v in hits.values())} 处")
for name, lst in sorted(hits.items(), key=lambda kv: -len(kv[1])):
    print(f"\n  {name}: {len(lst)} 处")
    for rva, off in lst[:10]:
        print(f"     ntoskrnl rva=0x{rva:X} -> 镜像内 +0x{off:X}")
