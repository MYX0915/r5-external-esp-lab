"""xref_fixed.py -- 修正版交叉引用

修正点：ntoskrnl 的"占用范围"只按**真实节**计算（排除 Pad* 空洞），
        否则其它模块在空洞里的地址会被误判成"指向隐藏镜像"。
"""
import glob, os, struct

NT_BASE = 0xFFFFF800E2C00000
m = open(r'C:\ProgramData\ntoskrnl_mem.bin', 'rb').read()

# --- ntoskrnl 真实节范围（排除 Pad）
e = struct.unpack_from('<I', m, 0x3C)[0]
nsec = struct.unpack_from('<H', m, e + 6)[0]
optsz = struct.unpack_from('<H', m, e + 20)[0]
opt = e + 24
nt_secs = []
so = opt + optsz
for i in range(nsec):
    s = so + i * 40
    nm = m[s:s + 8].rstrip(b'\0').decode('latin1', 'ignore')
    vs, va, rs, rp = struct.unpack_from('<IIII', m, s + 8)
    if nm.startswith('Pad') or vs == 0:
        continue
    nt_secs.append((NT_BASE + va, NT_BASE + va + vs, nm))
print(f"ntoskrnl 真实节 {len(nt_secs)} 个，覆盖:")
for a, b, nm in nt_secs[:6]:
    print(f"   {nm:<10} 0x{a:X} ~ 0x{b:X}")

def in_nt(v):
    for a, b, _ in nt_secs:
        if a <= v < b:
            return True
    return False

# --- 候选隐藏镜像：去掉落在 ntoskrnl 真实节里的
HID = []
dropped = []
for f in glob.glob(r'C:\ProgramData\kmod_*.bin'):
    d = open(f, 'rb').read()
    if d[:2] != b'MZ':
        continue
    e2 = struct.unpack_from('<I', d, 0x3C)[0]
    if d[e2:e2+4] != b'PE\0\0':
        continue
    optsz2 = struct.unpack_from('<H', d, e2 + 20)[0]
    sz = struct.unpack_from('<I', d, e2 + 24 + 56)[0]
    b = int(os.path.basename(f)[5:-4], 16)
    if in_nt(b):
        dropped.append((b, sz, os.path.basename(f)))
        continue
    HID.append((b, b + min(sz, len(d)), os.path.basename(f)))
HID.sort()
print(f"\n有效隐藏镜像 {len(HID)} 个（丢弃 {len(dropped)} 个：起点落在 ntoskrnl 真实节内）")
for b, e2, n in HID:
    print(f"   0x{b:016X}  0x{e2 - b:X}  {n}")

if not HID:
    print("\n没有有效隐藏镜像 —— 说明之前 dump 的 29 个全都与 ntoskrnl 节重叠")
    raise SystemExit

# --- 扫描
hits = {}
for i in range(0, len(m) - 8):
    v = struct.unpack_from('<Q', m, i)[0]
    if v < 0xFFFFF80000000000:
        continue
    if in_nt(v):
        continue
    for b, e2, n in HID:
        if b <= v < e2:
            hits.setdefault(n, []).append((i, v - b))
            break

print(f"\n命中 {sum(len(v) for v in hits.values())} 处")
for n, lst in sorted(hits.items(), key=lambda kv: -len(kv[1])):
    print(f"\n  {n}: {len(lst)} 处")
    for rva, off in lst[:8]:
        print(f"     ntoskrnl rva=0x{rva:X} -> 镜像内 +0x{off:X}")
