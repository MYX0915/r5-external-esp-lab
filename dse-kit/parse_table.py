"""parse_table.py -- 解析 ntoskrnl .rdata 0x1B18 处那张 0x18 步长的表

每项结构（推断）：
  +0x00  PVOID  -> 指向隐藏镜像内某个位置
  +0x08  ULONG  标志/计数
  +0x10  PVOID  -> 指向 ntoskrnl 内某个位置

目标：数出总项数，并把第三字段换算成 ntoskrnl RVA，
      再用 .pdata 判断它是否正好落在某个函数入口上（若是，说明它记录的是"被 hook 的函数"）。
"""
import glob, os, struct

NT_BASE = 0xFFFFF800E2C00000
m = open(r'C:\ProgramData\ntoskrnl_mem.bin', 'rb').read()

# 隐藏镜像范围
HID = []
for f in glob.glob(r'C:\ProgramData\kmod_*.bin'):
    d = open(f, 'rb').read()
    if d[:2] != b'MZ':
        continue
    e = struct.unpack_from('<I', d, 0x3C)[0]
    if d[e:e+4] != b'PE\0\0':
        continue
    optsz = struct.unpack_from('<H', d, e + 20)[0]
    sz = struct.unpack_from('<I', d, e + 24 + 56)[0]
    b = int(os.path.basename(f)[5:-4], 16)
    HID.append((b, b + min(sz, len(d)), os.path.basename(f)))
HID.sort()

def img_of(v):
    for b, e2, n in HID:
        if b <= v < e2:
            return n, v - b
    return None

# .pdata 里的函数边界（rva）
PD_RVA, PD_SIZE = 0xE2000, 0x6F8F4
funcs = []
for i in range(PD_SIZE // 12):
    b, e2, u = struct.unpack_from('<III', m, PD_RVA + i * 12)
    if b == 0 or b >= len(m):
        continue
    funcs.append((b, e2))
funcs.sort()
starts = {b for b, _ in funcs}

def containing_func(rva):
    lo, hi = 0, len(funcs) - 1
    best = None
    while lo <= hi:
        mid = (lo + hi) // 2
        if funcs[mid][0] <= rva:
            best = funcs[mid]
            lo = mid + 1
        else:
            hi = mid - 1
    if best and best[0] <= rva < best[1]:
        return best
    return None

# 导出表
hdr_e = struct.unpack_from('<I', m, 0x3C)[0]
opt = hdr_e + 24
exp_rva, exp_sz = struct.unpack_from('<II', m, opt + 0x70)
nf = struct.unpack_from('<I', m, exp_rva + 0x14)[0]
nn = struct.unpack_from('<I', m, exp_rva + 0x18)[0]
af, an, ao = struct.unpack_from('<III', m, exp_rva + 0x1C)
exp = {}
for i in range(nn):
    nr = struct.unpack_from('<I', m, an + i * 4)[0]
    nm = m[nr:m.find(b'\0', nr)].decode('latin1', 'ignore')
    oi = struct.unpack_from('<H', m, ao + i * 2)[0]
    fr = struct.unpack_from('<I', m, af + oi * 4)[0]
    exp.setdefault(fr, nm)

START = 0x1B18
# 向前找到表头
s = START
while s - 0x18 >= 0:
    v0 = struct.unpack_from('<Q', m, s - 0x18)[0]
    if img_of(v0):
        s -= 0x18
    else:
        break
# 向后数
entries = []
i = s
while i + 0x18 <= len(m):
    v0, v1, v2 = struct.unpack_from('<QQQ', m, i)
    hit = img_of(v0)
    if not hit:
        break
    entries.append((i, v0, v1, v2, hit))
    i += 0x18

print(f"表起点 rva=0x{s:X}  项数={len(entries)}  表尾 rva=0x{i:X}\n")
by_img = {}
funhit = 0
for rva, v0, v1, v2, (name, off) in entries:
    nt_rva = (v2 - NT_BASE) if NT_BASE <= v2 < NT_BASE + len(m) else None
    f = containing_func(nt_rva) if nt_rva is not None else None
    at_entry = (f is not None and f[0] == nt_rva)
    nm = exp.get(f[0], '') if f else ''
    if at_entry:
        funhit += 1
    by_img.setdefault(name, []).append((rva, off, v1, nt_rva, f, nm, at_entry))

for name, lst in sorted(by_img.items(), key=lambda kv: -len(kv[1])):
    print(f"=== {name}: {len(lst)} 项 ===")
    for rva, off, v1, nt_rva, f, nm, at_entry in lst[:12]:
        fs = f"函数 rva=0x{f[0]:X}" if f else "非函数内"
        tag = " <<= 指向函数入口" if at_entry else ""
        nm_s = f" [{nm}]" if nm else ""
        print(f"  表项@0x{rva:X}: img+0x{off:<8X} flag=0x{v1:X} -> nt_rva=0x{nt_rva:X} {fs}{nm_s}{tag}")
    print()

print(f"总计 {len(entries)} 项，其中 {funhit} 项的第三字段正好落在函数入口上")
