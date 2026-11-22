"""analyze_cfgtarget.py -- 分析 CFGRO 指向的那 4 个函数（kmod_FFFFF800783BA000.bin）

输出：模块节表、.pdata 函数清单、4 个目标偏移所属函数、函数体反汇编、
      以及函数体里所有"跳出模块"的地址引用（指向 ntoskrnl 或其它模块）
"""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

IMG = r'C:\ProgramData\kmod_FFFFF800783BA000.bin'
BASE = 0xFFFFF800783BA000
TARGETS = [0x1954, 0x195C, 0x1964, 0x196C]

d = open(IMG, 'rb').read()
md = Cs(CS_ARCH_X86, CS_MODE_64)

e = struct.unpack_from('<I', d, 0x3C)[0]
nsec = struct.unpack_from('<H', d, e + 6)[0]
optsz = struct.unpack_from('<H', d, e + 20)[0]
opt = e + 24
ep = struct.unpack_from('<I', d, opt + 16)[0]
size_img = struct.unpack_from('<I', d, opt + 56)[0]
ts = struct.unpack_from('<I', d, e + 8)[0]
secs = []
so = opt + optsz
for i in range(nsec):
    s = so + i * 40
    nm = d[s:s + 8].rstrip(b'\0').decode('latin1', 'ignore')
    vs, va, rs, rp = struct.unpack_from('<IIII', d, s + 8)
    ch = struct.unpack_from('<I', d, s + 36)[0]
    secs.append((nm, va, vs, rp, rs, ch))

print(f"镜像 {IMG.split(chr(92))[-1]}  size={len(d)} SizeOfImage=0x{size_img:X} ep=0x{ep:X} ts=0x{ts:08X}")
print("节表:")
for nm, va, vs, rp, rs, ch in secs:
    fl = ''.join([c for c, m in (('R', 0x40000000), ('W', 0x80000000), ('X', 0x20000000)) if ch & m])
    print(f"   {nm or '(noname)':<10} va=0x{va:<7X} vs=0x{vs:<7X} raw=0x{rp:<7X} flags={fl}")

def r2o(rva):
    for nm, va, vs, rp, rs, ch in secs:
        if va <= rva < va + max(vs, rs):
            return rp + (rva - va)
    return None

# .pdata 函数表
pdata = [s for s in secs if s[0] == '.pdata']
funcs = []
if pdata:
    nm, va, vs, rp, rs, ch = pdata[0]
    cnt = vs // 12
    for i in range(cnt):
        b, e2, u = struct.unpack_from('<III', d, rp + i * 12)
        if b == 0 or b >= size_img:
            continue
        funcs.append((b, e2))
    funcs.sort()
    print(f"\n.pdata 函数数 = {len(funcs)}")
    for b, e2 in funcs[:20]:
        print(f"   fun 0x{b:<7X} - 0x{e2:<7X} (size 0x{e2-b:X})")

def containing(rva):
    for b, e2 in funcs:
        if b <= rva < e2:
            return (b, e2)
    return None

# 模块内合法范围（用于判定"跳出"）
in_range = lambda v: v == 0 or (v >= BASE and v < BASE + size_img)

print("\n" + "=" * 60)
for t in TARGETS:
    f = containing(t)
    print(f"\n=== 目标 +0x{t:X} ===")
    if f:
        print(f"   所属函数: 0x{f[0]:X} - 0x{f[1]:X} (size 0x{f[1]-f[0]:X})")
    else:
        print("   不在 .pdata 函数内（可能是数据或叶函数）")
    o = r2o(t)
    if o is None:
        print("   无法定位到文件偏移")
        continue
    print("   反汇编:")
    for ins in md.disasm(d[o:o + 0x48], t):
        print(f"     +0x{ins.address:X} {ins.mnemonic:<7} {ins.op_str}")

# 对这些函数整体做"外部引用"扫描
print("\n" + "=" * 60)
print("目标函数体内指向模块外的地址（可能是 ntoskrnl 或其它模块）:")
seen = set()
for t in TARGETS:
    f = containing(t)
    if not f:
        continue
    if f in seen:
        continue
    seen.add(f)
    o = r2o(f[0])
    if o is None:
        continue
    body = d[o:o + (f[1] - f[0])]
    print(f"\n  函数 0x{f[0]:X}-0x{f[1]:X}:")
    n = 0
    for ins in md.disasm(body, f[0]):
        if 'rip' in ins.op_str and ('+' in ins.op_str or '-' in ins.op_str):
            import re
            m = re.search(r'rip ([+-]) (0x[0-9a-f]+)', ins.op_str)
            if m:
                sign = 1 if m.group(1) == '+' else -1
                tgt = ins.address + ins.size + sign * int(m.group(2), 16)
                if not in_range(tgt):
                    print(f"     +0x{ins.address:X} {ins.mnemonic} {ins.op_str}  -> 0x{tgt:016X}")
                    n += 1
        if ins.mnemonic == 'movabs' and ins.op_str.startswith('r'):
            m2 = re.search(r'(0x[0-9a-f]{12,})', ins.op_str)
            if m2:
                v = int(m2.group(1), 16)
                if not in_range(v):
                    print(f"     +0x{ins.address:X} {ins.mnemonic} {ins.op_str}  -> 0x{v:016X}")
                    n += 1
        if n > 12:
            break
